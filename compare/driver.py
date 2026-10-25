#!/usr/bin/env python3
"""Compare SDK execution with OpenTofu, retaining private state for recovery."""
import argparse,csv,io,json,os,re,secrets,shutil,subprocess,sys,time
from decimal import Decimal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from verify_absence import verify
from runtime import clean,load,write,ALLOWANCE
MANIFEST=load(ROOT/'compare/manifest.json')['examples']

def update_results():
    records={}
    for path in sorted((ROOT/'compare/evidence').glob('*.json')):
        record=load(path)
        if record.get('example') in MANIFEST:records[record['example']]=record
    lines=['# lmaws ↔ lmcloud comparisons','','Native writes run once with profile `lmaws`; native evidence can be reused. Read-only runs use `default`. IAM is deliberately skipped. Resource names are compared after replacing each unique run ID; payload objects/items are separately noted because the SDK ledger tracks their owning parent. Provider API cost is a conservative allowance, not observed request accounting. Raw state and logs stay under ignored `compare/runs/`.','','| Example | Native live result / estimated cost | lmcloud result / estimated cost | Resources, names and tags | Outputs / wall seconds | Cleanup | Same / differs / why |','| --- | --- | --- | --- | --- | --- | --- |']
    for name,meta in sorted(MANIFEST.items()):
        r=records.get(name)
        if not r:
            label='estimated only; IAM skipped' if meta['iam'] else 'not run'
            lines.append(f'| `{name}` | {label} | {label} | — | — | no attempted resources | {meta["notes"]} |');continue
        native=r['native'];cloud=r['lmcloud'];comp=r.get('comparison',{})
        resource_desc=comp.get('resources','not comparable')
        output=comp.get('outputs','not comparable')
        lines.append(f'| `{name}` | {native["status"]} / ${native.get("total_estimated_usd","0")} | {cloud["status"]} / ${cloud.get("total_estimated_usd","0")} | {resource_desc} | {output}; {native.get("wall_seconds","n/a")} / {cloud.get("wall_seconds","n/a")} | {r.get("leftover_count","unknown")} leftovers | {comp.get("why",meta["notes"]).replace(chr(10)," ").replace("|","/")} |')
    (ROOT/'compare/RESULTS.md').write_text('\n'.join(lines)+'\n')

def equivalent_resources(native,cloud):
    def norm(rows,run):
        return sorted((r['kind'],r['name'].replace(run,'<run>'),tuple(sorted((k,str(v).replace(run,'<run>')) for k,v in r.get('tags',{}).items()))) for r in rows if r['kind'] in ('bucket','queue','topic','parameter','table','log_group'))
    return norm(native.get('resources',[]),native.get('run_id','!'))==norm(cloud.get('resources',[]),cloud.get('run_id','!'))

def compare_outputs(native,cloud,write_mode):
    if native.get('status')!='passed' or cloud.get('status')!='passed':return 'not comparable: an engine was blocked'
    rows=list(csv.reader(io.StringIO(native.get('outputs_csv',''))))
    counts={}
    for row in rows[1:]:
        if len(row)==2:
            try:counts[row[0]]=Decimal(row[1])
            except Exception:pass
    provider=cloud.get('outputs',{}).get('comparison',{}).get('value',{}) or {}
    if write_mode:
        observed=cloud.get('observed_resources',[])
        provider={'created':sum(r['kind'] in ('bucket','queue','topic','parameter','table','log_group') for r in observed),'cleaned':cloud.get('leftover_count')}
        if any(r['kind']=='aws_s3_object' for r in observed):provider['objects']=sum(r['kind']=='aws_s3_object' for r in observed)
        if any(r['kind']=='aws_dynamodb_table_item' for r in observed):provider['items']=sum(r['kind']=='aws_dynamodb_table_item' for r in observed)
    shared={k:v for k,v in provider.items() if k in counts and isinstance(v,(int,float))}
    if not shared:return 'differs: no common numeric output shape'
    equal=all(counts[k]==Decimal(str(v)) for k,v in shared.items())
    missing=set(counts)-set(shared)
    return ('same' if equal and not missing else 'same supported counts; differs in '+','.join(sorted(missing)) if equal else 'differs: numeric outputs disagree')

def check_comparison_budget(native_cost,campaign_cost,cap,write_mode):
    if not cap.is_finite() or cap<0 or cap>Decimal('0.25'):raise RuntimeError('comparison cap must be between zero and 0.25')
    allowance=ALLOWANCE if write_mode else Decimal(0)
    if native_cost+allowance>cap:raise RuntimeError('example cap prohibits the next provider creation')
    if campaign_cost+native_cost+allowance>Decimal('0.25'):raise RuntimeError('whole-run cap prohibits the next provider creation')
    return cap-native_cost

def main():
    ap=argparse.ArgumentParser();ap.add_argument('example',choices=sorted(MANIFEST));ap.add_argument('--offline',action='store_true');ap.add_argument('--native-evidence');ap.add_argument('--host',default=str(ROOT/'target/lmaws'));ap.add_argument('--lmcloud');args=ap.parse_args()
    name=args.example;meta=MANIFEST[name];run_id='r'+secrets.token_hex(4)+'x'+secrets.token_hex(4)
    if meta['iam']:
        record=dict(example=name,run_id=run_id,native=dict(status='estimated_only',total_estimated_usd='0.00'),lmcloud=dict(status='estimated_only',total_estimated_usd='0.00'),leftover_count=0,comparison=dict(why='IAM live calls intentionally skipped under federated profiles',resources='no creations',outputs='estimated, not measured live'))
        write(ROOT/'compare/evidence'/(name+'-'+run_id+'.json'),record);update_results();print(name+': IAM skipped');return 0
    if args.offline:
        script=ROOT/'compare'/name/(name+'.lms');assert script.is_file()
        assert 'tofu.init' in script.read_text() and 'tofu.destroy' in script.read_text()
        assert 'hashicorp/aws' in (script.parent/'main.tf').read_text()
        print(name+': offline fixture contract verified');return 0
    if os.getenv('CI','').lower() in ('true','1','yes') or os.getenv('GITHUB_ACTIONS')=='true':raise RuntimeError('live comparisons forbidden in CI')
    if os.getenv('LMAWS_ENDPOINT'):raise RuntimeError('live comparison forbids LMAWS_ENDPOINT overrides')
    if os.getenv('LMAWS_LIVE')!='1':raise RuntimeError('set LMAWS_LIVE=1 explicitly for a real comparison')
    expected='lmaws' if meta['write'] else 'default'
    if (os.getenv('AWS_PROFILE') or os.getenv('AWS_DEFAULT_PROFILE') or 'default')!=expected:raise RuntimeError('example requires AWS_PROFILE='+expected)
    if os.getenv('AWS_REGION','us-east-1')!='us-east-1':raise RuntimeError('only us-east-1 is allowed')
    work=ROOT/'compare/runs'/name/run_id;work.mkdir(parents=True,exist_ok=False)
    native_work=work/'native';cloud_work=work/'lmcloud';native_work.mkdir();cloud_work.mkdir()
    env=dict(os.environ,AWS_PROFILE=expected,AWS_DEFAULT_PROFILE=expected,AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_COMPARE_RUN_ID=run_id,LMAWS_COMPARE_RUNTIME=str(ROOT/'compare/runtime.py'),LMAWS_COMPARE_VERIFIER=str(ROOT/'scripts/verify_absence.py'),LMAWS_COMPARE_CAMPAIGN=str(ROOT/'compare/runs/campaign.json'),LMAWS_COMPARE_PROVIDER_CACHE=str(ROOT/'compare/private/provider-cache'))
    for k in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_ROLE_SESSION_NAME','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI','LMAWS_ENDPOINT'):env.pop(k,None)
    bindir=work/'bin';bindir.mkdir()
    host=Path(args.host).resolve()
    if host.exists():(bindir/'lmaws').symlink_to(host)
    if args.lmcloud:(bindir/'lmcloud').symlink_to(Path(args.lmcloud).resolve())
    env['PATH']=str(bindir)+os.pathsep+env['PATH']
    if args.native_evidence:
        native=load(Path(args.native_evidence).resolve());assert native.get('example')==name and native.get('profile')==expected and native.get('live')
        native['status']='passed' if native.get('example_exit_code')==0 and not native.get('run_error') else 'blocked'
    else:
        env.update(LMAWS_LEDGER_DIR=str(native_work/'ledgers'),LMAWS_EVIDENCE_DIR=str(native_work/'evidence'))
        started=time.monotonic();p=subprocess.run(['lmscript',str(ROOT/'examples'/(name+'.lms'))],cwd=native_work,env=env,text=True,capture_output=True,timeout=360)
        (native_work/'private.log').write_text(p.stdout+p.stderr)
        files=list((native_work/'evidence').glob('live-cost-'+name+'-*.json'));assert len(files)==1,'native run did not emit unique evidence'
        native=load(files[0]);native['status']='passed' if p.returncode==0 else 'blocked';native['wall_seconds']=round(time.monotonic()-started,6)
        output=native_work/'data'/(name+'.csv')
        if output.exists():native['outputs_csv']=output.read_text()
        count_file=native_work/'data'/(name+'.count')
        if count_file.exists():native['outputs_count']=count_file.read_text().strip()
        # A native write failure still has to prove absence before the provider runs.
    if native.get('leftover_count')!=0:raise RuntimeError('native leftovers prohibit another creation')
    attempted=native.get('resources',[])+[{'kind':v['kind'],'name':v['name']} for v in native.get('rejected_creations',[])]
    previous_verification=sum((Decimal(str(v.get('estimated_usd',0))) for v in native.get('independent_readonly_verification',[])),Decimal(0))
    native['independent_readonly_verification']=verify(attempted)
    for resource in native.get('resources',[]):resource.setdefault('tags',{'lmaws_test':native['run_id']})
    prior=load(ROOT/'compare/runs/campaign.json');campaign=Decimal(str(prior.get('estimated_usd','0')))
    amount=Decimal(str(native.get('total_estimated_usd','0')))+previous_verification+sum((Decimal(str(v.get('estimated_usd',0))) for v in native['independent_readonly_verification']),Decimal(0))
    comparison_cap=Decimal(env.get('LMAWS_MAX_COST_USD','0.05'))
    remaining_cap=check_comparison_budget(amount,campaign,comparison_cap,meta['write'])
    env['LMAWS_MAX_COST_USD']=str(remaining_cap)
    write(ROOT/'compare/runs/campaign.json',{'estimated_usd':str(campaign+amount),'hard_ceiling_usd':'0.25'})
    started=time.monotonic();p=subprocess.run(['lmscript',str(ROOT/'compare'/name/(name+'.lms'))],cwd=cloud_work,env=env,text=True,capture_output=True,timeout=900)
    (cloud_work/'private.log').write_text(p.stdout+p.stderr)
    cloud=load(cloud_work/'cloud-result.json')
    if not cloud:
        cloud=dict(status='compile_or_bootstrap_failed',total_estimated_usd='0',leftover_count=0,run_error='No provider apply was reached; inspect private compile log',wall_seconds=round(time.monotonic()-started,6))
    record=dict(example=name,run_id=run_id,profile=expected,region='us-east-1',native=native,lmcloud=cloud,leftover_count=max(native['leftover_count'],cloud.get('leftover_count',1)),comparison={})
    same=equivalent_resources(native,cloud) if native['status']=='passed' and cloud['status']=='passed' else None
    record['comparison']=dict(resources=('same parent types/names/tags after run-ID normalization' if same else 'differs' if same is False else 'not comparable: a run was blocked'),outputs=compare_outputs(native,cloud,meta['write']),why=meta['notes']+(' Both engines passed.' if same else ' '+native['status']+' vs '+cloud['status']+'.'))
    record['comparison']['estimated_cost_delta_usd']=str(Decimal(str(cloud.get('total_estimated_usd',0)))-Decimal(str(native.get('total_estimated_usd',0))))
    if 'wall_seconds' in native and 'wall_seconds' in cloud:record['comparison']['wall_delta_seconds']=round(cloud['wall_seconds']-native['wall_seconds'],6)
    # Logs, provider state, parameter values and account identifiers never enter public records.
    for record_part in (native,cloud):
        record_part.pop('ledger',None)
        record_part.pop('events',None)
    write(ROOT/'compare/evidence'/(name+'-'+run_id+'.json'),record);update_results()
    print(name+': native '+native['status']+'; lmcloud '+cloud['status']+'; leftovers '+str(record['leftover_count']))
    if record['leftover_count']:return 1
    return 0 if native['status']=='passed' and cloud['status']=='passed' and same and record['comparison']['outputs']=='same' and not meta.get('unsupported_operations') else 3

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print('comparison failed: '+str(exc),file=sys.stderr);sys.exit(1)
