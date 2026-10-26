#!/usr/bin/env python3
"""Compare SDK execution with OpenTofu, retaining private state for recovery."""
import argparse,json,os,re,secrets,shutil,subprocess,sys,time
from decimal import Decimal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from verify_absence import verify
from runtime import clean,load,write,ALLOWANCE
from output_compare import compare_outputs
MANIFEST=load(ROOT/'compare/manifest.json')['examples']

def cost_label(engine):
    if engine['status'] in ('estimated_only','prior_denied','not_attempted'):
        return 'estimated only'
    return '$'+format(Decimal(str(engine.get('total_estimated_usd','0'))), '.8f')

def update_results():
    records={}
    for path in sorted((ROOT/'compare/evidence').glob('*.json'), key=lambda p: (load(p).get('recorded_at',0),p.name)):
        record=load(path)
        if record.get('example') in MANIFEST:records[record['example']]=record
    lines=['# lmaws ↔ lmcloud comparisons','','Native writes run once with profile `lmaws`; native evidence can be reused. Read-only runs use `default`. IAM is deliberately skipped. Resource names are compared after replacing each unique run ID; payload objects/items are separately noted because the SDK ledger tracks their owning parent. Provider cost is a conservative upper bound reserved before plan, not measured API request accounting; native costs use observed SDK attempts and lifetimes. Timings are end-to-end (native rendering versus multiple provider phases), with a shared warm provider cache. Raw state and logs stay under ignored `compare/runs/`.','','| Example | Native live result / estimated cost | lmcloud result / estimated cost | Resources, names and tags | Outputs / wall seconds | Cleanup | Same / differs / why |','| --- | --- | --- | --- | --- | --- | --- |']
    for name,meta in sorted(MANIFEST.items()):
        r=records.get(name)
        if not r:
            label='estimated only; IAM skipped' if meta['iam'] else 'not run'
            lines.append(f'| `{name}` | {label} | {label} | — | — | no attempted resources | {meta["notes"]} |');continue
        native=r['native'];cloud=r['lmcloud'];comp=r.get('comparison',{})
        resource_desc=comp.get('resources','not comparable')
        output=comp.get('outputs','not comparable')
        both=native['status']=='passed' and cloud['status']=='passed'
        full=both and resource_desc.startswith('same') and output.startswith('same:') and not meta.get('unsupported_operations')
        classification='same' if full else 'differs' if both else 'skipped' if meta['iam'] else 'not comparable'
        cleanup=f"native {native.get('leftover_count','unknown')}; lmcloud {cloud.get('leftover_count','unknown')}"
        lines.append(f'| `{name}` | {native["status"]} / {cost_label(native)} | {cloud["status"]} / {cost_label(cloud)} | {resource_desc} | {output}; {native.get("wall_seconds","n/a")} / {cloud.get("wall_seconds","n/a")} | {cleanup} leftovers | **{classification}**: {comp.get("why",meta["notes"]).replace(chr(10)," ").replace("|","/")} |')
    (ROOT/'compare/RESULTS.md').write_text('\n'.join(lines)+'\n')

def native_resources(native):
    """Recover confirmed child names from successful SDK ledger updates, never payloads."""
    parents=[dict(v) for v in native.get('resources',[])]
    path=Path(native.get('ledger',''))
    if not path.is_file():return native.get('observed_resources',parents)
    children={}
    for line in path.read_text().splitlines():
        row=json.loads(line)
        if row.get('event')!='updated' or not row.get('action','').startswith('update:'):continue
        parent=next((p for p in parents if p.get('id')==row.get('id') and p['kind']==row.get('kind')),None)
        if not parent or parent['kind'] not in ('bucket','table'):continue
        kind='aws_s3_object' if parent['kind']=='bucket' else 'aws_dynamodb_table_item'
        name=row['action'].removeprefix('update:')
        children[(kind,parent['name'],name)]=dict(kind=kind,name=name,parent=parent['name'],tags={})
    return parents+list(children.values())

def equivalent_resources(native,cloud):
    kinds={'bucket','queue','topic','parameter','table','log_group','aws_s3_object','aws_dynamodb_table_item'}
    def norm(rows,run):
        return sorted((r['kind'],r['name'].replace(run,'<run>'),r.get('parent','').replace(run,'<run>'),tuple(sorted((k,str(v).replace(run,'<run>')) for k,v in r.get('tags',{}).items()))) for r in rows if r['kind'] in kinds)
    return norm(native.get('observed_resources',native.get('resources',[])),native.get('run_id','!'))==norm(cloud.get('observed_resources',[]),cloud.get('run_id','!'))

def check_comparison_budget(native_cost,campaign_cost,cap,write_mode):
    if not cap.is_finite() or cap<0 or cap>Decimal('0.25'):raise RuntimeError('comparison cap must be between zero and 0.25')
    allowance=ALLOWANCE # provider API attempt counts are opaque, even for paid metadata reads
    if native_cost+allowance>cap:raise RuntimeError('example cap prohibits the next provider creation')
    if campaign_cost+native_cost+allowance>Decimal('0.25'):raise RuntimeError('whole-run cap prohibits the next provider creation')
    return cap-native_cost

def main():
    ap=argparse.ArgumentParser();ap.add_argument('example',choices=sorted(MANIFEST));ap.add_argument('--offline',action='store_true');ap.add_argument('--native-evidence');ap.add_argument('--host',default=str(ROOT/'target/lmaws'));ap.add_argument('--lmcloud');args=ap.parse_args()
    name=args.example;meta=MANIFEST[name];run_id='r'+secrets.token_hex(4)+'x'+secrets.token_hex(4)
    if meta['iam']:
        record=dict(recorded_at=time.time(),example=name,run_id=run_id,native=dict(status='estimated_only',total_estimated_usd='0.00'),lmcloud=dict(status='estimated_only',total_estimated_usd='0.00'),leftover_count=0,comparison=dict(why='IAM live calls intentionally skipped under federated profiles',resources='no creations',outputs='estimated, not measured live'))
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
    env=dict(os.environ,AWS_PROFILE=expected,AWS_DEFAULT_PROFILE=expected,AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_COMPARE_RUN_ID=run_id,LMAWS_COMPARE_RUNTIME=str(ROOT/'compare/runtime.py'),LMAWS_COMPARE_VERIFIER=str(ROOT/'scripts/verify_absence.py'),LMAWS_COMPARE_CAMPAIGN=os.getenv('LMAWS_COMPARE_CAMPAIGN',str(ROOT/'compare/runs/campaign.json')),LMAWS_COMPARE_PROVIDER_CACHE=os.getenv('LMAWS_COMPARE_PROVIDER_CACHE') or os.getenv('TF_PLUGIN_CACHE_DIR') or str(ROOT/'compare/private/provider-cache'))
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
        native=load(files[0]);native['example_exit_code']=p.returncode;native['status']='passed' if p.returncode==0 else 'blocked';native['wall_seconds']=round(time.monotonic()-started,6)
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
    native['observed_resources']=native_resources(native)
    write(native_work/'native-result.json',native)
    campaign_path=Path(env['LMAWS_COMPARE_CAMPAIGN']);prior=load(campaign_path);campaign=Decimal(str(prior.get('estimated_usd','0')))
    amount=Decimal(str(native.get('total_estimated_usd','0')))+previous_verification+sum((Decimal(str(v.get('estimated_usd',0))) for v in native['independent_readonly_verification']),Decimal(0))
    comparison_cap=Decimal(env.get('LMAWS_MAX_COST_USD','0.05'))
    remaining_cap=check_comparison_budget(amount,campaign,comparison_cap,meta['write'])
    env['LMAWS_MAX_COST_USD']=str(remaining_cap)
    write(campaign_path,{'estimated_usd':str(campaign+amount),'hard_ceiling_usd':'0.25'})
    started=time.monotonic();p=subprocess.run(['lmscript',str(ROOT/'compare'/name/(name+'.lms'))],cwd=cloud_work,env=env,text=True,capture_output=True,timeout=900)
    (cloud_work/'private.log').write_text(p.stdout+p.stderr)
    cloud=load(cloud_work/'cloud-result.json')
    if not cloud:
        cloud=dict(status='compile_or_bootstrap_failed',total_estimated_usd='0',leftover_count=1,cleanup_verification='unknown: missing final ledger',run_error='No final provider record; inspect private state and logs before assuming cleanup',wall_seconds=round(time.monotonic()-started,6))
    record=dict(recorded_at=time.time(),example=name,run_id=run_id,profile=expected,region='us-east-1',native=native,lmcloud=cloud,leftover_count=max(native['leftover_count'],cloud.get('leftover_count',1)),comparison={})
    same=equivalent_resources(native,cloud) if native['status']=='passed' and cloud['status']=='passed' else None
    record['comparison']=dict(resources=('same observed parent/child types, names and tags after run-ID normalization' if same else 'differs' if same is False else 'not comparable: a run was blocked'),outputs=compare_outputs(native,cloud,meta['write'],name),why=meta['notes']+(' Both engines passed.' if same else ' '+native['status']+' vs '+cloud['status']+'.'))
    record['comparison']['estimated_cost_delta_usd']=str(Decimal(str(cloud.get('total_estimated_usd',0)))-Decimal(str(native.get('total_estimated_usd',0))))
    if 'wall_seconds' in native and 'wall_seconds' in cloud:record['comparison']['wall_delta_seconds']=round(cloud['wall_seconds']-native['wall_seconds'],6)
    # Logs, provider state, parameter values and account identifiers never enter public records.
    for record_part in (native,cloud):
        record_part.pop('ledger',None)
        record_part.pop('events',None)
    write(ROOT/'compare/evidence'/(name+'-'+run_id+'.json'),record);update_results()
    print(name+': native '+native['status']+'; lmcloud '+cloud['status']+'; leftovers '+str(record['leftover_count']))
    if record['leftover_count']:return 1
    return 0 if native['status']=='passed' and cloud['status']=='passed' and same and record['comparison']['outputs'].startswith('same:') and not meta.get('unsupported_operations') else 3

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print('comparison failed: '+str(exc),file=sys.stderr);sys.exit(1)
