#!/usr/bin/env python3
"""Local-only live examples; no Cost Explorer, OIDC, CI credentials or arbitrary deletion."""
import argparse,json,os,pathlib,shutil,subprocess,tempfile,decimal,time
from verify_absence import verify
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--host',default='target/lmaws');p.add_argument('--example');p.add_argument('--read-only',action='store_true');p.add_argument('--write-only',action='store_true');p.add_argument('--continue-on-error',action='store_true');args=p.parse_args()
if os.environ.get('LMAWS_LIVE')!='1':raise SystemExit('Set LMAWS_LIVE=1 explicitly on your own local machine')
if os.environ.get('CI','').lower() in ('1','true','yes') or os.environ.get('GITHUB_ACTIONS')=='true':raise SystemExit('Live examples are forbidden in CI')
host=pathlib.Path(args.host).resolve();assert host.is_file(),host
examples=sorted(x.stem for x in (ROOT/'examples').glob('*.lms') if x.stem!='render-all')
writes={'before_after','queue_pipeline','sandbox_lifecycle','bucket_objects','table_items','topic_publish','log_retention'}
iam={'roles','identity','read_only_audit','service_matrix'}
examples=[n for n in examples if n not in iam]
if args.read_only:examples=[n for n in examples if n not in writes]
if args.write_only:examples=[n for n in examples if n in writes]
if args.example:
 assert args.example in examples,'unknown example';examples=[args.example]
env=dict(os.environ,AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_LIVE='1',LMAWS_LEDGER_DIR=str(ROOT/'ledgers'),LMAWS_EVIDENCE_DIR=str(ROOT/'evidence'))
for key in ['LMAWS_ENDPOINT','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_ROLE_SESSION_NAME','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI']:
 env.pop(key,None)
runner=shutil.which('lmscript');assert runner
# A private launcher gives the compiler the exact tested host; no release cache substitution.
base=pathlib.Path(tempfile.mkdtemp(prefix='lmaws-live-examples-'));bin_dir=base/'bin';bin_dir.mkdir();(bin_dir/'lmaws').symlink_to(host)
env['PATH']=str(bin_dir)+os.pathsep+env['PATH']
(ROOT/'evidence').mkdir(exist_ok=True);total=sum((decimal.Decimal(str(json.loads(f.read_text()).get('total_estimated_usd',0))) for f in (ROOT/'evidence').glob('live-cost-*.json') if f.name.startswith('live-cost-') and not f.name.startswith('live-cost-summary')),decimal.Decimal(0));results=[];failed_cases=[]
for name in examples:
 profile='lmaws' if name in writes else 'default'
 env['AWS_PROFILE']=profile;env['AWS_DEFAULT_PROFILE']=profile
 remaining=decimal.Decimal('0.25')-total
 if remaining<decimal.Decimal('0.002'):raise RuntimeError('whole live batch has insufficient cleanup reservation; refusing next example')
 env['LMAWS_MAX_COST_USD']=str(min(decimal.Decimal('0.05'),remaining))
 before=set((ROOT/'evidence').glob('live-cost-'+name+'-*.json'));work=base/name;work.mkdir()
 started=time.monotonic()
 result=subprocess.run([runner,str(ROOT/'examples'/(name+'.lms'))],cwd=work,env=env,text=True,encoding='utf-8',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=360)
 # Raw logs stay private, since service metadata belongs to the configured account.
 (base/(name+'.log')).write_text(result.stdout,encoding='utf-8')
 made=set((ROOT/'evidence').glob('live-cost-'+name+'-*.json'))-before
 if len(made)!=1:raise RuntimeError(name+': no unique cost evidence; inspect private logs '+str(base))
 evidence_path=next(iter(made));record=json.loads(evidence_path.read_text());assert record['live'] and record['profile']==profile and record['region']=='us-east-1'
 if record['leftover_count']!=0 or record['sweeper_leftover_count']!=0:
  raise RuntimeError(name+': leftovers remain; inspect '+str(evidence_path)+' and private run ledger')
 if result.returncode:
  record.update(example_exit_code=result.returncode,validation_status='blocked_or_failed')
  evidence_path.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
  total+=decimal.Decimal(str(record['total_estimated_usd']));failed_cases.append(dict(example=name,evidence=str(evidence_path.relative_to(ROOT)),exit_code=result.returncode,leftover_count=0))
  print(json.dumps(failed_cases[-1]),flush=True)
  if args.continue_on_error:continue
  raise RuntimeError(name+': example failed without leftovers; inspect private logs '+str(base))
 assert all(v['absent'] for v in record['provider_verification'])
 independent=verify(record['resources'])
 record['independent_readonly_verification']=independent
 record['independent_verification_estimated_usd']=str(sum((decimal.Decimal(v['estimated_usd']) for v in independent),decimal.Decimal(0)))
 record['wall_seconds']=round(time.monotonic()-started,6)
 for resource in record['resources']:resource['tags']={'lmaws_test':record['run_id']}
 record['tags_verification']='Host ownership-tag reads before update/delete; independent default-profile absence check after teardown'
 amount=decimal.Decimal(str(record['total_estimated_usd']));assert amount<=decimal.Decimal(record['cap_usd'] if isinstance(record['cap_usd'],str) else str(record['cap_usd']))
 total+=amount;assert total<=decimal.Decimal('0.25')
 assert 'estimated cost: '+record['estimated_cost_display'] in result.stdout
 png=work/'images'/(name+'.png');assert png.read_bytes().startswith(bytes.fromhex('89504e470d0a1a0a'))
 # Persist scenario intent without copying payloads, account IDs or secret values.
 ledger=pathlib.Path(record['ledger']);events=[json.loads(line) for line in ledger.read_text().splitlines()]
 touched=[dict(kind=e['kind'],action=e['action']) for e in events if e.get('event')=='updated']
 record.update(example_exit_code=result.returncode,png_generated=True,ledger_updates=touched,whole_batch_estimated_so_far_usd=str(total),user_test_command='lmctl autorun https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/'+name+'.lms')
 evidence_path.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
 item=dict(example=name,estimated_usd=str(amount),display=record['estimated_cost_display'],evidence=str(evidence_path.relative_to(ROOT)),resource_kinds=[r['kind'] for r in record['resources']],resource_names=[r['name'] for r in record['resources']],leftover_count=0)
 results.append(item);print(json.dumps(item),flush=True)
summary=dict(profile='per-example',region='us-east-1',local_only=True,oidc=False,cloud_credentials_in_ci=False,total_estimated_usd=str(total),write_profile='lmaws',read_profile='default',iam_live_skipped=sorted(iam),whole_run_cap_usd='0.25',example_default_cap_usd='0.05',examples=results,failed_examples=failed_cases,leftover_count=0)
(ROOT/'evidence'/('live-cost-summary-readonly-v012.json' if args.read_only else 'live-cost-summary-v012.json')).write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print('PASS' if not failed_cases else 'INCOMPLETE',len(results),'live examples; estimated cost: $'+str(total)+'; leftovers: 0; private logs:',base)
