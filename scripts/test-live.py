#!/usr/bin/env python3
"""Opt-in, default-profile live smoke. Only two run-owned free-tier resources.
The native host performs writes; AWS CLI independently verifies teardown and can
recover only matching ledger-listed, prefixed, tagged resources on failure.
"""
import json,os,pathlib,subprocess,sys,tempfile,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
if os.environ.get('LMAWS_LIVE')!='1':raise SystemExit('Live tests require explicit LMAWS_LIVE=1')
host=pathlib.Path(sys.argv[1]).resolve();runid='r'+uuid.uuid4().hex[:16]
env=dict(os.environ,AWS_PROFILE='default',AWS_DEFAULT_PROFILE='default',AWS_EC2_METADATA_DISABLED='true',LMAWS_LIVE='1')
for key in ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_ROLE_SESSION_NAME','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI','LMAWS_ENDPOINT']:
 env.pop(key,None)
def cli(*args,allow=False):
 p=subprocess.run(['aws',*args,'--profile','default','--region',region,'--output','json','--no-cli-pager'],env=env,text=True,encoding="utf-8",capture_output=True,timeout=40)
 if p.returncode and not allow:raise RuntimeError('AWS CLI verification failed: '+args[0]+'/'+args[1])
 return p
p=subprocess.run(['aws','configure','get','region','--profile','default'],env=env,text=True,encoding="utf-8",capture_output=True,timeout=15)
region=p.stdout.strip();assert region and region.replace('-','').isalnum(),'configure a default-profile region first'
env.update(AWS_REGION=region,AWS_DEFAULT_REGION=region)
ledgerdir=ROOT/'live-ledger'/runid;ledgerdir.mkdir(parents=True);ledger=ledgerdir/('lmaws-'+runid+'.jsonl')
queue='lmaws_'+runid+'_queue';parameter='lmaws_'+runid+'_parameter'
created=[];failure=None

def queue_url():
 p=cli('sqs','get-queue-url','--queue-name',queue,allow=True)
 if p.returncode==0:return json.loads(p.stdout)['QueueUrl']
 if any(code in p.stderr for code in ['(AWS.SimpleQueueService.NonExistentQueue)','(QueueDoesNotExist)','(NonExistentQueue)']):return None
 raise RuntimeError('Queue absence could not be verified; AWS error details withheld')

def parameter_exists():
 p=cli('ssm','describe-parameters','--parameter-filters','Key=Name,Option=Equals,Values='+parameter)
 return bool(json.loads(p.stdout).get('Parameters'))

def cleanup_fallback():
 # A ledger intent is written and forced BEFORE the host contacts AWS.
 records=[json.loads(s) for s in ledger.read_text(encoding="utf-8").splitlines()] if ledger.exists() else []
 intents={(r.get('kind'),r.get('id')) for r in records if r.get('event')=='intent' and r.get('action')=='create'}
 if ('queue',queue) in intents:
  url=queue_url()
  if url:
   tags=json.loads(cli('sqs','list-queue-tags','--queue-url',url).stdout).get('Tags',{})
   if tags.get('lmaws_test')==runid:
    cli('sqs','delete-queue','--queue-url',url);created.append(dict(kind='queue',name=queue,recovered=True))
 if ('parameter',parameter) in intents and parameter_exists():
  tags=json.loads(cli('ssm','list-tags-for-resource','--resource-type','Parameter','--resource-id',parameter).stdout).get('TagList',[])
  if any(t.get('Key')=='lmaws_test' and t.get('Value')==runid for t in tags):
   cli('ssm','delete-parameter','--name',parameter);created.append(dict(kind='parameter',name=parameter,recovered=True))

try:
 with tempfile.TemporaryDirectory(prefix='lmaws-live-') as td:
  d=pathlib.Path(td);schema=d/'schema.json';schema.write_bytes(subprocess.check_output([str(host),'--dsl-schema'],env=env,timeout=20));out=d/'live.dslb'
  # No secret values are fetched: all inventories are explicit metadata projections.
  lines=['p = _dsl_ schema='+json.dumps(str(schema))+';','let cloud = aws.region('+json.dumps(region)+');','check(cloud.identity().len() == 1);']
  for kind in ['buckets','vpcs','security_groups','queues','parameters']:lines+=['let '+kind+' = cloud.'+kind+'();']
  lines+=['let owned = cloud.run('+json.dumps(runid)+', '+json.dumps(str(ledger))+');','let q = owned.queue('+json.dumps(queue)+');','owned.put(q, "message", "lmaws nonsecret smoke message");','let p = owned.parameter('+json.dumps(parameter)+', "lmaws nonsecret fixture");','owned.put(p, "value", "lmaws updated fixture");','check(owned.remaining() == 2);']
  # Leave cleanup to the host finally block, deliberately testing failure teardown.
  lines+=['check(false);','end _dsl_','savedsl(p, '+json.dumps(str(out))+');']
  src=d/'live.lms';src.write_text('\n'.join(lines)+'\n')
  comp=subprocess.run(['lmscript',str(src)],env=env,text=True,encoding="utf-8",capture_output=True,timeout=60)
  if comp.returncode:raise RuntimeError('live script compilation failed')
  p=subprocess.run([str(host),'--dsl',str(out)],env=env,text=True,encoding="utf-8",capture_output=True,timeout=240)
  # Logs deliberately stay private, and are not echoed on errors.
  (ledgerdir/'host.stdout').write_text(p.stdout);(ledgerdir/'host.stderr').write_text(p.stderr)
  if p.returncode!=3 or 'check failed' not in p.stdout:raise RuntimeError('live script did not reach expected deliberate failure')
except BaseException as e:
 failure=e
finally:
 try:cleanup_fallback()
 except BaseException as e:failure=failure or e

records=[json.loads(s) for s in ledger.read_text(encoding="utf-8").splitlines()] if ledger.exists() else []
for record in records:
 if record.get('event')=='created':
  created.append(dict(kind=record['kind'],name=record.get('name',record['id']),recovered=False))
for attempt in range(30):
 if queue_url() is None and not parameter_exists():break
 time.sleep(2)
else:raise RuntimeError('Teardown verification failed; retain ledger for recovery')
assert {r['kind'] for r in created}=={'queue','parameter'},'both resources must have been created'
proof=dict(run_id=runid,profile='default',region=region,opt_in=True,read_only_inventories=['identity','buckets','vpcs','security_groups','queues','parameters'],created=created,all_deleted=True,independent_verification='AWS CLI GetQueueUrl and DescribeParameters metadata only',failure_teardown=True,ledger=str(ledger.relative_to(ROOT)))
(ROOT/'durable-memory').mkdir(exist_ok=True);(ROOT/'durable-memory/live-v010.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps(proof,indent=2))
if failure:raise RuntimeError('Live smoke failed; all run-owned resources were independently verified deleted') from None
print('PASS native live SDK smoke; deliberate run failure cleaned both resources')
