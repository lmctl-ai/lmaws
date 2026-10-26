#!/usr/bin/env python3
"""Compile all comparison scripts against a fake schema endpoint and test safety gates."""
import json,os,pathlib,re,shutil,subprocess,sys,tempfile
from unittest.mock import patch
from types import SimpleNamespace
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'compare'));sys.path.insert(0,str(ROOT/'scripts'))
import runtime
import driver
from decimal import Decimal
from driver import check_comparison_budget
manifest=json.loads((ROOT/'compare/manifest.json').read_text())['examples']
assert len(manifest)==30
assert check_comparison_budget(Decimal('0.001'),Decimal('0'),Decimal('0.05'),True)==Decimal('0.049')
for native_cost,campaign_cost,cap in [(Decimal('0.049'),Decimal('0'),Decimal('0.05')),(Decimal('0.001'),Decimal('0.248'),Decimal('0.05'))]:
 try:check_comparison_budget(native_cost,campaign_cost,cap,True)
 except RuntimeError:pass
 else:raise AssertionError('combined native/provider budget was allowed to exceed its cap')
try:check_comparison_budget(Decimal('0'),Decimal('0.248'),Decimal('0.05'),False)
except RuntimeError:pass
else:raise AssertionError('paid metadata reads escaped the shared provider allowance')
run='r1234abcdx5678abcd'
plan={'resource_changes':[{'mode':'managed','type':'aws_sqs_queue','change':{'actions':['create'],'after':{'name':'lmaws_'+run+'_audit','tags':{'lmaws_test':run}}}}]}
assert runtime.assert_owned(plan,run,True)[0]['kind']=='queue'
foreign_child=json.loads(json.dumps(plan));foreign_child['resource_changes'].append({'mode':'managed','type':'aws_s3_object','address':'aws_s3_object.foreign','change':{'actions':['create'],'after':{'bucket':'foreign-bucket','key':'foreign-key'}}})
try:runtime.assert_owned(foreign_child,run,True)
except RuntimeError:pass
else:raise AssertionError('child in a foreign parent was accepted')
for altered in [False,True]:
 bad=json.loads(json.dumps(plan))
 if altered:bad['resource_changes'][0]['change']['after']['tags']={}
 else:bad['resource_changes'][0]['change']['after']['name']='foreign'
 try:runtime.assert_owned(bad,run,True)
 except RuntimeError:pass
 else:raise AssertionError('unowned plan accepted')
try:runtime.assert_owned(plan,run,False)
except RuntimeError:pass
else:raise AssertionError('read-only comparison accepted cloud mutations')
native_owned={'run_id':'r1234abcdx5678abcd','resources':[{'kind':'bucket','name':'lmaws-r1234abcdx5678abcd-sample','tags':{'lmaws_test':'r1234abcdx5678abcd'}}]}
cloud_owned={'run_id':'r11112222x33334444','observed_resources':[{'kind':'bucket','name':'lmaws-r11112222x33334444-sample','tags':{'lmaws_test':'r11112222x33334444'}}]}
assert driver.equivalent_resources(native_owned,cloud_owned)
cloud_drift=json.loads(json.dumps(cloud_owned));cloud_drift['resources']=json.loads(json.dumps(cloud_drift['observed_resources']));cloud_drift['observed_resources'][0]['name']='foreign'
assert not driver.equivalent_resources(native_owned,cloud_drift),'planned equality hid observed drift'
with tempfile.TemporaryDirectory(prefix='lmaws-sdk-child-') as td:
 ledger=pathlib.Path(td)/'ledger.jsonl';ledger.write_text(json.dumps({'event':'updated','kind':'bucket','id':'own','action':'update:tiny.txt'})+'\n')
 sample={'ledger':str(ledger),'resources':[{'kind':'bucket','id':'own','name':'lmaws-owned'}]}
 resources=driver.native_resources(sample);assert len(resources)==2 and resources[1]['name']=='tiny.txt' and resources[1]['parent']=='lmaws-owned'


with tempfile.TemporaryDirectory(prefix='lmaws-compare-tests-') as tmp:
 tmp=pathlib.Path(tmp);fake=tmp/'bin';fake.mkdir();emitter=fake/'emit.py'
 # A loopback test seam must never silently become a real cloud comparison.
 with patch.dict(os.environ,{'LMAWS_LIVE':'1','AWS_PROFILE':'lmaws','AWS_REGION':'us-east-1','LMAWS_ENDPOINT':'http://127.0.0.1:9','CI':'false','GITHUB_ACTIONS':'false'}),patch.object(sys,'argv',['driver','bucket_objects','--native-evidence','missing']),patch.object(driver,'ROOT',tmp),patch('driver.subprocess.run',side_effect=AssertionError('unexpected subprocess')):
  try:driver.main()
  except RuntimeError as exc:assert 'LMAWS_ENDPOINT' in str(exc)
  else:raise AssertionError('test endpoint override was silently discarded')
 emitter.write_text('import pathlib\nprint(pathlib.Path('+repr(str(ROOT/'compare/lmcloud.dsl.json'))+').read_text())\n')
 if os.name=='nt':pass # Node spawnSync does not execute .cmd; bind the native Python executable below.
 else:
  shim=fake/'lmcloud';shim.write_text('#!/usr/bin/env python3\n'+emitter.read_text());shim.chmod(0o755)
 env=dict(os.environ,PATH=str(fake)+os.pathsep+os.environ['PATH'],LMAWS_LIVE='0')
 # Exercise the actual generated bootstrap with unset env variables, replacing
 # only HTTP transport with a harmless Python response. No provider is launched.
 bootstrap=(ROOT/'compare/bucket_objects/bucket_objects.lms').read_text().split('phase_init = _dsl_')[0]
 response='download = system('+json.dumps([sys.executable,'-c','print("mock-helper")'])+', 60000);'
 bootstrap=re.sub(r'download = system\(\[[^\n]+\], 60000\);',lambda match:response,bootstrap)
 bootstrap_file=tmp/'bootstrap.lms';bootstrap_file.write_text(bootstrap,encoding='utf-8')
 bootstrap_env=dict(env);bootstrap_env.pop('LMAWS_COMPARE_RUNTIME',None);bootstrap_env.pop('LMAWS_COMPARE_VERIFIER',None)
 boot=subprocess.run([shutil.which('lmscript'),'--no-preflight',str(bootstrap_file)],cwd=tmp,env=bootstrap_env,text=True,capture_output=True,timeout=45)
 assert boot.returncode==0,boot.stderr
 assert (tmp/'comparison-main.tf').read_bytes()==(ROOT/'compare/bucket_objects/main.tf').read_bytes(), 'HCL interpolation changed the run-owned configuration'
 assert (tmp/'compare-runtime.py').read_text().strip()=='mock-helper'
 assert (tmp/'verify_absence.py').read_text().strip()=='mock-helper'

 for name in manifest:
  script=ROOT/'compare'/name/(name+'.lms');source=script.read_text()
  assert 'read_file("compare/' not in source
  assert 'tofu.destroy' in source and 'tofu.last_error' in source
  check_script=script
  if os.name=='nt':
   check_script=fake/(name+'.lms')
   check_script.write_text(re.sub(r'cli="lmcloud" install="github:lmctl-ai/lmcloud@[^"]+"', 'cli="python emit.py"', source),encoding='utf-8')
  p=subprocess.run([shutil.which('lmscript'),'--check','--no-preflight',str(check_script)],cwd=fake,env=env,text=True,capture_output=True,timeout=45)
  assert p.returncode==0,(name,p.stderr[-2000:])
 # A provider apply error must still destroy and independently verify absence.
 original=pathlib.Path.cwd();work=tmp/'failure';work.mkdir();os.chdir(work)
 try:
  pathlib.Path('config.tf').write_text('')
  calls=[]
  def phase(argv,**kwargs):
   if argv[-1]=='--version':return SimpleNamespace(returncode=0,stdout='fake lmcloud version',stderr='')
   name=argv[-1].removeprefix('phase-').removesuffix('.dslb');calls.append(name)
   pathlib.Path('phase-'+name+'.ok').write_text('false' if name=='apply' else 'true')
   pathlib.Path('phase-'+name+'.error').write_text('')
   if name=='plan':pathlib.Path('plan.json').write_text(json.dumps(plan))
   if name=='inspect_after':pathlib.Path('snapshot-after.json').write_text('{"values":{"root_module":{"resources":[]}}}')
   return SimpleNamespace(returncode=0,stdout='',stderr='')
  args=['runtime','--name','before_after','--host','fake','--config','config.tf','--metadata',json.dumps({'write':True,'iam':False})]
  env={'LMAWS_LIVE':'1','AWS_PROFILE':'lmaws','AWS_REGION':'us-east-1','LMAWS_COMPARE_RUN_ID':run,'CI':'false','GITHUB_ACTIONS':'false'}
  with patch.dict(os.environ,env),patch.object(sys,'argv',args),patch('runtime.subprocess.run',side_effect=phase),patch('runtime.verify',return_value=[{'absent':True}]) as verify:
   assert runtime.main()==1
   assert calls==['init','validate','plan','apply','destroy','inspect_after'],calls
   assert verify.call_count==2
   result=json.loads(pathlib.Path('cloud-result.json').read_text());assert result['leftover_count']==0 and result['status']=='failed'
 finally:os.chdir(original)
print('PASS 30 comparison scripts with fake schema; ownership/profile and failure teardown checks')

with tempfile.TemporaryDirectory(prefix='lmaws-missing-result-') as td:
 tmp=pathlib.Path(td);(tmp/'compare/evidence').mkdir(parents=True)
 fixture=tmp/'native.json';fixture.write_text(json.dumps({'example':'bucket_objects','profile':'lmaws','live':True,'example_exit_code':0,'leftover_count':0,'resources':[],'total_estimated_usd':'0','run_id':'r1234abcdx5678abcd'}))
 env={'LMAWS_LIVE':'1','AWS_PROFILE':'lmaws','AWS_REGION':'us-east-1','CI':'false','GITHUB_ACTIONS':'false','LMAWS_COMPARE_CAMPAIGN':str(tmp/'campaign.json')}
 with patch.dict(os.environ,env),patch.object(driver,'ROOT',tmp),patch.object(sys,'argv',['driver','bucket_objects','--native-evidence',str(fixture),'--host',str(tmp/'missing-host')]),patch('driver.verify',return_value=[]),patch('driver.subprocess.run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='fixture bootstrap failure')):
  assert driver.main()==1
 result=json.loads(next((tmp/'compare/evidence').glob('*.json')).read_text())
 assert result['leftover_count']>0 and 'unknown' in result['lmcloud']['cleanup_verification']
 # File names deliberately disagree with time; cloning must not revive older results.
 old=dict(result,recorded_at=1);old['native']=dict(result['native'],status='old-marker')
 new=dict(result,recorded_at=2);new['native']=dict(result['native'],status='current-marker')
 (tmp/'compare/evidence/z-old.json').write_text(json.dumps(old));(tmp/'compare/evidence/a-new.json').write_text(json.dumps(new))
 for f in (tmp/'compare/evidence').glob('bucket_objects-*.json'):f.unlink()
 with patch.object(driver,'ROOT',tmp):driver.update_results()
 text=(tmp/'compare/RESULTS.md').read_text();assert 'current-marker' in text and 'old-marker' not in text
print('PASS observed-state parity, unknown cleanup and timestamp result selection')

assert runtime.phase_error('plan','provider["registry.opentofu.org/hashicorp/aws"]: failed to refresh cached credentials, credential_process exit status 1')=='aws_credentials_unavailable'
assert runtime.phase_error('init','Failed to install registry provider package')=='provider_download_failed'
assert runtime.phase_error('plan','AccessDenied for read action')=='aws_permission_denied'
print('PASS credential failures are not misreported as provider installation failures')

bucket_plan={'resource_changes':[{'address':'aws_s3_bucket.own','mode':'managed','type':'aws_s3_bucket','change':{'actions':['create'],'after':{'bucket':'lmaws-'+run+'-sample','tags':{'lmaws_test':run},'force_destroy':False}}},{'address':'aws_s3_object.own','mode':'managed','type':'aws_s3_object','change':{'actions':['create'],'after':{'bucket':None,'key':'tiny.txt','content':'tiny'}}}], 'configuration':{'root_module':{'resources':[{'address':'aws_s3_object.own','expressions':{'bucket':{'references':['aws_s3_bucket.own.id']}}}]}}}
assert runtime.assert_owned(bucket_plan,run,True)[0]['kind']=='bucket'
for mode in ('foreign_known_parent','oversized_content','file_source','multiple_children','force_destroy'):
 bad=json.loads(json.dumps(bucket_plan))
 if mode=='foreign_known_parent':bad['resource_changes'][1]['change']['after']['bucket']='foreign-bucket'
 elif mode=='oversized_content':bad['resource_changes'][1]['change']['after']['content']='x'*65537
 elif mode=='file_source':bad['resource_changes'][1]['change']['after']['source']='/private/file'
 elif mode=='multiple_children':bad['resource_changes'].append(bad['resource_changes'][1])
 else:bad['resource_changes'][0]['change']['after']['force_destroy']=True
 try:runtime.assert_owned(bad,run,True)
 except RuntimeError:pass
 else:raise AssertionError('unsafe child plan accepted: '+mode)
print('PASS bounded child content, known parent ownership and force-destroy rejection')
