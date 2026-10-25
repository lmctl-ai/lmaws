#!/usr/bin/env python3
"""Compile all comparison scripts against a fake schema endpoint and test safety gates."""
import json,os,pathlib,shutil,subprocess,sys,tempfile
from unittest.mock import patch
from types import SimpleNamespace
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'compare'));sys.path.insert(0,str(ROOT/'scripts'))
import runtime
manifest=json.loads((ROOT/'compare/manifest.json').read_text())['examples']
assert len(manifest)==30
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
with tempfile.TemporaryDirectory(prefix='lmaws-compare-tests-') as tmp:
 tmp=pathlib.Path(tmp);fake=tmp/'bin';fake.mkdir();emitter=fake/'emit.py'
 emitter.write_text('import pathlib\nprint(pathlib.Path('+repr(str(ROOT/'compare/lmcloud.dsl.json'))+').read_text())\n')
 if os.name=='nt':(fake/'lmcloud.cmd').write_text('@echo off\r\n"'+sys.executable+'" "'+str(emitter)+'" %*\r\n')
 else:
  shim=fake/'lmcloud';shim.write_text('#!/usr/bin/env python3\n'+emitter.read_text());shim.chmod(0o755)
 env=dict(os.environ,PATH=str(fake)+os.pathsep+os.environ['PATH'],LMAWS_LIVE='0')
 for name in manifest:
  script=ROOT/'compare'/name/(name+'.lms');source=script.read_text()
  assert 'read_file("compare/' not in source
  assert 'tofu.destroy' in source and 'tofu.last_error' in source
  p=subprocess.run([shutil.which('lmscript'),'--check','--no-preflight',str(script)],env=env,text=True,capture_output=True,timeout=45)
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
