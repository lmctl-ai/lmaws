#!/usr/bin/env python3
"""Bounded, process-scoped secret handoff. Loopback only; no real secret read."""
import importlib.util,pathlib,sys,json,os,tempfile,threading,http.server,copy
spec=importlib.util.spec_from_file_location('sdk',pathlib.Path(__file__).with_name('test-sdk-call.py'));sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)
sdk.ACC='254332045686';sdk.POC='go-fargate'
ARN='arn:aws:secretsmanager:us-east-1:254332045686:secret:poc-go-fargate-egtry-origin-bn8DfF'
SECRET='fake-origin-secret-MUST-NOT-ESCAPE-123456789';NAME='poc-go-fargate-egtry-origin';PH='{{env:EGTRY_ORIGIN_SECRET}}'
class Fake(sdk.Fake):
 reads=0;badtag=False;fail=False;failwrite=False;wires=[]
 def json_service(self,svc,action,body):
  if svc=='secretsmanager':
   if action=='DescribeSecret':return sdk.js({'ARN':ARN,'Name':NAME,'Tags':[{'Key':'app','Value':'wrong' if Fake.badtag else 'egtry'},{'Key':'poc','Value':'go-fargate'}]})
   if action=='GetSecretValue':
    Fake.reads+=1
    if Fake.fail:return sdk.js({'__type':'InvalidRequestException','message':SECRET},400)
    return sdk.js({'ARN':ARN,'Name':NAME,'SecretString':SECRET,'VersionStages':['AWSCURRENT']})
  return super().json_service(svc,action,body)
 def query(self,version,action,form):
  if action=='CreateRule':
   Fake.wires.append(form)
   if Fake.failwrite:return sdk.xml('<ErrorResponse><Error><Code>ValidationError</Code><Message>'+SECRET+'</Message></Error></ErrorResponse>',400)
  return super().query(version,action,form)
 def cloudfront(self,path,raw):
  if self.command=='POST':Fake.wires.append(raw.decode())
  return super().cloudfront(path,raw)
def main():
 host=pathlib.Path(sys.argv[1]).resolve();work=pathlib.Path(tempfile.mkdtemp(prefix='egtry-secret-'));empty=work/'empty';empty.write_text('');state=work/'state.json'
 def ledger():state.write_text(json.dumps({'poc':'go-fargate','resources':[{'service':'secretsmanager','op':'CreateSecret','arn':ARN,'name':NAME,'ids':[ARN,NAME]}],'records':{}}))
 ledger();server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fake);threading.Thread(target=server.serve_forever,daemon=True).start()
 env=dict(os.environ,CLASSPATH=str(host.parent.parent/'lmaws-0.1.27.jar'),CI='true',AWS_PROFILE='admin',AWS_DEFAULT_PROFILE='admin',LMAWS_ADMIN_GRANT='1',LMAWS_LIVE='1',LMAWS_APPLY='1',AWS_REGION='us-east-1',LMAWS_ENDPOINT=f'http://127.0.0.1:{server.server_port}',AWS_SHARED_CREDENTIALS_FILE=str(empty),AWS_CONFIG_FILE=str(empty),AWS_ACCESS_KEY_ID='test',AWS_SECRET_ACCESS_KEY='test',AWS_EC2_METADATA_DISABLED='true')
 env.pop('EGTRY_ORIGIN_SECRET',None)
 req={'ListenerArn':'arn:aws:elasticloadbalancing:us-east-1:254332045686:listener/app/poc-go-fargate/6cecfab750f95823/e941785ccdb0fc7f','Priority':157,'Conditions':[{'Field':'http-header','HttpHeaderConfig':{'HttpHeaderName':'X-Origin-Env','Values':[PH]}}],'Actions':[{'Type':'forward','TargetGroupArn':'arn:aws:elasticloadbalancing:us-east-1:254332045686:targetgroup/poc-go-fargate-egtry/123'}],'Tags':[{'Key':'poc','Value':'go-fargate'}]}
 n=0
 def run(arn=ARN,apply=False,ok=True,reads=0,e=None,request=None,service='elbv2',op='CreateRule',source=None):
  nonlocal n
  Fake.reads=0;Fake.wires=[]
  src=source or 'file_write("result.json",c.sdk_egtry_secret_apply('+','.join(json.dumps(x) for x in [arn,service,op,json.dumps(request or req),str(state)])+','+str(apply).lower()+').json());'
  result,proc=sdk.run_dsl(host,work,'let c=aws.region("us-east-1"); '+src,e or env)
  assert bool(result.get('ok'))==ok,(n,result)
  assert Fake.reads==reads,(n,Fake.reads)
  assert SECRET not in proc.stdout+proc.stderr
  for p in work.iterdir():
   if p.is_file():assert SECRET not in p.read_text(errors='replace'),p
  n+=1;print('ok',n,flush=True)
 run();run(apply=True,reads=1);assert SECRET in str(Fake.wires)
 # Fresh process successfully re-fetches; no shell env or prior Java state required.
 run(apply=True,reads=1);assert SECRET in str(Fake.wires)
 run(arn=ARN.replace('bn8DfF','xxxxxx'),ok=False)
 run(arn=ARN.replace('egtry-origin','mediator-origin'),ok=False)
 run(e=dict(env,AWS_PROFILE='default'),ok=False);run(e=dict(env,LMAWS_ADMIN_GRANT='0'),ok=False)
 run(e=dict(env,LMAWS_APPLY='0'),apply=True,ok=False)
 Fake.badtag=True;run(apply=True,ok=False);Fake.badtag=False
 state.write_text(json.dumps({'poc':'go-fargate','resources':[],'records':{}}));run(apply=True,ok=False);ledger()
 Fake.fail=True;run(apply=True,ok=False,reads=1);Fake.fail=False
 Fake.failwrite=True;run(apply=True,ok=False,reads=1);Fake.failwrite=False
 run(request=dict(req,Priority=1),ok=False)
 run(request=dict(req,Extra=PH),ok=False)
 run(service='ecs',op='RegisterTaskDefinition',ok=False)
 for op in ['GetSecretValue','BatchGetSecretValue']:
  run(ok=False,source='file_write("out.json",c.sdk_read("secretsmanager",'+json.dumps(op)+','+json.dumps(json.dumps({'SecretId':ARN}))+'));')
 cf={'DistributionConfigWithTags':{'DistributionConfig':{'CallerReference':'poc-go-fargate-egtry-test','Aliases':{'Quantity':1,'Items':['egtry-test.egtry.com']},'Origins':{'Quantity':2,'Items':[{'Id':str(i),'DomainName':'origin-go.lmctl.ai','CustomHeaders':{'Quantity':1,'Items':[{'HeaderName':'X-Origin-Env','HeaderValue':PH}]}} for i in range(2)]},'Enabled':True,'Comment':'egtry test'},'Tags':{'Items':[{'Key':'poc','Value':'go-fargate'}]}}}
 run(service='cloudfront',op='CreateDistributionWithTags',request=cf)
 run(service='cloudfront',op='CreateDistributionWithTags',request=cf,apply=True,reads=1);assert SECRET in str(Fake.wires)
 bad=copy.deepcopy(cf);bad['DistributionConfigWithTags']['DistributionConfig']['Aliases']['Items']=['www.egtry.com'];run(service='cloudfront',op='CreateDistributionWithTags',request=bad,ok=False)
 print(f'{n} bounded secret checks passed; loopback only');server.shutdown()
if __name__=='__main__':main()
