#!/usr/bin/env python3
"""Loopback AWS protocols; no credentials or network outside localhost."""
import importlib.util,pathlib,sys,json,os,tempfile,threading,http.server,urllib.parse,copy
spec=importlib.util.spec_from_file_location('sdk',pathlib.Path(__file__).with_name('test-sdk-call.py'));sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)
sdk.ACC='254332045686';sdk.POC='go-fargate'
ACC=sdk.ACC; SECRET='poc-go-fargate-egtry-origin'; ARN=f'arn:aws:secretsmanager:us-east-1:{ACC}:secret:{SECRET}-abc123';DIST=f'arn:aws:cloudfront::{ACC}:distribution/ENEWTEST'
class Fake(sdk.Fake):
 tag='go-fargate';exists=False;fail_secret=False;policies={};policy=json.dumps({'Version':'2012-10-17','Statement':[{'Sid':'Existing','Effect':'Allow','Action':'s3:GetObject','Resource':'arn:aws:s3:::www.egtry.com/*','Principal':{'Service':'cloudfront.amazonaws.com'},'Condition':{'StringEquals':{'AWS:SourceArn':f'arn:aws:cloudfront::{ACC}:distribution/E3HQY8QHHHAZP7'}}}]});reads=0;race=False;writes=[]
 def dispatch(self,raw):
  if 'policy' in urllib.parse.urlparse(self.path).query:
   Fake.reads+=self.command=='GET'
   if self.command=='GET':
    policy=Fake.policy if not(Fake.race and Fake.reads>=2) else Fake.policy+' '
    return self.reply((200,'application/json',policy,{}))
   Fake.writes.append(('bucket',raw.decode()));Fake.policy=raw.decode();return self.reply(sdk.xml(''))
  return super().dispatch(raw)
 def json_service(self,svc,action,body):
  if svc=='secretsmanager':
   if action=='DescribeSecret':
    if not Fake.exists:return sdk.js({'__type':'ResourceNotFoundException','message':'missing'},400)
    return sdk.js({'ARN':ARN,'Name':SECRET})
   if action=='CreateSecret':
    Fake.writes.append(('secret',body))
    if Fake.fail_secret:return sdk.js({'__type':'InvalidRequestException','message':body['SecretString']},400)
    Fake.exists=True;return sdk.js({'ARN':ARN,'Name':SECRET})
  return super().json_service(svc,action,body)
 def query(self,version,action,form):
  if version=='2010-05-08':
   role=form.get('RoleName',[''])[0]
   if action=='GetRole':return sdk.xml(f'<GetRoleResponse><GetRoleResult><Role><Arn>arn:aws:iam::{ACC}:role/{role}</Arn></Role></GetRoleResult></GetRoleResponse>')
   if action=='ListRoleTags':return sdk.xml(f'<ListRoleTagsResponse><ListRoleTagsResult><Tags><member><Key>poc</Key><Value>{Fake.tag}</Value></member></Tags><IsTruncated>false</IsTruncated></ListRoleTagsResult></ListRoleTagsResponse>')
   if action=='ListRolePolicies':return sdk.xml('<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames>'+''.join('<member>'+k+'</member>' for k in Fake.policies.get(role,{}))+'</PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>')
   if action=='GetRolePolicy':return sdk.xml('<GetRolePolicyResponse><GetRolePolicyResult><PolicyDocument>'+urllib.parse.quote(Fake.policies[role][form['PolicyName'][0]])+'</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>')
   if action=='PutRolePolicy':Fake.writes.append(('role',form));Fake.policies.setdefault(role,{})[form['PolicyName'][0]]=form['PolicyDocument'][0]
  return super().query(version,action,form)
def main():
 host=pathlib.Path(sys.argv[1]).resolve();work=pathlib.Path(tempfile.mkdtemp(prefix='egtry-prereq-'));empty=work/'empty';empty.write_text('');state=work/'state.json'
 server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Fake);threading.Thread(target=server.serve_forever,daemon=True).start()
 env=dict(os.environ,CLASSPATH=str(host.parent.parent/'lmaws-0.1.27.jar'),CI='true',AWS_PROFILE='admin',AWS_DEFAULT_PROFILE='admin',LMAWS_ADMIN_GRANT='1',LMAWS_LIVE='1',LMAWS_APPLY='1',AWS_REGION='us-east-1',LMAWS_ENDPOINT=f'http://127.0.0.1:{server.server_port}',AWS_SHARED_CREDENTIALS_FILE=str(empty),AWS_CONFIG_FILE=str(empty),AWS_ACCESS_KEY_ID='test',AWS_SECRET_ACCESS_KEY='test',AWS_EC2_METADATA_DISABLED='true',EGTRY_ORIGIN_SECRET='NEVER-ECHO-THIS-SECRET-12345678')
 n=0
 def run(src,ok=True,mut=False,e=None):
  nonlocal n
  Fake.writes.clear();result,proc=sdk.run_dsl(host,work,'let c=aws.region("us-east-1"); '+src,e or env)
  assert bool(result.get('ok'))==ok,(src,result)
  assert bool(Fake.writes)==mut,(src,Fake.writes)
  assert env['EGTRY_ORIGIN_SECRET'] not in proc.stdout+proc.stderr
  for p in work.glob('*.json'):assert env['EGTRY_ORIGIN_SECRET'] not in p.read_text()
  n+=1;print('ok',n,flush=True)
 def call(svc,op,req,apply=False,**kw):run('let r=c.sdk_call('+','.join(json.dumps(x) for x in [svc,op,json.dumps(req),'go-fargate',str(state)])+','+str(apply).lower()+'); file_write("out.json",r.json());',**kw)
 def adopt(role,record=False,**kw):run('let r=c.sdk_adopt_existing('+','.join(json.dumps(x) for x in ['iam',role,'go-fargate',str(state)])+','+str(record).lower()+');',**kw)
 run('file_write("ops.json",c.sdk_operations("s3").json());')
 operations=json.loads((work/'ops.json').read_text())
 assert {x['operation'] for x in operations if x['mode']!='denied'}=={'GetBucketPolicy','PutBucketPolicy'}
 secret={'Name':SECRET,'SecretString':'{{env:EGTRY_ORIGIN_SECRET}}','Tags':[{'Key':'poc','Value':'go-fargate'}]}
 call('secretsmanager','CreateSecret',secret);assert not state.exists()
 call('secretsmanager','CreateSecret',dict(secret,SecretString='literal'),ok=False)
 call('secretsmanager','CreateSecret',dict(secret,Name='other'),ok=False)
 Fake.fail_secret=True;call('secretsmanager','CreateSecret',secret,True,ok=False,mut=True);Fake.fail_secret=False
 call('secretsmanager','CreateSecret',secret,True,mut=True)
 call('secretsmanager','CreateSecret',secret,ok=False)
 call('secretsmanager','PutSecretValue',{'SecretId':ARN,'SecretString':'{{env:EGTRY_ORIGIN_SECRET}}'},ok=False)
 call('secretsmanager','DeleteSecret',{'SecretId':ARN},ok=False)
 for role in ['poc-go-fargate-task','poc-go-fargate-exec']:
  adopt(role);adopt(role,True)
 adopt('unapproved',ok=False)
 Fake.tag='wrong';adopt('poc-go-fargate-task',ok=False);Fake.tag='go-fargate'
 def policy(role,action,resources):return {'RoleName':role,'PolicyName':'egtry-origin-read','PolicyDocument':json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':action,'Resource':resources}]})}
 task=policy('poc-go-fargate-task','s3:GetObject',['arn:aws:s3:::www.egtry.com/*','arn:aws:s3:::egtry-v2-254332045686/*']);exe=policy('poc-go-fargate-exec','secretsmanager:GetSecretValue',ARN)
 call('iam','PutRolePolicy',task);call('iam','PutRolePolicy',exe)
 for action,resource in [('s3:*',['*']),('s3:PutObject',['arn:aws:s3:::www.egtry.com/*']),('s3:GetObject',['arn:aws:s3:::other/*'])]:call('iam','PutRolePolicy',policy('poc-go-fargate-task',action,resource),ok=False)
 bad=copy.deepcopy(task);doc=json.loads(bad['PolicyDocument']);doc['Statement'][0]['NotAction']='s3:DeleteObject';bad['PolicyDocument']=json.dumps(doc);call('iam','PutRolePolicy',bad,ok=False)
 call('iam','PutRolePolicy',policy('poc-go-fargate-exec','secretsmanager:GetSecretValue',ARN.replace('abc123','xxxxxx')),ok=False)
 for op,req in [('DeleteRole',{'RoleName':'poc-go-fargate-task'}),('AttachRolePolicy',{'RoleName':'poc-go-fargate-task','PolicyArn':'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}),('DeleteRolePolicy',{'RoleName':'poc-go-fargate-task','PolicyName':'egtry-origin-read'})]:call('iam',op,req,ok=False)
 call('iam','PutRolePolicy',task,True,mut=True);call('iam','PutRolePolicy',task,ok=False)
 call('iam','PutRolePolicy',exe,True,mut=True)
 # A ledger fixture simulates a distribution already created by this run.
 st=json.loads(state.read_text());st['resources'].append({'service':'cloudfront','op':'CreateDistributionWithTags','arn':DIST,'name':'ENEWTEST','ids':[DIST,'ENEWTEST']});state.write_text(json.dumps(st))
 old=Fake.policy;doc=json.loads(old);doc['Statement'].append({'Sid':'EgtryTestOacRead','Effect':'Allow','Principal':{'Service':'cloudfront.amazonaws.com'},'Action':'s3:GetObject','Resource':'arn:aws:s3:::www.egtry.com/*','Condition':{'StringEquals':{'AWS:SourceArn':DIST}}})
 req={'Bucket':'www.egtry.com','ExpectedBucketOwner':ACC,'Policy':json.dumps(doc),'LmawsPreviousPolicy':old}
 call('s3','GetBucketPolicy',{'Bucket':'www.egtry.com','ExpectedBucketOwner':ACC})
 call('s3','PutBucketPolicy',req)
 for change in ['existing','principal','wildcard','live','unrecorded','delete','metadata']:
  d=copy.deepcopy(doc)
  if change=='existing':d['Statement'][0]['Sid']='Modified'
  if change=='principal':d['Statement'][-1]['Principal']='*'
  if change=='wildcard':d['Statement'][-1]['Resource']='*'
  if change=='live':d['Statement'][-1]['Condition']['StringEquals']['AWS:SourceArn']=DIST.replace('ENEWTEST','E3HQY8QHHHAZP7')
  if change=='unrecorded':d['Statement'][-1]['Condition']['StringEquals']['AWS:SourceArn']=DIST.replace('ENEWTEST','EOTHER')
  if change=='delete':d['Statement']=d['Statement'][1:]
  if change=='metadata':d['Version']='bad'
  call('s3','PutBucketPolicy',dict(req,Policy=json.dumps(d)),ok=False)
 call('s3','PutBucketPolicy',dict(req,Bucket='other'),ok=False)
 call('s3','PutBucketPolicy',dict(req,ExpectedBucketOwner='999999999999'),ok=False)
 call('s3','PutBucketPolicy',dict(req,LmawsPreviousPolicy=old+' '),ok=False)
 Fake.race=True;Fake.reads=0;call('s3','PutBucketPolicy',req,True,ok=False);Fake.race=False;Fake.reads=0
 call('s3','PutBucketPolicy',req,True,mut=True)
 assert json.loads(state.read_text())['records']['rollback:s3:PutBucketPolicy:www.egtry.com']==old
 call('s3','DeleteBucketPolicy',{'Bucket':'www.egtry.com'},ok=False)
 print(f'{n} bounded prerequisite checks passed; loopback only')
 server.shutdown()
if __name__=='__main__':main()
