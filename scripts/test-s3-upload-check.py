#!/usr/bin/env python3
"""Actual SDK loopback proof of two-profile S3 upload verification; no AWS access."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,unquote
import hashlib,json,os,shutil,subprocess,tempfile,threading,xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[1]
VERSION=ET.parse(ROOT/'pom.xml').getroot().find('{*}version').text
JAR=ROOT/f'target/lmaws-{VERSION}.jar'
MD5=hashlib.md5(b'x').hexdigest();ACCOUNT='000000000000'
class Model:
 def __init__(self,mode):
  self.mode=mode;self.bucket=mode.startswith('explicit') or mode in ('sandbox_exists','recovery');self.object=mode in ('explicit_collision','recovery');self.calls=[];self.tagged=False;self.puts=0;self.deletes=0;self.bucket_deletes=0
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def send(self,status=200,body='',headers=None):
  data=body.encode();self.send_response(status)
  for k,v in (headers or {}).items():self.send_header(k,str(v))
  if not headers or 'Content-Length' not in headers:self.send_header('Content-Length',str(len(data)))
  self.end_headers()
  if self.command!='HEAD':self.wfile.write(data)
 def error(self,code,status=403):self.send(status,f'<Error><Code>{code}</Code><Message>synthetic error</Message></Error>',{'Content-Type':'application/xml'})
 def call(self):
  m=self.server.model;u=urlsplit(self.path);path=unquote(u.path);parts=path.strip('/').split('/',1);key=parts[1] if len(parts)>1 else '';profile=self.headers.get('X-Lmaws-Test-Profile','');body=self.rfile.read(int(self.headers.get('Content-Length','0')))
  m.calls.append((self.command,path,u.query,profile,dict(self.headers)))
  if self.command=='POST' and b'GetCallerIdentity' in body:
   return self.send(200,f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>{ACCOUNT}</Account><Arn>arn:aws:sts::{ACCOUNT}:federated-user/fixture</Arn><UserId>fixture</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>',{'Content-Type':'text/xml'})
  if self.command=='GET' and path=='/':
   assert not m.bucket,'inventory must occur after owned bucket deletion'
   return self.send(200,'<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>',{'Content-Type':'application/xml'})
  if self.command=='HEAD' and not key:return self.send(200 if m.bucket else 404,headers={'Content-Length':'0','x-amz-bucket-region':'us-east-1'})
  if self.command=='PUT' and not key and 'tagging' not in u.query:
   assert profile=='lmaws' and not m.bucket
   m.bucket=True;return self.send()
  if self.command=='PUT' and 'tagging' in u.query:
   assert profile=='lmaws'
   if m.mode=='tag_deny':return self.error('AccessDenied')
   tags=ET.fromstring(body);values={v.find('{*}Key').text:v.find('{*}Value').text for v in tags.findall('.//{*}Tag')};assert set(values)=={'lmaws_test'};m.run=values['lmaws_test'];m.tagged=True;return self.send()
  if self.command=='GET' and 'tagging' in u.query:return self.send(200,f'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>lmaws_test</Key><Value>{m.run}</Value></Tag></TagSet></Tagging>',{'Content-Type':'application/xml'})
  if self.command=='HEAD' and key:
   assert (profile=='default' or m.mode=='recovery' and profile=='lmaws') and self.headers.get('x-amz-expected-bucket-owner')==ACCOUNT
   if m.mode=='head_deny' and m.puts==0:return self.error('AccessDenied')
   if not m.object:return self.send(404,headers={'Content-Length':'0'})
   etag='bad' if m.mode=='etag_bad' else MD5
   return self.send(200,headers={'Content-Length':'1','ETag':'"'+etag+'"'})
  if self.command=='PUT' and key:
   assert profile=='default','PUT must never fall back to lmaws'
   assert self.headers.get('If-None-Match')=='*' and self.headers.get('x-amz-expected-bucket-owner')==ACCOUNT
   assert self.headers.get('Content-MD5'),'integrity header absent'
   m.puts+=1
   if m.mode=='put_deny':return self.error('AccessDenied')
   if m.mode=='put_race':m.object=True;return self.error('PreconditionFailed',412)
   assert not m.object,'existing object was overwritten'
   m.object=True;return self.send(headers={'ETag':'"'+MD5+'"'})
  if self.command=='DELETE' and key:
   assert profile=='lmaws' and m.object and self.headers.get('If-Match')=='"'+MD5+'"'
   m.deletes+=1;m.object=False;return self.send(204)
  if self.command=='DELETE' and not key:
   assert profile=='lmaws' and m.bucket
   if m.object:return self.error('BucketNotEmpty',409)
   m.bucket_deletes+=1;m.bucket=False;return self.send(204)
  raise AssertionError((self.command,path,u.query))
 def do_GET(self):self.call()
 def do_HEAD(self):self.call()
 def do_POST(self):self.call()
 def do_PUT(self):self.call()
 def do_DELETE(self):self.call()
with tempfile.TemporaryDirectory(prefix='lmaws-s3check-test-') as temporary:
 work=Path(temporary);schema=work/'schema.json'
 schema.write_text(subprocess.check_output(['java','-jar',str(JAR),'--lmcode-schema','--json'],cwd=ROOT,text=True))
 def run(mode,index,bucket='',allow=False,repeat=False,reject=False,bad_path=False):
  model=Model(mode);server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.model=model;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  try:
   runid=f'cafe{index:02x}';journal=work/('.lmaws-local-spoof' if bad_path else '.lmaws-local')/f'{runid}.json';result=work/(mode+'.json');source=work/(mode+'.lms');bc=work/(mode+'.dslb')
   code=f'let cloud=aws.region("us-east-1");let result=cloud.s3_upload_check({json.dumps(runid)},{json.dumps(bucket)},{str(allow).lower()},{json.dumps(str(journal))});file_write({json.dumps(str(result))},result.json());'
   if mode=='recovery':
    model.tagged=True;model.run=runid;journal.parent.mkdir(exist_ok=True);journal.write_text(json.dumps({'run_id':runid,'bucket':'lmaws-s3check-'+runid,'key':'lmaws-s3check/'+runid+'.txt','sandbox':'true','bucket_created':'true','tagged':'true','default_put':'passed','etag':'"'+MD5+'"'}));code=f'let cloud=aws.region("us-east-1");let result=cloud.s3_upload_cleanup({json.dumps(runid)},{json.dumps(str(journal))});file_write({json.dumps(str(result))},result.json());'
   source.write_text('let p=_dsl_ schema='+json.dumps(str(schema))+';\n'+code+'\nend _dsl_\nsavedsl(p,'+json.dumps(str(bc))+');\n')
   subprocess.run(['lmscript',str(source)],cwd=work,check=True,capture_output=True,text=True,timeout=30)
   env=dict(os.environ,AWS_PROFILE='lmaws',AWS_DEFAULT_PROFILE='lmaws',AWS_REGION='us-east-1',LMAWS_LIVE='1',LMAWS_ENDPOINT=f'http://127.0.0.1:{server.server_port}',LMAWS_MAX_COST_USD='0.05',LMAWS_LEDGER_DIR=str(work/'ledgers'))
   p=subprocess.run(['java','-jar',str(JAR),'--dry-run' if mode=='demo' else '--live','--profile','lmaws','--lmcode',str(bc)],cwd=work,env=env,text=True,capture_output=True,timeout=60)
   if reject:
    assert p.returncode!=0 and not model.calls,(mode,p.stdout,p.stderr);return {},model
   assert p.returncode==0,(mode,p.stdout,p.stderr)
   row=json.loads(result.read_text());assert journal.exists()
   if repeat:
    before=len(model.calls);again=subprocess.run(['java','-jar',str(JAR),'--dry-run' if mode=='demo' else '--live','--profile','lmaws','--lmcode',str(bc)],cwd=work,env=env,text=True,capture_output=True,timeout=30);assert again.returncode!=0 and len(model.calls)==before,'existing journal must refuse before SDK calls'
   return row,model
  finally:server.shutdown();server.server_close();thread.join()
 row,m=run('happy',0,repeat=True);assert row['state']=='clean' and row['leftovers']=='0' and row['etag_match']=='true' and row['head_before']=='absent' and row['head_after_delete']=='absent';assert (m.puts,m.deletes,m.bucket_deletes)==(1,1,1)
 for i,mode in enumerate(['put_deny','head_deny','etag_bad','tag_deny'],1):
  row,m=run(mode,i);assert row['state']=='failed' and row['leftovers']=='0' and m.bucket_deletes==1,(mode,row)
  if mode=='put_deny':assert row['first_put_denied']=='true' and m.puts==1 and m.deletes==0
  if mode in ('head_deny','tag_deny'):assert m.puts==0
 row,m=run('explicit',6,'existing-fixture',True);assert row['state']=='left' and row['object_left']=='true' and row['leftovers']=='1' and (m.deletes,m.bucket_deletes)==(0,0) and m.bucket and m.object
 row,m=run('explicit_collision',7,'existing-fixture',True);assert row['state']=='failed' and m.puts==0 and m.deletes==0 and m.bucket_deletes==0
 row,m=run('missing',8,'explicit-missing-fixture',True);assert row['state']=='failed' and not m.bucket and m.puts==0 and not any(c[0]=='PUT' for c in m.calls)
 run('explicit_without_flag',9,'existing-fixture',False,reject=True)
 run('bad_path',10,reject=True,bad_path=True)
 row,m=run('sandbox_exists',11);assert row['state']=='failed' and m.bucket and m.puts==0 and m.bucket_deletes==0
 row,m=run('put_race',12);assert row['state']=='cleanup_failed' and row['leftovers']=='unknown' and m.object and m.puts==1 and m.deletes==0
 row,m=run('recovery',13);assert row['leftovers']=='0' and m.deletes==1 and m.bucket_deletes==1
 row,m=run('demo',14);assert row['state']=='clean' and row['demo']=='true' and not m.calls,'demo must make zero SDK calls'
 print('PASS actual SDK S3 upload check: profile separation, conditional wire headers, ordered verification, failure cleanup, existing-bucket leave/collision, missing bucket, and journal replay refusal')
