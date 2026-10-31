#!/usr/bin/env python3
"""Actual SDK loopback proof of persistent, tagged S3 object operations. Never AWS."""
import base64,collections,hashlib,json,os,pathlib,socket,subprocess,tempfile,threading,time,xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,unquote,urlsplit
from xml.sax.saxutils import escape
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION=ET.parse(ROOT/'pom.xml').getroot().find('{*}version').text
JAR=ROOT/f'target/lmaws-{VERSION}.jar';BUCKET='lmaws-lmfiles-run01';RUN='run01';NS='http://s3.amazonaws.com/doc/2006-03-01/'
class Model:
 def __init__(self,mode='ok'):
  self.mode=mode;self.exists=False;self.tag=None;self.objects={};self.calls=[];self.headers=[];self.tag_reads=0;self.block=threading.Event();self.release=threading.Event()
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,status=200,body=b'',headers=None):
  if isinstance(body,str):body=body.encode()
  values={'Content-Type':'application/xml','x-amz-request-id':'fixture-request'};values.update(headers or {})
  self.send_response(status)
  for k,v in values.items():self.send_header(k,str(v))
  self.send_header('Content-Length',str(values.get('Content-Length',len(body)))) if 'Content-Length' not in values else None
  self.end_headers()
  if self.command!='HEAD':
   try:self.wfile.write(body)
   except (BrokenPipeError,ConnectionResetError):pass
 def error(self,code,status=403):return self.reply(status,f'<Error><Code>{code}</Code><Message>fixture error</Message></Error>')
 def parse(self):
  u=urlsplit(self.path);parts=unquote(u.path).strip('/').split('/',1);bucket=parts[0];key=parts[1] if len(parts)>1 else '';q=parse_qs(u.query,keep_blank_values=True)
  m=self.server.model;m.calls.append((self.command,key,q));m.headers.append(dict(self.headers));assert bucket==BUCKET,'unexpected bucket';return m,key,q
 def do_GET(self):
  m,key,q=self.parse();assert not key
  if 'tagging' in q:
   m.tag_reads+=1
   if not m.exists:return self.error('NoSuchBucket',404)
   if m.mode=='tag_denied':return self.error('AccessDenied')
   if m.tag is None:return self.error('NoSuchTagSet',404)
   tag='foreign' if m.mode=='flip_tag' and m.tag_reads>1 else m.tag
   return self.reply(200,f'<Tagging xmlns="{NS}"><TagSet><Tag><Key>lmaws_test</Key><Value>{tag}</Value></Tag></TagSet></Tagging>')
  assert q.get('list-type')==['2'],'unexpected GET operation'
  prefix=q.get('prefix',[''])[0];all_keys=sorted(k for k in m.objects if k.startswith(prefix));offset=int(q.get('continuation-token',['0'])[0]);limit=min(2,int(q.get('max-keys',['1000'])[0]));keys=all_keys[offset:offset+limit];truncated=offset+len(keys)<len(all_keys)
  xml=f'<ListBucketResult xmlns="{NS}"><IsTruncated>{str(truncated).lower()}</IsTruncated>'
  if truncated:xml+=f'<NextContinuationToken>{offset+len(keys)}</NextContinuationToken>'
  for k in keys:
   o=m.objects[k];xml+=f'<Contents><Key>{escape(k)}</Key><Size>{len(o["body"])}</Size><ETag>{o["etag"]}</ETag><LastModified>2026-10-27T00:00:00Z</LastModified><StorageClass>STANDARD</StorageClass></Contents>'
  return self.reply(200,xml+'</ListBucketResult>')
 def do_PUT(self):
  m,key,q=self.parse();assert self.headers.get('X-Lmaws-Test-Profile')=='lmaws'
  body=self.rfile.read(int(self.headers.get('Content-Length','0')))
  if 'tagging' in q:
   assert m.exists and not key
   m.tag=ET.fromstring(body).find('.//{*}Value').text;return self.reply()
  if not key:
   assert not m.exists,'must not recreate an existing bucket'
   m.exists=True
   if m.mode=="race_tag":m.tag="foreign"
   if m.mode=="slow_create":time.sleep(0.3)
   return self.reply()
  assert m.exists and m.tag==RUN,'PUT must have verified ownership'
  if 'aws-chunked' in self.headers.get('Content-Encoding',''):
   decoded=b'';remaining=body
   while True:
    line,remaining=remaining.split(b'\r\n',1);length=int(line.split(b';',1)[0],16)
    if length==0:break
    decoded+=remaining[:length];remaining=remaining[length+2:]
   body=decoded
   assert len(body)==int(self.headers['x-amz-decoded-content-length'])
  checksum=base64.b64encode(hashlib.sha256(body).digest()).decode()
  assert self.headers.get('x-amz-sdk-checksum-algorithm')=='SHA256'
  assert self.headers.get('x-amz-checksum-sha256')==checksum
  if self.headers.get('If-None-Match')=='*' and key in m.objects:return self.error('PreconditionFailed',412)
  if self.headers.get('If-Match') and (key not in m.objects or self.headers['If-Match']!=m.objects[key]['etag']):return self.error('PreconditionFailed',412)
  if m.mode=='put500':return self.error('SlowDown',503)
  etag='"'+hashlib.md5(body).hexdigest()+'"';m.objects[key]={'body':body,'etag':etag,'checksum':checksum,'type':self.headers.get('Content-Type',''),'cache':self.headers.get('Cache-Control',''),'metadata':{k[11:].lower():v for k,v in self.headers.items() if k.lower().startswith('x-amz-meta-')}}
  if m.mode=='drop_put':
   self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
  if m.mode=='block_put':m.block.set();assert m.release.wait(20),'test did not release in-flight PUT'
  return self.reply(200,headers={'ETag':etag,'x-amz-checksum-sha256':checksum,'x-amz-version-id':'fixture-version'})
 def do_HEAD(self):
  m,key,q=self.parse();assert key and not q;assert self.headers.get('x-amz-checksum-mode')=='ENABLED'
  if m.mode=='head403':return self.error('AccessDenied')
  if key not in m.objects:return self.error('NoSuchKey',404)
  o=m.objects[key];headers={'Content-Length':len(o['body']),'ETag':o['etag'],'Content-Type':o['type'],'Cache-Control':o['cache'],'x-amz-checksum-sha256':o['checksum'],'Last-Modified':'Tue, 27 Oct 2026 00:00:00 GMT'}
  headers.update({'x-amz-meta-'+k:v for k,v in o['metadata'].items()});return self.reply(200,headers=headers)
 def do_POST(self):
  m,key,q=self.parse();assert not key and 'delete' in q and self.headers.get('X-Lmaws-Test-Profile')=='lmaws';assert m.tag==RUN
  body=self.rfile.read(int(self.headers.get('Content-Length','0')));keys=[x.text for x in ET.fromstring(body).findall('.//{*}Key')];xml=f'<DeleteResult xmlns="{NS}">'
  for k in keys:
   if m.mode=='partial_delete' and k=='two.txt':xml+=f'<Error><Key>{k}</Key><Code>AccessDenied</Code><Message>fixture</Message></Error>'
   else:m.objects.pop(k,None);xml+=f'<Deleted><Key>{escape(k)}</Key></Deleted>'
  return self.reply(200,xml+'</DeleteResult>')
 def do_DELETE(self):
  m,key,q=self.parse();assert not key and not q and self.headers.get('X-Lmaws-Test-Profile')=='lmaws';assert m.tag==RUN
  if m.objects:return self.error('BucketNotEmpty',409)
  m.exists=False;m.tag=None;return self.reply(204)
class Harness:
 def __init__(self,mode='ok'):
  self.tmp=tempfile.TemporaryDirectory(prefix='s3-objects-');self.work=pathlib.Path(self.tmp.name);self.model=Model(mode);self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.model=self.model;threading.Thread(target=self.server.serve_forever,daemon=True).start();self.n=0
  self.schema=self.work/'schema.json';self.schema.write_text(subprocess.check_output(['java','-jar',str(JAR),'--lmcode-schema','--json'],text=True));self.payload=self.work/'payload.bin';self.payload.write_bytes(b'hello object')
 def __enter__(self):return self
 def __exit__(self,*args):self.model.release.set();self.server.shutdown();self.server.server_close();self.tmp.cleanup()
 def output(self,name,expr,rows=False):return 'file_write('+json.dumps(str(self.work/(name+'.json')))+','+expr+('.json()' if rows else '')+');\n'
 def read(self,name):return json.loads((self.work/(name+'.json')).read_text())
 def run(self,body,profile='lmaws',cap='0.05',ok=True,background=False):
  self.n+=1;source=self.work/f'code{self.n}.lms';bc=self.work/f'code{self.n}.dslb';source.write_text('let p=_dsl_ schema='+json.dumps(str(self.schema))+';\n'+body+'\nend _dsl_\nsavedsl(p,'+json.dumps(str(bc))+');\n')
  env=dict(os.environ,AWS_PROFILE=profile,AWS_DEFAULT_PROFILE=profile,AWS_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_LIVE='1',LMAWS_ENDPOINT=f'http://127.0.0.1:{self.server.server_port}',LMAWS_LEDGER_DIR=str(self.work/'ledgers'),LMAWS_MAX_COST_USD=cap,CI='true')
  compiled=subprocess.run(['lmscript',str(source)],env=env,cwd=self.work,capture_output=True,text=True,timeout=30);assert compiled.returncode==0,compiled.stderr
  command=['java','-jar',str(JAR),'--lmcode',str(bc)]
  if background:return subprocess.Popen(command,env=env,cwd=self.work,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  result=subprocess.run(command,env=env,cwd=self.work,capture_output=True,text=True,timeout=60);assert (result.returncode==0)==ok,result.stdout+result.stderr;return result
 def create(self):return 'let c=aws.region("us-east-1");'+self.output('bucket',f'c.s3_bucket_create_exact("{BUCKET}","{RUN}")')
 def attach(self):return 'let c=aws.region("us-east-1");'+self.output('attach',f'c.s3_bucket_attach("{BUCKET}","{RUN}")')
 def put(self,key='one.txt',options=None,name='put'):
  options=options if options is not None else {'content_type':'text/plain','cache_control':'max-age=60','metadata':{'kind':'fixture'},'if_none_match':'*'}
  return self.output(name,f'c.s3_put_file({json.dumps(BUCKET)},{json.dumps(key)},{json.dumps(str(self.payload))},{json.dumps(json.dumps(options))})')
 def summary(self,name='summary'):
  before=len(self.model.calls);self.run(self.output(name,f'aws.s3_ledger_summary("{RUN}")'));assert len(self.model.calls)==before;return self.read(name)
if __name__=='__main__':
 with Harness() as h:
  assert h.summary()['attempts']==0 and not (h.work/'ledgers'/f'{RUN}-s3-operations.jsonl').exists()
  body=h.create()+h.put()+h.output('head',f'c.s3_head_object("{BUCKET}","one.txt")')+h.output('list',f'c.s3_list_objects("{BUCKET}","",1000)',True)
  h.run(body);p=h.read('put');head=h.read('head');assert p['ok'] and p['bytes']==12 and p['checksum_verified'] and p['version_id']=='fixture-version';assert p['started'] and p['finished'] and p['request_id']
  assert head['exists'] and head['size']==12 and head['metadata']=={'kind':'fixture'} and head['content_type']=='text/plain' and head['cache_control']=='max-age=60' and head['checksum_sha256']==p['checksum_sha256']
  assert h.read('list')[0]['key']=='one.txt' and h.model.exists,'host close must not delete persistent resources'
  before=len(h.model.calls);h.run(h.create());assert h.read('bucket')['created'] is False and len(h.model.calls)==before+1
  h.run(h.attach()+h.put(name='conditional'));r=h.read('conditional');assert not r['ok'] and r['http_status']==412 and not r['ambiguous']
  options={'if_match':p['etag']};h.run(h.attach()+h.put(options=options,name='matched'));assert h.read('matched')['ok']
  h.run(h.attach()+h.put(options={'if_match':'"wrong"'},name='mismatch'));assert h.read('mismatch')['http_status']==412
  for key in ['two.txt','three.txt','four.txt','five.txt']:
   h.run(h.attach()+h.put(key))
  h.run(h.attach()+h.output('pages',f'c.s3_list_objects("{BUCKET}","",1000)',True));assert len(h.read('pages'))==5
  h.run(h.attach()+h.output('bounded',f'c.s3_list_objects("{BUCKET}","",1)',True),ok=False)
  h.model.mode='partial_delete';h.run(h.attach()+h.output('deleted',f'c.s3_delete_objects("{BUCKET}",'+json.dumps('["one.txt","two.txt"]')+')',True));out=h.read('deleted');assert out[0]['ok']=='true' and out[1]['error_code']=='AccessDenied'
  h.run(h.attach()+h.output('nonempty',f'c.s3_bucket_delete("{BUCKET}","{RUN}")'));assert h.read('nonempty')['error_code']=='BucketNotEmpty'
  h.model.mode='ok';remaining=json.dumps(list(h.model.objects));h.run(h.attach()+h.output('rest',f'c.s3_delete_objects("{BUCKET}",{json.dumps(remaining)})',True)+h.output('bucketGone',f'c.s3_bucket_delete("{BUCKET}","{RUN}")'));assert h.read('bucketGone')['ok'] and not h.model.exists
  h.run(h.attach());assert h.read('attach')['exists'] is False
  ledger=h.summary();assert ledger['attempts']==len(h.model.calls) and ledger['by_operation']['PutObject']['requests']==len([x for x in h.model.calls if x[0]=='PUT' and x[1]])
 with Harness() as h:
  h.run(h.create());before=len(h.model.calls)
  h.run(h.attach()+h.put('bad.txt',{'expected_sha256':'0'*64},'badsha'))
  assert h.read('badsha')['error_code']=='LocalChecksumMismatch' and not h.read('badsha')['ambiguous']
  assert not any(m=='PUT' and key for m,key,q in h.model.calls[before:])
  h.payload.unlink();h.run(h.attach()+h.put('missing.txt',name='missing'));assert h.read('missing')['error_code']=='LocalIO' and not h.read('missing')['ambiguous']
  h.model.mode='head403';h.run(h.attach()+h.output('forbidden',f'c.s3_head_object("{BUCKET}","one.txt")'));assert h.read('forbidden')['exists'] is None and h.read('forbidden')['http_status']==403
  h.run(h.attach()+h.output('limit',f'c.s3_list_objects("{BUCKET}","",4294967297)',True),ok=False)
 with Harness('race_tag') as h:
  h.run(h.create(),ok=False);assert h.model.tag=='foreign' and not any(m=='PUT' and 'tagging' in q for m,key,q in h.model.calls),'never retag a bucket whose ownership changed'
 with Harness('slow_create') as h:
  first=h.run(h.create(),background=True);second=h.run(h.create(),background=True)
  assert first.wait(30)==second.wait(30)==0
  assert len([1 for m,key,q in h.model.calls if m=='PUT' and not key and 'tagging' not in q])==1,'exact-name creation must serialize and reattach across executors'
 for mode in ['put500','drop_put']:
  with Harness(mode) as h:
   h.run(h.create()+h.put());r=h.read('put');assert not r['ok'] and r['ambiguous'],r
   assert len([x for x in h.model.calls if x[0]=='PUT' and x[1]])==1,'SDK must not invisibly retry an ambiguous PUT'
 for tag in [None,'foreign']:
  with Harness() as h:
   h.model.exists=True;h.model.tag=tag;h.run(h.create(),ok=False);assert all(m!='PUT' for m,k,q in h.model.calls)
 with Harness('flip_tag') as h:
  h.model.exists=True;h.model.tag=RUN;h.run(h.attach()+h.put(),ok=False);assert not h.model.objects
 for profile in ['default','admin']:
  with Harness() as h:h.run(h.create(),profile=profile,ok=False);assert not h.model.calls
 with Harness() as h:
  h.run('let c=aws.region("us-east-1");c.s3_bucket_create_exact("production-bucket","run01");',ok=False);assert not h.model.calls
  h.run(h.create(),cap='0.0000065');before=len(h.model.calls);h.run(h.attach(),cap='0.0000065',ok=False);assert len(h.model.calls)==before,'restart may not reset cumulative cap'
  assert h.summary()['by_operation']['PutBucketTagging']['requests']==1
 with Harness() as h:
  h.run(h.create(),cap='0.000001',ok=False);assert not h.model.exists and not any(m=='PUT' for m,key,q in h.model.calls),'do not create a bucket if tagging cannot fit the cap'
 with Harness('block_put') as h:
  process=h.run(h.create()+h.put(),background=True);assert h.model.block.wait(30),'inflight signal';process.kill();process.wait(10);h.model.release.set();h.model.mode='ok'
  h.run(h.attach()+h.put(name='uncertainRetry')+h.output('proof',f'c.s3_head_object("{BUCKET}","one.txt")'));assert h.read('uncertainRetry')['http_status']==412 and h.read('proof')['checksum_sha256']
  assert h.summary()['by_operation']['PutObject']['requests']==2,'only the explicit uncertain retry may repeat'
 print('PASS S3 SDK wire checksums/headers, receipts/412/ambiguity, bounded pagination, per-key deletion, exact-tag guards, process kill/reattach, zero-request no-op and cumulative cap')
