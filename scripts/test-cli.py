#!/usr/bin/env python3
"""CLI, schema parity, failure codes and managed memory enforcement."""
import hashlib,http.server,json,os,pathlib,struct,subprocess,sys,tempfile,threading,time,shutil
root=pathlib.Path(__file__).resolve().parents[1];host=pathlib.Path(sys.argv[1]).resolve();env=dict(os.environ);env.pop('LMAWS_LIVE',None);env['CLASSPATH']=str(pathlib.Path(__file__).resolve().parents[1]/'target/lmaws-0.1.27.jar')
with host.open('rb') as binary: is_elf=binary.read(4)==b'\x7fELF'
LMSCRIPT=shutil.which('lmscript.cmd' if os.name=='nt' else 'lmscript') or 'lmscript'
def script_command(*args): return (['cmd.exe','/c',LMSCRIPT] if os.name=='nt' and LMSCRIPT.lower().endswith('.cmd') else [LMSCRIPT])+list(args)
def run(args,code=0,extra=None):
 p=subprocess.run(([str(host)] if host.suffix!='.cmd' else ['cmd.exe','/c',str(host)])+args,env=dict(env,**(extra or {})),text=True,encoding="utf-8",capture_output=True,timeout=120)
 assert p.returncode==code,(args,p.returncode,p.stdout[-1200:],p.stderr[-1200:]);return p
assert run(['--version']).stdout=='lmaws 0.1.27\n'
assert run(['--notices']).stdout==(root/'THIRD_PARTY_NOTICES').read_text(encoding="utf-8")
assert 'LMAWS_MAX_MEMORY_MB' in run(['--help']).stdout
assert '\u2014 AWS SDK' in run(['--help'],extra={'JAVA_TOOL_OPTIONS':'-Dstdout.encoding=windows-1252 -Dstderr.encoding=windows-1252'}).stdout
schema=run(['--lmcode-schema','--json']).stdout;assert schema==(root/'schema/lmaws.dsl.json').read_text(encoding="utf-8");json.loads(schema)
p=subprocess.run(script_command('--lmcode-signatures',str(root/'schema/lmaws.dsl.json')),text=True,encoding="utf-8",capture_output=True,timeout=45);assert p.returncode==0,p.stderr
assert p.stdout==run(['--lmcode-signatures']).stdout,'schema/registry signature mismatch'
p=subprocess.run(script_command('--lmcode-signatures',str(root/'schema/lmaws.dsl.json'),'--without-std'),text=True,encoding="utf-8",capture_output=True,timeout=45);assert p.returncode==0,p.stderr
assert p.stdout==run(['--lmcode-signatures','--without-std']).stdout,'host-only schema/registry signature mismatch'
assert 'str_len' not in json.loads(schema)['functions'],'schema must omit built-in std'

run([],2);run(['--nonesuch'],2);run(['--lmcode','missing-bytecode.dslb'],3)
for raw in ['0','-1','wat','1.5','99999999999999999999999999']:
 assert 'positive whole' in run(['--version'],2,{'LMAWS_MAX_MEMORY_MB':raw}).stdout
for raw in ['-0.01','0.250001','nan','1e100']:
 assert 'LMAWS_MAX_COST_USD' in run(['--version'],2,{'LMAWS_MAX_COST_USD':raw}).stdout
workflow=(root/'.github/workflows/ci.yml').read_text(encoding='utf-8').lower()
assert 'id-token:' not in workflow and 'configure-aws-credentials' not in workflow and 'secrets.aws_' not in workflow,'CI must remain fake-only with no OIDC or cloud credentials'
run(['--self-test'])
with tempfile.TemporaryDirectory(prefix='lmaws-cli-') as d:
 d=pathlib.Path(d);bad=d/'bad.dslb';bad.write_bytes(b'not bytecode');run(['--lmcode',str(bad)],3)
 retired=run(['--dry-run','--lmcode','missing-bytecode.dslb'],2)
 assert 'LMCODE_RETURN_BEGIN' in retired.stdout and 'CLI_USAGE' in retired.stdout
 sentinel=d/'sentinel';bytecode=d/'effect.dslb'
 def u16(n): return struct.pack('>H',n)
 def u32(n): return struct.pack('>I',n)
 def make_effect(output,effect_path,value,function):
  strings=[str(effect_path),value,'fn '+function+'(string, string) -> void']
  code=b'\x02'+u32(0)+b'\x02'+u32(1)+b'\x07'+u16(0)+b'\x02'+b'\x11'
  image=bytearray(b'DSLB'+u16(6)+hashlib.sha256(schema.encode()).digest()+u32(len(strings)))
  for item in strings:
   raw=item.encode();image+=b'\x01'+u32(len(raw))+raw
  image+=u16(1)+u32(2)+u16(0)+u16(0)+u16(2)+u32(len(code))+code+u32(0)+u16(0)
  output.write_bytes(image)
 make_effect(bytecode,sentinel,'ran','file_write')
 manifest=d/'invocation.json';part={'index':0,'file':str(bytecode.resolve())}
 def invocation(dry_marker):
  data={'version':1,'mode':'single','parts':[part]}
  if dry_marker is not ...: data['dry']=dry_marker
  manifest.write_text(json.dumps(data),encoding='utf-8')
  result=run(['--lmcode',str(bytecode.resolve())],2 if dry_marker is ... or not isinstance(dry_marker,bool) else 0,{'LMCODE_INVOCATION_FILE':str(manifest.resolve())})
  return result
 invocation(...);assert not sentinel.exists(),'missing dry marker dispatched an effect'
 invocation('true');assert not sentinel.exists(),'non-boolean dry marker dispatched an effect'
 invocation(True);assert not sentinel.exists(),'dry invocation called the effectful callback'
 invocation(False);assert sentinel.read_text(encoding='utf-8')=='ran','real invocation did not call the callback'
 assert '"dry":true' in invocation(True).stdout,'dry success marker missing'
 part_a=d/'part-a.dslb';part_b=d/'part-b.dslb';trace=d/'builder-trace'
 make_effect(part_a,trace,'A','file_append');make_effect(part_b,trace,'B','file_append')
 manifest.write_text(json.dumps({'version':1,'mode':'builder','dry':False,'parts':[{'index':0,'file':str(part_a.resolve())},{'index':1,'file':str(part_b.resolve())}]}),encoding='utf-8')
 built=run(['--lmcode',str(part_a.resolve()),'--lmcode',str(part_b.resolve())],0,{'LMCODE_INVOCATION_FILE':str(manifest.resolve())})
 assert trace.read_text(encoding='utf-8')=='AB','builder parts did not share one effect sequence'
 assert '"parts":2' in built.stdout and 'LMCODE_RETURN_BEGIN' in built.stdout
 deny=d/'ci-denied.lms'
 deny.write_text('s=load_schema(cli=\"java ai.lmctl.lmaws.Main\");\np = _lmcode_ s;\nlet cloud=aws.region("us-east-1"); let who=cloud.identity();\nend _lmcode_\nr=run_lmcode(p); assert(!r.ok && r.phase=="run");\n')
 compiled=subprocess.run(script_command(str(deny)),env=dict(env,CI='true',LMAWS_LIVE='1',LMAWS_ENDPOINT='',LMAWS_LEDGER_DIR=str(d/'ci-ledgers')),text=True,encoding='utf-8',capture_output=True,timeout=60);assert compiled.returncode==0,(compiled.stdout,compiled.stderr)
 code=d/'budget.lms'
 code.write_text('s=load_schema(cli=\"java ai.lmctl.lmaws.Main\");\np = _lmcode_ s;\nlet i = 0; while (i < 10000) { let data = str_repeat("x", 1000000); i = i + 1; }\nend _lmcode_\nr=run_lmcode(p); assert(!r.ok && r.phase=="run");\n')
 p=subprocess.run(script_command(str(code)),text=True,encoding="utf-8",capture_output=True,timeout=60);assert p.returncode==0,p.stderr
 # Real mutations are profile-gated before any SDK client is opened.  Use a
 # deliberately missing profile and a loopback endpoint-free live session: the
 # expected guard must win over credential resolution/network access.
 guard=d/'profile-guard.lms'
 guard.write_text('s=load_schema(cli=\"java ai.lmctl.lmaws.Main\");\np = _lmcode_ s;\nlet cloud=aws.example("profile_guard"); let run=cloud.example_run(); let q=run.queue("guard");\nend _lmcode_\nr=run_lmcode(p); assert(!r.ok && r.phase=="run");\n')
 compiled=subprocess.run(script_command(str(guard)),env=dict(env,LMAWS_LIVE='1',AWS_PROFILE='default',AWS_DEFAULT_PROFILE='default',AWS_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_LEDGER_DIR=str(d/'profile-ledgers'),LMAWS_EVIDENCE_DIR=str(d/'profile-evidence'),CI='false',LMAWS_ENDPOINT=''),text=True,encoding='utf-8',capture_output=True,timeout=60);assert compiled.returncode==0,(compiled.stdout,compiled.stderr)
 small=subprocess.run(script_command(str(code)),env=dict(env,LMAWS_MAX_MEMORY_MB='64'),text=True,encoding='utf-8',capture_output=True,timeout=60);assert small.returncode==0,small.stderr
 # Host switches behind the scripts' host_run helper; each has a red control.
 def lms(name,body,after,extra=None):
  path=d/name;path.write_text('s=load_schema(cli=\"java ai.lmctl.lmaws.Main\");\np = _lmcode_ s;\n'+body+'\nend _lmcode_\n'+after+'\n',encoding='utf-8')
  return subprocess.run(script_command(str(path)),env=dict(env,**(extra or {})),text=True,encoding='utf-8',capture_output=True,timeout=90)
 log=d/'host.log'
 def loud(name): return 'let spend = aws.spend("all",30,10,0.25);\nspend.write("'+(d/name).as_posix()+'");'
 def spin(count): return 'let i = 0; while (i < '+str(count)+') { i = i + 1; }'
 logged=lms('log.lms',loud('logged'),'r=run_lmcode(p);assert(r.ok);',{'LMAWS_LOG_FILE':str(log)})
 assert logged.returncode==0,(logged.stdout,logged.stderr)
 assert 'estimated cost:' in log.read_text(encoding='utf-8') and 'estimated cost:' not in logged.stdout,'LMAWS_LOG_FILE did not capture host stdout'
 assert 'LMCODE_RETURN' not in log.read_text(encoding='utf-8'),'the terminal frame must stay on real stdout'
 plain=lms('plain.lms',loud('plain'),'r=run_lmcode(p);assert(r.ok);')
 assert plain.returncode==0 and 'estimated cost:' in plain.stdout,'red control: host stdout is forwarded without LMAWS_LOG_FILE'
 failed=lms('log-fail.lms','check(1 == 2);','r=run_lmcode(p);assert(!r.ok);println("failure-is-data");',{'LMAWS_LOG_FILE':str(d/'fail.log')})
 assert failed.returncode==0 and 'failure-is-data' in failed.stdout,'a failure frame was lost with LMAWS_LOG_FILE set'
 assert 'LMCODE_RETURN' in run(['--lmcode',str(bad)],3,{'LMAWS_LOG_FILE':str(d/'bad.log')}).stdout,'a failure frame left stdout'
 quick=lms('deadline-ok.lms',spin(100),'r=run_lmcode(p);assert(r.ok);',{'LMAWS_DEADLINE_MS':'60000'})
 assert quick.returncode==0,'red control: a deadline that is not reached changes nothing'
 unset=lms('deadline-unset.lms',spin(100),'r=run_lmcode(p);assert(r.ok);')
 assert unset.returncode==0,'red control: no deadline by default'
 for raw in ['0','-1','wat']:
  sentinel.unlink(missing_ok=True)
  assert 'CLI_USAGE' in run(['--lmcode',str(bytecode)],2,{'LMAWS_DEADLINE_MS':raw}).stdout,raw
  assert not sentinel.exists(),'an invalid deadline must refuse before the program runs'
 calls=[];hang=[0]
 class Spy(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
   calls.append(self.path);time.sleep(hang[0]);self.send_response(500);self.send_header('Content-Length','0');self.end_headers()
  do_GET=do_POST
  def log_message(self,*args):pass
 spy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Spy);threading.Thread(target=spy.serve_forever,daemon=True).start()
 online={k:v for k,v in env.items() if k not in ('CI','GITHUB_ACTIONS')}
 online.update(LMAWS_LIVE='1',LMAWS_ENDPOINT='http://127.0.0.1:%d'%spy.server_address[1],AWS_ACCESS_KEY_ID='poc-test-invalid',AWS_SECRET_ACCESS_KEY='poc-test-invalid',AWS_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_LEDGER_DIR=str(d/'spy-ledgers'))
 reader='let cloud=aws.region("us-east-1"); let who=cloud.identity();'
 def spied(name,offline,extra=None):
  path=d/name;path.write_text('s=load_schema(cli=\"java ai.lmctl.lmaws.Main\");\np = _lmcode_ s;\n'+reader+'\nend _lmcode_\nr=run_lmcode(p);println("ok="+str(r.ok));\n',encoding='utf-8')
  return subprocess.run(script_command(str(path)),env=dict(online,**({'LMAWS_OFFLINE':'1'} if offline else {}),**(extra or {})),text=True,encoding='utf-8',capture_output=True,timeout=90)
 calm=spied('offline.lms',True);assert calm.returncode==0 and 'ok=true' in calm.stdout,(calm.stdout,calm.stderr)
 assert not calls,('LMAWS_OFFLINE reached the endpoint',calls)
 spied('online.lms',False);assert calls,'red control: without LMAWS_OFFLINE this program calls AWS'
 hang[0]=30;started=time.monotonic()
 slow=spied('deadline.lms',False,{'LMAWS_DEADLINE_MS':'1500'})
 assert slow.returncode!=0 and 'ok=' not in slow.stdout and 'deadline reached' in slow.stdout+slow.stderr,(slow.stdout,slow.stderr)
 assert time.monotonic()-started<25,'LMAWS_DEADLINE_MS did not stop a host waiting on AWS'
 spy.shutdown();spy.server_close()
 if sys.platform=='linux' and is_elf:
  import resource
  def limit():resource.setrlimit(resource.RLIMIT_AS,(6*1024**3,6*1024**3))
  p=subprocess.run([str(host),'--lmcode',str(bytecode)],env=env,text=True,encoding="utf-8",capture_output=True,timeout=180,preexec_fn=limit)
  assert p.returncode==3 and 'LMAWS_MAX_MEMORY_MB' in p.stdout,(p.returncode,p.stdout[-1000:],p.stderr[-1000:])
print('PASS CLI, signatures, eight SDK groups, malformed input and memory limits')
