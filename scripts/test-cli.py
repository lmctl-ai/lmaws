#!/usr/bin/env python3
"""CLI, schema parity, failure codes and managed memory enforcement."""
import json,os,pathlib,subprocess,sys,tempfile,shutil
root=pathlib.Path(__file__).resolve().parents[1];host=pathlib.Path(sys.argv[1]).resolve();env=dict(os.environ);env.pop('LMAWS_LIVE',None)
with host.open('rb') as binary: is_elf=binary.read(4)==b'\x7fELF'
def run(args,code=0,extra=None):
 p=subprocess.run(([str(host)] if host.suffix!='.cmd' else ['cmd.exe','/c',str(host)])+args,env=dict(env,**(extra or {})),text=True,encoding="utf-8",capture_output=True,timeout=120)
 assert p.returncode==code,(args,p.returncode,p.stdout[-1200:],p.stderr[-1200:]);return p
assert run(['--version']).stdout=='lmaws 0.1.20\n'
assert run(['--notices']).stdout==(root/'THIRD_PARTY_NOTICES').read_text(encoding="utf-8")
assert 'LMAWS_MAX_MEMORY_MB' in run(['--help']).stdout
assert '\u2014 AWS SDK' in run(['--help'],extra={'JAVA_TOOL_OPTIONS':'-Dstdout.encoding=windows-1252 -Dstderr.encoding=windows-1252'}).stdout
schema=run(['--dsl-schema','--json']).stdout;assert schema==(root/'schema/lmaws.dsl.json').read_text(encoding="utf-8");json.loads(schema)
p=subprocess.run([shutil.which('lmscript'),'--dsl-signatures',str(root/'schema/lmaws.dsl.json')],text=True,encoding="utf-8",capture_output=True,timeout=45);assert p.returncode==0,p.stderr
assert p.stdout==run(['--dsl-signatures']).stdout,'schema/registry signature mismatch'
p=subprocess.run([shutil.which('lmscript'),'--dsl-signatures',str(root/'schema/lmaws.dsl.json'),'--without-std'],text=True,encoding="utf-8",capture_output=True,timeout=45);assert p.returncode==0,p.stderr
assert p.stdout==run(['--dsl-signatures','--without-std']).stdout,'host-only schema/registry signature mismatch'
assert 'str_len' not in json.loads(schema)['functions'],'schema must omit built-in std'

run([],2);run(['--nonesuch'],2);run(['--dsl','missing-bytecode.dslb'],3)
for raw in ['0','-1','wat','1.5','99999999999999999999999999']:
 assert 'positive whole' in run(['--version'],2,{'LMAWS_MAX_MEMORY_MB':raw}).stderr
for raw in ['-0.01','0.250001','nan','1e100']:
 assert 'LMAWS_MAX_COST_USD' in run(['--version'],2,{'LMAWS_MAX_COST_USD':raw}).stderr
workflow=(root/'.github/workflows/ci.yml').read_text(encoding='utf-8').lower()
assert 'id-token:' not in workflow and 'configure-aws-credentials' not in workflow and 'secrets.aws_' not in workflow,'CI must remain fake-only with no OIDC or cloud credentials'
run(['--self-test'])
with tempfile.TemporaryDirectory(prefix='lmaws-cli-') as d:
 d=pathlib.Path(d);bad=d/'bad.dslb';bad.write_bytes(b'not bytecode');run(['--dsl',str(bad)],3)
 deny=d/'ci-denied.lms';deny_out=d/'ci-denied.dslb'
 deny.write_text('p = _dsl_ schema='+json.dumps(str(root/'schema/lmaws.dsl.json'))+';\nlet cloud=aws.region("us-east-1"); let who=cloud.identity();\nend _dsl_\nsavedsl(p,'+json.dumps(str(deny_out))+');\n')
 compiled=subprocess.run([shutil.which('lmscript'),str(deny)],text=True,encoding='utf-8',capture_output=True,timeout=60);assert compiled.returncode==0,compiled.stderr
 denied=run(['--dsl',str(deny_out)],3,{'CI':'true','LMAWS_LIVE':'1','LMAWS_ENDPOINT':'','LMAWS_LEDGER_DIR':str(d/'ci-ledgers')})
 assert 'disabled in CI' in denied.stdout
 code=d/'budget.lms';out=d/'budget.dslb'
 code.write_text('p = _dsl_ schema='+json.dumps(str(root/'schema/lmaws.dsl.json'))+';\nlet i = 0; while (i < 10000) { let data = str_repeat("x", 1000000); i = i + 1; }\nend _dsl_\nsavedsl(p, '+json.dumps(str(out))+');\n')
 p=subprocess.run([shutil.which('lmscript'),str(code)],text=True,encoding="utf-8",capture_output=True,timeout=60);assert p.returncode==0,p.stderr
 dry=d/'dry.lms';dry_out=d/'dry.dslb'
 dry.write_text('p = _dsl_ schema='+json.dumps(str(root/'schema/lmaws.dsl.json'))+';\nlet cloud = aws.region(""); check(cloud.tables().len() == 3); let owned = cloud.run("dry01", '+json.dumps(str(d/'lmaws-dry.jsonl'))+'); let q = owned.queue("safe"); check(owned.remaining() == 1); owned.cleanup(); check(owned.remaining() == 0);\nend _dsl_\nsavedsl(p, '+json.dumps(str(dry_out))+');\n')
 compiled=subprocess.run([shutil.which('lmscript'),str(dry)],text=True,encoding="utf-8",capture_output=True,timeout=60);assert compiled.returncode==0,compiled.stderr
 run(['--dry-run','--dsl',str(dry_out)],extra={'LMAWS_MAX_MEMORY_MB':'64','LMAWS_ENDPOINT':'http://127.0.0.1:9','AWS_PROFILE':'lmaws-no-such-profile','AWS_EC2_METADATA_DISABLED':'true'})
 # Real mutations are profile-gated before any SDK client is opened.  Use a
 # deliberately missing profile and a loopback endpoint-free live session: the
 # expected guard must win over credential resolution/network access.
 guard=d/'profile-guard.lms';guard_out=d/'profile-guard.dslb'
 guard.write_text('p = _dsl_ schema='+json.dumps(str(root/'schema/lmaws.dsl.json'))+';\nlet cloud=aws.example("profile_guard"); let run=cloud.example_run(); let q=run.queue("guard");\nend _dsl_\nsavedsl(p,'+json.dumps(str(guard_out))+');\n')
 compiled=subprocess.run([shutil.which('lmscript'),str(guard)],text=True,encoding='utf-8',capture_output=True,timeout=60);assert compiled.returncode==0,compiled.stderr
 denied=run(['--dsl',str(guard_out)],3,{'LMAWS_LIVE':'1','AWS_PROFILE':'default','AWS_DEFAULT_PROFILE':'default','AWS_REGION':'us-east-1','AWS_EC2_METADATA_DISABLED':'true','LMAWS_LEDGER_DIR':str(d/'profile-ledgers'),'LMAWS_EVIDENCE_DIR':str(d/'profile-evidence'),'CI':'false','LMAWS_ENDPOINT':''})
 assert 'AWS_PROFILE=lmaws' in denied.stdout and 'active profile: default' in denied.stdout,denied.stdout
 small=run(['--dsl',str(out)],3,{'LMAWS_MAX_MEMORY_MB':'64'});assert 'LMAWS_MAX_MEMORY_MB' in small.stderr and 'memory budget' in small.stdout
 if sys.platform=='linux' and is_elf:
  import resource
  def limit():resource.setrlimit(resource.RLIMIT_AS,(6*1024**3,6*1024**3))
  p=subprocess.run([str(host),'--dsl',str(out)],env=env,text=True,encoding="utf-8",capture_output=True,timeout=180,preexec_fn=limit)
  assert p.returncode==3 and 'LMAWS_MAX_MEMORY_MB' in p.stderr,(p.returncode,p.stdout[-1000:],p.stderr[-1000:])
print('PASS CLI, signatures, eight SDK groups, malformed input and memory limits')
