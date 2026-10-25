#!/usr/bin/env python3
"""CLI, schema parity, failure codes and managed memory enforcement."""
import json,os,pathlib,subprocess,sys,tempfile,shutil
root=pathlib.Path(__file__).resolve().parents[1];host=pathlib.Path(sys.argv[1]).resolve();env=dict(os.environ);env.pop('LMAWS_LIVE',None)
def run(args,code=0,extra=None):
 p=subprocess.run(([str(host)] if host.suffix!='.cmd' else ['cmd.exe','/c',str(host)])+args,env=dict(env,**(extra or {})),text=True,capture_output=True,timeout=120)
 assert p.returncode==code,(args,p.returncode,p.stdout[-1200:],p.stderr[-1200:]);return p
assert run(['--version']).stdout=='lmaws 0.1.0\n'
assert run(['--notices']).stdout==(root/'THIRD_PARTY_NOTICES').read_text()
assert 'LMAWS_MAX_MEMORY_MB' in run(['--help']).stdout
schema=run(['--dsl-schema','--json']).stdout;assert schema==(root/'schema/lmaws.dsl.json').read_text();json.loads(schema)
p=subprocess.run([shutil.which('lmscript'),'--dsl-signatures',str(root/'schema/lmaws.dsl.json')],text=True,capture_output=True,timeout=45);assert p.returncode==0,p.stderr
assert p.stdout==run(['--dsl-signatures']).stdout,'schema/registry signature mismatch'
run([],2);run(['--nonesuch'],2);run(['--dsl','missing-bytecode.dslb'],3)
for raw in ['0','-1','wat','1.5','99999999999999999999999999']:
 assert 'positive whole' in run(['--version'],2,{'LMAWS_MAX_MEMORY_MB':raw}).stderr
run(['--self-test'])
with tempfile.TemporaryDirectory(prefix='lmaws-cli-') as d:
 d=pathlib.Path(d);bad=d/'bad.dslb';bad.write_bytes(b'not bytecode');run(['--dsl',str(bad)],3)
 code=d/'budget.lms';out=d/'budget.dslb'
 code.write_text('p = _dsl_ schema='+json.dumps(str(root/'schema/lmaws.dsl.json'))+';\nlet i = 0; while (i < 10000) { let data = str_repeat("x", 1000000); i = i + 1; }\nend _dsl_\nsavedsl(p, '+json.dumps(str(out))+');\n')
 p=subprocess.run([shutil.which('lmscript'),str(code)],text=True,capture_output=True,timeout=60);assert p.returncode==0,p.stderr
 small=run(['--dsl',str(out)],3,{'LMAWS_MAX_MEMORY_MB':'64'});assert 'LMAWS_MAX_MEMORY_MB' in small.stderr and 'memory budget' in small.stdout
 if sys.platform=='linux' and host.suffix!='.sh' and os.environ.get('LMAWS_NATIVE')=='1':
  import resource
  def limit():resource.setrlimit(resource.RLIMIT_AS,(6*1024**3,6*1024**3))
  p=subprocess.run([str(host),'--dsl',str(out)],env=env,text=True,capture_output=True,timeout=180,preexec_fn=limit)
  assert p.returncode==3 and 'LMAWS_MAX_MEMORY_MB' in p.stderr,(p.returncode,p.stdout[-1000:],p.stderr[-1000:])
print('PASS CLI, signatures, eight SDK groups, malformed input and memory limits')
