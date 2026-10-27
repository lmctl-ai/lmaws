#!/usr/bin/env python3
"""Use synthetic credentials and a fresh loopback endpoint; no AWS access."""
import os,pathlib,socket,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
cp=str(root/'target/classes')+os.pathsep+(root/'target/dependency-classpath.txt').read_text().strip()
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
env=dict(os.environ,LMAWS_LIVE='1',LMAWS_APPLY='1',AWS_PROFILE='lmaws',LMAWS_ENDPOINT=f'http://127.0.0.1:{port}',LMAWS_TEST_PORT=str(port),AWS_EC2_METADATA_DISABLED='true')
subprocess.run(['java','-cp',cp,'ai.lmctl.lmaws.ScenarioTransportChecks'],cwd=root,env=env,check=True,timeout=120)

subprocess.run(['java','-cp',cp,'ai.lmctl.lmaws.ServerlessChecks'],cwd=root,env=env,check=True,timeout=60)

# A VM assertion after a successful persistent step must clean up before exit.
import json,tempfile,shutil
with tempfile.TemporaryDirectory(prefix='lmaws-serverless-error-') as directory:
    work=pathlib.Path(directory);state=work/'.lmweblab-local'/'state.json'
    script=work/'failure.lms';bytecode=work/'failure.dslb';schema=work/'schema.json'
    host=pathlib.Path(env.get('LMAWS_TEST_HOST',str(root/'target/jvm-bin/lmaws'))).resolve()
    runner=['cmd.exe','/c',str(host)] if host.suffix.lower()=='.cmd' else [str(host)]
    schema.write_bytes(subprocess.check_output(runner+['--dsl-schema','--json'],env=env,timeout=30))
    execute=runner+['--dry-run','--dsl',bytecode.as_posix()]
    script.write_text('let p=_dsl_ schema='+json.dumps(schema.as_posix())+';\nlet run=aws.demo().serverless_stack("cafe05","example.com",'+json.dumps(state.as_posix())+');let made=run.step("table","{}");check(false);\nend _dsl_\nsavedsl(p,'+json.dumps(bytecode.as_posix())+');\nlet result=system('+json.dumps(execute)+',60000);assert(result.code!=0);\n',encoding='utf-8')
    compiler=shutil.which('lmscript.cmd' if os.name=='nt' else 'lmscript')
    compiler_args=['cmd.exe','/c',compiler] if os.name=='nt' else [compiler]
    result=subprocess.run(compiler_args+[str(script)],cwd=work,env=env,timeout=90,capture_output=True,text=True)
    assert result.returncode==0,(result.stdout,result.stderr)
    assert json.loads(state.read_text())['status']=='down','VM failure skipped persistent teardown'
print('PASS serverless VM-error cleanup through the compiled CLI')
