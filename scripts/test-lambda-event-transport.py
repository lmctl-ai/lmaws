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
    script=work/'failure.lms';bytecode=work/'failure.dslb'
    script.write_text('let p=_dsl_ cli="lmaws";\nlet run=aws.demo().serverless_stack("cafe05","example.com",'+json.dumps(str(state))+');let made=run.step("table","{}");check(false);\nend _dsl_\nsavedsl(p,'+json.dumps(str(bytecode))+');\nlet result=system(concat(dsl_cli(p),["--dry-run","--dsl",'+json.dumps(str(bytecode))+']),60000);assert(result.code!=0);\n')
    subprocess.run([shutil.which('lmscript'),str(script)],cwd=work,env=env,check=True,timeout=90,capture_output=True,text=True)
    assert json.loads(state.read_text())['status']=='down','VM failure skipped persistent teardown'
print('PASS serverless VM-error cleanup through the compiled CLI')
