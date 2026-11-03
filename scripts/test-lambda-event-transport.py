#!/usr/bin/env python3
"""Use synthetic credentials and a fresh loopback endpoint; no AWS access."""
import json,os,pathlib,socket,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
cp=str(root/'target/classes')+os.pathsep+(root/'target/dependency-classpath.txt').read_text().strip()
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
env=dict(os.environ,LMAWS_LIVE='1',LMAWS_APPLY='1',AWS_PROFILE='lmaws',LMAWS_ENDPOINT=f'http://127.0.0.1:{port}',LMAWS_TEST_PORT=str(port),AWS_EC2_METADATA_DISABLED='true')
subprocess.run(['java','-cp',cp,'ai.lmctl.lmaws.ScenarioTransportChecks'],cwd=root,env=env,check=True,timeout=120)

subprocess.run(['java','-cp',cp,'ai.lmctl.lmaws.ServerlessChecks'],cwd=root,env=env,check=True,timeout=60)

# A VM assertion after a successful persistent step must clean up before exit.
import tempfile,shutil
with tempfile.TemporaryDirectory(prefix='lmaws-serverless-error-') as directory:
    work=pathlib.Path(directory);state=work/'.lmweblab-local'/'state.json'
    script=work/'failure.lms'
    host=pathlib.Path(env.get('LMAWS_TEST_HOST',str(root/'target/jvm-bin/lmaws'))).resolve()
    env['PATH']=str(host.parent)+os.pathsep+env.get('PATH','')
    script.write_text('s=load_schema(cli="lmaws");\np = _lmcode_ s;\nlet run=aws.demo().serverless_stack("cafe05","example.com",'+json.dumps(state.as_posix())+');let made=run.step("table","{}");check(false);\nend _lmcode_\nr=run_lmcode(p);assert(!r.ok);\n',encoding='utf-8')
    compiler=shutil.which('lmscript.cmd' if os.name=='nt' else 'lmscript')
    compiler_args=['cmd.exe','/c',compiler] if os.name=='nt' else [compiler]
    result=subprocess.run(compiler_args+[str(script)],cwd=work,env=env,timeout=90,capture_output=True,text=True)
    assert result.returncode==0,(result.stdout,result.stderr)
    assert json.loads(state.read_text())['status']=='down',('VM failure skipped persistent teardown',state.read_text())
print('PASS serverless VM-error cleanup through a current host invocation')

subprocess.run(["java","-cp",cp,"ai.lmctl.lmaws.ServerlessAccountingChecks"],cwd=root,env=env,check=True,timeout=60)

with socket.socket() as reservation:
    reservation.bind(('127.0.0.1',0));log_port=reservation.getsockname()[1]
log_env=dict(env,LMAWS_ENDPOINT=f'http://127.0.0.1:{log_port}',LMAWS_TEST_PORT=str(log_port))
subprocess.run(['java','-cp',cp,'ai.lmctl.lmaws.RuntimeLogGroupChecks'],cwd=root,env=log_env,check=True,timeout=60)
