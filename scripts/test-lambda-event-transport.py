#!/usr/bin/env python3
import os, pathlib, subprocess
root=pathlib.Path(__file__).resolve().parents[1]
cp=str(root/'target/classes')+os.pathsep+(root/'target/dependency-classpath.txt').read_text().strip()
env=os.environ.copy();env.update({'LMAWS_LIVE':'1','LMAWS_APPLY':'1','AWS_PROFILE':'lmaws'})
for port, cls in [('18765','ai.lmctl.lmaws.LambdaTransportChecks'),('18766','ai.lmctl.lmaws.EventBridgeTransportChecks')]:
    env['LMAWS_ENDPOINT']='http://127.0.0.1:'+port
    subprocess.run(['java','-cp',cp,cls],cwd=root,env=env,check=True,timeout=60)
print('PASS Lambda and EventBridge SDK loopback transport checks')
