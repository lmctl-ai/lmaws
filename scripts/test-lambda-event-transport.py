#!/usr/bin/env python3
"""Use synthetic credentials and a fresh loopback endpoint; no AWS access."""
import os,pathlib,socket,subprocess
root=pathlib.Path(__file__).resolve().parents[1]
cp=str(root/'target/classes')+os.pathsep+(root/'target/dependency-classpath.txt').read_text().strip()
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
env=dict(os.environ,LMAWS_LIVE='1',LMAWS_APPLY='1',AWS_PROFILE='lmaws',LMAWS_ENDPOINT=f'http://127.0.0.1:{port}',LMAWS_TEST_PORT=str(port),AWS_EC2_METADATA_DISABLED='true')
subprocess.run(['java','-cp',cp,'ai.lmctl.lmaws.ScenarioTransportChecks'],cwd=root,env=env,check=True,timeout=120)
