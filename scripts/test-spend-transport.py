#!/usr/bin/env python3
"""AWS SDK protocols on loopback only, optionally exercise the compiled native host too."""
from pathlib import Path
import os,subprocess,sys,xml.etree.ElementTree as ET
root=Path(__file__).resolve().parents[1]
version=ET.parse(root/'pom.xml').getroot().find('{http://maven.apache.org/POM/4.0.0}version').text
jar=root/'target'/f'lmaws-{version}.jar'
env=dict(os.environ,AWS_PROFILE='default',AWS_DEFAULT_PROFILE='default',AWS_REGION='us-east-1',LMAWS_SPEND_REGIONS='us-east-1',LMAWS_LIVE='0',LMAWS_SPEND_LIVE='0',AWS_EC2_METADATA_DISABLED='true',CI='true')
env.pop('LMAWS_ENDPOINT',None)
args=['java','-cp',str(jar),'ai.lmctl.lmaws.SpendSourceChecks']
if len(sys.argv)>1:args.append(str(Path(sys.argv[1]).resolve()))
subprocess.run(args,cwd=root,env=env,check=True,timeout=240)
