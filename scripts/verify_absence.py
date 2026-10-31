#!/usr/bin/env python3
"""Fresh default-profile lmaws scripts verify provider absence, never local ledgers."""
import json,os,pathlib,shutil,subprocess,tempfile,time
from decimal import Decimal

KINDS={'bucket','queue','topic','parameter','table','log_group'}
def _invoke(resource):
    if os.environ.get('LMAWS_LIVE')!='1':raise RuntimeError('independent checks require explicit LMAWS_LIVE=1')
    if os.environ.get('CI','').lower() in ('1','true','yes') or os.environ.get('GITHUB_ACTIONS')=='true':raise RuntimeError('real independent checks are forbidden in CI')
    root=pathlib.Path(tempfile.mkdtemp(prefix='lmaws-independent-'))
    env=dict(os.environ,AWS_PROFILE='default',AWS_DEFAULT_PROFILE='default',AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',LMAWS_LIVE='1',LMAWS_LEDGER_DIR=str(root/'ledgers'),LMAWS_EVIDENCE_DIR=str(root/'evidence'),LMAWS_MAX_COST_USD='0.002')
    for key in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_ROLE_SESSION_NAME','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI','LMAWS_ENDPOINT'):
        env.pop(key,None)
    program=root/'verify.lms'
    program.write_text('# Read-only exact-name provider check; no resource values are read.\np=_dsl_ cli="lmaws" install="github:lmctl-ai/lmaws@latest";\nlet cloud=aws.example("independent_check");\nfile_write("exists.json",str(cloud.resource_exists('+json.dumps(resource['kind'])+','+json.dumps(resource['name'])+')));\nend _dsl_\nsavedsl(p,"verify.dslb");\nr=system(concat(dsl_cli(p),["--lmcode","verify.dslb"]),{timeoutMs:45000});\nif(r.code!=0){println(r.stderr);}\nassert(r.code==0);\n')
    executable=shutil.which('lmctl')
    if not executable:raise RuntimeError('lmctl is required for independent lmaws checks')
    result=subprocess.run([executable,str(program)],cwd=root,env=env,text=True,capture_output=True,timeout=60)
    (root/'private.log').write_text(result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('independent lmaws '+resource['kind']+' lookup failed; private log '+str(root/'private.log'))
    exists=json.loads((root/'exists.json').read_text())
    if not isinstance(exists,bool):raise RuntimeError('independent lmaws result is not an existence boolean')
    evidence=list((root/'evidence').glob('live-cost-independent_check-*.json'))
    if len(evidence)!=1:raise RuntimeError('independent lmaws check lacks a unique cost receipt')
    receipt=json.loads(evidence[0].read_text())
    if receipt.get('profile')!='default' or not receipt.get('live'):raise RuntimeError('independent check did not use the default live profile')
    requests=sum(v['requests'] for v in receipt.get('service_requests',{}).values())
    return {'exists':exists,'requests':requests,'estimated_usd':str(receipt['total_estimated_usd'])}

def verify(resources, *, timeout_seconds=60):
    results=[]
    for resource in resources:
        kind,name=resource['kind'],resource['name']
        if kind not in KINDS or not isinstance(name,str) or not name.startswith('lmaws') or '\0' in name:raise ValueError('refusing a resource outside the supported test prefix/types')
        deadline=time.monotonic()+timeout_seconds;requests=0;amount=Decimal(0)
        while True:
            record=_invoke(resource);requests+=record['requests'];amount+=Decimal(record['estimated_usd'])
            if record['exists'] is False:break
            if time.monotonic()>=deadline:raise RuntimeError('independent provider check still finds the requested '+kind)
            time.sleep(1)
        results.append(dict(kind=kind,name=name,absent=True,profile='default',region='us-east-1',requests=requests,estimated_usd=str(amount),engine='lmaws via lmctl',unit_price_usd='mixed: see native cost receipt'))
    return results
