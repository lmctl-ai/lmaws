#!/usr/bin/env python3
"""Independent metadata-only absence checks using the read-only default profile.

Authorization, transport and unrecognized errors are never treated as absence.
No delete API or credential value is used here.
"""
import json,os,re,subprocess,time
from decimal import Decimal

def verify(resources, *, timeout_seconds=60):
    env=dict(os.environ,AWS_PROFILE='default',AWS_DEFAULT_PROFILE='default',AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',AWS_MAX_ATTEMPTS='1',AWS_PAGER='')
    for key in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_ROLE_SESSION_NAME','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI','LMAWS_ENDPOINT'):
        env.pop(key,None)
    results=[]
    for resource in resources:
        kind,name=resource['kind'],resource['name']
        if not re.fullmatch(r'lmaws[_-][a-z0-9_.-]+',name):raise ValueError('refusing a name outside the test prefix')
        table={
            'bucket':(['s3api','head-bucket','--bucket',name],{'404','NoSuchBucket','NotFound'},Decimal('0.0000004')),
            'queue':(['sqs','get-queue-url','--queue-name',name],{'AWS.SimpleQueueService.NonExistentQueue','QueueDoesNotExist'},Decimal('0.0000004')),
            'parameter':(['ssm','describe-parameters','--parameter-filters',json.dumps([{'Key':'Name','Option':'Equals','Values':[name]}])],set(),Decimal(0)),
            'table':(['dynamodb','describe-table','--table-name',name],{'ResourceNotFoundException'},Decimal(0)),
            'log_group':(['logs','describe-log-groups','--log-group-name-prefix',name],set(),Decimal(0)),
            'topic':(['sns','list-topics'],set(),Decimal('0.0000005')),
        }
        if kind not in table:raise ValueError('unsupported independent verification kind')
        args,absent_codes,unit_price=table[kind];deadline=time.monotonic()+timeout_seconds;attempts=0;absent=False
        while True:
            attempts+=1
            result=subprocess.run(['aws','--profile','default','--region','us-east-1',*args,'--output','json'],env=env,text=True,capture_output=True,timeout=40)
            if result.returncode:
                match=re.search(r'An error occurred \(([^)]+)\)',result.stderr)
                code=match.group(1) if match else 'unrecognized_error'
                if code not in absent_codes:raise RuntimeError('independent read-only '+kind+' verification failed: '+code)
                absent=True
            elif kind=='parameter':absent=not any(x['Name']==name for x in json.loads(result.stdout).get('Parameters',[]))
            elif kind=='log_group':absent=not any(x['logGroupName']==name for x in json.loads(result.stdout).get('logGroups',[]))
            elif kind=='topic':absent=not any(x['TopicArn'].rsplit(':',1)[-1]==name for x in json.loads(result.stdout).get('Topics',[]))
            if absent:break
            if time.monotonic()>=deadline:raise RuntimeError('independent verification still finds '+kind+' '+name)
            time.sleep(1)
        results.append(dict(kind=kind,name=name,absent=True,profile='default',region='us-east-1',requests=attempts,unit_price_usd=str(unit_price),estimated_usd=str(unit_price*attempts)))
    return results
