#!/usr/bin/env python3
"""Run-owned OpenTofu phases. Called by the generated, remotely runnable LMScripts.

All writes require lmaws; state and operation output remain private. The public
record contains only resource descriptors, counts, prices and sanitized failures.
"""
import argparse,json,os,re,secrets,shutil,signal,subprocess,sys,time
from decimal import Decimal
from pathlib import Path
repository_scripts=Path(__file__).resolve().parent.parent/"scripts"
if (repository_scripts/"verify_absence.py").is_file():sys.path.insert(0,str(repository_scripts))
from verify_absence import verify

PRICES={'s3.request_upper_bound':Decimal('0.000005'),'sqs.request':Decimal('0.0000004'),'sns.request':Decimal('0.0000005'),'dynamodb.write_1kib':Decimal('0.000000625'),'ssm.standard':Decimal(0),'logs.empty_group':Decimal(0)}
ALLOWANCE=Decimal('0.0025')
TYPES={'aws_s3_bucket':'bucket','aws_sqs_queue':'queue','aws_ssm_parameter':'parameter','aws_dynamodb_table':'table','aws_sns_topic':'topic','aws_cloudwatch_log_group':'log_group'}
CHILDREN={'aws_s3_object','aws_dynamodb_table_item'}

def clean(value):
    if isinstance(value,dict):return {k:clean(v) for k,v in value.items()}
    if isinstance(value,list):return [clean(v) for v in value]
    if isinstance(value,str):return re.sub(r'(?<!\d)\d{12}(?!\d)','<account>',value)
    if isinstance(value,Decimal):return str(value)
    return value

def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
    with temporary.open('w',encoding='utf-8') as stream:
        stream.write(json.dumps(clean(value),indent=2)+'\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)

def load(path,default=None):
    try:return json.loads(Path(path).read_text())
    except FileNotFoundError:return {} if default is None else default

def state_resources(state):
    out=[]
    def visit(module):
        for resource in module.get('resources',[]):
            if resource.get('mode','managed')!='managed':continue
            typ=resource['type'];values=resource.get('values',{});kind=TYPES.get(typ,typ)
            name=values.get('bucket') if kind=='bucket' else values.get('name')
            if typ=='aws_s3_object':name=values.get('key')
            if typ=='aws_dynamodb_table_item':name=values.get('table_name')
            out.append(dict(kind=kind,provider_type=typ,name=name or '',tags=values.get('tags') or {},address=resource.get('address','')))
        for child in module.get('child_modules',[]):visit(child)
    visit(state.get('values',{}).get('root_module',{}))
    return out

def assert_owned(plan,run_id,write_mode):
    changes=plan.get('resource_changes',[])
    resources=[]
    children=[]
    parents={}
    for change in changes:
        if change.get('mode','managed')!='managed':continue
        actions=change['change']['actions'];typ=change['type'];after=change['change'].get('after') or {}
        if not write_mode:raise RuntimeError('read-only comparison contains a managed resource')
        if actions!=['create']:raise RuntimeError('only creation in a fresh local state is allowed')
        if typ not in TYPES and typ not in CHILDREN:raise RuntimeError('provider resource outside the allowed tiny-resource set')
        if typ in CHILDREN:children.append(change)
        if typ in TYPES:
            kind=TYPES[typ];name=after.get('bucket') if kind=='bucket' else after.get('name')
            if not isinstance(name,str) or not name.startswith(('lmaws_','lmaws-')) or run_id not in name:raise RuntimeError('plan name is not run-owned')
            if (after.get('tags') or {}).get('lmaws_test')!=run_id:raise RuntimeError('plan ownership tag does not match this ledger')
            if typ=='aws_dynamodb_table' and after.get('billing_mode')!='PAY_PER_REQUEST':raise RuntimeError('only on-demand DynamoDB is allowed')
            if typ=='aws_ssm_parameter' and (after.get('type')!='String' or after.get('tier','Standard')!='Standard'):raise RuntimeError('only Standard String parameters are allowed')
            resources.append(dict(kind=kind,name=name,tags={'lmaws_test':run_id},request_unit_price_usd_upper_bound='0.000005',request_allowance=500))
            parents[change.get('address','')]=dict(kind=kind,name=name)
    config={r.get('address'):r for r in plan.get('configuration',{}).get('root_module',{}).get('resources',[])}
    for child in children:
        field='bucket' if child['type']=='aws_s3_object' else 'table_name'
        expected='bucket' if field=='bucket' else 'table'
        target=(child['change'].get('after') or {}).get(field)
        references=config.get(child.get('address'),{}).get('expressions',{}).get(field,{}).get('references',[])
        owned=any(parent['kind']==expected and (target==parent['name'] or any(ref==address or ref.startswith(address+'.') for ref in references)) for address,parent in parents.items() if address)
        if not owned:raise RuntimeError('child object/item does not reference the newly owned parent')
    if write_mode and not resources:raise RuntimeError('write comparison has no planned AWS resource')
    if len(resources)>1:raise RuntimeError('one parent AWS resource per comparison is the approved scope')
    return resources

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--name',required=True);ap.add_argument('--host',required=True);ap.add_argument('--config',required=True);ap.add_argument('--metadata',required=True);args=ap.parse_args()
    metadata=json.loads(args.metadata);is_write=metadata['write'];live=os.getenv('LMAWS_LIVE')=='1'
    profile=os.getenv('AWS_PROFILE') or os.getenv('AWS_DEFAULT_PROFILE') or 'default'
    if metadata.get('iam'):
        write(Path('cloud-result.json'),dict(example=args.name,status='estimated_only',reason='IAM intentionally skipped for federated profiles',leftover_count=0,total_estimated_usd='0.00'));return 0
    if live and (os.getenv('CI','').lower() in ('true','1','yes') or os.getenv('GITHUB_ACTIONS')=='true'):raise RuntimeError('live comparison is forbidden in CI')
    if live and profile!=('lmaws' if is_write else 'default'):raise RuntimeError('this comparison requires AWS_PROFILE='+('lmaws' if is_write else 'default'))
    if os.getenv('AWS_REGION','us-east-1')!='us-east-1':raise RuntimeError('comparison region must be us-east-1')
    if os.getenv('LMAWS_ENDPOINT'):raise RuntimeError('live comparison forbids endpoint overrides')
    cap=Decimal(os.getenv('LMAWS_MAX_COST_USD','0.05'))
    if not cap.is_finite() or cap<0 or cap>Decimal('0.25'):raise RuntimeError('cost cap must be between zero and 0.25')
    run_id=os.getenv('LMAWS_COMPARE_RUN_ID') or 'r'+secrets.token_hex(4)+'x'+secrets.token_hex(4)
    if not re.fullmatch(r'r[a-f0-9]{8}x[a-f0-9]{8}',run_id):raise RuntimeError('run id must be r<8 hex>x<8 hex>')
    infra=Path('infrastructure');infra.mkdir(exist_ok=True)
    old=load(infra/'terraform.tfstate')
    if any(r.get('mode')=='managed' for r in old.get('resources',[])) or state_resources(old):raise RuntimeError('existing state retains resources; preserve it and run its own teardown')
    shutil.copyfile(args.config,infra/'main.tf')
    (infra/'run.auto.tfvars.json').write_text(json.dumps({'run_id':run_id}))
    provider_cache=Path(os.getenv('LMAWS_COMPARE_PROVIDER_CACHE') or os.getenv('TF_PLUGIN_CACHE_DIR') or str(Path.cwd()/'.provider-cache')).resolve();provider_cache.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,TF_PLUGIN_CACHE_DIR=str(provider_cache),AWS_PROFILE=profile,AWS_DEFAULT_PROFILE=profile,AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',AWS_MAX_ATTEMPTS='2',TF_INPUT='0',TF_IN_AUTOMATION='1',TF_VAR_run_id=run_id)
    for k in ('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_SECURITY_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_ROLE_ARN','AWS_ROLE_SESSION_NAME','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI','AWS_CONTAINER_CREDENTIALS_FULL_URI','TF_LOG','TF_LOG_PROVIDER','TF_LOG_PATH'):env.pop(k,None)
    engine_version=subprocess.run([args.host,'--version'],text=True,capture_output=True,timeout=15).stdout.strip()
    ledger={'engine_version':engine_version,'schema':'lmaws-tofu-ledger-v2','example':args.name,'run_id':run_id,'profile':profile,'region':'us-east-1','live':live,'resources':[],'events':[],'price_table':{k:str(v) for k,v in PRICES.items()},'price_method':'Conservative upper bound of 500 provider/verification requests at the maximum table price, reserved before plan; not observed SDK request counts or an invoice measurement; tiny storage included','cap_usd':str(cap),'request_allowance':500,'request_unit_price_usd':'0.000005','total_estimated_usd':'0','leftover_count':0}
    archive=Path(os.getenv('LMAWS_COMPARE_LEDGER_DIR','comparison-ledgers'))/(args.name+'-'+run_id+'.json')
    archive.parent.mkdir(parents=True,exist_ok=True)
    archive_fd=os.open(archive,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(archive_fd)
    def event(kind,**values):
        ledger['events'].append(dict(event=kind,at=time.time(),**values));write(Path('ledger.json'),ledger);write(archive,ledger)
    def phase(name):
        started=time.monotonic();p=subprocess.run([args.host,'--dsl','phase-'+name+'.dslb'],env=env,text=True,capture_output=True,timeout=180)
        Path('private-'+name+'.log').write_text(p.stdout+p.stderr)
        errpath=Path('phase-'+name+'.error');error=errpath.read_text() if errpath.exists() else ''
        okpath=Path('phase-'+name+'.ok');ok=okpath.exists() and okpath.read_text().strip()=='true'
        event('phase',phase=name,ok=ok,wall_seconds=round(time.monotonic()-started,6),exit_code=p.returncode)
        if p.returncode or not ok:
            # Detailed diagnostics are kept locally, never copied to public evidence.
            summary='provider_download_failed' if re.search(r'install|registry|download|provider.*package',error,re.I) else 'lmcloud_'+name+'_failed'
            raise RuntimeError(summary)
    campaign=Path(os.getenv('LMAWS_COMPARE_CAMPAIGN',str(Path.cwd()/'campaign.json'))).resolve();campaign.parent.mkdir(parents=True,exist_ok=True)
    lock=campaign.with_suffix('.lock');lock_fd=None
    attempted=False;planned=[];snapshot={};status='failed';error='';cleanup_error='';started=time.monotonic();estimated=Decimal(0)
    old_handlers={}
    def interrupted(signum,frame):raise KeyboardInterrupt('comparison interrupted')
    for sig in (signal.SIGINT,signal.SIGTERM):old_handlers[sig]=signal.signal(sig,interrupted)
    try:
        lock_fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        previous=Decimal(str(load(campaign).get('estimated_usd','0')))
        if live and (ALLOWANCE>cap or previous+ALLOWANCE>Decimal('0.25')):raise RuntimeError('cost cap refused the next provider creation')
        event('opened')
        phase('init');phase('validate')
        if not live:
            status='validated_offline'
        else:
            # Data sources can issue charged metadata calls during plan. Reserve
            # the conservative request bound before plan for both read/write runs.
            estimated=ALLOWANCE;ledger['total_estimated_usd']=str(estimated)
            write(campaign,{'estimated_usd':str(previous+estimated),'hard_ceiling_usd':'0.25'})
            phase('plan');plan=load('plan.json');planned=assert_owned(plan,run_id,is_write)
            ledger['resources']=planned;event('planned',resource_count=len(planned))
            if is_write:
                ledger['preflight_absence']=verify(planned,timeout_seconds=0)
                event('preflight_absent')
            attempted=True;event('apply_started');phase('apply');phase('inspect')
            snapshot=load('snapshot.json');ledger['observed_resources']=state_resources(snapshot)
            event('observed');status='passed'
    except (Exception,KeyboardInterrupt) as exc:
        error=str(exc);event('failed',code=error)
    finally:
        if attempted:
            try:phase('destroy')
            except (Exception,KeyboardInterrupt) as exc:cleanup_error=str(exc)
            try:
                phase('inspect_after');after=load('snapshot-after.json');remaining=state_resources(after)
                if remaining:cleanup_error='state retains managed resources'
            except Exception as exc:cleanup_error=cleanup_error or str(exc)
            try:
                ledger['independent_readonly_verification']=verify(planned)
            except Exception as exc:cleanup_error=cleanup_error or str(exc)
            if cleanup_error:ledger['leftover_count']=max(1,len(planned));status='cleanup_failed'
        for sig,handler in old_handlers.items():signal.signal(sig,handler)
        if lock_fd is not None:os.close(lock_fd);lock.unlink(missing_ok=True)
        minutes=Decimal(str(max(0,time.monotonic()-started)/60))
        for resource in ledger['resources']:resource['minutes_alive_upper_bound']=str(minutes)
        ledger.update(status=status,run_error=error,cleanup_error=cleanup_error,wall_seconds=round(time.monotonic()-started,6),total_estimated_usd=str(estimated),outputs=clean(snapshot.get('values',{}).get('outputs',{})))
        write(Path('cloud-result.json'),ledger);event('finished',status=status)
    print('lmcloud comparison '+args.name+': '+status+'; estimated cost: $'+str(estimated)+'; leftovers: '+str(ledger['leftover_count']))
    return 0 if status in ('passed','validated_offline') else 1

def sweep_current():
    state=load('infrastructure/terraform.tfstate');managed=[r for r in state.get('resources',[]) if r.get('mode')=='managed']
    failures=[p.name for p in Path('comparison-ledgers').glob('*.json') if load(p).get('leftover_count',0)]
    print(json.dumps(dict(dry_run=True,leftover_count=max(len(managed),len(failures)),retained_state=bool(managed),failed_ledgers=failures),indent=2))
    return 1 if managed or failures else 0

if __name__=='__main__':
    if sys.argv[1:]==['--sweep']:sys.exit(sweep_current())
    try:sys.exit(main())
    except Exception as exc:print('comparison refused: '+str(exc),file=sys.stderr);sys.exit(2)
