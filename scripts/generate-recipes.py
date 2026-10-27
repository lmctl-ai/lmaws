#!/usr/bin/env python3
"""Generate thin runnable recipe entries and their synthetic-only examples."""
from pathlib import Path
import re,sys
ROOT=Path(__file__).resolve().parents[1]
INVENTORIES=['identity','buckets','instances','vpcs','security_groups','tables','queues','topics','functions','log_groups','alarms','zones','secrets','parameters','clusters','roles']
LIFECYCLES=['queue','topic','table','bucket','parameter','log_group']
ITEMS=[]
for name in INVENTORIES:
 ITEMS.append(dict(name='inventory_'+name,category='Identity and access posture' if name in ('identity','roles','security_groups') else 'Inventory',task=name,library='inventory',function='recipe_inventory',what='Inspect bounded '+name.replace('_',' ')+' metadata'+(' (synthetic only; federated IAM cases skipped live)' if name in ('identity','roles') else ''),access='Read-only',cost='$0.00 synthetic; live capped request estimate in ledger'))
ITEMS.append(dict(name='inventory',category='Inventory',task='all',library='inventory',function='recipe_inventory',what='Review all supported inventories; IAM entries are skipped live',access='Read-only',cost='$0.00 synthetic; live request cap $0.05'))
for kind in LIFECYCLES:
 ITEMS.append(dict(name='sandbox_'+kind,category='Safe lifecycle sandboxes',task=kind,library='lifecycle',function='recipe_lifecycle',what='Create and tear down one owned '+kind.replace('_',' ')+' with its run ledger',access='Write with the lmaws profile',cost='Synthetic $0.00; live generally below $0.0001; cap $0.05'))
ITEMS.append(dict(name='lifecycle',category='Safe lifecycle sandboxes',task='queue',library='lifecycle',function='recipe_lifecycle',what='Select a disposable queue/topic/table/bucket/parameter/log-group lifecycle',access='Write with the lmaws profile',cost='Synthetic $0.00; live generally below $0.0001; cap $0.05'))
for name,function,what in [('prefix_search','recipe_prefix_search','Find every literal lmaws prefix variant through native account APIs'),('leftover_report','recipe_leftovers','Inspect account resources by age and their creation-ledger proof'),('sweeper','recipe_sweeper','Plan account cleanup; explicit delete checks prefix, tag and run ledger')]:
 ITEMS.append(dict(name=name,category='Leftover search and cleanup by prefix',task=name,library='prefix',function=function,what=what,access='Read-only',cost='$0.00 synthetic; live request cap $0.05'))
for name,function,category,what in [('idle_instances','recipe_idle','Idle and waste detection','Flag stopped-instance state for further review; never delete'),('tag_compliance','recipe_compliance','Tag and naming compliance','Report missing and unknown tag presence without assuming compliance'),('naming_compliance','recipe_naming','Tag and naming compliance','Check case-sensitive lmaws_ and lmaws- naming among prefix candidates')]:
 ITEMS.append(dict(name=name,category=category,task=name,library='audits',function=function,what=what,access='Read-only',cost='$0.00 synthetic; live request cap $0.05'))

for name,what in [('spend_detail','Review account spend detail and optimization signals'),('ec2_spend','Break down EC2 compute spend and current resource signals'),('savings_plans','Review Savings Plans and Reserved Instance utilization and coverage'),('eip_audit','Review idle public IPv4 allocations and estimated run-rate'),('ebs_audit','Review EBS attachments and snapshot retention signals'),('bandwidth','Break down billed transfer categories and network counters'),('lambda_spend','Review Lambda usage and spend signals'),('dynamodb_spend','Review DynamoDB usage and spend signals')]:
 ITEMS.append(dict(name=name,category='Cost and spend',task=name,library='spend',function='recipe_spend',what=what,access='Read-only',cost='Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25'))
ITEMS.append(dict(name='policy_lint',category='Identity and access posture',task='policy_lint',library='iam_policy',function='recipe_policy_lint',what='Validate and lint an IAM managed policy JSON document offline against lmaws guardrails',access='Read-only',cost='$0.00 offline lint'))
ITEMS.append(dict(name='grant_session_policy',category='Identity and access posture',task='grant_session_policy',library='iam_policy',function='recipe_grant_session_policy',what='Preview statement-level diff or grant the lmaws_session customer-managed IAM policy',access='Write with the admin profile',cost='$0.00 IAM metadata; live apply requires AWS_PROFILE=admin and LMAWS_ADMIN_GRANT=1'))
ITEMS.append(dict(name='session_doctor',category='Identity and access posture',task='session_doctor',library='iam_policy',function='recipe_session_doctor',what='Inspect profile session types, 0600 credential cache expiry and dry-run/read-only permission probes',access='Read-only',cost='$0.00 synthetic; live read and EC2 DryRun probes create no resources; cap $0.05'))
ITEMS.append(dict(name='grant_lambda_role',category='Identity and access posture',task='grant_lambda_role',library='iam_role',function='recipe_grant_lambda_role',what='Preview or apply the pre-built lmaws_lambda_exec execution role with the mandatory boundary and scoped data access',access='Write with the admin profile',cost='$0.00 synthetic; live IAM metadata only; apply requires AWS_PROFILE=admin, LMAWS_ADMIN_GRANT=1 and --apply'))

COMPUTE_ARGS='--region us-east-1 --profile default --output data/NAME [--live]'
for name,what,access,cost,args,run in [
 ('fleet_status','Discover tagged instances: state, type, addresses and root-storage policy','Read-only','$0.00 synthetic; live EC2 Describe calls are free; cap $0.05','--tag-key Project --tag-value VALUE '+COMPUTE_ARGS,'--tag-key Project'),
 ('cpu_credits','CPU credit balance, usage, surplus and headroom of burstable instances, without SSH','Read-only','$0.00 synthetic; live CloudWatch statistics about $0.00005 per instance; cap $0.05','--tag-key Project --tag-value VALUE --instance ID --hours 24 '+COMPUTE_ARGS,'--tag-key Project --hours 24'),
 ('eip_map','Map Elastic IPs to instances, flag idle ones, report pinned addresses (never releases)','Read-only','$0.00 synthetic; live Describe calls are free; cap $0.05','--tag-key Project '+COMPUTE_ARGS,''),
 ('ami_lookup','Latest Ubuntu 24.04 and Amazon Linux 2023 AMIs (arm64, x86_64) from public SSM parameters','Read-only with the lmaws-ec2 profile','$0.00 (public SSM parameters are free)',COMPUTE_ARGS.replace('--profile default','--profile lmaws-ec2'),''),
 ('spot_prices','Spot price history per AZ for nano types, cheapest AZ and saving vs On-Demand','Read-only','$0.00 synthetic; live Describe calls are free; cap $0.05','--types t4g.nano,t3.nano --hours 3 '+COMPUTE_ARGS,'--types t4g.nano,t3.nano'),
 ('ebs_roots','EBS volumes, attachments, root DeleteOnTermination and the AZ lock, as a report','Read-only','$0.00 synthetic; live Describe calls are free; cap $0.05',COMPUTE_ARGS,''),
 ('spot_nano_lifecycle','Launch one tagged no-public-IP spot nano, check it, terminate it and prove zero leftovers','Write with the lmaws-ec2 profile','Synthetic $0.00; live about $0.0005 (spot nano minutes + 8 GiB gp3); cap $0.05',COMPUTE_ARGS.replace('--profile default','--profile lmaws-ec2').replace('data/NAME','.lmaws-local/compute/spot_nano_lifecycle').replace('[--live]','[--live --apply]'),'--live --apply --profile lmaws-ec2')]:
 ITEMS.append(dict(name=name,category='Compute and fleet',task=name,library='compute',function='recipe_'+name,what=what,access=access,cost=cost,args=args.replace('NAME',name),run=run))

PB_ARGS='--prefix lmaws --region us-east-1 --output data/NAME'
for name,what,access,cost,args,run in [
 ('session_policy','Generate the 23-statement lmaws_session IAM managed policy with the fluent builder, statement size report and optional snapshot diff','Read-only','$0.00 offline policy compilation and diff','--policy lmaws_session --prefix lmaws --domain example.com --region us-east-1 --types t4g.nano,t3.nano --max-gib 8 [--file SNAPSHOT.json] --output data/NAME','--domain example.com'),
 ('policy_s3_sandbox','Build a prefix-scoped S3 bucket and object sandbox policy with account-boundary and tagged-delete guardrails','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_sqs_sandbox','Build a prefix-scoped SQS queue sandbox policy with account-boundary and region-lock guardrails','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_sns_sandbox','Build a prefix-scoped SNS topic sandbox policy with account-boundary and region-lock guardrails','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_dynamodb_sandbox','Build a prefix-scoped DynamoDB table sandbox policy with account-boundary and region-lock guardrails','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_ssm_sandbox','Build a prefix-scoped SSM Parameter Store sandbox policy with public parameter read access','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_logs_sandbox','Build a prefix-scoped CloudWatch Logs sandbox policy with account-boundary and region-lock guardrails','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_ec2_spot_sandbox','Build a tag-gated EC2 spot nano sandbox policy with instance-type and 8 GiB volume caps','Read-only','$0.00 offline policy compilation','--prefix lmaws --types t4g.nano,t3.nano --max-gib 8 --region us-east-1 --output data/NAME','--types t4g.nano,t3.nano --max-gib 8'),
 ('policy_web_stack','Build a static site stack policy (S3 bucket + CloudFront OAC + ACM + Route53 record pattern lock)','Read-only','$0.00 offline policy compilation','--prefix lmaws --domain example.com --region us-east-1 --output data/NAME','--domain example.com'),
 ('policy_ci_bucket_deployer','Build a least-privilege CI static asset uploader and CloudFront invalidation policy','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_lambda_deployer','Build a prefix- and tag-scoped Lambda function and EventBridge rule deployer policy','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_tag_operator','Build a tag discovery and tag-gated resource tagging operator policy','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_read_only_auditor','Build a zero-secret read-only inventory and posture auditor policy with region lock','Read-only','$0.00 offline policy compilation',PB_ARGS,'--region us-east-1'),
 ('policy_billing_viewer','Build a read-only Cost Explorer, Budgets, Pricing and CloudWatch metrics viewer policy','Read-only','$0.00 offline policy compilation',PB_ARGS,''),
 ('policy_break_glass','Build an MFA-gated, time-windowed and bastion-IP-locked emergency break-glass policy','Read-only','$0.00 offline policy compilation','--cidr 203.0.113.10/32 --from 2026-01-01T00:00:00Z --to 2026-01-01T04:00:00Z --output data/NAME','--cidr 203.0.113.10/32'),
 ('policy_ip_restricted','Build a corporate/bastion CIDR-locked policy with single-host /32 security-group ingress enforcement','Read-only','$0.00 offline policy compilation','--prefix lmaws --cidr 203.0.113.10/32 --output data/NAME','--cidr 203.0.113.10/32'),
 ('policy_mfa_deletes','Build a sandbox policy that requires hardware/virtual MFA for every destructive delete or terminate action','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_region_lock','Build a regional policy with an explicit NotAction exemption list for global AWS control planes','Read-only','$0.00 offline policy compilation',PB_ARGS,'--region us-east-1'),
 ('policy_deny_untagged_delete','Build a defense-in-depth policy pairing request-tag creation gates with explicit Denies on untagged deletes','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_permission_boundary','Build a maximum IAM permission boundary capping delegated roles to prefix, tag, nano and region guardrails','Read-only','$0.00 offline policy compilation',PB_ARGS,'--prefix lmaws'),
 ('policy_fit_inline','Compact a multi-statement policy into the 2048-character STS inline session limit and report byte savings','Read-only','$0.00 offline policy compaction',PB_ARGS,'--prefix lmaws'),
 ('policy_split_managed','Split a large policy into balanced <= 6144-char managed policy parts while preserving Deny guardrails','Read-only','$0.00 offline policy splitting','--policy lmaws_session --domain example.com --output data/NAME','--domain example.com'),
 ('policy_explain_denial','Parse an AWS AccessDenied message, identify the failing statement/condition and emit a minimal builder fix','Read-only','$0.00 offline denial analysis','[--error TEXT] --output data/NAME',''),
 ('policy_from_ledger','Synthesize a least-privilege IAM policy and fluent builder program from observed SDK calls in run ledgers','Read-only','$0.00 offline ledger synthesis','[--ledger FILE] --output data/NAME',''),
 ('policy_diff_review','Compare two policy versions statement-by-statement and report added, modified, removed and unchanged rules','Read-only','$0.00 offline statement diff',PB_ARGS,''),
 ('policy_simulate_probes','Evaluate allow and deny security probes against a policy offline or via IAM SimulateCustomPolicy','Read-only','$0.00 offline; live IAM simulator requires AWS_PROFILE=admin','--policy lmaws_session [--probes SPEC] [--live --profile admin] --output data/NAME',''),
 ('policy_migrate_json','Migrate hand-written IAM policy JSON into a typed fluent lmaws permission builder program','Read-only','$0.00 offline JSON migration','[--file POLICY.json] --output data/NAME',''),
 ('policy_cheat_sheet','Map every lmaws capability to its exact IAM statement Sids, scope rationale, missing-permission error and minimal builder fix','Read-only','$0.00 offline IAM cheat sheet','--policy lmaws_session --prefix lmaws --domain example.com --output data/NAME','--domain example.com')]:
 ITEMS.append(dict(name=name,category='Permission builder and IAM analysis',task=name,library='policy_builder',function='recipe_policy_builder',what=what,access=access,cost=cost,args=args.replace('NAME',name),run=run))

HYGIENE_ARGS='--region us-east-1 --profile default --output data/NAME [--live]'
for name,category,what,run in [
 ('quickstart','Inventory','Quickstart: one command to an account snapshot picture (resources per service)',''),
 ('open_ports','Identity and access posture','Security groups open to the internet, by port, with admin/database ports flagged',''),
 ('secret_age','Identity and access posture','Secrets not changed for 90+ days (values are never read)',''),
 ('which_profile','Identity and access posture','Which AWS profile and flags each kind of recipe needs',''),
 ('unattached_volumes','Idle and waste detection','Unattached EBS volumes with size and monthly cost (never deletes)',''),
 ('public_ipv4_cost','Idle and waste detection','Every billed public IPv4 address (Elastic and auto-assigned) and its monthly cost',''),
 ('log_retention_audit','Idle and waste detection','Log groups that never expire, grouped by retention','')]:
 ITEMS.append(dict(name=name,category=category,task=name,library='hygiene',function='recipe_'+name,what=what,access='Read-only',cost='$0.00 synthetic and offline' if name=='which_profile' else '$0.00 synthetic; live Describe/List calls are free; cap $0.05',args=('--output data/NAME' if name=='which_profile' else HYGIENE_ARGS).replace('NAME',name),run=run))

def flatten(path,seen=None):
 seen=set() if seen is None else seen
 path=path.resolve()
 if path in seen:return ''
 seen.add(path);lines=[]
 for line in path.read_text().splitlines():
  match=re.fullmatch(r'\s*import\s+"([^"]+)";\s*',line)
  if match:lines.append(flatten(path.parent/match.group(1),seen))
  elif line.lstrip().startswith(('#','//')):continue
  else:lines.append(line)
 return '\n'.join(lines).strip()+'\n'

def generate_discovery(check=False):
 for name in ['find_lmaws_resources','leftover_report','sweeper']:
  text='# Account-level prefix discovery; names, tags and IDs are projected by lmaws.\n# Read-only by default. --delete additionally requires --live and --profile lmaws.\n# Run: lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/'+name+'.lms\n'
  text+=flatten(ROOT/'recipes/lib/discovery.lms')
  text+='\nlet options=recipe_options(ARGV);\noptions.task="'+name+'";\noptions.live=options.live || getenv("LMAWS_LIVE","0")=="1";\n'
  if name=='find_lmaws_resources':text+='assert(!options.apply);\n'
  else:text+='if(!contains(ARGV,"--older-hours")) {options.older_hours=24;}\n'
  text+='if(!options.output_explicit) {options.output="data/'+name+'";}\nlet report=recipe_discovery(options);\nif(!options.preview) {\n for(row in report.rows) {println(json_stringify({service:get(row,"service",""),name:get(row,"name",""),age_hours:get(row,"age_hours",""),run_id:get(row,"run_id",""),status:get(row,"status","ok")}));}\n recipe_discovery_picture(report,"'+name+'");\n println(recipe_cost_line(report));\n}\n'
  target=ROOT/'examples'/(name+'.lms')
  if check:assert target.read_text()==text, str(target)+' is stale'
  else:target.write_text(text)

def generate(check=False):

 for item in ITEMS:
  name=item['name'];example='recipe_'+name;lib='recipes/lib/'+item['library']+'.lms'
  args='--task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/'+name+' [--live]'
  if item['library']=='spend':args='--period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR]'
  if item['library']=='prefix':args+=' --ledger-dir .lmaws-local/recipes/ledgers --older-hours 24 [--delete --profile lmaws]'
  if item['access']=='Write with the lmaws profile':args=args.replace('--profile default','--profile lmaws')+' [--apply]'
  if name=='policy_lint':args='--file POLICY.json --top 20 --output data/policy_lint'
  if name=='grant_session_policy':args='--policy lmaws_session --file POLICY.json --profile admin --top 20 --output data/grant_session_policy [--live] [--apply]'
  if name=='session_doctor':args='--profile lmaws --region us-east-1 --top 20 --output data/session_doctor [--live]'
  if name=='grant_lambda_role':args='--role lmaws_lambda_exec --profile admin [--live] [--apply] [--output .lmaws-local/iam-role/report]'
  if 'args' in item:args=item['args']
  when={'Identity and access posture':'Before a posture review; IAM-dependent recipes remain synthetic for federated profiles','Permission builder and IAM analysis':'When specifying, shrinking, splitting, diffing, explaining or simulating AWS IAM policies without hand-editing raw JSON','Inventory':'Before a change or when reviewing current service coverage','Cost and spend':'When investigating a billing period or prioritizing savings opportunities','Idle and waste detection':'When triaging stopped resources; confirm age and usage before action','Tag and naming compliance':'Before enforcing tag or naming policies; review unknown metadata','Leftover search and cleanup by prefix':'After a test run or shutdown to review names and local ledger records','Safe lifecycle sandboxes':'Before a service integration, validate a disposable create/cleanup path','Compute and fleet':'When reviewing a small EC2 fleet without SSH or the aws CLI, or proving a disposable spot lifecycle'}[item['category']]
  header='\n'.join('# '+k+': '+v for k,v in [('Access',item['access']),('What',item['what']),('When',when),('Run',('lmctl recipes/'+name+'.lms '+item['run']).strip() if 'run' in item else 'lmctl recipes/'+name+'.lms '+('--task queue ' if name=='lifecycle' else '')+'--top 10'),('Preview','lmctl recipes/'+name+'.lms --preview'),('Arguments',args),('Typical-cost',item['cost']),('Category',item['category']),('Library',lib),('Function',item['function']),('Example',example)])
  body='\nimport "./lib/'+item['library']+'.lms";\nlet options=recipe_options(ARGV);\n'
  if name not in ['inventory','lifecycle']:
   body+='options.task='+repr(item['task']).replace("'",'"')+';\n'
  elif name=='inventory':body+='if (!contains(ARGV,"--task")) {options.task="all";}\n'
  else:body+='if (!contains(ARGV,"--task")) {options.task="queue";}\n'
  if item['library']=='prefix' and name!='prefix_search':body+='if (!contains(ARGV,"--older-hours")) {options.older_hours=24;}\n'
  body+='if (!contains(ARGV,"--output")) {options.output="data/'+name+'";}\n'
  body+='let report='+item['function']+'(options);\nif (!options.preview) {println("report:",get(report,"output_file",options.output+".json"));println(recipe_cost_line(report));}\n'
  body=re.sub(r'\nimport \"[^\"]+\";\n', '\n', body)
  if name in ['grant_session_policy','grant_lambda_role']:body=body.replace('recipe_options(ARGV)','recipe_grant_options(ARGV)')
  entry=header+'\n# Generated standalone entry; reusable source: '+lib+'\n'+flatten(ROOT/lib)+'\n'+body
  target=ROOT/'recipes'/(name+'.lms')
  if check:assert target.read_text()==entry, str(target)+' is stale; run generate-recipes.py'
  else:target.write_text(entry)
  exheader='# Synthetic-only: '+item['what']+'.\n# This picture-first example always disables live AWS and apply, even if inherited.\n# Run: lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/'+example+'.lms\n'
  exbody='import "../recipes/lib/'+item['library']+'.lms";\nlet options=recipe_options(ARGV);\noptions.live=false;options.apply=false;options.preview=false;options.profile="default";\noptions.task="'+item['task']+'";options.output="data/'+example+'";\nlet report='+item['function']+'(options);\nassert(is_array(report.rows));\n'
  if item['library']=='lifecycle':exbody+='assert(len(report.rows)==1 && report.rows[0].remaining==0);\nreport.rows[0].name="owned synthetic '+item['task']+'";\n'
  if item['library']=='compute':exbody+='recipe_compute_picture(report,"'+item['task']+'","'+example+'");\n'
  elif item['library']=='hygiene':exbody+='recipe_hygiene_picture(report,"'+item['task']+'","'+example+'");\n'
  elif item['library']=='policy_builder':exbody+='recipe_policy_picture(report,"'+item['task']+'","'+example+'");\n'
  else:exbody+='recipe_picture(report.rows,"'+item['what']+'","'+example+'");\n'
  if item['library']=='spend':
   exbody=exbody.replace('let report=recipe_spend(options);','options.cap=0.25;\nlet report=recipe_spend(options);')
   exbody=exbody.replace('recipe_picture(report.rows,"'+item['what']+'","'+example+'");','recipe_spend_picture(report,"'+example+'");')
  exbody+='println(recipe_cost_line(report));\n'
  exbody=re.sub(r'^import \"[^\"]+\";\n', '', exbody)
  content=exheader+'# Generated standalone example from '+lib+'\n'+flatten(ROOT/lib)+'\n'+exbody
  target=ROOT/'examples'/(example+'.lms')
  if check:assert target.read_text()==content, str(target)+' is stale; run generate-recipes.py'
  else:target.write_text(content)
 generate_discovery(check)
 return ITEMS
if __name__=='__main__':
 generate('--check' in sys.argv);print('checked' if '--check' in sys.argv else 'generated',len(ITEMS),'recipes and synthetic examples')
