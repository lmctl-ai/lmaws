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
for name,function,what in [('prefix_search','recipe_prefix_search','Find lmaws_ and lmaws- names across supported account inventories'),('leftover_report','recipe_leftovers','Inspect aged active/pending records in the local run ledgers'),('sweeper','recipe_sweeper','Dry-run leftover review; discovery never authorizes deletion')]:
 ITEMS.append(dict(name=name,category='Leftover search and cleanup by prefix',task=name,library='prefix',function=function,what=what,access='Read-only',cost='$0.00 synthetic; live request cap $0.05'))
for name,function,category,what in [('idle_instances','recipe_idle','Idle and waste detection','Flag stopped-instance state for further review; never delete'),('tag_compliance','recipe_compliance','Tag and naming compliance','Report missing and unknown tag presence without assuming compliance'),('naming_compliance','recipe_naming','Tag and naming compliance','Check case-sensitive lmaws_ and lmaws- naming among prefix candidates')]:
 ITEMS.append(dict(name=name,category=category,task=name,library='audits',function=function,what=what,access='Read-only',cost='$0.00 synthetic; live request cap $0.05'))

for name,what in [('spend_detail','Review account spend detail and optimization signals'),('ec2_spend','Break down EC2 compute spend and current resource signals'),('savings_plans','Review Savings Plans and Reserved Instance utilization and coverage'),('eip_audit','Review idle public IPv4 allocations and estimated run-rate'),('ebs_audit','Review EBS attachments and snapshot retention signals'),('bandwidth','Break down billed transfer categories and network counters'),('lambda_spend','Review Lambda usage and spend signals'),('dynamodb_spend','Review DynamoDB usage and spend signals')]:
 ITEMS.append(dict(name=name,category='Cost and spend',task=name,library='spend',function='recipe_spend',what=what,access='Read-only',cost='Synthetic actual $0.00; live CE $0.01/request plus metrics; default/hard cap $0.25'))

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

def generate(check=False):

 for item in ITEMS:
  name=item['name'];example='recipe_'+name;lib='recipes/lib/'+item['library']+'.lms'
  args='--task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/'+name+' [--live]'
  if item['library']=='spend':args='--period 30 --top 10 --region us-east-1 --profile default --cap 0.25 [--live] [--output PRIVATE_DIR]'
  if item['library']=='prefix':args+=' --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0'
  if item['access'].startswith('Write'):args=args.replace('--profile default','--profile lmaws')+' [--apply]'
  if 'args' in item:args=item['args']
  when={'Identity and access posture':'Before a posture review; IAM-dependent recipes remain synthetic for federated profiles','Inventory':'Before a change or when reviewing current service coverage','Cost and spend':'When investigating a billing period or prioritizing savings opportunities','Idle and waste detection':'When triaging stopped resources; confirm age and usage before action','Tag and naming compliance':'Before enforcing tag or naming policies; review unknown metadata','Leftover search and cleanup by prefix':'After a test run or shutdown to review names and local ledger records','Safe lifecycle sandboxes':'Before a service integration, validate a disposable create/cleanup path','Compute and fleet':'When reviewing a small EC2 fleet without SSH or the aws CLI, or proving a disposable spot lifecycle'}[item['category']]
  header='\n'.join('# '+k+': '+v for k,v in [('Access',item['access']),('What',item['what']),('When',when),('Run',('lmctl recipes/'+name+'.lms '+item['run']).strip() if 'run' in item else 'lmctl recipes/'+name+'.lms '+('--task queue ' if name=='lifecycle' else '')+'--top 10'),('Preview','lmctl recipes/'+name+'.lms --preview'),('Arguments',args),('Typical-cost',item['cost']),('Category',item['category']),('Library',lib),('Function',item['function']),('Example',example)])
  body='\nimport "./lib/'+item['library']+'.lms";\nlet options=recipe_options(ARGV);\n'
  if name not in ['inventory','lifecycle']:
   body+='options.task='+repr(item['task']).replace("'",'"')+';\n'
  elif name=='inventory':body+='if (!contains(ARGV,"--task")) {options.task="all";}\n'
  else:body+='if (!contains(ARGV,"--task")) {options.task="queue";}\n'
  body+='if (!contains(ARGV,"--output")) {options.output="data/'+name+'";}\n'
  body+='let report='+item['function']+'(options);\nif (!options.preview) {println("report:",get(report,"output_file",options.output+".json"));println(recipe_cost_line(report));}\n'
  body=re.sub(r'\nimport \"[^\"]+\";\n', '\n', body)
  entry=header+'\n# Generated standalone entry; reusable source: '+lib+'\n'+flatten(ROOT/lib)+'\n'+body
  target=ROOT/'recipes'/(name+'.lms')
  if check:assert target.read_text()==entry, str(target)+' is stale; run generate-recipes.py'
  else:target.write_text(entry)
  exheader='# Synthetic-only: '+item['what']+'.\n# This picture-first example always disables live AWS and apply, even if inherited.\n# Run: lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/'+example+'.lms\n'
  exbody='import "../recipes/lib/'+item['library']+'.lms";\nlet options=recipe_options(ARGV);\noptions.live=false;options.apply=false;options.preview=false;options.profile="default";\noptions.task="'+item['task']+'";options.output="data/'+example+'";\nlet report='+item['function']+'(options);\nassert(is_array(report.rows));\n'
  if item['library']=='lifecycle':exbody+='assert(len(report.rows)==1 && report.rows[0].remaining==0);\nreport.rows[0].name="owned synthetic '+item['task']+'";\n'
  if item['library']=='compute':exbody+='recipe_compute_picture(report,"'+item['task']+'","'+example+'");\n'
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
 return ITEMS
if __name__=='__main__':
 generate('--check' in sys.argv);print('checked' if '--check' in sys.argv else 'generated',len(ITEMS),'recipes and synthetic examples')
