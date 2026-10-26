#!/usr/bin/env python3
"""Generate thin runnable recipe entries and their synthetic-only examples."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
INVENTORIES=['identity','buckets','instances','vpcs','security_groups','tables','queues','topics','functions','log_groups','alarms','zones','secrets','parameters','clusters','roles']
LIFECYCLES=['queue','topic','table','bucket','parameter','log_group']
ITEMS=[]
for name in INVENTORIES:
 ITEMS.append(dict(name='inventory_'+name,category='Identity and access posture' if name in ('identity','roles','security_groups') else 'Inventory',task=name,library='inventory',function='recipe_inventory',what='Inspect bounded '+name.replace('_',' ')+' metadata'+(' (synthetic only; federated IAM cases skipped live)' if name in ('identity','roles') else ''),access='Read-only',cost='$0.00 displayed; capped request estimate in ledger'))
ITEMS.append(dict(name='inventory',category='Inventory',task='all',library='inventory',function='recipe_inventory',what='Review all supported inventories; IAM entries are skipped live',access='Read-only',cost='$0.00 displayed; request cap $0.05'))
for kind in LIFECYCLES:
 ITEMS.append(dict(name='sandbox_'+kind,category='Safe lifecycle sandboxes',task=kind,library='lifecycle',function='recipe_lifecycle',what='Create and tear down one owned '+kind.replace('_',' ')+' with its run ledger',access='Write with the lmaws profile',cost='Synthetic $0.00; live generally below $0.0001; cap $0.05'))
ITEMS.append(dict(name='lifecycle',category='Safe lifecycle sandboxes',task='queue',library='lifecycle',function='recipe_lifecycle',what='Select a disposable queue/topic/table/bucket/parameter/log-group lifecycle',access='Write with the lmaws profile',cost='Synthetic $0.00; live generally below $0.0001; cap $0.05'))
for name,function,what in [('prefix_search','recipe_prefix_search','Find lmaws_ and lmaws- names across supported account inventories'),('leftover_report','recipe_leftovers','Inspect aged active/pending records in the local run ledgers'),('sweeper','recipe_sweeper','Dry-run leftover review; discovery never authorizes deletion')]:
 ITEMS.append(dict(name=name,category='Leftover search and cleanup by prefix',task=name,library='prefix',function=function,what=what,access='Read-only',cost='$0.00 synthetic; live request cap $0.05'))
for name,function,category,what in [('idle_instances','recipe_idle','Idle and waste detection','Flag stopped-instance state for further review; never delete'),('tag_compliance','recipe_compliance','Tag and naming compliance','Report missing and unknown tag presence without assuming compliance')]:
 ITEMS.append(dict(name=name,category=category,task=name,library='audits',function=function,what=what,access='Read-only',cost='$0.00 displayed; request cap $0.05'))

def generate():
 for item in ITEMS:
  name=item['name'];example='recipe_'+name;lib='recipes/lib/'+item['library']+'.lms'
  args='--task TASK --period 30 --top 10 --prefix lmaws --region us-east-1 --profile default --output data/'+name+' [--live]'
  if item['library']=='prefix':args+=' --ledger-dir .lmaws-local/recipes/ledgers --older-hours 0'
  if item['access'].startswith('Write'):args=args.replace('--profile default','--profile lmaws')+' [--apply]'
  header='\n'.join('# '+k+': '+v for k,v in [('Access',item['access']),('What',item['what']),('When','Reusable '+item['category'].lower()+'; defaults to synthetic fixtures'),('Run','lmctl recipes/'+name+'.lms '+('--task queue ' if name=='lifecycle' else '')+'--top 10'),('Preview','lmctl recipes/'+name+'.lms --preview (or lmctl script --dry-run recipes/'+name+'.lms)'),('Arguments',args),('Typical-cost',item['cost']),('Category',item['category']),('Library',lib),('Function',item['function']),('Example',example)])
  body='\nimport "./lib/'+item['library']+'.lms";\nlet options=recipe_options(ARGV);\n'
  if name not in ['inventory','lifecycle']:
   body+='options.task='+repr(item['task']).replace("'",'"')+';\n'
  elif name=='inventory':body+='if (!contains(ARGV,"--task")) {options.task="all";}\n'
  else:body+='if (!contains(ARGV,"--task")) {options.task="queue";}\n'
  body+='if (!contains(ARGV,"--output")) {options.output="data/'+name+'";}\n'
  body+='let report='+item['function']+'(options);\nif (!options.preview) {println("report:",options.output+".json");}\n'
  (ROOT/'recipes'/ (name+'.lms')).write_text(header+'\n'+body)
  exheader='# Synthetic-only: '+item['what']+'.\n# This picture-first example always disables live AWS and apply, even if inherited.\n# Run: lmctl https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/'+example+'.lms\n'
  exbody='import "../recipes/lib/'+item['library']+'.lms";\nlet options=recipe_options(ARGV);\noptions.live=false;options.apply=false;options.preview=false;options.profile="default";\noptions.task="'+item['task']+'";options.output="data/'+example+'";\nlet report='+item['function']+'(options);\nassert(is_array(report.rows));\n'
  if item['library']=='lifecycle':exbody+='assert(len(report.rows)==1 && report.rows[0].remaining==0);\nreport.rows[0].name="owned synthetic '+item['task']+'";\n'
  exbody+='recipe_picture(report.rows,"'+item['what']+'","'+example+'");\n'
  (ROOT/'examples'/(example+'.lms')).write_text(exheader+exbody)
 return ITEMS
if __name__=='__main__':
 generate();print('generated',len(ITEMS),'recipes and synthetic examples')
