#!/usr/bin/env python3
"""Run spend examples on deterministic host fixtures; optionally publish only their fake images."""
from pathlib import Path
import os,json,subprocess,tempfile,shutil,struct,sys,re,argparse
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--render',action='store_true');args=p.parse_args()
names=['spend_detail','ec2_spend','savings_plans','eip_audit','ebs_audit','bandwidth','lambda_spend','dynamodb_spend']
env=dict(os.environ,LMAWS_LIVE='0',LMAWS_SPEND_LIVE='0',AWS_PROFILE='default',AWS_EC2_METADATA_DISABLED='true')
env.pop('LMAWS_ENDPOINT',None)
proof=[];outputs={}
for name in names:
 with tempfile.TemporaryDirectory(prefix='lmaws-spend-gallery-') as directory:
  work=Path(directory)
  result=subprocess.run(['lmscript',str(root/'examples'/f'{name}.lms')],cwd=work,env=env,capture_output=True,text=True,timeout=240)
  if result.returncode:raise SystemExit(name+': '+(result.stdout+result.stderr)[-6000:])
  report_path=work/'data'/name/'report.json';report=json.loads(report_path.read_text())
  assert report['metadata']['mode']=='synthetic' and report['metadata']['source']['synthetic'] is True,name
  assert report['summary']['status']=='complete',name
  assert report['summary']['ce_requests']<=25 and float(report['summary']['estimated_cost_usd'])<=.25,name
  assert result.stdout.strip().splitlines()[-1].startswith('estimated cost: $'),name
  cost=float(result.stdout.strip().splitlines()[-1].split('$')[1]);assert abs(cost-float(report['summary']['estimated_cost_usd']))<1e-9,name
  assert re.search(r'Cost Explorer requests: \d+',result.stdout),name
  images=sorted((work/'images').glob('*.png'));assert any(image.name==name+'.png' for image in images),name
  for image in images:
   data=image.read_bytes();assert data[:8]==b'\x89PNG\r\n\x1a\n' and struct.unpack('>II',data[16:24])==(900,560) and len(data)<300*1024,image
   if args.render:
    # Rendering is impossible in this process with live mode; require the source proof above too.
    shutil.copyfile(image,root/'docs/images'/image.name)
  assert '123456789012' not in report_path.read_text(),name
  if name=='spend_detail':outputs[name]=report_path.read_bytes()
  proof.append({'name':name,'mode':'synthetic','images':len(images),'ce_requests':report['summary']['ce_requests'],'metric_units':report['summary']['metric_units'],'estimated_cost_usd':cost})
  print(name+': PASS ('+str(len(images))+' images, estimated query cost $'+str(cost)+')',flush=True)
Path(tempfile.gettempdir(),'lmaws-spend-gallery-proof.json').write_text(json.dumps({'synthetic_only':True,'examples':proof},indent=2)+'\n')
print('spend examples: 8 passed; '+str(sum(x['images'] for x in proof))+' synthetic figures verified')
