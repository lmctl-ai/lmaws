#!/usr/bin/env python3
"""Dry-run only: list retained comparison states requiring attention. No AWS calls."""
import argparse,json,time
from pathlib import Path
from runtime import load,clean
p=argparse.ArgumentParser();p.add_argument('--older-than-hours',type=float,default=0);args=p.parse_args()
if args.older_than_hours<0:p.error('age must be non-negative')
root=Path(__file__).resolve().parent/'runs';findings=[]
for state in root.glob('**/terraform.tfstate'):
 if time.time()-state.stat().st_mtime<args.older_than_hours*3600:continue
 d=load(state)
 for resource in d.get('resources',[]):
  if resource.get('mode')!='managed':continue
  for instance in resource.get('instances',[]):
   attrs=instance.get('attributes',{});findings.append(dict(state=str(state),kind=resource.get('type'),name=attrs.get('name') or attrs.get('bucket') or attrs.get('key'),tags=attrs.get('tags') or {}))
for result in root.glob('**/cloud-result.json'):
 d=load(result)
 if d.get('leftover_count',0) and not any(str(result.parent) in x['state'] for x in findings):findings.append(dict(state=str(result),status=d.get('status'),cleanup_error=d.get('cleanup_error')))
print(json.dumps(clean(dict(dry_run=True,leftover_count=len(findings),findings=findings)),indent=2))
raise SystemExit(1 if findings else 0)
