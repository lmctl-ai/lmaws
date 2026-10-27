#!/usr/bin/env python3
"""Offline checks: reject malformed private specs and fail closed before real SDK calls."""
import os,pathlib,subprocess,tempfile,xml.etree.ElementTree as ET,json
ROOT=pathlib.Path(__file__).resolve().parents[1]
jar=ROOT/'target'/('lmaws-'+ET.parse(ROOT/'pom.xml').getroot().find('{*}version').text+'.jar')
with tempfile.TemporaryDirectory(prefix='fleet-spec-') as tmp:
 p=pathlib.Path(tmp)/'Check.java'
 p.write_text('''import ai.lmctl.lmaws.*; class Check {public static void main(String[] a)throws Exception {if(a[0].equals("guard")){try(var b=new AwsBackend("us-east-1",false)){try{FleetRoles.plan(b);throw new AssertionError("unconfigured live plan accepted");}catch(IllegalStateException e){if(!e.getMessage().contains("LMAWS_FLEET_ROLES_SPEC"))throw e;}}}else FleetRoles.Spec.active();}}''')
 env=dict(os.environ,CI='false',AWS_EC2_METADATA_DISABLED='true')
 for key in ['LMAWS_ENDPOINT','LMAWS_FLEET_ROLES_SPEC']:env.pop(key,None)
 def run(mode,ok):
  r=subprocess.run(['java','--class-path',str(jar),str(p),mode],env=env,capture_output=True,text=True,timeout=30)
  assert (r.returncode==0)==ok,r.stderr+r.stdout
 run('guard',True)
 valid=dict(instance_1='node1',instance_2='node2',role_tag_1='primary',role_tag_2='secondary',role_1='unit-role1',role_2='unit-role2',boundary_name='unit-boundary',legacy_role='unit-legacy',project_tag='unit',deploy_role='unit-deploy',asset_bucket='unit.example.invalid',inline_policy_name='unit_permissions')
 for spec,ok in [(valid,True),({},False),([],False),(dict(valid,instance_1='*'),False),(dict(valid,role_1='unit-role2'),False),(dict(valid,extra='bad'),False)]:
  env['LMAWS_FLEET_ROLES_SPEC']=json.dumps(spec);run('spec',ok)
print('PASS offline fleet spec validation and unconfigured-live refusal; no AWS calls')
