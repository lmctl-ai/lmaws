#!/usr/bin/env python3
"""IAM Lambda-role contract and SDK protocol checks; loopback only, never AWS."""
from __future__ import annotations
import http.server, json, os, pathlib, shutil, subprocess, tempfile, threading, urllib.parse, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
TRUST={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
SPEC={"trust_policy":TRUST,"permissions_boundary":"arn:aws:iam::123456789012:policy/lmaws_boundary","managed_policies":["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],"inline_policies":{"lmaws_lambda_data":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem"],"Resource":"arn:aws:dynamodb:*:*:table/lmaws_*"}]}}}

class Fake(http.server.BaseHTTPRequestHandler):
    calls=[];mutations=[];exists=False;foreign=False;foreign_tags=False;inline=False;inline_docs={}
    def log_message(self,*a): pass
    def send_xml(self,body,status=200):
        data=body.encode();self.send_response(status);self.send_header("Content-Type","text/xml");self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get("Content-Length","0")));form=urllib.parse.parse_qs(raw.decode("utf-8","replace"));action=form.get("Action",[""])[0];Fake.calls.append((action,form))
        if action=="GetCallerIdentity":return self.send_xml('<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>')
        if action=="GetPolicy":return self.send_xml('<GetPolicyResponse><GetPolicyResult><Policy><Arn>arn:aws:iam::123456789012:policy/lmaws_boundary</Arn><DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>')
        if action=="GetRole":
            if not Fake.exists:return self.send_xml('<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>',404)
            if Fake.foreign:return self.send_xml('<GetRoleResponse><GetRoleResult><Role><Path>/</Path><RoleName>lmaws_lambda_exec</RoleName><Arn>arn:aws:iam::123456789012:role/lmaws_lambda_exec</Arn><AssumeRolePolicyDocument>%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22lambda.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D</AssumeRolePolicyDocument><PermissionsBoundary><PermissionsBoundaryArn>arn:aws:iam::123456789012:policy/other</PermissionsBoundaryArn></PermissionsBoundary></Role></GetRoleResult></GetRoleResponse>')
            return self.send_xml('<GetRoleResponse><GetRoleResult><Role><Path>/</Path><RoleName>lmaws_lambda_exec</RoleName><Arn>arn:aws:iam::123456789012:role/lmaws_lambda_exec</Arn><AssumeRolePolicyDocument>%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22lambda.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D</AssumeRolePolicyDocument><PermissionsBoundary><PermissionsBoundaryArn>arn:aws:iam::123456789012:policy/lmaws_boundary</PermissionsBoundaryArn></PermissionsBoundary></Role></GetRoleResult></GetRoleResponse>')
        if action=="ListAttachedRolePolicies" and not form.get("Marker"):
            return self.send_xml('<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies/><IsTruncated>true</IsTruncated><Marker>next</Marker></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>')
        if action=="ListAttachedRolePolicies":return self.send_xml('<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies><member><PolicyArn>arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>')
        if action=="ListRolePolicies":return self.send_xml('<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames>'+('<member>lmaws_lambda_data</member>' if Fake.inline else '')+'</PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>')
        if action=="GetRolePolicy":
            doc=urllib.parse.quote(json.dumps(Fake.inline_docs[form["PolicyName"][0]]))
            return self.send_xml('<GetRolePolicyResponse><GetRolePolicyResult><PolicyDocument>'+doc+'</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>')
        if action=="ListInstanceProfilesForRole":return self.send_xml('<ListInstanceProfilesForRoleResponse><ListInstanceProfilesForRoleResult><InstanceProfiles/><IsTruncated>false</IsTruncated></ListInstanceProfilesForRoleResult></ListInstanceProfilesForRoleResponse>')
        if action=="ListRoleTags" and Fake.foreign_tags:return self.send_xml('<ListRoleTagsResponse><ListRoleTagsResult><Tags><member><Key>lmaws_test</Key><Value>foreign</Value></member></Tags><IsTruncated>false</IsTruncated></ListRoleTagsResult></ListRoleTagsResponse>')
        if action=="ListRoleTags":return self.send_xml('<ListRoleTagsResponse><ListRoleTagsResult><Tags><member><Key>lmaws_test</Key><Value>lambda_exec</Value></member><member><Key>lmaws_role</Key><Value>lambda_execution</Value></member></Tags><IsTruncated>false</IsTruncated></ListRoleTagsResult></ListRoleTagsResponse>')
        if action in {"CreateRole","AttachRolePolicy","PutRolePolicy","DetachRolePolicy","DeleteRolePolicy","DeleteRole"}:
            if action=="PutRolePolicy":Fake.inline_docs[form["PolicyName"][0]]=json.loads(form["PolicyDocument"][0])
            if action=="DeleteRolePolicy":Fake.inline_docs.pop(form["PolicyName"][0],None)
            Fake.mutations.append((action,form));Fake.exists=action=="CreateRole" or (Fake.exists and action!="DeleteRole");Fake.inline=action=="PutRolePolicy" or (Fake.inline and action!="DeleteRolePolicy");return self.send_xml('<'+action+'Response><'+action+'Result/></'+action+'Response>')
        raise AssertionError((action,form))

def run_dsl(host,work,source,env,apply=True):
    schema=work/"schema.json";argv=["cmd.exe","/c",str(host)] if host.suffix.lower()==".cmd" else [str(host)]
    schema.write_bytes(subprocess.check_output(argv+["--dsl-schema"],env=env,timeout=30)); src=work/"role.lms";bc=work/"role.dslb";src.write_text('p=_dsl_ schema='+json.dumps(schema.as_posix())+';\n'+source+'\nend _dsl_\nsavedsl(p,'+json.dumps(bc.as_posix())+');\n',encoding="utf-8");lms=shutil.which("lmscript.cmd" if os.name=="nt" else "lmscript") or "lmscript";comp=["cmd.exe","/c",lms] if os.name=="nt" and lms.lower().endswith(".cmd") else [lms];compiled=subprocess.run(comp+[str(src)],cwd=work,env=env,capture_output=True,text=True,timeout=60);assert compiled.returncode==0,(compiled.stdout,compiled.stderr);return subprocess.run(argv+(["--apply"] if apply else [])+["--dsl",str(bc)],cwd=work,env=env,capture_output=True,text=True,timeout=180)

def main(host):
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Fake);threading.Thread(target=server.serve_forever,daemon=True).start();work=pathlib.Path(tempfile.mkdtemp(prefix="lmaws-iam-role-"));empty=work/"empty";empty.write_text("")
    env=dict(os.environ,CI="true",AWS_PROFILE="admin",AWS_DEFAULT_PROFILE="admin",LMAWS_ADMIN_GRANT="1",LMAWS_LIVE="1",AWS_REGION="us-east-1",LMAWS_ENDPOINT=f"http://127.0.0.1:{server.server_port}",AWS_SHARED_CREDENTIALS_FILE=str(empty),AWS_CONFIG_FILE=str(empty),AWS_ACCESS_KEY_ID="test",AWS_SECRET_ACCESS_KEY="test",AWS_EC2_METADATA_DISABLED="true")
    spec=json.dumps(SPEC,separators=(",",":"))
    try:
        Fake.calls.clear();Fake.mutations.clear();r=run_dsl(host,work,'let c=aws.region("us-east-1"); let x=c.iam_role_put("lmaws_lambda_exec",'+json.dumps(spec)+',false); file_write("preview.json",x.json());',env);assert r.returncode==0,r.stderr;assert not Fake.mutations,"preview mutated AWS";assert json.loads((work/"preview.json").read_text())["applied"]=="false"
        Fake.calls.clear();Fake.mutations.clear();r=run_dsl(host,work,'let c=aws.region("us-east-1"); let x=c.iam_role_put("lmaws_lambda_exec",'+json.dumps(spec)+',true); file_write("create.json",x.json());',env);assert r.returncode==0,r.stderr;assert any(x[0]=="CreateRole" for x in Fake.mutations);assert any(x[0]=="AttachRolePolicy" for x in Fake.mutations);assert any(x[0]=="PutRolePolicy" for x in Fake.mutations)
        before=len(Fake.mutations);r=run_dsl(host,work,'let c=aws.region("us-east-1"); let x=c.iam_role_put("lmaws_lambda_exec",'+json.dumps(spec)+',true);',env);assert r.returncode==0,r.stderr;assert len(Fake.mutations)==before,"identical role changed permissions"
        create=next(form for action,form in Fake.mutations if action=="CreateRole")
        assert create["PermissionsBoundary"]==["arn:aws:iam::123456789012:policy/lmaws_boundary"]
        assert json.loads(create["AssumeRolePolicyDocument"][0])==TRUST
        assert create["Tags.member.1.Key"]==["lmaws_test"] and create["Tags.member.1.Value"]==["lambda_exec"]
        assert any(action=="ListAttachedRolePolicies" and form.get("Marker")==["next"] for action,form in Fake.calls),"pagination lost"
        Fake.foreign=True;Fake.mutations.clear();r=run_dsl(host,work,'let c=aws.region("us-east-1"); let x=c.iam_role_delete("lmaws_lambda_exec",true);',env);assert r.returncode!=0 and not Fake.mutations,"foreign role was mutable"
        Fake.foreign=False;Fake.foreign_tags=True;Fake.mutations.clear()
        r=run_dsl(host,work,'let c=aws.region("us-east-1");let x=c.iam_role_put("lmaws_lambda_exec",'+json.dumps(spec)+',true);',env)
        assert r.returncode!=0 and not Fake.mutations,"unowned role was adopted"
        Fake.foreign_tags=False;Fake.mutations.clear()
        r=run_dsl(host,work,'let c=aws.region("us-east-1"); let x=c.iam_role_delete("lmaws_lambda_exec",true);',env)
        assert r.returncode==0,r.stderr
        assert {action for action,_ in Fake.mutations}=={"DetachRolePolicy","DeleteRolePolicy","DeleteRole"},Fake.mutations
        for extra,apply in [({"AWS_PROFILE":"lmaws"},True),({"LMAWS_ADMIN_GRANT":"0"},True),({},False)]:
            Fake.mutations.clear();r=run_dsl(host,work,'let c=aws.region("us-east-1");let x=c.iam_role_put("lmaws_lambda_exec",'+json.dumps(spec)+',true);',dict(env,**extra),apply)
            assert r.returncode!=0 and not Fake.mutations,"administrative role guard failed"
        print("PASS Lambda role loopback preview/create/idempotence/foreign guard, boundary, trust, ownership tags and inline policy protocol")
    finally:server.shutdown();server.server_close()
if __name__=="__main__":main(pathlib.Path(sys.argv[1]).resolve())
