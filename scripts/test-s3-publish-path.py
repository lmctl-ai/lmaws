#!/usr/bin/env python3
"""Offline loopback coverage for Cloud.s3_publish_path.

The server only implements read requests.  Any mutating HTTP verb or unknown
request fails, so this test cannot accidentally create, upload, or invalidate
anything while exercising the effective-path report.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = ET.parse(ROOT / "pom.xml").getroot().find("{*}version").text
JAR = ROOT / "target" / f"lmaws-{VERSION}.jar"
ACCOUNT = "000000000000"
KEY_ID = "12345678-1234-1234-1234-123456789abc"


class ReadOnlyBackend(BaseHTTPRequestHandler):
    mode = "full"
    calls: list[tuple[str, str, str]] = []

    def log_message(self, *_args):
        pass

    def reply(self, status=200, body="", content_type="application/xml"):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def fail_write(self):
        raise AssertionError(f"mutating or unexpected request: {self.command} {self.path}")

    def do_PUT(self): self.fail_write()
    def do_DELETE(self): self.fail_write()
    def do_PATCH(self): self.fail_write()

    def do_HEAD(self):
        self.fail_write()

    def do_POST(self):
        parsed = urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        action = self.headers.get("X-Amz-Target", "")
        self.calls.append((self.command, parsed.path, action or parse_qs(body.decode()).get("Action",[""])[0]))
        if b"GetCallerIdentity" in body or "GetCallerIdentity" in action:
            if self.mode=="deny_identity": return self.reply(403,"<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>")
            caller_arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/fixture-role/session" if self.mode=="role_identity" else f"arn:aws:sts::{ACCOUNT}:federated-user/fake"
            return self.reply(200, f"""<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>{ACCOUNT}</Account><Arn>{caller_arn}</Arn><UserId>fake</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>""")
        if "DescribeKey" in action or b"DescribeKey" in body:
            if self.mode=="kms_deny_describe": return self.reply(403,json.dumps({"__type":"AccessDeniedException","message":"fixture denied"}),"application/x-amz-json-1.1")
            return self.reply(200, json.dumps({"KeyMetadata": {"KeyId": KEY_ID, "Arn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY_ID}", "KeyState": "Disabled" if self.mode=="kms_disabled" else "Enabled"}}), "application/x-amz-json-1.1")
        if "GetKeyPolicy" in action or b"GetKeyPolicy" in body:
            if self.mode=="kms_deny_policy": return self.reply(403,json.dumps({"__type":"AccessDeniedException","message":"fixture denied"}),"application/x-amz-json-1.1")
            return self.reply(200, json.dumps({"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]})}), "application/x-amz-json-1.1")
        return self.reply(500, "unexpected POST")

    def do_GET(self):
        parsed = urlsplit(self.path)
        if self.mode!="deny_identity": assert self.headers.get("x-amz-expected-bucket-owner")==ACCOUNT,"metadata must bind owner context"
        query = parse_qs(parsed.query, keep_blank_values=True)
        self.calls.append((self.command, parsed.path, parsed.query))
        if self.mode=="deny_all_reads": return self.reply(403,"<Error><Code>AccessDenied</Code></Error>")
        if self.mode=="no_policy" and "policy" in query:return self.reply(404,"<Error><Code>NoSuchBucketPolicy</Code></Error>")
        if self.mode in {"deny_policy", "deny_policy405"} and "policy" in query:
            return self.reply(405 if self.mode == "deny_policy405" else 403, "<Error><Code>AccessDenied</Code><Message>GetBucketPolicy denied</Message></Error>")
        if self.mode == "deny_encryption" and "encryption" in query:
            return self.reply(403, "<Error><Code>AccessDenied</Code><Message>GetBucketEncryption denied</Message></Error>")
        if self.mode == "deny_ownership" and "ownershipControls" in query:
            return self.reply(403, "<Error><Code>AccessDenied</Code><Message>GetBucketOwnershipControls denied</Message></Error>")
        if self.mode == "deny_bpa" and "publicAccessBlock" in query:
            return self.reply(403, "<Error><Code>AccessDenied</Code><Message>GetPublicAccessBlock denied</Message></Error>")
        if "policy" in query:
            statement = {"Sid": "DenyVpc", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-foreign"}}}
            if self.mode == "deny_unconditional":
                statement = {"Sid": "DenyAllPuts", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "*"}
            if self.mode in {"deny_principal","deny_principal_match","role_identity"}:
                expected=f"arn:aws:sts::{ACCOUNT}:federated-user/fake" if self.mode=="deny_principal_match" else f"arn:aws:iam::{ACCOUNT}:role/other"
                statement={"Sid":"PrincipalGuard","Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"*","Condition":{"ArnNotEquals":{"aws:PrincipalArn":expected}}}
            policy = {"Version": "2012-10-17", "Statement": [statement]}
            return self.reply(200, json.dumps(policy), "application/json")
        if "encryption" in query:
            if self.mode.startswith("sse_kms") or self.mode.startswith("kms_"):
                key_id="alias/private-fixture" if self.mode=="kms_alias" else KEY_ID
                enabled="false" if self.mode=="sse_kms_object" else "true"
                return self.reply(200, "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>" + key_id + "</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>"+enabled+"</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>")
            return self.reply(200, "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>")
        if "ownershipControls" in query:
            return self.reply(200, "<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>")
        if "publicAccessBlock" in query:
            return self.reply(200, "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>")
        return self.reply(404, "<Error><Code>NoSuchKey</Code></Error>")


def run(mode: str, profile: str = "default"):
    ReadOnlyBackend.mode = mode
    ReadOnlyBackend.calls = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ReadOnlyBackend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="lmaws-publish-path-") as td:
            work = Path(td)
            schema = work / "schema.json"
            schema.write_text(subprocess.check_output(["java", "-jar", str(JAR), "--lmcode-schema", "--json"], text=True))
            source = work / "check.lms"
            result = work / "result.json"
            inline_policy = {"Version": "2012-10-17", "Statement": [
                {"Sid": "Upload", "Effect": "Allow", "Action": ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"], "Resource": "arn:aws:s3:::*/*", "Condition": {"StringEquals": {"s3:ResourceAccount": ACCOUNT}}},
                {"Sid": "DenyDelete", "Effect": "Deny", "Action": ["s3:Delete*", "s3:PutObjectAcl"], "Resource": "*"},
                {"Sid": "DenyForeign", "Effect": "Deny", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::*/*", "Condition": {"StringNotEquals": {"s3:ResourceAccount": ACCOUNT}}},
                {"Sid": "KmsS3", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*", "Condition": {"StringEquals": {"kms:CallerAccount": ACCOUNT}, "StringLike": {"kms:ViaService": "s3.*.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::*"}}},
            ]}
            source.write_text(f'''let p=_dsl_ schema="{schema}";
let c=aws.region("us-east-1");
let r=c.s3_publish_path("fixture-bucket","dataset/model_list.json",{json.dumps(json.dumps(inline_policy))});
file_write("{result}",r.json());
end _dsl_
savedsl(p,"{work / "check.dslb"}");
''')
            env = dict(os.environ, AWS_PROFILE=profile, AWS_DEFAULT_PROFILE=profile, AWS_REGION="us-east-1", LMAWS_LIVE="1", LMAWS_ENDPOINT=f"http://127.0.0.1:{server.server_port}", CI="false")
            compile_proc = subprocess.run(["lmscript", str(source)], cwd=work, env=env, capture_output=True, text=True, timeout=60)
            assert compile_proc.returncode == 0, compile_proc.stdout + compile_proc.stderr
            proc = subprocess.run(["java", "-jar", str(JAR), "--lmcode", str(work / "check.dslb")], cwd=work, env=env, capture_output=True, text=True, timeout=60)
            return proc, (json.loads(result.read_text()) if result.exists() else {}), list(ReadOnlyBackend.calls)
    finally:
        server.shutdown(); server.server_close(); thread.join()


if __name__ == "__main__":
    proc, report, calls = run("full")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert calls and all(method in {"GET", "POST"} for method, _path, _query in calls)
    assert all(operation in {"GetCallerIdentity","TrentService.DescribeKey","TrentService.GetKeyPolicy"} for method,path,operation in calls if method=="POST")
    text = json.dumps(report)
    assert "allowed" in text and "unknown" in text
    layers={r["layer"]:r for r in report}
    assert {"session_policy","identity","bucket_policy","encryption","kms","ownership","public_access_block","request_requirements"} <= layers.keys()
    assert layers["session_policy"]["status"]=="allowed",report
    assert layers["encryption"]["algorithm"]=="AES256" and layers["kms"]["status"]=="allowed"
    assert "aws:SourceVpc" in text
    assert ACCOUNT not in text and KEY_ID not in text and re.search(r"[0-9a-f]{8}-[0-9a-f-]{27,}", text) is None
    for mode,permission in [("deny_policy","s3:GetBucketPolicy"),("deny_policy405","s3:GetBucketPolicy"),("deny_encryption","s3:GetEncryptionConfiguration"),("deny_ownership","s3:GetOwnershipControls"),("deny_bpa","s3:GetPublicAccessBlock")]:
        proc, report, calls = run(mode)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "unknown: needs "+permission in json.dumps(report),report
        if mode in {"deny_policy","deny_policy405"}: assert next(r for r in report if r["layer"]=="session_policy")["status"]=="allowed","other owner-bound reads establish ownership"
    # A readable, unconditional bucket-policy Deny must be surfaced as denied;
    # a conditional SourceVpc/PrincipalArn rule remains unknown without the
    # request context rather than being guessed to match.
    proc, report, calls = run("deny_unconditional")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "denied" in json.dumps(report)
    proc, report, calls = run("sse_kms")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "KMS" in json.dumps(report)
    kms_rows=[r for r in report if r["layer"]=="kms_session_policy"]
    assert len(kms_rows)==2 and all(r["status"]=="allowed" and r["encryption_context"]=="arn:aws:s3:::fixture-bucket" for r in kms_rows),report
    for mode in ["sse_kms_object","kms_alias","kms_disabled","kms_deny_describe","kms_deny_policy","deny_principal","deny_principal_match","no_policy","deny_all_reads","deny_identity","role_identity"]:
        proc,report,calls=run(mode);assert proc.returncode==0,proc.stderr
        layers={r["layer"]:r for r in report};serialized=json.dumps(report)
        assert ACCOUNT not in serialized and KEY_ID not in serialized and "alias/private-fixture" not in serialized
        if mode=="sse_kms_object":assert all(r["encryption_context"]=="arn:aws:s3:::fixture-bucket/dataset/model_list.json" for r in report if r["layer"]=="kms_session_policy")
        if mode=="kms_disabled":assert layers["kms"]["status"].startswith("denied:")
        if mode=="kms_deny_describe":assert "unknown: needs kms:DescribeKey" in serialized
        if mode=="kms_deny_policy":assert "unknown: needs kms:GetKeyPolicy" in serialized
        if mode=="deny_principal":assert layers["bucket_policy"]["status"].startswith("denied:"),report
        if mode in {"deny_principal_match","no_policy"}:assert layers["bucket_policy"]["status"]=="allowed",report
        if mode=="deny_all_reads":assert layers["session_policy"]["status"].startswith("unknown:"),report
        if mode=="role_identity":assert layers["bucket_policy"]["status"].startswith("unknown:") and "iam:GetRole" in serialized
        if mode=="deny_identity":assert "unknown: needs sts:GetCallerIdentity" in serialized
        assert all(op in {"GetCallerIdentity","TrentService.DescribeKey","TrentService.GetKeyPolicy"} for method,path,op in calls if method=="POST")
    proc, _report, calls = run("full", profile="lmaws")
    assert proc.returncode != 0 and not calls, "non-default profiles must be refused before SDK dispatch"
    proc, _report, calls = run("full", profile="admin")
    assert proc.returncode != 0 and not calls, "admin must be refused before SDK dispatch"
    print("PASS read-only S3 effective-path loopback: policy/encryption/ownership/BPA/KMS, unknown permissions, masking, and profile guards")
