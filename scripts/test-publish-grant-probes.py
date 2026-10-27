#!/usr/bin/env python3
"""Synthetic DSL and loopback SDK transport proof for closed-set publish grant probes."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote
import json, os, subprocess, tempfile, threading, xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = ET.parse(ROOT / "pom.xml").getroot().find("{*}version").text
JAR = ROOT / f"target/lmaws-{VERSION}.jar"
ACCOUNT = "000000000000"


class FakeModel:
    def __init__(self, mode="happy"):
        self.mode = mode
        self.calls = []
        self.last_if_match = None


class FakeHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body="", content_type="application/xml", headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, str(v))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def handle_all(self):
        m = self.server.model
        u = urlsplit(self.path)
        path = unquote(u.path)
        query = u.query
        target = self.headers.get("X-Amz-Target", "")
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        m.calls.append((self.command, path, query, target))

        if self.command == "POST" and "Action=GetCallerIdentity" in body:
            return self.reply(
                200,
                f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                f"<GetCallerIdentityResult><Account>{ACCOUNT}</Account>"
                f"<Arn>arn:aws:sts::{ACCOUNT}:federated-user/default-synthetic</Arn>"
                f"<UserId>SYNTHETIC</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>",
                "text/xml",
            )

        if "secretsmanager" in target:
            if m.mode == "wrong_allow":
                return self.reply(400, '{"__type":"ResourceNotFoundException","Message":"not found"}', "application/x-amz-json-1.1")
            return self.reply(400, '{"__type":"AccessDeniedException","Message":"explicit deny"}', "application/x-amz-json-1.1")

        if "AmazonSSM" in target:
            if m.mode == "wrong_allow":
                return self.reply(400, '{"__type":"ParameterNotFound","Message":"not found"}', "application/x-amz-json-1.1")
            return self.reply(400, '{"__type":"AccessDeniedException","Message":"explicit deny"}', "application/x-amz-json-1.1")

        if "/2020-05-31/distribution/" in path:
            if "E00000NONEXIST" in path:
                if m.mode == "wrong_allow":
                    return self.reply(404, '<ErrorResponse xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Error><Type>Sender</Type><Code>NoSuchDistribution</Code><Message>missing</Message></Error></ErrorResponse>')
                return self.reply(403, '<ErrorResponse xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>denied</Message></Error></ErrorResponse>')
            if self.command == "POST" and path.endswith("/invalidation"):
                assert "*" not in body, "wildcard invalidation forbidden"
                return self.reply(201, '<Invalidation xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Id>ISYNTH01</Id><Status>InProgress</Status><CreateTime>2026-10-27T12:00:00Z</CreateTime><InvalidationBatch><Paths><Quantity>1</Quantity><Items><Path>/__perm_check/cafe01</Path></Items></Paths><CallerReference>ref</CallerReference></InvalidationBatch></Invalidation>')
            if self.command == "GET" and "/invalidation/" in path:
                return self.reply(200, '<Invalidation xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Id>ISYNTH01</Id><Status>Completed</Status><CreateTime>2026-10-27T12:00:00Z</CreateTime><InvalidationBatch><Paths><Quantity>1</Quantity><Items><Path>/__perm_check/cafe01</Path></Items></Paths><CallerReference>ref</CallerReference></InvalidationBatch></Invalidation>')

        if self.command == "GET" and path == "/":
            return self.reply(200, '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>synthetic-publish-bucket</Name><CreationDate>2026-01-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>')

        if self.command == "HEAD" and path == "/synthetic-publish-bucket":
            return self.reply(200, "")

        if self.command == "GET" and "list-type=2" in query:
            assert "max-keys=1" in query, f"expected max-keys=1 in ListObjectsV2: {query}"
            return self.reply(200, '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>synthetic-publish-bucket</Name><Prefix>dataset/</Prefix><KeyCount>1</KeyCount><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>dataset/sample.json</Key><Size>12</Size><ETag>"11223344556677889900aabbccddeeff"</ETag></Contents></ListBucketResult>')

        if self.command == "GET" and path == "/synthetic-publish-bucket":
            if "policy" in query:
                return self.reply(404, "<Error><Code>NoSuchBucketPolicy</Code><Message>none</Message></Error>")
            if "encryption" in query:
                return self.reply(200, '<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>')
            if "ownershipControls" in query:
                return self.reply(200, '<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>')
            if "publicAccessBlock" in query:
                return self.reply(200, '<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>')

        if self.command == "HEAD":
            return self.reply(200, "", headers={"ETag": '"11223344556677889900aabbccddeeff"', "Content-Length": "12"})

        if self.command == "PUT":
            if "acl" in query:
                return self.reply(403, "<Error><Code>AccessDenied</Code><Message>explicit deny</Message></Error>")
            m.last_if_match = self.headers.get("If-Match")
            if m.mode == "put_403":
                return self.reply(403, "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>")
            return self.reply(412, "<Error><Code>PreconditionFailed</Code><Message>wrong etag</Message></Error>")

        if self.command == "DELETE":
            if m.mode == "delete_204":
                return self.reply(204, "")
            return self.reply(403, "<Error><Code>AccessDenied</Code><Message>explicit deny</Message></Error>")

        raise AssertionError((self.command, path, query, target))

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = handle_all


with tempfile.TemporaryDirectory(prefix="lmaws-publish-probes-") as tmp:
    work = Path(tmp)
    schema = work / "schema.json"
    schema.write_text(subprocess.check_output(["java", "-jar", str(JAR), "--dsl-schema", "--json"], cwd=ROOT, text=True))

    def run_dsl(mode, dsl_body, profile="default", expect_ok=True):
        model = FakeModel(mode)
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeHandler)
        server.model = model
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            src = work / "probe.lms"
            bc = work / "probe.dslb"
            src.write_text(f'let p = _dsl_ schema={json.dumps(str(schema))};\n{dsl_body}\nend _dsl_\nsavedsl(p, {json.dumps(str(bc))});\n')
            subprocess.run(["lmscript", str(src)], cwd=work, check=True, capture_output=True, text=True, timeout=30)
            env = dict(
                os.environ,
                AWS_PROFILE=profile,
                AWS_DEFAULT_PROFILE=profile,
                AWS_REGION="us-east-1",
                LMAWS_LIVE="1",
                LMAWS_ENDPOINT=f"http://127.0.0.1:{server.server_port}",
                LMAWS_MAX_COST_USD="0.05",
                LMAWS_LEDGER_DIR=str(work / "ledgers"),
                LMAWS_EVIDENCE_DIR=str(work / "evidence"),
            )
            p = subprocess.run(
                ["java", "-jar", str(JAR), "--live", "--profile", profile, "--dsl", str(bc)],
                cwd=work,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
            )
            assert (p.returncode == 0) == expect_ok, (mode, p.returncode, p.stdout, p.stderr)
            return p, model
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    out_file = work / "out.json"
    batch_spec = json.dumps([
        {"id": "id", "kind": "identity_sanity", "target": "", "extra": ""},
        {"id": "own", "kind": "bucket_owner_sanity", "target": "synthetic-publish-bucket", "extra": ""},
        {"id": "meta", "kind": "bucket_metadata_sanity", "target": "synthetic-publish-bucket", "extra": ""},
        {"id": "put", "kind": "s3_put_if_match_wrong_etag", "target": "synthetic-publish-bucket/dataset/*", "extra": ""},
        {"id": "del", "kind": "s3_delete_nonexistent", "target": "synthetic-publish-bucket/dataset/*", "extra": "cafe01"},
        {"id": "acl", "kind": "s3_put_acl_nonexistent", "target": "synthetic-publish-bucket/dataset/*", "extra": "cafe01"},
        {"id": "sec", "kind": "secrets_get_nonexistent", "target": "__perm_check_nonexistent_cafe01", "extra": ""},
        {"id": "ssm", "kind": "ssm_get_nonexistent", "target": "/__perm_check_nonexistent_cafe01", "extra": ""},
        {"id": "cfneg", "kind": "cloudfront_invalidate_nonexistent_dist", "target": "E00000NONEXIST", "extra": "cafe01"},
        {"id": "cfopt", "kind": "cloudfront_invalidate_opt_in", "target": "E1SYNTHETIC123", "extra": "opt_in:cafe01"},
    ])
    _, model = run_dsl(
        "happy",
        f'let cloud = aws.region("us-east-1"); check(cloud.publish_grant_probe_kinds().len() == 10); let rows = cloud.publish_grant_probes({json.dumps(batch_spec)}); file_write({json.dumps(str(out_file))}, rows.json());',
    )
    rows = json.loads(out_file.read_text())
    assert len(rows) == 10 and all(r["status"] == "PASS" for r in rows), rows
    assert model.last_if_match == '"00000000000000000000000000000000"'

    # Wrongly-granted case: S3 PutObject returns 403 -> status must be FAIL
    run_dsl(
        "put_403",
        f'let cloud = aws.region("us-east-1"); let r = cloud.publish_grant_probe("s3_put_if_match_wrong_etag", "synthetic-publish-bucket/dataset/*", ""); check(r.get("status") == "FAIL" && r.get("http_status") == "403");',
    )

    # Non-403 DeleteObject (204) -> immediate FAIL and batch stop
    run_dsl(
        "delete_204",
        f'let cloud = aws.region("us-east-1"); let r = cloud.publish_grant_probe("s3_delete_nonexistent", "synthetic-publish-bucket/dataset/*", "cafe01"); check(r.get("status") == "FAIL" && r.get("stop_immediately") == "true");',
    )

    # Refuse unknown probe kinds and non-default profiles
    run_dsl("happy", 'let cloud = aws.region("us-east-1"); cloud.publish_grant_probe("unconditional_put", "b/k", "");', expect_ok=False)
    run_dsl("happy", 'let cloud = aws.region("us-east-1"); cloud.publish_grant_probe("identity_sanity", "", "");', profile="admin", expect_ok=False)

    print("PASS synthetic DSL publish grant probes: 10 safe kinds, conditional If-Match wire header, 403 PutObject failure detection, 204 DeleteObject immediate stop, and profile/kind refusals")
