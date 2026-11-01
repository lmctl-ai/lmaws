#!/usr/bin/env python3
"""CI live reads: LMAWS_OIDC_ALLOWED_ROLE. Against a loopback fake endpoint (no AWS, no real credentials).
Without the allowlist CI refuses as before. With it (the OIDC mode) the credentials come from the OIDC source only:
(environment keys as exported by aws-actions/configure-aws-credentials, or a web identity token file + AWS_ROLE_ARN,
GitHub OIDC), the caller must be an allowed role, and only the read checks run: writes, a listing, IAM role access,
the admin profile and a caller or AWS_ROLE_ARN outside the allowlist stay refused; a refused request is never sent."""
import http.server, os, pathlib, re, subprocess, sys, tempfile, threading, urllib.parse
ROOT = pathlib.Path(__file__).resolve().parents[1]
JAR = ROOT / "target" / "lmaws-0.1.27.jar"
ACCOUNT, ROLE = "000000000000", "lmaws-ci"
ALLOWED = f"arn:aws:iam::{ACCOUNT}:role/{ROLE}"
class Fake(http.server.BaseHTTPRequestHandler):
    seen = []; caller_role = ROLE
    def log_message(self, *a): pass
    def handle_any(self):
        n = int(self.headers.get("content-length", "0")); body = self.rfile.read(n).decode("utf-8", "replace")
        target = self.headers.get("x-amz-target", ""); q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        action = urllib.parse.parse_qs(body).get("Action", q.get("Action", [""]))[0]
        op = target.rsplit(".", 1)[-1] if target else (action or f"{self.command} {self.path.split('?')[0]}")
        key = (re.search(r"Credential=([A-Z0-9]+)/", self.headers.get("authorization", "")) or [None, None])[1]
        Fake.seen.append((op, key))
        status, ctype, out = 200, "text/xml", b""
        if op == "GetCallerIdentity":
            out = f"<GetCallerIdentityResponse><GetCallerIdentityResult><Account>{ACCOUNT}</Account><Arn>arn:aws:sts::{ACCOUNT}:assumed-role/{Fake.caller_role}/run-1</Arn><UserId>X</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>".encode()
        elif op == "AssumeRoleWithWebIdentity":   # the SDK's own web identity provider (GitHub OIDC path)
            out = (f"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAWEBIDENTITY</AccessKeyId>"
                   f"<SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>"
                   f"<AssumedRoleUser><Arn>arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/gh</Arn><AssumedRoleId>X:gh</AssumedRoleId></AssumedRoleUser>"
                   f"</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>").encode()
        elif op == "DescribeTable":
            ctype, out = "application/x-amz-json-1.0", b'{"Table":{"TableName":"lmaws-ci-read-check","TableStatus":"ACTIVE"}}'
        elif self.command == "HEAD" and "lmaws-ci-read-write" in self.path:
            status = 404   # the bucket to create does not exist yet, so the create path goes on to its write
        self.send_response(status); self.send_header("content-type", ctype); self.send_header("content-length", str(len(out))); self.end_headers()
        if self.command != "HEAD": self.wfile.write(out)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_any

def case(mode, **env):
    with tempfile.TemporaryDirectory(prefix="lmaws-ci-read-") as td:
        cfg = pathlib.Path(td) / "config"; cfg.write_text("")
        tok = pathlib.Path(td) / "token"; tok.write_text("eyJ.fake-oidc-token.sig")
        e = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "LMAWS_")) and k != "CI"}
        e.update(AWS_CONFIG_FILE=str(cfg), AWS_SHARED_CREDENTIALS_FILE=str(cfg), AWS_EC2_METADATA_DISABLED="true", AWS_REGION="us-east-1", LMAWS_FAST_WAITS="1")
        if env.pop("PROFILE_FILE_CREDS", None):   # keys only in a shared credentials file (profile default)
            cred = pathlib.Path(td) / "credentials"; cred.write_text("[default]\naws_access_key_id = AKIAPROFILEFILE\naws_secret_access_key = s\n"); env["AWS_SHARED_CREDENTIALS_FILE"] = str(cred)
        e.update({k: (str(tok) if v == "TOKEN" else v) for k, v in env.items() if v is not None})
        before = len(Fake.seen)
        r = subprocess.run(["java", "-cp", str(JAR), "ai.lmctl.lmaws.CiLiveReadChecks", mode], env=e, capture_output=True, text=True, timeout=120)
        line = (r.stdout.strip().splitlines() or [r.stderr.strip()[:300]])[-1]
        return line, Fake.seen[before:]

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake); threading.Thread(target=server.serve_forever, daemon=True).start()
fake = "http://127.0.0.1:%d" % server.server_port
READS = ["GetCallerIdentity", "HEAD /lmaws-ci-read-check", "DescribeTable"]
fails = 0
def expect(name, got, ok):
    global fails
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got {got}")); fails += 0 if ok else 1
assert subprocess.run(["java", "-cp", str(JAR), "ai.lmctl.lmaws.CiLiveReadChecks"], capture_output=True, text=True, timeout=60).stdout.strip() == "PASS CiLiveReadChecks allowlist"
print("PASS C0 allowlist and caller-matching unit checks")
live = dict(AWS_PROFILE="default", LMAWS_LIVE="1")
ci = dict(CI="true", LMAWS_OIDC_ALLOWED_ROLE=ALLOWED, LMAWS_ENDPOINT=fake, **live)
line, _ = case("construct", CI="true", **live)
expect("C1 CI without the allowlist: live refused as before", line, line.startswith("REFUSED") and "disabled in CI" in line)
line, seen = case("construct", CI="true", LMAWS_OIDC_ALLOWED_ROLE="*", LMAWS_ENDPOINT=fake, **live)
expect("C2 an allowlist entry that is not a role ARN is refused, nothing sent", (line, seen), line.startswith("REFUSED") and "must list IAM role ARNs" in line and not seen)
line, _ = case("construct", CI=None, **live, LMAWS_ENDPOINT=fake)
expect("C3 outside CI nothing changes (no read-only filter)", line, line == "OK constructed ciLiveRead=false")
line, seen = case("reads", **ci)
expect("C4 CI, allowed role: identity, bucket and table checks work", (line, seen), line == "OK reads identity=1 bucket=true table=true" and [s[0] for s in seen] == ["GetCallerIdentity"] + READS)
for mode, what, why in (("write", "a bucket create", "S3:CreateBucket is refused in CI"), ("list", "a bucket listing", "S3:ListBuckets is refused in CI"), ("iam", "IAM role access", "IAM role grants require")):
    line, seen = case(mode, **ci)
    expect(f"C5 CI, allowed role: {what} is refused ({why}) and never sent", (line, seen), line.startswith("REFUSED") and why in line and all(s[0] == "GetCallerIdentity" or s[0].startswith("HEAD") or s[0] == "DescribeTable" for s in seen))
line, seen = case("write", CI=None, LMAWS_ENDPOINT=fake, **live)
expect("C6 outside CI the same write still reaches the endpoint (unchanged)", (line, seen), any(s[0].startswith("PUT") for s in seen))
line, seen = case("construct", **{**ci, "AWS_PROFILE": "admin"})
expect("C7 CI, allowlist set: the admin profile is refused, nothing sent", (line, seen), line.startswith("REFUSED") and "admin profile is refused" in line and not seen)
Fake.caller_role = "someone-else"
line, seen = case("reads", **ci)
expect("C8 CI: a caller outside the allowlist is refused after GetCallerIdentity only", (line, seen), line.startswith("REFUSED") and "caller's role is not in" in line and [s[0] for s in seen] == ["GetCallerIdentity"])
Fake.caller_role = ROLE
line, seen = case("construct", **ci, AWS_ROLE_ARN=f"arn:aws:iam::{ACCOUNT}:role/someone-else")
expect("C9 CI: AWS_ROLE_ARN outside the allowlist is refused before any request", (line, seen), line.startswith("REFUSED") and "AWS_ROLE_ARN is not in" in line and not seen)
# the SDK's DefaultCredentialsProvider (no LMAWS_ENDPOINT: the live path; AWS_ENDPOINT_URL points the SDK at the fake)
sdk = dict(CI="true", LMAWS_OIDC_ALLOWED_ROLE=ALLOWED, AWS_ENDPOINT_URL=fake, **live)
line, seen = case("reads", **sdk, AWS_ACCESS_KEY_ID="AKIAENVCREDS", AWS_SECRET_ACCESS_KEY="s", AWS_SESSION_TOKEN="t")
expect("C10 CI: environment credentials (configure-aws-credentials) as the OIDC source (no profile) sign every read", (line, seen), line == "OK reads identity=1 bucket=true table=true" and [s[0] for s in seen] == ["GetCallerIdentity"] + READS and all(s[1] == "AKIAENVCREDS" for s in seen))
line, seen = case("reads", **sdk, AWS_WEB_IDENTITY_TOKEN_FILE="TOKEN", AWS_ROLE_ARN=ALLOWED, AWS_ROLE_SESSION_NAME="gh")
expect("C11 CI: GitHub OIDC (web identity token file + AWS_ROLE_ARN) as the OIDC source", (line, seen), line == "OK reads identity=1 bucket=true table=true" and seen[0][0] == "AssumeRoleWithWebIdentity" and [s[0] for s in seen[1:]] == ["GetCallerIdentity"] + READS and all(s[1] == "ASIAWEBIDENTITY" for s in seen[1:]))
line, seen = case("write", **{**sdk, "AWS_PROFILE": "lmaws"}, AWS_ACCESS_KEY_ID="AKIAENVCREDS", AWS_SECRET_ACCESS_KEY="s")
expect("C12 CI, OIDC source, mutation profile: the write reaches the CI filter, is refused and never sent", (line, seen), line.startswith("REFUSED") and "S3:CreateBucket is refused in CI" in line and not any(s[0].startswith("PUT") for s in seen))
line, seen = case("reads", **sdk, PROFILE_FILE_CREDS="1")
expect("C13 CI, OIDC mode: credentials only in a profile file are NOT used (OIDC source only), nothing signed is sent", (line, seen), line.startswith("REFUSED") and not any(s[1] == "AKIAPROFILEFILE" for s in seen))
server.shutdown()
print(f"ci-live-read checks: {'PASS' if not fails else 'FAIL'} ({fails} failed)"); sys.exit(1 if fails else 0)
