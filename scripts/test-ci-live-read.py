#!/usr/bin/env python3
"""LMAWS_CI_LIVE_READ=1: in CI, read-only live checks only. Against a loopback fake endpoint (no AWS, no credentials).
Without the opt-in CI refuses as before; with it the cert-aws-checks reads work, and every write, an inventory listing,
IAM role access, the admin profile and live spend stay refused; a refused request never reaches the endpoint."""
import http.server, os, pathlib, subprocess, sys, tempfile, threading
ROOT = pathlib.Path(__file__).resolve().parents[1]
JAR = ROOT / "target" / "lmaws-0.1.27.jar"
class Fake(http.server.BaseHTTPRequestHandler):
    seen = []
    def log_message(self, *a): pass
    def handle_any(self):
        n = int(self.headers.get("content-length", "0")); body = self.rfile.read(n).decode("utf-8", "replace")
        target = self.headers.get("x-amz-target", "")
        op = target.rsplit(".", 1)[-1] if target else ("GetCallerIdentity" if "GetCallerIdentity" in body else f"{self.command} {self.path.split('?')[0]}")
        Fake.seen.append(op)
        if op == "GetCallerIdentity":
            out = b"<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000000</Account><Arn>arn:aws:sts::000000000000:assumed-role/lmaws-ci/x</Arn><UserId>X</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"
            self.send_response(200); self.send_header("content-type", "text/xml")
        elif op == "DescribeTable":
            out = b'{"Table":{"TableName":"lmaws-ci-read-check","TableStatus":"ACTIVE"}}'; self.send_response(200); self.send_header("content-type", "application/x-amz-json-1.0")
        elif self.command == "HEAD" and "lmaws-ci-read-write" in self.path:
            out = b""; self.send_response(404)   # the bucket to create does not exist yet, so the create path goes on to its write
        else:
            out = b""; self.send_response(200)
        self.send_header("content-length", str(len(out))); self.end_headers()
        if self.command != "HEAD": self.wfile.write(out)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = handle_any

def case(mode, **env):
    with tempfile.TemporaryDirectory(prefix="lmaws-ci-read-") as td:
        cfg = pathlib.Path(td) / "config"; cfg.write_text("")
        e = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "LMAWS_")) and k != "CI"}
        e.update(AWS_CONFIG_FILE=str(cfg), AWS_SHARED_CREDENTIALS_FILE=str(cfg), AWS_EC2_METADATA_DISABLED="true", AWS_REGION="us-east-1", LMAWS_FAST_WAITS="1")
        e.update({k: v for k, v in env.items() if v is not None})
        before = len(Fake.seen)
        r = subprocess.run(["java", "-cp", str(JAR), "ai.lmctl.lmaws.CiLiveReadChecks", mode], env=e, capture_output=True, text=True, timeout=120)
        line = (r.stdout.strip().splitlines() or [r.stderr.strip()[:200]])[-1]
        return line, Fake.seen[before:]

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake); threading.Thread(target=server.serve_forever, daemon=True).start()
fake = "http://127.0.0.1:%d" % server.server_port
fails = 0
def expect(name, got, ok):
    global fails
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got {got}")); fails += 0 if ok else 1
assert subprocess.run(["java", "-cp", str(JAR), "ai.lmctl.lmaws.CiLiveReadChecks"], capture_output=True, text=True, timeout=60).stdout.strip() == "PASS CiLiveReadChecks allowlist"
print("PASS C0 allowlist unit checks")
live = dict(AWS_PROFILE="default", LMAWS_LIVE="1")
line, _ = case("construct", CI="true", **live)
expect("C1 CI without the opt-in: live refused as before", line, line.startswith("REFUSED") and "disabled in CI" in line)
line, _ = case("construct", CI="true", LMAWS_CI_LIVE_READ="true", **live)
expect("C2 the opt-in takes only the value 1", line, line.startswith("REFUSED") and "disabled in CI" in line)
line, _ = case("construct", CI=None, **live, LMAWS_ENDPOINT=fake)
expect("C3 outside CI nothing changes (no read-only filter)", line, line == "OK constructed ciLiveRead=false")
line, seen = case("reads", CI="true", LMAWS_CI_LIVE_READ="1", LMAWS_ENDPOINT=fake, **live)
expect("C4 with the opt-in: identity, bucket and table checks work", (line, seen), line == "OK reads identity=1 bucket=true table=true" and seen == ["GetCallerIdentity", "HEAD /lmaws-ci-read-check", "DescribeTable"])
for mode, what, why in (("write", "a bucket create", "S3:CreateBucket is refused in CI"), ("list", "a bucket listing", "S3:ListBuckets is refused in CI"), ("iam", "IAM role access", "IAM role grants require")):
    line, seen = case(mode, CI="true", LMAWS_CI_LIVE_READ="1", LMAWS_ENDPOINT=fake, **live)
    expect(f"C5 with the opt-in {what} is refused ({why}) and never sent", (line, seen), line.startswith("REFUSED") and why in line and all(s == "GetCallerIdentity" or s.startswith("HEAD") or s == "DescribeTable" for s in seen))
line, seen = case("write", CI=None, LMAWS_ENDPOINT=fake, **live)
expect("C6 outside CI the same write still reaches the endpoint (unchanged)", (line, seen), any(s.startswith("PUT") for s in seen))
line, _ = case("construct", CI="true", LMAWS_CI_LIVE_READ="1", AWS_PROFILE="admin", LMAWS_LIVE="1")
expect("C7 with the opt-in the admin profile is refused", line, line.startswith("REFUSED") and "admin profile is refused" in line)
server.shutdown()
print(f"ci-live-read checks: {'PASS' if not fails else 'FAIL'} ({fails} failed)"); sys.exit(1 if fails else 0)
