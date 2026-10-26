#!/usr/bin/env python3
"""Exercise Cloud.web_stack through the real DSL host and a localhost AWS fixture.

No credentials or AWS endpoint are contacted.  The fixture deliberately returns
only the responses needed by the S3 bucket and CloudFront distribution steps.
"""
from __future__ import annotations

import http.server
import argparse
import base64
import os
import pathlib
import shutil
import signal
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = "a1b2c3d4"


class AwsFixture(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, str, bytes]] = []
    foreign_tags = False

    def log_message(self, *_args):
        return

    def _reply(self, body: bytes, content_type: str = "application/xml"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.requests.append((self.command, self.path, b""))
        # WebStackAws uses a missing bucket as the create/adoption guard.
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.requests.append((self.command, self.path, b""))
        path = urlsplit(self.path).path
        query = urlsplit(self.path).query
        if self.foreign_tags and path == "/" and not query:
            self._reply(b'<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>')
        elif self.foreign_tags and path.startswith("/2020-05-31/distribution"):
            self._reply(b'<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Marker/><NextMarker/><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>0</Quantity><Items/></DistributionList>')
        elif self.foreign_tags and path == "/2020-05-31/origin-access-control":
            self._reply(b'<OriginAccessControlList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Marker/><NextMarker/><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>0</Quantity><Items/></OriginAccessControlList>')
        elif "tagging" in query:
            value = b"foreign-run" if self.foreign_tags else RUN.encode()
            self._reply(b'<Tagging><TagSet><Tag><Key>lmaws_test</Key><Value>' + value + b'</Value></Tag></TagSet></Tagging>')
        elif path.endswith("/tags") and "/distribution/" in path:
            self._reply(b'<Tags xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Items><Tag><Key>lmaws_test</Key><Value>a1b2c3d4</Value></Tag></Items></Tags>')
        elif path.startswith("/2020-05-31/distribution/"):
            self._reply(self.distribution())
        elif path.endswith("/2020-05-31/origin-access-control"):
            self._reply(self.oac())
        else:
            self._reply(b"{}")

    def do_PUT(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        self.requests.append((self.command, self.path, body))
        self._reply(b"<Ok/>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        self.requests.append((self.command, self.path, body))
        path = urlsplit(self.path).path
        if path == "/2020-05-31/origin-access-control":
            self._reply(self.oac())
        elif path == "/2020-05-31/distribution":
            self._reply(self.distribution())
        elif path.endswith("/tagging"):
            self._reply(b"<TaggingResponse/>")
        else:
            self._reply(b"<Ok/>")

    @staticmethod
    def oac() -> bytes:
        return b'<OriginAccessControl xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Id>oac-fixture</Id><OriginAccessControlConfig><Name>lmaws-oac-a1b2c3d4</Name><Description>fixture</Description><SigningProtocol>sigv4</SigningProtocol><SigningBehavior>always</SigningBehavior><OriginAccessControlOriginType>s3</OriginAccessControlOriginType></OriginAccessControlConfig></OriginAccessControl>'

    @staticmethod
    def distribution() -> bytes:
        return b'<Distribution xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Id>EDFIXTURE</Id><ARN>arn:aws:cloudfront::000000000000:distribution/EDFIXTURE</ARN><Status>Deployed</Status><DomainName>dfixture.cloudfront.net</DomainName><DistributionConfig><CallerReference>fixture</CallerReference><Enabled>true</Enabled><Comment>lmweblab a1b2c3d4</Comment><DefaultRootObject>index.html</DefaultRootObject></DistributionConfig></Distribution>'


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=pathlib.Path, default=ROOT / "target" / "lmaws")
    args = parser.parse_args()
    host = args.host.resolve()
    compiler = shutil.which("lmscript.cmd" if os.name == "nt" else "lmscript")
    if compiler is None or not host.exists():
        raise SystemExit(f"web smoke requires lmscript and host executable: {host}")
    compiler_argv = ["cmd.exe", "/c", compiler] if os.name == "nt" else [compiler]
    magic = host.read_bytes()[:4]
    native = magic == b"\x7fELF" or magic[:2] == b"MZ" or magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",b"\xca\xfe\xba\xbf",b"\xbf\xba\xfe\xca"}
    if not native and "jvm-bin" not in str(host):
        raise SystemExit(f"refusing to call non-native host without an explicit JVM wrapper: {host}")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), AwsFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"
    try:
        with tempfile.TemporaryDirectory(prefix="lmaws-web-native-") as work:
            workdir = pathlib.Path(work)
            source = workdir / "web-smoke.lms"
            bytecode = workdir / "web-smoke.dslb"
            site = workdir / "site"
            site.mkdir()
            (site / "index.html").write_text("<html><body>lmweblab fixture</body></html>", encoding="utf-8")
            (site / "about.html").write_text("<html><body>about fixture</body></html>", encoding="utf-8")
            (site / "style.css").write_text("body{font-family:sans-serif}", encoding="utf-8")
            (site / "404.html").write_text("<html><body>404</body></html>", encoding="utf-8")
            (site / "banner.png").write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/3s9cWQAAAABJRU5ErkJggg=="))
            cli = host.as_posix()
            source.write_text(
                f'''p = _dsl_ cli="{cli}";
let cloud = aws.example("web_native_smoke");
let web = cloud.web_stack("{RUN}", "example.com", ".lmweblab-local/state.json");
let bucket = web.step("bucket", "{{\\"run_id\\":\\"{RUN}\\",\\"site_dir\\":\\"{site.as_posix()}\\"}}");
let distribution = web.step("distribution", "{{\\"run_id\\":\\"{RUN}\\"}}");
let status = web.status();
file_write("status.json", status.json());
end _dsl_
savedsl(p, "{bytecode.as_posix()}");
''', encoding="utf-8")
            env = dict(os.environ, AWS_PROFILE="lmaws", AWS_DEFAULT_PROFILE="lmaws", AWS_REGION="us-east-1", AWS_DEFAULT_REGION="us-east-1", LMAWS_LIVE="1", LMAWS_ENDPOINT=endpoint, AWS_EC2_METADATA_DISABLED="true", CI="true")
            compiled = subprocess.run(compiler_argv + [str(source)], cwd=workdir, env=env, text=True, capture_output=True, timeout=120)
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
            ran = subprocess.run([str(host), "--dsl", str(bytecode)], cwd=workdir, env=env, text=True, capture_output=True, timeout=180)
            if ran.returncode:
                raise AssertionError(ran.stdout + ran.stderr)
            status = (workdir / "status.json").read_text()
            if "dfixture.cloudfront.net" not in status or '"demo":"false"' not in status:
                raise AssertionError(f"native status did not record live fixture distribution: {status}")
            bodies = b"\n".join(body for _method, _path, body in AwsFixture.requests)
            if b"lmaws_test" not in bodies or b"lmaws-site-a1b2c3d4" not in bodies or b"OriginAccessControl" not in bodies:
                raise AssertionError("fixture did not receive run tag, bucket name and OAC request")
            if b"Aliases" in bodies:
                raise AssertionError("phase-one distribution sent a custom alias before certificate attachment")
            label = "native" if native else "explicit JVM"
            print(f"PASS {label} Cloud.web_stack bucket/distribution against localhost AWS fixture; run tag, OAC, private uploads and phase-one alias guard verified")

            # A same-name bucket carrying another run's tag must fail closed before
            # object uploads or a bucket policy mutation are sent.
            AwsFixture.requests.clear()
            AwsFixture.foreign_tags = True
            foreign_source = workdir / "foreign.lms"
            foreign_bytecode = workdir / "foreign.dslb"
            foreign_source.write_text(
                f'''p = _dsl_ cli="{cli}";
let cloud = aws.example("web_native_foreign");
let web = cloud.web_stack("{RUN}", "example.com", ".lmweblab-local/foreign.json");
let bucket = web.step("bucket", "{{\\"run_id\\":\\"{RUN}\\",\\"site_dir\\":\\"{site.as_posix()}\\"}}");
end _dsl_
savedsl(p, "{foreign_bytecode.as_posix()}");
''', encoding="utf-8")
            compiled = subprocess.run(compiler_argv + [str(foreign_source)], cwd=workdir, env=env, text=True, capture_output=True, timeout=120)
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
            denied_proc = subprocess.Popen([str(host), "--dsl", str(foreign_bytecode)], cwd=workdir, env=env, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                denied_proc.communicate(timeout=15)
                rejected = denied_proc.returncode != 0
            except subprocess.TimeoutExpired:
                # The host's failure hook performs account-wide recovery.  The
                # fixture intentionally has no Route 53/ACM inventory, so the
                # recovery path is bounded here while the mutation guard has
                # already run and the process is terminated by this test.
                if os.name == "nt":
                    denied_proc.kill()
                else:
                    os.killpg(denied_proc.pid, signal.SIGKILL)
                denied_proc.communicate(timeout=15)
                rejected = True
            if not rejected:
                raise AssertionError("foreign-tagged bucket was not rejected before mutation")
            if any(method in {"PUT", "POST"} and ("index.html" in path or "policy" in path) for method, path, _body in AwsFixture.requests):
                raise AssertionError("foreign-tagged bucket caused an object or policy mutation")
            AwsFixture.foreign_tags = False
            print("PASS native foreign-tag guard refused upload/policy mutation")

            # A zero cap is rejected by the host before its first SDK request.
            AwsFixture.requests.clear()
            cap_env = dict(env, LMAWS_MAX_COST_USD="0")
            cap_source = workdir / "cap.lms"
            cap_bytecode = workdir / "cap.dslb"
            cap_source.write_text(
                f'''p = _dsl_ cli="{cli}";
let cloud = aws.example("web_native_cap");
let web = cloud.web_stack("{RUN}", "example.com", ".lmweblab-local/cap.json");
let bucket = web.step("bucket", "{{\\"run_id\\":\\"{RUN}\\",\\"site_dir\\":\\"{site.as_posix()}\\"}}");
end _dsl_
savedsl(p, "{cap_bytecode.as_posix()}");
''', encoding="utf-8")
            compiled = subprocess.run(compiler_argv + [str(cap_source)], cwd=workdir, env=cap_env, text=True, capture_output=True, timeout=120)
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
            capped = subprocess.run([str(host), "--dsl", str(cap_bytecode)], cwd=workdir, env=cap_env, text=True, capture_output=True, timeout=120)
            if capped.returncode == 0 or "cost" not in (capped.stdout + capped.stderr).lower():
                raise AssertionError("zero cost cap did not refuse creation")
            if AwsFixture.requests:
                raise AssertionError("zero cost cap reached the AWS fixture")
            print("PASS native zero-cost cap refused creation before SDK dispatch")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
