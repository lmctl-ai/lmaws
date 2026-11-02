#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prove that `lmscript --dry-run` reaches lmaws as a dry invocation and makes
ZERO mutating provider requests: a loopback HTTP spy answers S3/SQS read routes
and records every request. A real run of the same program must attempt a
mutating PUT/POST/DELETE (control)."""
import http.server, json, os, subprocess, sys, tempfile, threading

LMSCRIPT, HOST, SCHEMA = sys.argv[1], sys.argv[2], sys.argv[3]
seen = []


class Spy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply_xml(self, status, xml_body):
        data = xml_body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", errors="replace") if n else ""
        target = self.headers.get("X-Amz-Target") or ""
        seen.append((self.command, self.path, target, body))
        if self.command in ("PUT", "DELETE"):
            return self.reply_xml(
                500,
                "<Error><Code>InternalError</Code><Message>spy refuses mutations</Message></Error>",
            )
        if self.command == "POST":
            if "GetQueueUrl" in target or "ListQueues" in target or "Action=GetQueueUrl" in body or "Action=ListQueues" in body:
                data = b'{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"spy: no queue"}'
                self.send_response(400)
                self.send_header("Content-Type", "application/x-amz-json-1.0")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            return self.reply_xml(
                500,
                "<ErrorResponse><Error><Code>InternalError</Code><Message>spy refuses mutations</Message></Error></ErrorResponse>",
            )
        return self.reply_xml(
            404,
            "<Error><Code>NoSuchBucket</Code><Message>spy: nothing exists</Message></Error>",
        )

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = handle_any


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Spy)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ep = f"http://127.0.0.1:{srv.server_address[1]}"
prog = f"""
s = load_schema(schema={json.dumps(SCHEMA)});
p = _lmcode_ s;
  cloud.set_endpoint("all", {json.dumps(ep)});
  let created = cloud.bucket_create("lmaws-dry-spy");
  let err_ok = cloud.last_error().code() == ErrorCode.OK;
  let m = cloud.object_put("lmaws-dry-spy", "k.txt", "payload", "text/plain", str_map().set("env", "dev"));
  let body = cloud.object_get("lmaws-dry-spy", "k.txt");
  cloud.object_delete("lmaws-dry-spy", "k.txt");
  let deleted = cloud.bucket_delete("lmaws-dry-spy");
  let qc = cloud.queue_create("lmaws-dry-spy-q");
  let id = cloud.queue_send("lmaws-dry-spy-q", "hello");
  let batch = cloud.queue_receive("lmaws-dry-spy-q", 1, 0, 30);
  let qd = cloud.queue_delete("lmaws-dry-spy-q");
  cloud.set_abort_on_error(false);
  cloud.object_get("lmaws-dry-spy-missing", "missing.txt");
  let err_nf = cloud.last_error().code() == ErrorCode.NOT_FOUND;
  lmcode_return_put("created", created);
  lmcode_return_put("err_ok", err_ok);
  lmcode_return_put("err_nf", err_nf);
  lmcode_return_put("body", body);
  lmcode_return_put("qc", qc);
  lmcode_return_put("n", batch.len());
end _lmcode_
r = run_lmcode(p, {{command:[{json.dumps(HOST)}, "cloud", "--lmcode", "$DSLFILE"]}});
assert(r.ok && r.result.err_ok && r.result.err_nf, "dry enum ErrorCode check failed");
println(json_stringify(r));
"""

def is_mutating(entry):
    method, _path, target, body = entry
    if method in ("PUT", "DELETE"):
        return True
    if method == "POST":
        return not ("GetQueueUrl" in target or "ListQueues" in target or "Action=GetQueueUrl" in body or "Action=ListQueues" in body)
    return False


with tempfile.TemporaryDirectory() as d:
    f = os.path.join(d, "dry.lms")
    open(f, "w").write(prog)
    dry = subprocess.run([LMSCRIPT, "--dry-run", f], capture_output=True, text=True, timeout=120)
    dry_seen = list(seen)
    del seen[:]
    real = subprocess.run([LMSCRIPT, f], capture_output=True, text=True, timeout=120)
    real_seen = list(seen)
srv.shutdown()

mut = [s for s in dry_seen if is_mutating(s)]
print(f"dry run: rc={dry.returncode} requests={len(dry_seen)} mutating={len(mut)}")
if (
    dry.returncode != 0
    or mut
    or not dry_seen
    or '"dry":true' not in dry.stdout
    or '"err_ok":true' not in dry.stdout
    or '"err_nf":true' not in dry.stdout
):
    print(dry.stdout, dry.stderr, dry_seen, file=sys.stderr)
    sys.exit("FAIL: dry run made mutating requests or did not reach the host in dry mode")
if not any(is_mutating(s) for s in real_seen):
    print(real.stdout, real.stderr, real_seen, file=sys.stderr)
    sys.exit("FAIL: control real run did not attempt a mutation (spy is blind)")
print(f"control real run attempted {sum(1 for s in real_seen if is_mutating(s))} mutating request(s)")
print("PASS: lmscript --dry-run made zero mutating AWS requests")
