#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test-go.sh — Verification gate for the Go port of lmaws (shared lmcloud schema, built on hostkit).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

unset LMAWS_LIVE LMCLOUD_ENDPOINT LMCLOUD_STORAGE_ENDPOINT LMCLOUD_QUEUE_ENDPOINT \
  LMAWS_ENDPOINT LMAWS_STORAGE_ENDPOINT LMAWS_QUEUE_ENDPOINT \
  AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3 AWS_ENDPOINT_URL_SQS

LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
LMCLOUD_DIR="${LMCLOUD_DIR:-/home/ubuntu/cloud/lmcloud}"
SIM_SH="${SIM_SH:-${LMCLOUD_DIR}/scripts/sim.sh}"
LMCLOUD_SIM_CACHE="${LMCLOUD_SIM_DIR:-${LMCLOUD_DIR}/.cache/sims}"
BIN="$ROOT/bin/lmaws"
SIM_NAME="lmaws-test-go-$$"
ENFORCE_PID=""
ENFORCE_TMP=""

cleanup() {
  if [[ -n "$ENFORCE_PID" ]]; then
    kill "$ENFORCE_PID" >/dev/null 2>&1 || true
    wait "$ENFORCE_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$ENFORCE_TMP" && -d "$ENFORCE_TMP" ]]; then
    rm -rf "$ENFORCE_TMP"
  fi
  if [[ -x "$SIM_SH" ]]; then
    LMCLOUD_SIM_DIR="$LMCLOUD_SIM_CACHE" "$SIM_SH" stop aws --name "$SIM_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "=== 1. Pin & schema lock verification ==="
test -f "$ROOT/sdk.lock"
test -f "$ROOT/lmcloud.lock"
grep -q "06cd9ae991d90fea9ad38f3b071da646c76832f4" "$ROOT/sdk.lock"
grep -q "06cd9ae991d9" "$ROOT/go.mod"
"$ROOT/scripts/sync-lmcloud-schema.sh" --verify

echo "=== 2. Go vet & unit tests (-race -count=3) ==="
go vet ./...
go test -race -count=3 ./...

echo "=== 3. Build Go host binary ==="
mkdir -p "$ROOT/bin"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/lmaws
test -x "$BIN"

echo "=== 4. Linkage check (system libraries only) ==="
if [[ "$(uname -s)" == "Linux" ]]; then
  if readelf -l "$BIN" 2>/dev/null | grep -q "INTERP"; then
    ldd_out="$(ldd "$BIN" 2>&1 || true)"
    echo "$ldd_out"
    if echo "$ldd_out" | grep -Evq '(linux-vdso|ld-linux|libc\.so|libpthread\.so|libdl\.so|libm\.so|librt\.so|libresolv\.so)'; then
      echo "ERROR: unexpected dynamic library linkage in $BIN" >&2
      exit 1
    fi
  else
    echo "Static ELF binary verified (no dynamic interpreter)."
  fi
fi

echo "=== 5. Schema byte parity & signature parity ==="
want_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$ROOT/lmcloud.lock")"
got_sha="$("$BIN" --lmcode-schema --json | sha256sum | awk '{print $1}')"
[[ "$got_sha" == "$want_sha" ]] || { echo "served schema sha256 $got_sha != lmcloud.lock $want_sha" >&2; exit 1; }
cmp -s <("$BIN" --lmcode-schema) "$ROOT/schema/lmcloud.dsl.json"
cmp -s <("$BIN" --lmcode-schema --json) "$ROOT/schema/lmcloud.dsl.json"
cmp -s <("$BIN" cloud --lmcode-schema --json) "$ROOT/schema/lmcloud.dsl.json"
diff -u <("$BIN" --lmcode-signatures) <("$LMSCRIPT_BIN" --lmcode-signatures "$ROOT/schema/lmcloud.dsl.json")
diff -u <("$BIN" --lmcode-signatures --without-std) <("$LMSCRIPT_BIN" --lmcode-signatures --without-std "$ROOT/schema/lmcloud.dsl.json")
diff -u <("$BIN" cloud --lmcode-signatures) <("$LMSCRIPT_BIN" --lmcode-signatures "$ROOT/schema/lmcloud.dsl.json")
diff -u <("$BIN" cloud --lmcode-signatures --without-std) <("$LMSCRIPT_BIN" --lmcode-signatures --without-std "$ROOT/schema/lmcloud.dsl.json")

echo "=== 6. Exit code & memory budget contract ==="
"$BIN" --version | grep -q "^lmaws "
"$BIN" --help | grep -q "Usage:"
"$BIN" --notices | grep -q "Third-Party Software Notices"
"$BIN" --sweep | grep -q '"ok":true'

set +e
"$BIN" --unknown-flag >/dev/null 2>&1
rc_unknown=$?
set -e
if [[ "$rc_unknown" -ne 2 ]]; then
  echo "ERROR: expected exit code 2 for unknown flag, got $rc_unknown" >&2
  exit 1
fi

corrupt_file="$(mktemp)"
printf 'NOT_LMCODE_BYTECODE' > "$corrupt_file"
set +e
"$BIN" --lmcode "$corrupt_file" >/dev/null 2>&1
rc_corrupt=$?
LMAWS_MAX_MEMORY_MB="invalid" "$BIN" --lmcode "$corrupt_file" >/dev/null 2>&1
rc_bad_mem=$?
set -e
rm -f "$corrupt_file"
if [[ "$rc_corrupt" -ne 3 ]]; then
  echo "ERROR: expected exit code 3 for corrupt bytecode, got $rc_corrupt" >&2
  exit 1
fi
if [[ "$rc_bad_mem" -ne 2 ]]; then
  echo "ERROR: expected exit code 2 for invalid LMAWS_MAX_MEMORY_MB, got $rc_bad_mem" >&2
  exit 1
fi

echo "=== 7. Dry & real run_lmcode smoke test + HTTP spy dry-run proof ==="
"$LMSCRIPT_BIN" -e '
p = _lmcode_ schema="schema/lmcloud.dsl.json";
  let prov = cloud.provider();
  let c1 = cloud.bucket_create("smoke-bucket-aws");
  let c2 = cloud.bucket_create("smoke-bucket-aws");
  let exists = cloud.bucket_exists("smoke-bucket-aws");
  let d1 = cloud.bucket_delete("smoke-bucket-aws");
  lmcode_return_put("prov", prov);
  lmcode_return_put("c1", c1);
  lmcode_return_put("c2", c2);
  lmcode_return_put("exists", exists);
  lmcode_return_put("d1", d1);
end _lmcode_
r_real = run_lmcode(p, {command:["'"$BIN"'", "--lmcode", "$DSLFILE"]});
assert(r_real.ok && r_real.result.prov == "aws" && r_real.result.c1 && !r_real.result.c2 && r_real.result.exists && r_real.result.d1, "real run smoke failed");
'
"$LMSCRIPT_BIN" --dry-run -e '
p = _lmcode_ schema="schema/lmcloud.dsl.json";
  let prov = cloud.provider();
  let c1 = cloud.bucket_create("smoke-bucket-aws");
  let ok_code = cloud.last_error().code() == ErrorCode.OK;
  let exists = cloud.bucket_exists("smoke-bucket-aws");
  let d1 = cloud.bucket_delete("smoke-bucket-aws");
  cloud.set_abort_on_error(false);
  cloud.object_get("smoke-bucket-aws-missing", "k");
  let nf_code = cloud.last_error().code() == ErrorCode.NOT_FOUND;
  lmcode_return_put("prov", prov);
  lmcode_return_put("c1", c1);
  lmcode_return_put("ok_code", ok_code);
  lmcode_return_put("nf_code", nf_code);
  lmcode_return_put("exists", exists);
  lmcode_return_put("d1", d1);
end _lmcode_
r_dry = run_lmcode(p, {command:["'"$BIN"'", "cloud", "--lmcode", "$DSLFILE"]});
assert(r_dry.ok && r_dry.dry && r_dry.result.prov == "aws" && r_dry.result.c1 && r_dry.result.ok_code && r_dry.result.nf_code && r_dry.result.exists && r_dry.result.d1, "dry run smoke failed");
'
python3 "$ROOT/scripts/test-dry-spy.py" "$LMSCRIPT_BIN" "$BIN" "$ROOT/schema/lmcloud.dsl.json"

echo "=== 8. Memory budget exceeded exit 3 check ==="
set +e
LMAWS_MAX_MEMORY_MB=1 "$LMSCRIPT_BIN" -e '
p = _lmcode_ schema="schema/lmcloud.dsl.json";
  cloud.bucket_create("mem-budget-bucket");
  let s = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let i = 0;
  while (i < 18) {
    s = s + s;
    i = i + 1;
  }
  cloud.object_put("mem-budget-bucket", "big.txt", s);
end _lmcode_
r = run_lmcode(p, {command:["'"$BIN"'", "--lmcode", "$DSLFILE"]});
assert(!r.ok, "expected memory budget failure");
'
rc_mem_prog=$?
set -e
if [[ "$rc_mem_prog" -ne 0 ]]; then
  echo "ERROR: memory budget assertion script failed with $rc_mem_prog" >&2
  exit 1
fi

echo "=== 9. Conformance suite against cached released awssim (object-storage + queue) ==="
ENDPOINT="$(LMCLOUD_SIM_DIR="$LMCLOUD_SIM_CACHE" "$SIM_SH" start aws --name "$SIM_NAME" --free-port)"
echo "awssim running at $ENDPOINT (name: $SIM_NAME)"

LMSCRIPT_BIN="$LMSCRIPT_BIN" "$LMCLOUD_DIR/tests/run-conformance.sh" "$BIN" "$ENDPOINT" object-storage
LMSCRIPT_BIN="$LMSCRIPT_BIN" "$LMCLOUD_DIR/tests/run-conformance.sh" "$BIN" "$ENDPOINT" queue

LMCLOUD_SIM_DIR="$LMCLOUD_SIM_CACHE" "$SIM_SH" stop aws --name "$SIM_NAME"

echo "=== 10. Enforced-auth (--auth enforce) verification on cached released awssim (middleware enabled) ==="
ENFORCE_TMP="$(mktemp -d)"
cat > "$ENFORCE_TMP/auth.json" <<EOF
{
  "credentials": [
    {
      "accessKeyId": "test",
      "secretAccessKey": "test",
      "policy": {
        "Statement": [
          {
            "Effect": "Allow",
            "Action": ["s3:*", "sqs:*"],
            "Resource": "*"
          },
          {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*denied*"
          }
        ]
      }
    }
  ]
}
EOF
ENFORCE_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
"$LMCLOUD_SIM_CACHE/awssim" serve --port "$ENFORCE_PORT" --auth enforce --auth-config "$ENFORCE_TMP/auth.json" >"$ENFORCE_TMP/sim.log" 2>&1 &
ENFORCE_PID=$!
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$ENFORCE_PORT/_floci/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
(
  export LMAWS_SIM_ACCESS_KEY_ID="test"
  export LMAWS_SIM_SECRET_ACCESS_KEY="test"
  cd "$LMCLOUD_DIR/tests/conformance/object-storage"
  "$LMSCRIPT_BIN" 12-auth-enforced-denial.lms "$BIN" "http://127.0.0.1:$ENFORCE_PORT" enforce
)
(
  export LMAWS_SIM_ACCESS_KEY_ID="test"
  export LMAWS_SIM_SECRET_ACCESS_KEY="test"
  cd "$LMCLOUD_DIR/tests/conformance/queue"
  "$LMSCRIPT_BIN" 13-queue-auth-enforced-denial.lms "$BIN" "http://127.0.0.1:$ENFORCE_PORT" enforce
)
kill "$ENFORCE_PID" >/dev/null 2>&1 || true
wait "$ENFORCE_PID" >/dev/null 2>&1 || true
ENFORCE_PID=""

AWSSIM_AUTH_JAR="${AWSSIM_AUTH_JAR:-/home/ubuntu/cloud/awssim/build/upstream-jvm/target/quarkus-app/quarkus-run.jar}"
AWSSIM_JAVA="${AWSSIM_JAVA:-}"
if [[ -z "$AWSSIM_JAVA" ]]; then
  if [[ -x "/home/ubuntu/tools/graalvm-community-openjdk-25.0.2+10.1/bin/java" ]]; then
    AWSSIM_JAVA="/home/ubuntu/tools/graalvm-community-openjdk-25.0.2+10.1/bin/java"
  else
    AWSSIM_JAVA="java"
  fi
fi
if [[ -f "$AWSSIM_AUTH_JAR" ]]; then
  echo "=== 11. Full conformance against fixed awssim JVM build in --auth enforce with LMAWS_COMPAT_STRIP_S3_XID=0 (0 skips) ==="
  ENFORCE_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  "$AWSSIM_JAVA" -jar "$AWSSIM_AUTH_JAR" serve --port "$ENFORCE_PORT" --auth enforce --auth-config "$ENFORCE_TMP/auth.json" >"$ENFORCE_TMP/jvm-sim.log" 2>&1 &
  ENFORCE_PID=$!
  for _ in $(seq 1 100); do
    if curl -fsS "http://127.0.0.1:$ENFORCE_PORT/_floci/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done
  OUT="$(
    export LMAWS_SIM_ACCESS_KEY_ID="test"
    export LMAWS_SIM_SECRET_ACCESS_KEY="test"
    export LMAWS_COMPAT_STRIP_S3_XID="0"
    LMSCRIPT_BIN="$LMSCRIPT_BIN" "$LMCLOUD_DIR/tests/run-conformance.sh" "$BIN" "http://127.0.0.1:$ENFORCE_PORT" all
  )"
  echo "$OUT"
  grep -q "pass 25 / 25, skip 0, fail 0" <<<"$OUT" || { echo "ERROR: enforced conformance did not pass 25/25 with 0 skips" >&2; exit 1; }
  kill "$ENFORCE_PID" >/dev/null 2>&1 || true
  wait "$ENFORCE_PID" >/dev/null 2>&1 || true
  ENFORCE_PID=""
fi

rm -rf "$ENFORCE_TMP"
ENFORCE_TMP=""

echo "=== ALL GO PORT CHECKS PASSED ==="
