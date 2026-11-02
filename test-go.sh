#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# test-go.sh — Verification gate for the Go port of lmaws (shared lmcloud schema, SIM/FAKE ONLY).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
LMCLOUD_DIR="${LMCLOUD_DIR:-/home/ubuntu/cloud/lmcloud}"
LMCLOUD_SIMS_DIR="${LMCLOUD_SIMS_DIR:-/home/ubuntu/cloud/lmcloud-sims}"
LMCLOUD_SIM_CACHE="${LMCLOUD_SIM_DIR:-$LMCLOUD_SIMS_DIR/.cache/sims}"
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
  if [[ -x "$LMCLOUD_SIMS_DIR/scripts/sim.sh" ]]; then
    LMCLOUD_SIM_DIR="$LMCLOUD_SIM_CACHE" "$LMCLOUD_SIMS_DIR/scripts/sim.sh" stop aws --name "$SIM_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "=== 1. Pin & schema lock verification ==="
test -f "$ROOT/sdk.lock"
test -f "$ROOT/lmcloud.lock"
"$ROOT/scripts/sync-lmcloud-schema.sh" --verify

echo "=== 2. Go vet & unit tests ==="
go vet ./...
go test -v ./...

echo "=== 3. Build Go host binary ==="
mkdir -p "$ROOT/bin"
CGO_ENABLED=0 go build -o "$BIN" ./cmd/lmaws
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

echo "=== 7. Dry & real run_lmcode smoke test ==="
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
r_dry = run_lmcode(p, {command:["'"$BIN"'", "--dry", "--lmcode", "$DSLFILE"]});
assert(r_dry.ok && r_dry.result.prov == "aws", "dry run smoke failed");
r_real = run_lmcode(p, {command:["'"$BIN"'", "--lmcode", "$DSLFILE"]});
assert(r_real.ok && r_real.result.prov == "aws" && r_real.result.c1 && !r_real.result.c2 && r_real.result.exists && r_real.result.d1, "real run smoke failed");
'

echo "=== 8. Memory budget exceeded exit 3 check ==="
set +e
LMAWS_MAX_MEMORY_MB=1 "$LMSCRIPT_BIN" -e '
p = _lmcode_ schema="schema/lmcloud.dsl.json";
  cloud.bucket_create("mem-budget-bucket");
  let s = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  let i = 0;
  while (i < 16) {
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

echo "=== 9. Conformance suite against awssim (object-storage + queue) ==="
ENDPOINT="$(LMCLOUD_SIM_DIR="$LMCLOUD_SIM_CACHE" "$LMCLOUD_SIMS_DIR/scripts/sim.sh" start aws --name "$SIM_NAME" --free-port)"
echo "awssim running at $ENDPOINT (name: $SIM_NAME)"

LMSCRIPT_BIN="$LMSCRIPT_BIN" "$LMCLOUD_DIR/tests/run-conformance.sh" "$BIN" "$ENDPOINT" object-storage
LMSCRIPT_BIN="$LMSCRIPT_BIN" "$LMCLOUD_DIR/tests/run-conformance.sh" "$BIN" "$ENDPOINT" queue

LMCLOUD_SIM_DIR="$LMCLOUD_SIM_CACHE" "$LMCLOUD_SIMS_DIR/scripts/sim.sh" stop aws --name "$SIM_NAME"

echo "=== 10. Enforced-auth (--auth enforce) verification for Scenarios 12 & 13 ==="
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
            "Resource": ["arn:aws:s3:::allowed-*", "arn:aws:sqs:*:000000000000:allowed-*"]
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
rm -rf "$ENFORCE_TMP"
ENFORCE_TMP=""

echo "=== ALL GO PORT CHECKS PASSED ==="
