#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# scripts/live-readonly.sh — Manual Stage 1 AWS Live Read-Only verification script.
#
# Gated by the double opt-in: LMCLOUD_LIVE=1 AND LMAWS_LIVE=1.
# Usage (operator manual run):
#   LMCLOUD_LIVE=1 LMAWS_LIVE=1 \
#   LMAWS_LIVE_ACCOUNT=254332045686 \
#   LMAWS_LIVE_REGION=us-east-1 \
#   ./scripts/live-readonly.sh
set -euo pipefail

if [[ "${LMCLOUD_LIVE:-}" != "1" || "${LMAWS_LIVE:-}" != "1" ]]; then
  echo "ERROR: scripts/live-readonly.sh requires double opt-in: LMCLOUD_LIVE=1 and LMAWS_LIVE=1" >&2
  echo "Usage: LMCLOUD_LIVE=1 LMAWS_LIVE=1 LMAWS_LIVE_ACCOUNT=254332045686 LMAWS_LIVE_REGION=us-east-1 $0" >&2
  exit 2
fi

export LMAWS_LIVE_ACCOUNT="${LMAWS_LIVE_ACCOUNT:-254332045686}"
export LMAWS_LIVE_REGION="${LMAWS_LIVE_REGION:-us-east-1}"

if [[ "$LMAWS_LIVE_ACCOUNT" != "254332045686" ]]; then
  echo "ERROR: LMAWS_LIVE_ACCOUNT must be 254332045686 (got: $LMAWS_LIVE_ACCOUNT)" >&2
  exit 2
fi
if [[ "$LMAWS_LIVE_REGION" != "us-east-1" ]]; then
  echo "ERROR: LMAWS_LIVE_REGION must be us-east-1 (got: $LMAWS_LIVE_REGION)" >&2
  exit 2
fi

# Endpoint overrides are forbidden in live mode.
unset LMCLOUD_ENDPOINT LMCLOUD_STORAGE_ENDPOINT LMCLOUD_QUEUE_ENDPOINT \
  LMAWS_ENDPOINT LMAWS_STORAGE_ENDPOINT LMAWS_QUEUE_ENDPOINT \
  AWS_ENDPOINT_URL AWS_ENDPOINT_URL_S3 AWS_ENDPOINT_URL_SQS AWS_ENDPOINT_URL_STS

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f /home/ubuntu/tools/env.sh ]]; then
  # shellcheck disable=SC1091
  source /home/ubuntu/tools/env.sh
fi

LMSCRIPT_BIN="${LMSCRIPT_BIN:-/home/ubuntu/lmctl-mono/lmscript/bin/lmscript}"
BIN="${LMAWS_BIN:-$ROOT/bin/lmaws}"

mkdir -p "$ROOT/bin"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/lmaws

JOURNAL_TMP="$(mktemp -d -t lmaws-live-readonly-XXXXXX)"
chmod 0700 "$JOURNAL_TMP"
trap 'rm -rf "$JOURNAL_TMP"' EXIT

RAND_HEX="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
export LMCLOUD_RUN_ID="run-$(date -u +%s)-${RAND_HEX}"
export LMAWS_LIVE_JOURNAL_DIR="$JOURNAL_TMP"
export PROBE_SUFFIX="$RAND_HEX"

echo "=== AWS Live Stage 1 (Read-Only) Verification ==="
echo "Account: $LMAWS_LIVE_ACCOUNT | Region: $LMAWS_LIVE_REGION | RunID: $LMCLOUD_RUN_ID"

"$LMSCRIPT_BIN" -e '
p = _lmcode_ schema="schema/lmcloud.dsl.json";
  cloud.set_abort_on_error(false);

  let prov = cloud.provider();

  // 1. bucket_list
  let buckets = cloud.bucket_list();
  let bucket_list_code = cloud.last_error().code();

  // 2. bucket_exists on a guaranteed non-existent probe name
  let missing_bucket = "lmcloud-conf-000000000000-readonly-probe";
  let missing_bkt_exists = cloud.bucket_exists(missing_bucket);
  let missing_bkt_code = cloud.last_error().code();

  // 3. object_list / object_list_all / object_head
  let obj_list_ok = false;
  let obj_list_all_ok = false;
  let obj_head_ok = false;
  if (len(buckets) > 0) {
    let b0 = buckets[0];
    let b0_exists = cloud.bucket_exists(b0);
    let b0_exists_ok = b0_exists && cloud.last_error().code() == ErrorCode.OK;

    let page = cloud.object_list(b0, "lmcloud-readonly-nonexistent-prefix-", 5);
    obj_list_ok = b0_exists_ok && cloud.last_error().code() == ErrorCode.OK && len(page.items()) == 0;

    let all_keys = cloud.object_list_all(b0, "lmcloud-readonly-nonexistent-prefix-");
    obj_list_all_ok = cloud.last_error().code() == ErrorCode.OK && len(all_keys) == 0;

    let hm = cloud.object_head(b0, "lmcloud-readonly-nonexistent-key");
    obj_head_ok = cloud.last_error().code() == ErrorCode.OK && !hm.exists();
  } else {
    let page = cloud.object_list(missing_bucket, "", 5);
    obj_list_ok = cloud.last_error().code() == ErrorCode.NOT_FOUND;

    let all_keys = cloud.object_list_all(missing_bucket, "");
    obj_list_all_ok = cloud.last_error().code() == ErrorCode.NOT_FOUND;

    let hm = cloud.object_head(missing_bucket, "k");
    obj_head_ok = cloud.last_error().code() == ErrorCode.NOT_FOUND && !hm.exists();
  }

  // 4. queue_list
  let queues = cloud.queue_list();
  let queue_list_code = cloud.last_error().code();

  // 5. queue_exists on a guaranteed non-existent probe name
  let missing_queue = "lmcloud-conf-000000000000-readonly-q";
  let missing_q_exists = cloud.queue_exists(missing_queue);
  let missing_q_code = cloud.last_error().code();

  // 6. Verify all mutating ops + object_get + queue_receive are refused in Stage 1
  cloud.bucket_create(missing_bucket);
  let mut_bkt_create_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.bucket_delete(missing_bucket);
  let mut_bkt_delete_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.object_put(missing_bucket, "k", "v");
  let mut_obj_put_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.object_delete(missing_bucket, "k");
  let mut_obj_delete_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.object_get(missing_bucket, "k");
  let mut_obj_get_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.queue_create(missing_queue);
  let mut_q_create_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.queue_delete(missing_queue);
  let mut_q_delete_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.queue_send(missing_queue, "hello");
  let mut_q_send_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.queue_receive(missing_queue, 1, 0, 30);
  let mut_q_recv_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.queue_ack(missing_queue, "rh-1");
  let mut_q_ack_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  cloud.queue_nack(missing_queue, "rh-1", 10);
  let mut_q_nack_denied = cloud.last_error().code() == ErrorCode.PERMISSION_DENIED && cloud.last_error().provider_code() == "LiveMutationDisabled";

  let all_mutations_denied = mut_bkt_create_denied && mut_bkt_delete_denied &&
    mut_obj_put_denied && mut_obj_delete_denied && mut_obj_get_denied &&
    mut_q_create_denied && mut_q_delete_denied && mut_q_send_denied &&
    mut_q_recv_denied && mut_q_ack_denied && mut_q_nack_denied;

  lmcode_return_put("prov", prov);
  lmcode_return_put("bucket_count", len(buckets));
  lmcode_return_put("bucket_list_ok", bucket_list_code == ErrorCode.OK);
  lmcode_return_put("missing_bkt_ok", !missing_bkt_exists && missing_bkt_code == ErrorCode.OK);
  lmcode_return_put("obj_list_ok", obj_list_ok);
  lmcode_return_put("obj_list_all_ok", obj_list_all_ok);
  lmcode_return_put("obj_head_ok", obj_head_ok);
  lmcode_return_put("queue_count", len(queues));
  lmcode_return_put("queue_list_ok", queue_list_code == ErrorCode.OK);
  lmcode_return_put("missing_q_ok", !missing_q_exists && missing_q_code == ErrorCode.OK);
  lmcode_return_put("all_mutations_denied", all_mutations_denied);
end _lmcode_

r = run_lmcode(p, {command:["'"$BIN"'", "--lmcode", "$DSLFILE"]});
println("Result: " + str(r.result));
assert(r.ok, "live read-only invocation failed: " + str(r));
assert(r.result.prov == "aws", "expected provider aws");
assert(r.result.bucket_list_ok, "bucket_list failed");
assert(r.result.missing_bkt_ok, "bucket_exists on missing bucket failed");
assert(r.result.obj_list_ok, "object_list check failed");
assert(r.result.obj_list_all_ok, "object_list_all check failed");
assert(r.result.obj_head_ok, "object_head check failed");
assert(r.result.queue_list_ok, "queue_list failed");
assert(r.result.missing_q_ok, "queue_exists on missing queue failed");
assert(r.result.all_mutations_denied, "one or more mutating ops were not denied with LiveMutationDisabled");
'

JOURNAL_FILE="$JOURNAL_TMP/$LMCLOUD_RUN_ID.jsonl"
test -f "$JOURNAL_FILE"
python3 - "$JOURNAL_FILE" <<'PY'
import json, sys
path = sys.argv[1]
charged_nano = 0
events = 0
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        rec = json.loads(line)
        events += 1
        if rec.get("event") in ("settle", "cost", "confirmed", "failed"):
            charged_nano += int(rec.get("charged_nano_usd", 0))
print(f"Journal verified: {events} records, total metered spend = {charged_nano} nano-USD (${charged_nano / 1e9:.9f} USD)")
assert charged_nano > 0, "expected positive metered spend for read-only calls"
assert charged_nano <= 50_000_000, "metered spend exceeded $0.05 default cap"
PY

echo "=== AWS LIVE READ-ONLY STAGE 1 VERIFICATION PASSED ==="
