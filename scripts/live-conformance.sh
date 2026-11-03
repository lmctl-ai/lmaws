#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# live-conformance.sh — Run the 23 non-auth lmcloud conformance scenarios
# against real AWS S3 and SQS in us-east-1 (account 254332045686) under
# hostkit/safety LiveGuard with unique lmcloud-conf-<run12>-<rand8>- names and
# mandatory LIFO sweeper teardown on exit.
#
# Runner-loss & sweeper recovery notes:
#   - Even if the local journal directory ($LMAWS_LIVE_JOURNAL_DIR) is lost
#     due to catastrophic runner termination, running:
#       LMCLOUD_LIVE=1 LMAWS_LIVE=1 LMAWS_LIVE_MUTATE=1 lmaws --sweep --apply <RUN_ID>
#     recovers and sweeps leftovers by scanning prefix `lmcloud-conf-<run12>-`
#     and verifying remote ownership tags (`lmcloud-owner=conformance`,
#     `lmcloud-run=<RUN_ID>`, `lmcloud_run_id=<RUN_ID>`, non-empty nonce &
#     create token, and `lmcloud_created_at >= <run_start_epoch>`).
#   - Residual risk: S3 `CreateBucket` does not support atomic creation-time
#     tags. If a runner is killed in the narrow window after `CreateBucket`
#     succeeds and before `PutBucketTagging` completes, the resulting untagged
#     bucket is intentionally retained (`retained > 0`, exit code 1) rather than
#     deleted without tag proof, and must be inspected/removed manually.
#
# Usage:
#   ./scripts/live-conformance.sh --check
#   LMCLOUD_LIVE=1 LMAWS_LIVE=1 LMAWS_LIVE_MUTATE=1 ./scripts/live-conformance.sh [all|object-storage|queue] [RUN_ID]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LMCLOUD_DIR="${LMCLOUD_DIR:-/home/ubuntu/cloud/lmcloud}"
if [[ ! -d "$LMCLOUD_DIR/tests/conformance" && -d "$ROOT/../lmcloud/tests/conformance" ]]; then
  LMCLOUD_DIR="$(cd "$ROOT/../lmcloud" && pwd)"
fi
CONFORMANCE_SH="$LMCLOUD_DIR/tests/run-conformance.sh"
BIN="${LMAWS_BIN:-$ROOT/bin/lmaws}"

if [[ ! -x "$CONFORMANCE_SH" ]]; then
  echo "ERROR: conformance runner not found at $CONFORMANCE_SH (set LMCLOUD_DIR)" >&2
  exit 2
fi

if [[ "${1:-}" == "--check" ]]; then
  mkdir -p "$(dirname "$BIN")"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/lmaws
  grep -q "LMAWS_LIVE_MUTATE=1" <<<"$("$BIN" --help)"
  grep -q "\-\-sweep" <<<"$("$BIN" --help)"
  "$CONFORMANCE_SH" --live --check
  exit 0
fi

SUITE="${1:-all}"
ARG_RUN_ID="${2:-}"

if [[ "${LMCLOUD_LIVE:-}" != "1" || "${LMAWS_LIVE:-}" != "1" || "${LMAWS_LIVE_MUTATE:-}" != "1" ]]; then
  echo "ERROR: live conformance requires triple opt-in: LMCLOUD_LIVE=1 LMAWS_LIVE=1 LMAWS_LIVE_MUTATE=1" >&2
  exit 2
fi

export LMCLOUD_LIVE=1
export LMAWS_LIVE=1
export LMAWS_LIVE_MUTATE=1
export LMAWS_LIVE_ACCOUNT="${LMAWS_LIVE_ACCOUNT:-254332045686}"
export LMAWS_LIVE_REGION="${LMAWS_LIVE_REGION:-us-east-1}"
export LMAWS_LIVE_COST_CAP_USD="${LMAWS_LIVE_COST_CAP_USD:-0.05}"
export LMAWS_LIVE_MAX_BUCKETS="${LMAWS_LIVE_MAX_BUCKETS:-16}"
export LMAWS_LIVE_MAX_QUEUES="${LMAWS_LIVE_MAX_QUEUES:-16}"

if [[ -n "$ARG_RUN_ID" ]]; then
  RUN_ID="$ARG_RUN_ID"
elif [[ -n "${LMAWS_RUN_ID:-}" ]]; then
  RUN_ID="$LMAWS_RUN_ID"
else
  RAND_HEX="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  RUN_ID="run-$(date -u +%s)-${RAND_HEX}"
fi

RUN_NONCE="$(printf '%s' "${RUN_ID##*-}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-f0-9' | cut -c1-12)"
if [[ "${#RUN_NONCE}" -lt 6 ]]; then
  echo "ERROR: RUN_ID '$RUN_ID' must end with at least 6 hex chars (e.g. run-<epoch>-<12hex>)" >&2
  exit 2
fi

RAND_SUFFIX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
export LMAWS_RUN_ID="$RUN_ID"
export LMCLOUD_RUN_ID="$RUN_ID"
export LMCLOUD_NAME_PREFIX="lmcloud-conf-${RUN_NONCE}-${RAND_SUFFIX}-"

if [[ -z "${LMAWS_LIVE_JOURNAL_DIR:-}" ]]; then
  LMAWS_LIVE_JOURNAL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lmaws-live-journal.XXXXXX")"
fi
mkdir -p "$LMAWS_LIVE_JOURNAL_DIR"
chmod 0700 "$LMAWS_LIVE_JOURNAL_DIR"
export LMAWS_LIVE_JOURNAL_DIR
export LMCLOUD_LIVE_JOURNAL_DIR="$LMAWS_LIVE_JOURNAL_DIR"

mkdir -p "$(dirname "$BIN")"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/lmaws

SWEEP_DONE=0
sweep_on_exit() {
  local rc=$?
  if [[ "$SWEEP_DONE" -eq 0 && -x "$BIN" ]]; then
    echo "=== Running mandatory exit LIFO sweep for $RUN_ID ==="
    "$BIN" --sweep --apply --journal-dir "$LMAWS_LIVE_JOURNAL_DIR" "$RUN_ID" || true
  fi
  exit "$rc"
}
trap sweep_on_exit EXIT

echo "=== Live AWS Conformance Stage 2 ==="
echo "  account:     $LMAWS_LIVE_ACCOUNT"
echo "  region:      $LMAWS_LIVE_REGION"
echo "  run_id:      $RUN_ID"
echo "  name_prefix: $LMCLOUD_NAME_PREFIX"
echo "  cost_cap:    \$$LMAWS_LIVE_COST_CAP_USD"
echo "  journal_dir: $LMAWS_LIVE_JOURNAL_DIR"

"$CONFORMANCE_SH" --live --name-prefix "$LMCLOUD_NAME_PREFIX" "$BIN" "" "$SUITE" "$RUN_ID"

echo "=== Running post-campaign LIFO sweep for $RUN_ID ==="
"$BIN" --sweep --apply --journal-dir "$LMAWS_LIVE_JOURNAL_DIR" "$RUN_ID"
SWEEP_DONE=1
