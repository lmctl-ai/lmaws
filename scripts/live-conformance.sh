#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# live-conformance.sh — Run the 23 non-auth lmcloud conformance scenarios
# against real AWS S3 and SQS in us-east-1 (account 254332045686) under
# hostkit/safety LiveGuard.
#
# Per-scenario campaign architecture:
#   - Each scenario runs as its own isolated campaign with a fresh RUN_ID
#     (`run-<epoch>-<12hex>`), fresh 80-bit random name prefix
#     (`lmcloud-conf-<run12>-<rand8>-`), its own journal file
#     (`$LMAWS_LIVE_JOURNAL_DIR/<RUN_ID>.jsonl`), its own resource limits
#     (`LMAWS_LIVE_MAX_BUCKETS=4`, `LMAWS_LIVE_MAX_QUEUES=4`) and cost cap,
#     and its own immediate `lmaws --sweep --apply` after the scenario (even
#     if the scenario fails).
#   - A global spend guard sums `charged_nano_usd` across all per-scenario
#     journals created by this invocation and aborts remaining scenarios if
#     cumulative spend reaches the $0.25 (`250,000,000` nano-USD) hard ceiling.
#   - Final cleanup and the EXIT trap sweep ONLY the run IDs created by this
#     invocation (never `--all-stale`).
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
#   ./scripts/live-conformance.sh --check [all|object-storage|queue]
#   LMCLOUD_LIVE=1 LMAWS_LIVE=1 LMAWS_LIVE_MUTATE=1 ./scripts/live-conformance.sh [all|object-storage|queue]
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
  CHECK_SUITE="${2:-all}"
  mkdir -p "$(dirname "$BIN")"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/lmaws
  grep -q "LMAWS_LIVE_MUTATE=1" <<<"$("$BIN" --help)"
  grep -q "\-\-sweep" <<<"$("$BIN" --help)"
  "$CONFORMANCE_SH" --live --check "$CHECK_SUITE"
  exit 0
fi

SUITE="${1:-all}"

if [[ "${LMCLOUD_LIVE:-}" != "1" || "${LMAWS_LIVE:-}" != "1" || "${LMAWS_LIVE_MUTATE:-}" != "1" ]]; then
  echo "ERROR: live conformance requires triple opt-in: LMCLOUD_LIVE=1 LMAWS_LIVE=1 LMAWS_LIVE_MUTATE=1" >&2
  exit 2
fi

# Validate suite and collect the scenario list from run-conformance.sh --live --check.
CHECK_OUT="$("$CONFORMANCE_SH" --live --check "$SUITE")"
SCENARIOS=()
while IFS= read -r line; do
  if [[ "$line" =~ ^ok[[:space:]]+[0-9]+[[:space:]]+-[[:space:]]+(\[check\][[:space:]]+)?([^[:space:]]+)[[:space:]]+\((--check|syntax[[:space:]]+OK)\)$ ]]; then
    SCENARIOS+=("${BASH_REMATCH[2]}")
  fi
done <<<"$CHECK_OUT"

total="${#SCENARIOS[@]}"
if [[ "$total" -eq 0 ]]; then
  echo "ERROR: no live conformance scenarios discovered for suite '$SUITE'" >&2
  exit 2
fi

export LMCLOUD_LIVE=1
export LMAWS_LIVE=1
export LMAWS_LIVE_MUTATE=1
export LMAWS_LIVE_ACCOUNT="${LMAWS_LIVE_ACCOUNT:-254332045686}"
export LMAWS_LIVE_REGION="${LMAWS_LIVE_REGION:-us-east-1}"
export LMAWS_LIVE_COST_CAP_USD="${LMAWS_LIVE_COST_CAP_USD:-0.05}"
export LMAWS_LIVE_MAX_BUCKETS="${LMAWS_LIVE_MAX_BUCKETS:-4}"
export LMAWS_LIVE_MAX_QUEUES="${LMAWS_LIVE_MAX_QUEUES:-4}"

if [[ -z "${LMAWS_LIVE_JOURNAL_DIR:-}" ]]; then
  LMAWS_LIVE_JOURNAL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lmaws-live-journal.XXXXXX")"
fi
mkdir -p "$LMAWS_LIVE_JOURNAL_DIR"
chmod 0700 "$LMAWS_LIVE_JOURNAL_DIR"
export LMAWS_LIVE_JOURNAL_DIR
export LMCLOUD_LIVE_JOURNAL_DIR="$LMAWS_LIVE_JOURNAL_DIR"

if [[ -z "${LMAWS_BIN:-}" || ! -x "$BIN" ]]; then
  mkdir -p "$(dirname "$BIN")"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/lmaws
fi

CREATED_RUN_IDS=()
CREATED_RUN_IDS_FILE="$LMAWS_LIVE_JOURNAL_DIR/created-run-ids.txt"
: > "$CREATED_RUN_IDS_FILE"
chmod 0600 "$CREATED_RUN_IDS_FILE"

HARD_CEILING_NANO_USD=250000000
TOTAL_SPEND_NANO_USD=0

# sum_created_journals_nano_usd sums all charged_nano_usd entries across the
# per-scenario journal files created by this invocation.
sum_created_journals_nano_usd() {
  local sum=0
  local rid jfile val
  for rid in "${CREATED_RUN_IDS[@]}"; do
    jfile="$LMAWS_LIVE_JOURNAL_DIR/${rid}.jsonl"
    if [[ -f "$jfile" ]]; then
      while IFS= read -r val; do
        if [[ -n "$val" ]]; then
          sum=$((sum + val))
        fi
      done < <(grep -o '"charged_nano_usd":[0-9]*' "$jfile" 2>/dev/null | cut -d: -f2 || true)
    fi
  done
  printf '%s\n' "$sum"
}

FINAL_SWEEP_DONE=0
sweep_on_exit() {
  local rc=$?
  if [[ "$FINAL_SWEEP_DONE" -eq 0 && -x "$BIN" && "${#CREATED_RUN_IDS[@]}" -gt 0 ]]; then
    echo "=== Running mandatory exit LIFO sweep for created runs: ${CREATED_RUN_IDS[*]} ===" >&2
    "$BIN" --sweep --apply --journal-dir "$LMAWS_LIVE_JOURNAL_DIR" "${CREATED_RUN_IDS[@]}" || true
  fi
  exit "$rc"
}
trap sweep_on_exit EXIT

echo "=== Live AWS Conformance Stage 2 (per-scenario campaigns) ==="
echo "  account:       $LMAWS_LIVE_ACCOUNT"
echo "  region:        $LMAWS_LIVE_REGION"
echo "  suite:         $SUITE ($total scenarios)"
echo "  per_scen_cap:  \$$LMAWS_LIVE_COST_CAP_USD (global hard ceiling: \$0.25)"
echo "  max_buckets:   $LMAWS_LIVE_MAX_BUCKETS"
echo "  max_queues:    $LMAWS_LIVE_MAX_QUEUES"
echo "  journal_dir:   $LMAWS_LIVE_JOURNAL_DIR"
echo "1..$total"

pass=0
fail=0
skip=0
idx=0

for scen in "${SCENARIOS[@]}"; do
  idx=$((idx + 1))

  journal_sum="$(sum_created_journals_nano_usd)"
  if [[ "$journal_sum" -gt "$TOTAL_SPEND_NANO_USD" ]]; then
    TOTAL_SPEND_NANO_USD="$journal_sum"
  fi
  if [[ "$TOTAL_SPEND_NANO_USD" -ge "$HARD_CEILING_NANO_USD" ]]; then
    echo "not ok $idx - $scen # ABORTED: cumulative spend (${TOTAL_SPEND_NANO_USD} nano-USD) reached \$0.25 hard ceiling"
    fail=$((fail + 1))
    while [[ "$idx" -lt "$total" ]]; do
      idx=$((idx + 1))
      rem_scen="${SCENARIOS[$((idx - 1))]}"
      echo "not ok $idx - $rem_scen # ABORTED: cumulative spend (${TOTAL_SPEND_NANO_USD} nano-USD) reached \$0.25 hard ceiling"
      fail=$((fail + 1))
    done
    break
  fi

  SCEN_RAND_HEX="$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  SCEN_RUN_ID="run-$(date -u +%s)-${SCEN_RAND_HEX}"
  SCEN_RAND_SUFFIX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  SCEN_PREFIX="lmcloud-conf-${SCEN_RAND_HEX}-${SCEN_RAND_SUFFIX}-"

  CREATED_RUN_IDS+=("$SCEN_RUN_ID")
  printf '%s\n' "$SCEN_RUN_ID" >> "$CREATED_RUN_IDS_FILE"

  SCEN_SLICE="${scen%%/*}"
  SCEN_BASE="${scen#*/}"

  scen_ok=0
  scen_out=""
  if scen_out="$(
    LMCLOUD_SCENARIO_FILTER="$SCEN_BASE" \
    LMAWS_RUN_ID="$SCEN_RUN_ID" \
    LMCLOUD_RUN_ID="$SCEN_RUN_ID" \
    LMCLOUD_NAME_PREFIX="$SCEN_PREFIX" \
    "$CONFORMANCE_SH" --live --name-prefix "$SCEN_PREFIX" "$BIN" "" "$SCEN_SLICE" "$SCEN_RUN_ID" 2>&1
  )"; then
    scen_ok=1
  fi

  sweep_ok=0
  sweep_out=""
  if sweep_out="$(
    LMAWS_RUN_ID="$SCEN_RUN_ID" \
    LMCLOUD_RUN_ID="$SCEN_RUN_ID" \
    "$BIN" --sweep --apply --journal-dir "$LMAWS_LIVE_JOURNAL_DIR" "$SCEN_RUN_ID" 2>&1
  )"; then
    sweep_ok=1
  fi

  scen_charged="$(printf '%s' "$sweep_out" | grep -o '"charged_nano_usd":[0-9]*' | head -n1 | cut -d: -f2 || true)"
  if [[ -n "$scen_charged" ]]; then
    TOTAL_SPEND_NANO_USD=$((TOTAL_SPEND_NANO_USD + scen_charged))
  fi
  journal_sum="$(sum_created_journals_nano_usd)"
  if [[ "$journal_sum" -gt "$TOTAL_SPEND_NANO_USD" ]]; then
    TOTAL_SPEND_NANO_USD="$journal_sum"
  fi

  if [[ "$scen_ok" -eq 1 && "$sweep_ok" -eq 1 ]]; then
    echo "ok $idx - $scen (run_id=$SCEN_RUN_ID prefix=$SCEN_PREFIX)"
    pass=$((pass + 1))
  else
    echo "not ok $idx - $scen (run_id=$SCEN_RUN_ID prefix=$SCEN_PREFIX)"
    if [[ "$scen_ok" -eq 0 ]]; then
      printf '%s\n' "$scen_out" >&2
    fi
    if [[ "$sweep_ok" -eq 0 ]]; then
      printf 'sweep failed for %s: %s\n' "$SCEN_RUN_ID" "$sweep_out" >&2
    fi
    fail=$((fail + 1))
  fi
done

final_sweep_ok=1
if [[ "${#CREATED_RUN_IDS[@]}" -gt 0 ]]; then
  echo "=== Running final post-suite LIFO sweep for ${#CREATED_RUN_IDS[@]} created run(s) ==="
  if ! "$BIN" --sweep --apply --journal-dir "$LMAWS_LIVE_JOURNAL_DIR" "${CREATED_RUN_IDS[@]}"; then
    final_sweep_ok=0
  fi
fi
FINAL_SWEEP_DONE=1

echo "# pass $pass / $total, skip $skip, fail $fail (total_spend_nano_usd=$TOTAL_SPEND_NANO_USD)"
[[ "$fail" -eq 0 && "$final_sweep_ok" -eq 1 ]]
