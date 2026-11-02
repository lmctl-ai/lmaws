#!/usr/bin/env bash
# Copies schema/lmcloud.dsl.json from an lmcloud checkout (or verifies existing copy) against lmcloud.lock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="$ROOT/lmcloud.lock"
DEST="$ROOT/schema/lmcloud.dsl.json"
LMCLOUD_DIR="${1:-/home/ubuntu/cloud/lmcloud}"

if [[ "${1:-}" == "--verify" ]]; then
  want_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$LOCK_FILE")"
  got_sha="$(sha256sum "$DEST" | awk '{print $1}')"
  if [[ "$got_sha" != "$want_sha" ]]; then
    echo "error: $DEST sha256 ($got_sha) does not match lmcloud.lock ($want_sha)" >&2
    exit 1
  fi
  echo "verified $DEST ($got_sha)"
  exit 0
fi

SRC="$LMCLOUD_DIR/schema/lmcloud.dsl.json"
if [[ ! -f "$SRC" ]]; then
  echo "error: source schema not found: $SRC" >&2
  exit 1
fi

cp "$SRC" "$DEST"
src_commit="$(git -C "$LMCLOUD_DIR" rev-parse HEAD)"
src_branch="$(git -C "$LMCLOUD_DIR" rev-parse --abbrev-ref HEAD)"
got_sha="$(sha256sum "$DEST" | awk '{print $1}')"

python3 - "$LOCK_FILE" "$src_branch" "$src_commit" "$got_sha" <<'PY'
import json, sys
lock_path, branch, commit, sha = sys.argv[1:5]
doc = {
    "repo": "lmctl-ai/lmcloud",
    "branch": branch,
    "commit": commit,
    "file": "schema/lmcloud.dsl.json",
    "sha256": sha,
}
with open(lock_path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY

cmp -s "$SRC" "$DEST"
echo "synced $DEST from $LMCLOUD_DIR@$src_commit ($got_sha)"
