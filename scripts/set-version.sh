#!/usr/bin/env bash
# Set the version everywhere it is written (pom, the host's VERSION and help text, the jar name in test.sh and build-native.sh).
# Used by CI to build and test the exact version it then releases: scripts/set-version.sh 0.1.28
set -euo pipefail
new="${1:?usage: set-version.sh X.Y.Z}"
[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not X.Y.Z: $new" >&2; exit 2; }
cd "$(dirname "$0")/.."
old=$(sed -n 's/.*VERSION="\([0-9.]*\)".*/\1/p' src/main/java/ai/lmctl/lmaws/Main.java | head -1)
[[ -n "$old" ]] || { echo "current version not found in Main.java" >&2; exit 1; }
[[ "$old" == "$new" ]] && exit 0
sed -i "s/\\b${old//./\\.}\\b/$new/g" pom.xml test.sh scripts/build-native.sh src/main/java/ai/lmctl/lmaws/Main.java
echo "version $old -> $new"
