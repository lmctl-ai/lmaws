#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
timeout 120 python3 scripts/sync-sdk.py --ensure
timeout 180 mvn -q dependency:build-classpath -Dmdep.outputFile=target/dependency-classpath.txt
timeout 30 python3 scripts/lock-deps.py
