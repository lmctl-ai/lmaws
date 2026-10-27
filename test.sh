#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
scripts/select-compiler.sh >/dev/null
if ! command -v timeout >/dev/null && command -v gtimeout >/dev/null; then timeout() { gtimeout "$@"; }; export -f timeout; fi
timeout 120 python3 scripts/sync-sdk.py --ensure
timeout 180 mvn -q verify
timeout 90 mvn -q dependency:build-classpath -Dmdep.outputFile=target/dependency-classpath.txt
timeout 30 python3 scripts/lock-deps.py
timeout 30 python3 scripts/test-verify-absence.py
timeout 30 python3 scripts/test-compare-outputs.py
timeout 180 python3 scripts/test-compare.py
mkdir -p target/jvm-bin
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  python3 - <<'PYWIN'
from pathlib import Path
p=Path("target/jvm-bin/lmaws.cmd");jar=Path("target/lmaws-0.1.20.jar").resolve()
p.write_text('@echo off\njava -cp "'+str(jar)+'" ai.lmctl.lmaws.Main %*\n')
PYWIN
  jvm=target/jvm-bin/lmaws.cmd
  # Windows' resolver does not execute the extensionless Unix wrapper.
  rm -f target/jvm-bin/lmaws
else
  cat > target/jvm-bin/lmaws <<'WRAPPER'
#!/usr/bin/env bash
exec java -cp "$(cd "$(dirname "$0")/.." && pwd)/lmaws-0.1.20.jar" ai.lmctl.lmaws.Main "$@"
WRAPPER
  chmod +x target/jvm-bin/lmaws
  jvm=target/jvm-bin/lmaws
fi
export PATH="$PWD/target/jvm-bin:$PATH"
export LMAWS_TEST_HOST="$jvm"
timeout 300 python3 scripts/test-cli.py "$jvm"
timeout 300 python3 scripts/test-fake.py "$jvm"
timeout 240 python3 scripts/test-iam-role.py "$jvm"
timeout 180 python3 scripts/test-web-fake.py
timeout 180 python3 scripts/test-web-http.py
timeout 180 python3 scripts/test-web-ec2.py
timeout 180 python3 scripts/test-web-ec2.py --unsupported-zone
timeout 180 python3 scripts/test-prefix-fake.py "$jvm"
timeout 180 python3 scripts/test-spend-api.py "$jvm"
timeout 300 python3 scripts/test-spend-transport.py
timeout 180 python3 scripts/test-lambda-event-transport.py
timeout 180 python3 scripts/test-upload-transport.py
timeout 30 java -cp target/lmaws-0.1.20.jar ai.lmctl.lmaws.PolicySimulationChecks
timeout 180 python3 scripts/test-s3-upload-check.py
timeout 300 python3 scripts/test-fleet-spec.py
if [[ "${LMAWS_NATIVE:-0}" == 1 ]]; then
 exe=target/lmaws; [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && exe=target/lmaws.exe
 export PATH="$PWD/target:$PATH"
 export LMAWS_TEST_HOST="$exe"
 timeout 300 python3 scripts/test-cli.py "$exe"
 timeout 300 python3 scripts/test-fake.py "$exe"
 timeout 240 python3 scripts/test-iam-role.py "$exe"
 timeout 180 python3 scripts/test-web-native.py --host "$exe"
 timeout 180 python3 scripts/test-spend-api.py "$exe"
 timeout 300 python3 scripts/test-spend-transport.py "$exe"
 if [[ "$(uname -s)" == Linux ]]; then timeout 30 python3 scripts/check-linux-linkage.py "$exe"; fi
fi
if [[ "${LMAWS_NATIVE:-0}" == 1 ]]; then timeout 1500 python3 scripts/test-gallery.py --run; else echo "note: example images run in the native CI stage; checking committed gallery now"; timeout 30 python3 scripts/test-gallery.py; fi

timeout 60 python3 scripts/test-recipes.py
if [[ ( "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ) && "${LMAWS_NATIVE:-0}" != 1 ]]; then
  echo "DEFER recipe execution to the mandatory native Windows stage: Node cannot schema-probe a JVM .cmd host"
else
timeout 180 python3 scripts/test-recipe-execution.py
fi
