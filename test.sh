#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v timeout >/dev/null && command -v gtimeout >/dev/null; then timeout() { gtimeout "$@"; }; export -f timeout; fi
timeout 120 python3 scripts/sync-sdk.py --ensure
timeout 180 mvn -q verify
timeout 90 mvn -q dependency:build-classpath -Dmdep.outputFile=target/dependency-classpath.txt
timeout 30 python3 scripts/lock-deps.py
mkdir -p target/jvm-bin
cat > target/jvm-bin/lmaws <<'WRAPPER'
#!/usr/bin/env bash
exec java -cp "$(cd "$(dirname "$0")/.." && pwd)/lmaws-0.1.0.jar" ai.lmctl.lmaws.Main "$@"
WRAPPER
chmod +x target/jvm-bin/lmaws
export PATH="$PWD/target/jvm-bin:$PATH"
jvm=target/jvm-bin/lmaws
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  python3 - <<'PYWIN'
from pathlib import Path
p=Path("target/jvm-bin/lmaws.cmd");jar=Path("target/lmaws-0.1.0.jar").resolve()
p.write_text('@echo off\njava -cp "'+str(jar)+'" ai.lmctl.lmaws.Main %*\n')
PYWIN
  jvm=target/jvm-bin/lmaws.cmd
fi
timeout 300 python3 scripts/test-cli.py "$jvm"
timeout 300 python3 scripts/test-fake.py "$jvm"
if [[ "${LMAWS_NATIVE:-0}" == 1 ]]; then
 exe=target/lmaws; [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && exe=target/lmaws.exe
 export PATH="$PWD/target:$PATH"
 timeout 300 python3 scripts/test-cli.py "$exe"
 timeout 300 python3 scripts/test-fake.py "$exe"
 if [[ "$(uname -s)" == Linux ]]; then timeout 30 python3 scripts/check-linux-linkage.py "$exe"; fi
fi
if [[ "${LMAWS_NATIVE:-0}" == 1 ]]; then timeout 1500 python3 scripts/test-gallery.py --run; else echo "note: example images run in the native CI stage; checking committed gallery now"; timeout 30 python3 scripts/test-gallery.py; fi
