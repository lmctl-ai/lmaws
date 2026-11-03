#!/usr/bin/env bash
# Select a compiler that can build lmcode v6 and use the current host invocation API.
set -euo pipefail
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lmaws-compiler-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
if [[ -n "${LMSCRIPT_BIN:-}" ]]; then
  candidate="$LMSCRIPT_BIN"
elif [[ "$OSTYPE" == msys* || "$OSTYPE" == mingw* ]]; then
  candidate="$(command -v lmscript.cmd || command -v lmscript || true)"
else
  candidate="$(command -v lmscript || true)"
fi
run_candidate() {
  case "$candidate" in
    *.cmd|*.bat)
      local win_candidate
      win_candidate="$(cygpath -w "$candidate" 2>/dev/null || printf '%s' "$candidate")"
      cmd.exe /c "$win_candidate" "$@"
      ;;
    *) "$candidate" "$@" ;;
  esac
}
printf '%s\n' '{"dsl.schema":2,"name":"compiler_probe","types":{},"functions":{},"context":{}}' > "$WORK/probe.schema.json"
python3 - "$(native "$WORK/probe.schema.json")" "$(native "$WORK")" <<'PYPROBE'
import pathlib,sys
schema=pathlib.Path(sys.argv[1]);work=pathlib.Path(sys.argv[2])
source="\n".join([
 "import os,pathlib,shutil,sys",
 "args=sys.argv[1:]",
 "if '--lmcode-schema' in args:",
 " print(pathlib.Path(SCHEMA_PATH).read_text(),end='')",
 " raise SystemExit(0)",
 "if '--lmcode' in args:",
 " index=args.index('--lmcode')",
 " shutil.copyfile(args[index+1],os.environ['LMCODE_PROBE_OUTPUT'])",
 " print('LMCODE_RETURN_BEGIN\\n{\"ok\":true,\"result\":null}\\nLMCODE_RETURN_END')",
 " raise SystemExit(0)",
 "raise SystemExit(2)",
]).replace('SCHEMA_PATH',repr(str(schema)))
(work/'probe-host.py').write_text(source)
python='python' if sys.platform=='win32' else pathlib.Path(sys.executable).name
(work/'probe.lms').write_text('s=load_schema(cli='+repr(python+' probe-host.py')+');\np = _lmcode_ s;\nlet n = str_len("implicit std");\nend _lmcode_\nr=run_lmcode(p); assert(r.ok);\n')
PYPROBE
if [ -n "$candidate" ] &&
   (cd "$WORK" && PATH="$WORK${PATH:+:$PATH}" LMCODE_PROBE_OUTPUT="$(native "$WORK/probe.lmcode")" run_candidate "$(native "$WORK/probe.lms")" > /dev/null 2>&1) &&
   python3 - "$(native "$WORK/probe.lmcode")" <<'PYVERIFY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
sys.exit(0 if p.is_file() and p.read_bytes()[:6] == b'DSLB\x00\x06' else 1)
PYVERIFY
then
  printf '%s\n' "$candidate"
else
  if [ -n "${LMAWS_DEBUG:-}" ]; then
    echo "--- compiler probe diagnostics (candidate=$candidate)" >&2
    cat "$WORK/probe.lms" >&2 || true
    [ -n "$candidate" ] && run_candidate "$(native "$WORK/probe.lms")" 2>&1 | head -10 >&2
    ls -la "$WORK" >&2
  fi
  echo "error: no implicit-std lmcode v6 compiler with current invocation support was found; build mono main or set LMSCRIPT_BIN" >&2
  exit 2
fi
