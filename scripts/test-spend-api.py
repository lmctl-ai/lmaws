#!/usr/bin/env python3
"""Offline acceptance tests for the read-only Spend API; never contacts AWS."""
from __future__ import annotations
import json, os, subprocess, sys, tempfile, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "target/jvm-bin/lmaws"
LMSCRIPT = os.environ.get("LMSCRIPT_BIN") or shutil.which("lmscript.cmd" if os.name == "nt" else "lmscript") or "lmscript"

def launcher_argv(binary, *args):
    prefix = ["cmd.exe", "/c", str(binary)] if os.name == "nt" and str(binary).lower().endswith((".cmd", ".bat")) else [str(binary)]
    return prefix + list(args)
SCHEMA = ROOT / "schema/lmaws.dsl.json"
BASE_ENV = dict(os.environ)
BASE_ENV.update({"AWS_PROFILE": "default", "LMAWS_LIVE": "0", "LMAWS_SPEND_LIVE": "0", "CI": "true", "AWS_EC2_METADATA_DISABLED": "true"})
BASE_ENV.pop("LMAWS_ENDPOINT", None)

def execute(source: str, *, code: int = 0, env: dict[str, str] | None = None):
    with tempfile.TemporaryDirectory(prefix="lmaws-spend-api-") as raw:
        directory=Path(raw);src=directory/"case.lms"
        accepted=code==0
        src.write_text('s=load_schema(cli="java ai.lmctl.lmaws.Main");\np = _lmcode_ s;\n'+source+'\nend _lmcode_\nr=run_lmcode(p); println(json_stringify(r)); assert(r.ok == '+str(accepted).lower()+');\n',encoding="utf-8")
        command=launcher_argv(LMSCRIPT,str(src))
        run_env=dict(BASE_ENV,PATH=str(HOST.parent)+os.pathsep+BASE_ENV.get("PATH",""))
        run_env.update(env or {})
        result=subprocess.run(command,cwd=directory,env=run_env,text=True,capture_output=True,timeout=180)
        assert result.returncode==0,(result.returncode,result.stdout[-2000:],result.stderr[-2000:])
        envelope=json.loads(result.stdout.strip().splitlines()[-1]);result.returncode=0 if envelope.get("ok") else 3
        assert result.returncode==code,(result.returncode,result.stdout[-2000:],result.stderr[-2000:])
        return result,directory

def assert_safe_report(path: Path) -> dict:
    report = json.loads((path / "report.json").read_text(encoding="utf-8"))
    encoded = json.dumps(report)
    metadata = report["metadata"]
    summary = report["summary"]
    assert metadata["mode"] == "synthetic", report
    assert summary["mode"] == "synthetic", report
    assert summary["ce_requests"] == 10, report
    assert summary["metric_requests"] == 3, report
    assert summary["metric_units"] == 18, report
    assert abs(float(summary["estimated_cost_usd"]) - 0.10018) < 1e-8, report
    assert "123456789012" not in encoded and "account_id" not in encoded.lower(), report
    return report

with tempfile.TemporaryDirectory(prefix="lmaws-spend-suite-") as raw:
    directory = Path(raw)
    source = 'let spend = aws.spend("all", 30, 10, 0.25); spend.write(' + json.dumps(str(directory / "out")) + ');'
    result, _ = execute(source)
    report = assert_safe_report(directory / "out")
    for name in ("daily_chart.csv", "services_chart.csv", "idle_chart.csv", "gauge_chart.csv", "transfer_chart.csv"):
        assert (directory / "out" / name).is_file(), name

    for invalid in [
        'aws.spend("all", 0, 10, 0.25);',
        'aws.spend("all", 30, 0, 0.25);',
        'aws.spend("all", 30, 10, 0.26);',
        'aws.spend("not-a-topic", 30, 10, 0.25);',
    ]:
        execute(invalid, code=3)

    execute('let a = aws.spend("all", 30, 10, 0.25); let b = aws.spend("all", 30, 10, 0.25);', code=3)
    execute('let cloud = aws.demo(); let s = cloud.spend("all", 30, 10, 0.25);', code=3)

    execute('let s = aws.spend("all", 30, 10, 0.25); s.write(' + json.dumps(str(directory / "blocked")) + ');',
            code=3, env={"LMAWS_LIVE": "1", "LMAWS_SPEND_LIVE": "1", "AWS_PROFILE": "lmaws"})
    execute('let s = aws.spend("all", 30, 10, 0.25); s.write(' + json.dumps(str(directory / "ci-blocked")) + ');',
            code=3, env={"LMAWS_LIVE": "1", "LMAWS_SPEND_LIVE": "1", "AWS_PROFILE": "default", "CI": "true"})

print("spend API checks: 12 cases passed; synthetic only, no AWS CLI or credentials")
