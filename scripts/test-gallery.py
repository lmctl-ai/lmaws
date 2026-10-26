#!/usr/bin/env python3
"""Static gallery contract plus optional isolated execution proof."""
from pathlib import Path
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
examples = sorted(p.stem for p in (root / "examples").glob("*.lms") if p.stem != "render-all")
assert len(examples) >= 30, len(examples)
readme = (root / "README.md").read_text(encoding="utf-8")
for name in examples:
    assert f"examples/{name}.lms" in readme, name
    image = root / "docs" / "images" / f"{name}.png"
    assert image.exists(), image
    data = image.read_bytes()
    assert data.startswith(b"\x89PNG\r\n\x1a\n"), image
    assert len(data) <= 300_000, image
    source = (root / "examples" / f"{name}.lms").read_text(encoding="utf-8")
    assert "savedsl(" in source and "assert(r.code == 0)" in source, name
assert len(re.findall(r"lmctl(?: autorun)? https://raw.githubusercontent.com/lmctl-ai/lmaws/main/examples/", readme)) >= 30
print(f"gallery: {len(examples)} examples and images verified")

def run_examples():
    runner = shutil.which("lmscript")
    if runner is None:
        raise SystemExit("gallery --run: lmscript is not on PATH")
    offline_env = dict(os.environ, LMAWS_LIVE="0", AWS_EC2_METADATA_DISABLED="true")
    offline_env.pop("LMAWS_ENDPOINT", None)
    evidence = {"examples": len(examples), "passed": [], "failed": [], "timeout_seconds": 120, "live_forced_off": True}
    outputs = {}
    for name in examples:
        with tempfile.TemporaryDirectory(prefix=f"lmaws-gallery-{name}-") as work:
            result = subprocess.run(
                [runner, str(root / "examples" / f"{name}.lms")],
                cwd=work, env=offline_env, text=True, encoding="utf-8", capture_output=True, timeout=120,
            )
            if result.returncode:
                evidence["failed"].append({"name": name, "returncode": result.returncode,
                                           "output": (result.stdout + result.stderr)[-4000:]})
                continue
            image = Path(work) / "images" / f"{name}.png"
            if not image.exists() or not image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
                evidence["failed"].append({"name": name, "output": "missing or invalid generated PNG"})
                continue
            csv = Path(work) / "data" / f"{name}.csv"
            count_file = Path(work) / "data" / f"{name}.count"
            if not csv.exists() and not count_file.exists():
                evidence["failed"].append({"name": name, "output": "missing host-generated data artifact"})
                continue
            outputs[name] = (csv.read_bytes() if csv.exists() else count_file.read_bytes())
            evidence["passed"].append(name)
    # Inventory is a representative deterministic CSV; lifecycle ledgers are intentionally excluded.
    with tempfile.TemporaryDirectory(prefix="lmaws-gallery-repeat-") as one, tempfile.TemporaryDirectory(prefix="lmaws-gallery-repeat-") as two:
        for work in (one, two):
            result = subprocess.run([runner, str(root / "examples" / "inventory.lms")],
                                    cwd=work, env=offline_env, text=True, encoding="utf-8", capture_output=True, timeout=120)
            if result.returncode:
                raise SystemExit("gallery --run: inventory repeat failed: " + (result.stdout + result.stderr)[-2000:])
        first = (Path(one) / "data" / "inventory.csv").read_bytes()
        second = (Path(two) / "data" / "inventory.csv").read_bytes()
        evidence["deterministic_inventory_csv"] = first == second
    evidence["passed_count"] = len(evidence["passed"])
    evidence["failed_count"] = len(evidence["failed"])
    proof = Path(tempfile.gettempdir()) / "lmaws-gallery-run.json"
    proof.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"gallery --run: {evidence['passed_count']}/{len(examples)} passed; proof={proof}")
    if evidence["failed"]:
        for failure in evidence["failed"]:
            print(f"FAIL {failure['name']}: {failure.get('output', '')}")
        raise SystemExit(1)
    if not evidence["deterministic_inventory_csv"]:
        raise SystemExit("gallery --run: inventory CSV was not deterministic")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true", help="execute every example in isolated temp directories")
    if parser.parse_args().run:
        run_examples()
