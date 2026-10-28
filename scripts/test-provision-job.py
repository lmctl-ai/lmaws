#!/usr/bin/env python3
"""Offline provisioning-job regression checks.

Uses the freshly built JVM host with aws.demo() and the released lmfiles host.
No AWS endpoint, credentials, admin profile, or live mutation is permitted.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION=ET.parse(ROOT/"pom.xml").getroot().find("{http://maven.apache.org/POM/4.0.0}version").text
JAR=ROOT/"target"/f"lmaws-{VERSION}.jar"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_lmctl(cwd: pathlib.Path, script: pathlib.Path, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["lmctl", str(script), *args], cwd=cwd, env=env,
        text=True, capture_output=True, timeout=180, check=False,
    )


def main() -> int:
    if os.name=="nt":
        print("SKIP provisioning job subprocess composition on Windows; JVM .cmd schema probing is unsupported by the current runner; native gallery remains separate")
        return 0
    check(JAR.exists(), f"missing {JAR}; build the current JVM host first")
    with tempfile.TemporaryDirectory(prefix="lmaws-provision-job-") as raw:
        work = pathlib.Path(raw)
        wrapper = work / "lmaws"
        wrapper.write_text(
            "#!/bin/sh\nexec java -cp " + str(JAR) + " ai.lmctl.lmaws.Main \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        bindir = work / "bin"
        bindir.mkdir()
        (bindir / "lmaws").symlink_to(wrapper)
        config = work / "config.json"
        config.write_text((ROOT / "recipes" / "provision.config.json").read_text(), encoding="utf-8")
        script = ROOT / "recipes" / "provision.lms"
        env = dict(os.environ)
        env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
        env["AWS_PROFILE"] = "default"
        env["AWS_DEFAULT_PROFILE"] = "default"
        env.pop("LMAWS_ENDPOINT", None)
        env.pop("LMPROV_LEDGER_DIR", None)
        env.pop("LMAWS_MAX_COST_USD", None)
        env.pop("AWS_ENDPOINT_URL", None)
        env.pop("AWS_ENDPOINT_URL_STS", None)
        env["LMAWS_LIVE"] = "1"  # the recipe must still select aws.demo() without --live

        def invoke(op: str, ident: str, *extra: str) -> subprocess.CompletedProcess[str]:
            result = run_lmctl(work, script, "--operation", op, "--lmprov-id", ident,
                               "--config", str(config), *extra, env=env)
            check(result.returncode == 0, f"{op} {ident} failed:\n{result.stdout}\n{result.stderr}")
            return result

        # Preview is a planning operation and creates no local registry/receipt.
        preview = run_lmctl(work, script, "--preview", "--lmprov-id", "preview-001",
                            "--config", str(config), env=env)
        check(preview.returncode == 0, preview.stderr)
        check(not (work / ".lmaws-local").exists(), "preview created local state")

        for ident in ("run-a", "run-b"):
            invoke("create", ident)
            record_path = work / ".lmaws-local" / "provision" / f"{ident}.json"
            check(record_path.exists(), f"missing record for {ident}")
            check((record_path.parent.stat().st_mode & 0o777)==0o700,"registry directory is not private")
            record = json.loads(record_path.read_text())
            check(record["lmprov_id"] == ident and record["stage"] == "created", record)
            before = (record["stage"], json.dumps(record.get("history", []), sort_keys=True))
            invoke("stop", ident, "--dry")
            after = json.loads(record_path.read_text())
            check((after["stage"], json.dumps(after.get("history", []), sort_keys=True)) == before, "dry stop changed lifecycle state")
            invoke("start", ident, "--dry")
            after = json.loads(record_path.read_text()); check((after["stage"], json.dumps(after.get("history", []), sort_keys=True)) == before,
                  "dry start changed lifecycle state")
            invoke("terminate", ident, "--dry")
            after = json.loads(record_path.read_text()); check((after["stage"], json.dumps(after.get("history", []), sort_keys=True)) == before,
                  "dry terminate changed lifecycle state")

        # Simulate an accepted launch whose created receipt never reached lmfiles.
        orphan=work/"accepted-before-record.lms"
        orphan.write_text('p=_lmcode_ cli="lmaws" install="github:lmctl-ai/lmaws@latest";\nlet cloud=aws.demo();cloud.ec2_provision_run("{\\\"lmprov_id\\\":\\\"resume-c\\\",\\\"owner\\\":\\\"lmctl\\\",\\\"purpose\\\":\\\"on-demand-provisioning\\\"}");\nend _lmcode_\nsavedsl(p,"accepted.dslb");let r=system(concat(dsl_cli(p),["--dsl","accepted.dslb"]),120000);assert(r.code==0);\n')
        direct_env=dict(env,LMAWS_LIVE="0",LMPROV_LEDGER_DIR=str(work/".lmaws-local/provision/host"))
        accepted=run_lmctl(work,orphan,env=direct_env);check(accepted.returncode==0,accepted.stdout+accepted.stderr)
        invoke("create","resume-c")
        resumed=json.loads((work/".lmaws-local/provision/resume-c.json").read_text())
        check(resumed["stage"]=="created" and resumed["last_receipt"]["reattached"],"launch/record crash gap did not recover")

        # A rejected request cannot overwrite the configuration of the real record.
        invoke("create","run-b","--volume-gib","20")
        preserved=json.loads((work/".lmaws-local/provision/run-b.json").read_text())
        check(preserved["config"]["volume_gib"]==10 and preserved["history"][-1]["stage"]=="failed","failed config change overwrote confirmed metadata")

        # The lmfiles registry is authoritative even if its inspection copy is lost/corrupted.
        copy=work/".lmaws-local/provision/run-b.json"
        copy.write_text("corrupted inspection copy")
        invoke("errors","run-b")
        check(json.loads(copy.read_text())["stage"]=="created","continuation trusted the JSON inspection copy")

        # Confirmed lifecycle and read-only/error paths for one instance.
        for op in ("status", "stop", "start", "status", "errors", "terminate"):
            invoke(op, "run-a")
        final = json.loads((work / ".lmaws-local" / "provision" / "run-a.json").read_text())
        stages = [entry["stage"] for entry in final["history"]]
        check("requested" in stages and "created" in stages and "stopped" in stages
              and "started" in stages and "terminated" in stages, stages)
        check(final["lmprov_id"] == "run-a", final)
        other = json.loads((work / ".lmaws-local" / "provision" / "run-b.json").read_text())
        check(other["lmprov_id"] == "run-b" and other["lmprov_id"] != final["lmprov_id"], "records collided")

        # Unknown config paths fail closed; inherited profile/live flags never turn the demo live.
        bad = run_lmctl(work, script, "--operation", "create", "--lmprov-id", "bad-001",
                        "--config", str(work / "missing.json"), env=env)
        check(bad.returncode != 0, "missing config was silently accepted")
        # A demo caller cannot overwrite a record belonging to AWS mode.
        switch=work/"switch-mode.lms"
        switch.write_text('p=_lmcode_ cli="lmfiles" install="github:lmctl-ai/lmfiles@latest";\nlet db=registry.open(".lmaws-local/provision/run-b.mv","provision","{}");db.item_upsert("{\\\"id\\\":\\\"run-b\\\"}","{\\\"mode\\\":\\\"aws\\\"}");db.close();\nend _lmcode_\nsavedsl(p,"switch.dslb");let r=system(concat(dsl_cli(p),["--dsl","switch.dslb"]),120000);assert(r.code==0);\n')
        changed=run_lmctl(work,switch,env=env);check(changed.returncode==0,changed.stdout+changed.stderr)
        mixed=run_lmctl(work,script,"errors","run-b",env=env)
        check(mixed.returncode!=0 and "mode mismatch" in mixed.stderr,"demo and AWS registry modes were mixed")

        picture=work/"picture";picture.mkdir()
        example_env=dict(env,AWS_PROFILE="lmaws",LMAWS_LIVE="1")
        example=run_lmctl(picture,ROOT/"examples/provision_job.lms",env=example_env)
        check(example.returncode==0,example.stdout[-2000:]+example.stderr[-3000:])
        check((picture/"images/provision_job.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n"),"missing real gallery picture")
        check('"same_volume":true' in example.stdout and '"boot_count":2' in example.stdout and '"leftovers":0' in example.stdout,"example omitted lifecycle proof")
    print("PASS provisioning job demo lifecycle, dry-run immutability, two-ID isolation, preview and config guards")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
