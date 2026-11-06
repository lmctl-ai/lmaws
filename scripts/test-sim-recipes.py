#!/usr/bin/env python3
"""Run every recipes/sim/*.lms recipe against freshly started awssim emulators.

Starts three loopback awssim processes on free ports (open mode, EC2-enabled open mode with a
seeded VPC/subnet, and --auth enforce with the policy that auth_enforced_denial.lms authors),
runs each recipe in its own temporary working directory and asserts the PASS line.

Binaries: --awssim/AWSSIM_BIN (else PATH), --lmaws/LMAWS_BIN (native host, else PATH),
--cloud-host/LMAWS_CLOUD_BIN (Go lmaws build serving the shared lmcloud schema; built from
./cmd/lmaws into build/sim/ when absent), --lmscript/LMSCRIPT_BIN (else PATH).
No AWS credentials are read and no network leaves the loopback interface.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECIPES = ROOT / "recipes" / "sim"
EC2_RECIPES = {"ec2_web_server", "ec2_fleet_inventory", "leftover_sweep"}
ENFORCE_RECIPES = {"auth_enforced_denial"}
EC2_HEADERS = {"Authorization": "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/ec2/aws4_request, SignedHeaders=host, Signature=x"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def which(explicit: str | None, env: str, name: str) -> str | None:
    for candidate in (explicit, os.environ.get(env)):
        if candidate:
            return str(Path(candidate).resolve())
    return shutil.which(name)


def start_sim(binary: str, port: int, log: Path, extra: list[str], env: dict[str, str]) -> subprocess.Popen:
    proc = subprocess.Popen([binary, "serve", "--port", str(port), *extra], stdout=log.open("w"), stderr=subprocess.STDOUT, env=env)
    url = f"http://127.0.0.1:{port}/_floci/health"
    for _ in range(600):
        if proc.poll() is not None:
            raise SystemExit(f"awssim on port {port} exited early; see {log}")
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return proc
        except Exception:
            time.sleep(0.2)
    raise SystemExit(f"awssim on port {port} did not become healthy; see {log}")


def ec2(port: int, action: str, **params: str) -> str:
    body = "&".join([f"Action={action}", "Version=2016-11-15", *(f"{k}={v}" for k, v in params.items())]).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body, headers=EC2_HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def seed_network(port: int) -> tuple[str, str]:
    """awssim's built-in default VPC id is not an EC2-style id, so create a real-looking one."""
    vpc = ec2(port, "CreateVpc", CidrBlock="10.0.0.0/16").split("<vpcId>")[1].split("<")[0]
    subnet = ec2(port, "CreateSubnet", VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a").split("<subnetId>")[1].split("<")[0]
    return vpc, subnet


def build_cloud_host() -> str:
    out = ROOT / "build" / "sim" / "lmaws-cloud"
    out.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED="0", GOTOOLCHAIN=os.environ.get("GOTOOLCHAIN", "auto"))
    subprocess.run(["go", "build", "-trimpath", "-o", str(out), "./cmd/lmaws"], cwd=ROOT, check=True, env=env)
    return str(out)


def run_persistence(sim: str, lmscript: str, hostargs: list[str], env: dict[str, str], work: Path, timeout: int) -> bool:
    """persistence_restart.lms across a real emulator restart: write with --data-dir, stop, start again, verify."""
    data_dir = work / "persist-data"
    data_dir.mkdir()
    out_dir = work / "persist-out"
    out_dir.mkdir()
    cwd = work / "persistence_restart_restart"
    cwd.mkdir()
    port = free_port()
    recipe = str(RECIPES / "persistence_restart.lms")

    def phase(name: str) -> subprocess.CompletedProcess[str]:
        cmd = [lmscript, recipe, "--phase", name, "--endpoint", f"http://127.0.0.1:{port}", "--out", str(out_dir), "--run", "restart1", *hostargs]
        return subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)

    proc = start_sim(sim, port, work / "awssim-persist-1.log", ["--data-dir", str(data_dir)], env)
    try:
        wrote = phase("write")
    finally:
        proc.terminate()
        proc.wait(timeout=30)
    if wrote.returncode != 0:
        (cwd / "stdout.txt").write_text(wrote.stdout + wrote.stderr)
        return False
    proc = start_sim(sim, port, work / "awssim-persist-2.log", ["--data-dir", str(data_dir)], env)
    try:
        verified = phase("verify")
    finally:
        proc.terminate()
        proc.wait(timeout=30)
    ok = verified.returncode == 0 and "PASS persistence_restart" in verified.stdout
    if not ok:
        (cwd / "stdout.txt").write_text(verified.stdout + verified.stderr)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--awssim")
    ap.add_argument("--lmaws", help="native lmaws executable (AWS SDK for Java host)")
    ap.add_argument("--cloud-host", help="Go lmaws build serving the lmcloud schema")
    ap.add_argument("--lmscript")
    ap.add_argument("--only", action="append", default=[], help="recipe stem to run (repeatable)")
    ap.add_argument("--timeout", type=int, default=420)
    args = ap.parse_args()

    awssim = which(args.awssim, "AWSSIM_BIN", "awssim")
    lmaws = which(args.lmaws, "LMAWS_BIN", "lmaws")
    lmscript = which(args.lmscript, "LMSCRIPT_BIN", "lmscript")
    cloud = which(args.cloud_host, "LMAWS_CLOUD_BIN", "lmaws-cloud") or build_cloud_host()
    missing = [n for n, v in (("awssim", awssim), ("lmaws", lmaws), ("lmscript", lmscript)) if not v]
    if missing:
        print("missing executables: " + ", ".join(missing) + " (pass --<name> or set <NAME>_BIN; awssim releases: https://github.com/lmctl-ai/awssim/releases)", file=sys.stderr)
        return 2

    recipes = sorted(p for p in RECIPES.glob("*.lms") if not args.only or p.stem in args.only)
    if not recipes:
        print("no recipes selected", file=sys.stderr)
        return 2

    work = Path(tempfile.mkdtemp(prefix="lmaws-sim-recipes-"))
    procs: list[subprocess.Popen] = []
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "LMAWS_", "LMCLOUD_"))}
    base_env["PATH"] = str(Path(lmaws).parent) + os.pathsep + base_env.get("PATH", "")
    failures: list[str] = []
    try:
        open_port, ec2_port, enforce_port = free_port(), free_port(), free_port()
        procs.append(start_sim(awssim, open_port, work / "awssim-open.log", [], base_env))
        print(f"awssim open mode on {open_port}")
        procs.append(start_sim(awssim, ec2_port, work / "awssim-ec2.log", [], dict(base_env, FLOCI_SERVICES_EC2_ENABLED="true")))
        vpc, subnet = seed_network(ec2_port)
        print(f"awssim EC2 mode on {ec2_port} ({vpc}, {subnet})")
        prep = work / "prepare"
        prep.mkdir()
        subprocess.run([lmscript, str(RECIPES / "auth_enforced_denial.lms"), "--prepare", "--out", str(prep)], cwd=prep, env=base_env, check=True, capture_output=True, text=True)
        auth_config = prep / "awssim-auth.json"
        procs.append(start_sim(awssim, enforce_port, work / "awssim-enforce.log", ["--auth", "enforce", "--auth-config", str(auth_config)], base_env))
        print(f"awssim enforce mode on {enforce_port} with {auth_config.name}")

        for recipe in recipes:
            port = ec2_port if recipe.stem in EC2_RECIPES else enforce_port if recipe.stem in ENFORCE_RECIPES else open_port
            cwd = work / recipe.stem
            cwd.mkdir()
            cmd = [lmscript, str(recipe), "--endpoint", f"http://127.0.0.1:{port}", "--host", lmaws, "--cloud-host", cloud]
            started = time.monotonic()
            try:
                result = subprocess.run(cmd, cwd=cwd, env=base_env, text=True, capture_output=True, timeout=args.timeout)
                ok = result.returncode == 0 and f"PASS {recipe.stem}" in result.stdout
                detail = "" if ok else (result.stdout + result.stderr).strip().splitlines()[-1:] or ["(no output)"]
            except subprocess.TimeoutExpired:
                ok, detail = False, ["timeout"]
            status = "ok" if ok else "FAIL"
            print(f"{status:4} {recipe.stem:26} {time.monotonic() - started:6.1f}s" + ("" if ok else f"  {detail[0][:200]}"))
            if not ok:
                failures.append(recipe.stem)
                (cwd / "stdout.txt").write_text(result.stdout if 'result' in locals() else "")

        if not args.only or "persistence_restart" in args.only:
            started = time.monotonic()
            ok = run_persistence(awssim, lmscript, ["--host", lmaws, "--cloud-host", cloud], base_env, work, args.timeout)
            print(f"{'ok' if ok else 'FAIL':4} {'persistence_restart*':26} {time.monotonic() - started:6.1f}s" + ("" if ok else "  (write, emulator restart with --data-dir, verify)"))
            if not ok:
                failures.append("persistence_restart(restart)")
    finally:
        for proc in procs:
            proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
    summary = {"recipes": len(recipes), "failed": failures, "work": str(work)}
    print(json.dumps(summary))
    if failures:
        print(f"FAIL {len(failures)}/{len(recipes)} recipes; logs under {work}", file=sys.stderr)
        return 1
    shutil.rmtree(work, ignore_errors=True)
    print(f"PASS {len(recipes)} sim recipes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
