#!/usr/bin/env python3
"""Presigned upload and conditional DynamoDB checks using synthetic transports only."""
from pathlib import Path
import os, subprocess, sys, xml.etree.ElementTree as ET, socket

root = Path(__file__).resolve().parents[1]
version = ET.parse(root / "pom.xml").getroot().find("{http://maven.apache.org/POM/4.0.0}version").text
jar = root / "target" / f"lmaws-{version}.jar"
if not jar.exists():
    raise SystemExit(f"missing managed jar: {jar}")
env = dict(os.environ, AWS_PROFILE="lmaws", AWS_DEFAULT_PROFILE="lmaws", AWS_EC2_METADATA_DISABLED="true", LMAWS_LIVE="0")
env.pop("LMAWS_ENDPOINT", None)
classpath = str(root / "target/classes") + os.pathsep + (root / "target/dependency-classpath.txt").read_text().strip()
args = ["java", "-cp", classpath, "ai.lmctl.lmaws.UploadChecks"]
subprocess.run(args, cwd=root, env=env, check=True, timeout=90)
with socket.socket() as reservation:
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
loop_env = dict(env, LMAWS_ENDPOINT=f"http://127.0.0.1:{port}", LMAWS_TEST_PORT=str(port), LMAWS_LIVE="1")
for test_class in ("UploadTransportChecks", "QueueWorkerTransportChecks"):
    subprocess.run(["java", "-cp", classpath, "ai.lmctl.lmaws."+test_class], cwd=root, env=loop_env, check=True, timeout=90)
subprocess.run(["java", "-cp", classpath, "ai.lmctl.lmaws.RemainingChecks"], cwd=root, env=env, check=True, timeout=90)
