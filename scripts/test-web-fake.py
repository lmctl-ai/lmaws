#!/usr/bin/env python3
"""Run credential-free web safety and SDK request tests against the built host."""
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]
import xml.etree.ElementTree as ET
version=ET.parse(root/"pom.xml").findtext("{http://maven.apache.org/POM/4.0.0}version")
for name in ("WebStackChecks","WebTransportChecks"):
 subprocess.run(["java","-cp",str(root/("target/lmaws-"+version+".jar")),"ai.lmctl.lmaws."+name],cwd=root,check=True,timeout=60)
