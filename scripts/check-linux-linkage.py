#!/usr/bin/env python3
"""Release policy: system glibc only, with a glibc 2.35 symbol ceiling."""
import pathlib
import re
import shutil
import subprocess
import sys


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=20)


def allowed(name):
    return name in {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1"} or bool(re.fullmatch(r"ld-linux[\w.-]*\.so(?:\.\d+)*", name))


def check(host):
    if shutil.which("readelf"):
        dynamic = run("readelf", "-dW", host)
        needed = re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic)
        headers = run("readelf", "-lW", host)
        interpreter = re.search(r"Requesting program interpreter: ([^]]+)", headers)
        if not interpreter or not allowed(pathlib.Path(interpreter[1]).name):
            raise ValueError("Linux requires the system glibc dynamic loader")
        versions = [tuple(map(int, v.split("."))) for v in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", run("readelf", "--version-info", "-W", host))]
        if versions and max(versions) > (2, 35):
            raise ValueError("binary requires glibc newer than 2.35: " + str(max(versions)))
    else:
        diagnostic = run("ldd", host)
        if "not found" in diagnostic:
            raise ValueError("unresolved runtime dependency")
        needed = []
        for line in diagnostic.splitlines():
            name = pathlib.Path(line.strip().split()[0]).name
            if name.startswith("linux-vdso"):
                continue
            needed.append(name)
    if "libc.so.6" not in needed:
        raise ValueError("Linux must dynamically link system glibc")
    bad = [name for name in needed if not allowed(name)]
    if bad:
        raise ValueError("unexpected shared libraries: " + ", ".join(bad))
    print("glibc >= 2.35 policy passed; dynamic dependencies: " + ", ".join(needed))


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: check-linux-linkage.py BINARY")
        check(sys.argv[1])
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("Linux linkage check failed: " + str(error), file=sys.stderr)
        sys.exit(1)
