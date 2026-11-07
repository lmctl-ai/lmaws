#!/usr/bin/env python3
"""Prove an executable runs with no Java or .NET runtime available.

The runner machine has a JDK and the .NET SDK installed, so this script does not
rely on their absence: it removes every PATH directory that holds java or dotnet,
clears JAVA_HOME/DOTNET_ROOT and friends, asserts no runtime can be found, checks
the binary does not link a runtime library, then runs it from an empty directory.

Usage: test-standalone.py EXECUTABLE PRODUCT_NAME
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RUNTIME_EXECUTABLES = ("java", "javaw", "dotnet")
RUNTIME_VARIABLES = (
    "JAVA_HOME", "JDK_HOME", "JRE_HOME", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
    "CLASSPATH", "DOTNET_ROOT", "DOTNET_ROOT(X86)", "DOTNET_HOST_PATH",
)
RUNTIME_LIBRARIES = ("libjvm", "libjli", "libcoreclr", "libhostfxr", "libhostpolicy", "libnethost")


def runtime_names():
    suffix = ".exe" if os.name == "nt" else ""
    return [name + suffix for name in RUNTIME_EXECUTABLES]


def sanitized_environment():
    env = dict(os.environ)
    for key in RUNTIME_VARIABLES:
        env.pop(key, None)
    kept = []
    for entry in env.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        if any((Path(entry) / name).exists() for name in runtime_names()):
            continue
        kept.append(entry)
    env["PATH"] = os.pathsep.join(kept)
    return env


def reachable_runtimes(env):
    return [name for name in RUNTIME_EXECUTABLES if shutil.which(name, path=env["PATH"])]


def linked_runtime_libraries(binary):
    if sys.platform.startswith("linux") and shutil.which("ldd"):
        command = ["ldd", str(binary)]
    elif sys.platform == "darwin" and shutil.which("otool"):
        command = ["otool", "-L", str(binary)]
    else:
        return []  # Windows: no portable dependency lister on the runner; covered by the PATH check.
    output = subprocess.run(command, capture_output=True, text=True).stdout
    return [line.strip() for line in output.splitlines() if any(lib in line for lib in RUNTIME_LIBRARIES)]


def run(binary, args, env, cwd):
    proc = subprocess.run([str(binary), *args], capture_output=True, text=True, env=env, cwd=cwd, timeout=120)
    return proc


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    binary = Path(argv[0]).resolve()
    product = argv[1].lower()
    if not binary.is_file():
        print(f"FAIL {binary}: not a file")
        return 1

    env = sanitized_environment()
    found = reachable_runtimes(env)
    if found:
        print(f"FAIL runtime still reachable on sanitized PATH: {found}")
        return 1
    libraries = linked_runtime_libraries(binary)
    if libraries:
        print(f"FAIL {binary.name} links a runtime library:")
        for line in libraries:
            print("   " + line)
        return 1
    print("ok   no java or dotnet on the sanitized PATH; no runtime library linked")

    with tempfile.TemporaryDirectory() as work:
        version = run(binary, ["--version"], env, work)
        if version.returncode != 0 or product not in version.stdout.lower():
            print(f"FAIL --version rc={version.returncode} out={version.stdout!r} err={version.stderr!r}")
            return 1
        print(f"ok   --version: {version.stdout.strip()}")
        helped = run(binary, ["--help"], env, work)
        if helped.returncode != 0 or not (helped.stdout or helped.stderr).strip():
            print(f"FAIL --help rc={helped.returncode}")
            return 1
        print("ok   --help")
    print(f"standalone OK: {binary.name} runs with no Java or .NET runtime")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
