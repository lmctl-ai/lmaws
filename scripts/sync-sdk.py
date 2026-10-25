#!/usr/bin/env python3
"""Fetch the released Java SDK by immutable commit and verify its archive digest."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--verify", action="store_true")
parser.add_argument("--ensure", action="store_true", help="verify existing sources, otherwise fetch the pinned archive")
args = parser.parse_args()
lock = json.loads((root / "sdk.lock").read_text(encoding="utf-8"))
destination = root / "third_party/lmcode-java"
manifest_path = destination / ".sdk-files.json"
if args.verify or args.ensure and manifest_path.is_file():
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["commit"] == lock["commit"], "SDK commit differs from sdk.lock"
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file() and path != manifest_path}
    assert actual == set(manifest["files"]), "SDK source file set differs from verified archive"
    assert "src/main/java/io/lmctl/lmcode/Registry.java" in actual, "SDK Java sources are missing"
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == digest, "SDK source modified: " + name
    print("SDK sources verified: " + lock["tag"])
else:
    url = f'https://codeload.github.com/{lock["repo"]}/tar.gz/{lock["commit"]}'
    with urllib.request.urlopen(url, timeout=90) as response:
        archive_bytes = response.read(32 * 1024 * 1024 + 1)
    assert len(archive_bytes) <= 32 * 1024 * 1024, "SDK archive exceeds download bound"
    assert hashlib.sha256(archive_bytes).hexdigest() == lock["sha256"], "SDK archive hash differs from sdk.lock"
    assert not destination.exists() or not any(destination.iterdir()), "SDK directory already exists; use --verify or a clean checkout"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive:
            relative = PurePosixPath(*PurePosixPath(member.name).parts[1:])
            if member.isfile() and (str(relative).startswith("src/main/java/io/lmctl/lmcode/") and relative.suffix == ".java" or str(relative) == "LICENSE"):
                assert not relative.is_absolute() and ".." not in relative.parts
                data = archive.extractfile(member).read()
                path = destination.joinpath(*relative.parts)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                files[str(relative)] = hashlib.sha256(data).hexdigest()
    assert "src/main/java/io/lmctl/lmcode/Registry.java" in files and "LICENSE" in files, "SDK source/license missing"
    manifest_path.write_text(json.dumps({"commit": lock["commit"], "files": files}, indent=2) + "\n", encoding="utf-8")
    print("SDK sources fetched: " + lock["tag"])
