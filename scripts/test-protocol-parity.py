#!/usr/bin/env python3
"""Compare five deterministic offline operations with pre-migration host results."""
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

host = pathlib.Path(sys.argv[1]).resolve()
baseline = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
expected = {
    "identity": "a0f761c79c700c792cd563c14111a0f6324cff837da56eeb8c672b06a397f1bd",
    "buckets": "73a9400ee60971481ccabbe27ca0872d16c45248edcb50b45b8cab6363b849d7",
    "instances": "54522ed349128f08c24bd8d6b6144ceffd3593663e03e2e99a57ca7312fdf710",
    "vpcs": "fd898d1492d2cc04ddba7b96161f2f3c35d90f19fd18f762f1d82e23fb45554a",
    "queues": "384a5cb26fa0af1d90de609b0169baa23e939f8a9aa2da2ed7985ccda33792a2",
}

def run(command, *args):
    argv=list(command)
    if os.name=="nt" and argv and argv[0].lower().endswith(".cmd"):
        argv=["cmd.exe","/c",*argv]
    return subprocess.run([*argv, *map(str, args)], capture_output=True, check=True).stdout

def u16(value): return struct.pack(">H", value)
def u32(value): return struct.pack(">I", value)

new_schema = run([str(host)], "--lmcode-schema", "--json")
if baseline is not None:
    old_schema = run(["java", "-jar", str(baseline)], "--lmcode-schema", "--json")
    assert old_schema == new_schema, "baseline and current host schemas differ"
else:
    old_schema = new_schema

def bytecode(operation, output_path):
    imports = [
        "method Cloud.demo() -> Cloud",
        f"method Cloud.{operation}() -> Rows",
        "method Rows.json() -> string",
        "fn file_write(string, string) -> void",
    ]
    constants = [str(output_path), *imports, "aws", "Cloud"]
    table = b"".join(b"\x01" + u32(len(value.encode())) + value.encode() for value in constants)
    # Keep one output path on the stack, then call aws.demo(), the inventory,
    # Rows.json(), and file_write in the same order on both host versions.
    code = (b"\x02" + u32(0) + b"\x06" + u16(0)
            + b"\x08" + u16(0) + b"\x00"
            + b"\x08" + u16(1) + b"\x00"
            + b"\x08" + u16(2) + b"\x00"
            + b"\x07" + u16(3) + b"\x02\x11")
    return (b"DSLB" + u16(6) + hashlib.sha256(old_schema).digest()
            + u32(len(constants)) + table + u16(len(imports))
            + b"".join(u32(index) for index in range(1, 5))
            + u16(1) + u32(5) + u32(6) + u16(0) + u16(2)
            + u32(len(code)) + code + u32(0) + u16(0))

with tempfile.TemporaryDirectory(prefix="lmaws-protocol-parity-") as temporary:
    work = pathlib.Path(temporary)
    observed = {}
    for operation, digest in expected.items():
        program = work / f"{operation}.lmcode"
        output = work / f"{operation}.json"
        program.write_bytes(bytecode(operation, output))
        if baseline is not None:
            run(["java", "-jar", str(baseline)], "--lmcode", program)
            old = output.read_bytes()
        run([str(host)], "--lmcode", program)
        current = output.read_bytes()
        current_hash = hashlib.sha256(current).hexdigest()
        assert current_hash == digest, f"{operation}: result differs from the recorded pre-migration result"
        if baseline is not None:
            assert current == old, f"{operation}: old and current result bytes differ"
        observed[operation] = current_hash
print(json.dumps(observed, sort_keys=True))
print("PASS offline operation parity: " + ", ".join(expected))
