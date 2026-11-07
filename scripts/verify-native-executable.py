#!/usr/bin/env python3
"""Fail unless every file given is a native executable, not bytecode or a script.

Accepted: ELF (Linux), Mach-O thin or fat (macOS), PE without a CLR header (Windows).
Rejected: ZIP/JAR archives, Java .class files, .NET managed (IL) assemblies,
shell/batch scripts, and anything without a recognised native executable header.

Usage:
  verify-native-executable.py FILE [FILE ...]
  verify-native-executable.py --self-test
"""
import struct
import sys
import tempfile
from pathlib import Path

HEADER_BYTES = 65536
ELF_MAGIC = b"\x7fELF"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # 32-bit, big-endian header
    b"\xce\xfa\xed\xfe",  # 32-bit, little-endian header
    b"\xfe\xed\xfa\xcf",  # 64-bit, big-endian header
    b"\xcf\xfa\xed\xfe",  # 64-bit, little-endian header
}
CAFEBABE = b"\xca\xfe\xba\xbe"  # shared by fat Mach-O and Java class files
ZIP_MAGIC = b"PK\x03\x04"
CLR_DIRECTORY_INDEX = 14  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR runtime header)


def classify(data: bytes) -> str:
    head = data[:4]
    if head == ELF_MAGIC:
        return "elf"
    if head in MACHO_MAGICS:
        return "macho"
    if head == CAFEBABE:
        # Fat Mach-O stores a small architecture count here; a Java class stores its
        # minor/major version (major is at least 45), so the threshold separates them.
        nfat = struct.unpack(">I", data[4:8])[0] if len(data) >= 8 else 0
        return "macho-fat" if 0 < nfat < 32 else "java-class"
    if data[:2] == b"MZ":
        return "pe"
    if head == ZIP_MAGIC:
        return "zip-archive"
    if data[:2] == b"#!":
        return "script"
    return "unknown"


def pe_has_clr_header(data: bytes) -> bool:
    """True when a PE image carries a CLR (.NET managed) header, i.e. it is IL, not native code."""
    if len(data) < 0x40:
        raise ValueError("truncated MZ header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("MZ header without a valid PE signature")
    optional = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:  # PE32
        dirs = optional + 96
    elif magic == 0x20B:  # PE32+
        dirs = optional + 112
    else:
        raise ValueError(f"unknown optional header magic 0x{magic:x}")
    count = struct.unpack_from("<I", data, dirs - 4)[0]
    if count <= CLR_DIRECTORY_INDEX:
        return False
    rva, size = struct.unpack_from("<II", data, dirs + CLR_DIRECTORY_INDEX * 8)
    return rva != 0 or size != 0


def check(path: Path) -> tuple:
    """Return (ok, message) for one file."""
    if not path.is_file():
        return False, "not a file"
    with path.open("rb") as handle:
        header = handle.read(HEADER_BYTES)
    if not header:
        return False, "empty file"
    kind = classify(header)
    if kind in ("elf", "macho", "macho-fat"):
        return True, f"native ({kind})"
    if kind == "pe":
        try:
            managed = pe_has_clr_header(header)
        except (ValueError, struct.error) as error:
            return False, f"invalid PE image: {error}"
        if managed:
            return False, "managed .NET (IL) assembly, not native code"
        return True, "native (pe)"
    if kind == "java-class":
        return False, "Java class file (bytecode)"
    if kind == "zip-archive":
        return False, "ZIP/JAR archive (bytecode bundle), not an executable"
    if kind == "script":
        return False, "script, not a compiled executable"
    return False, "unrecognised format, not a native executable"


def self_test() -> int:
    def pe(managed: bool) -> bytes:
        buf = bytearray(0x200)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 0x80)
        buf[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", buf, 0x84 + 16, 0xF0)
        struct.pack_into("<H", buf, 0x98, 0x20B)  # PE32+
        dirs = 0x98 + 112
        struct.pack_into("<I", buf, dirs - 4, 16)
        if managed:
            struct.pack_into("<II", buf, dirs + CLR_DIRECTORY_INDEX * 8, 0x2000, 0x48)
        return bytes(buf)

    cases = [
        ("elf", b"\x7fELF" + b"\0" * 60, True),
        ("mach-o 64 little-endian", b"\xcf\xfa\xed\xfe" + b"\0" * 60, True),
        ("mach-o fat (2 archs)", b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\0" * 60, True),
        ("pe native", pe(managed=False), True),
        ("pe managed (.NET IL)", pe(managed=True), False),
        ("java class (major 65)", b"\xca\xfe\xba\xbe\0\0\0\x41" + b"\0" * 60, False),
        ("jar / zip", b"PK\x03\x04" + b"\0" * 60, False),
        ("shell script", b"#!/bin/sh\necho hi\n", False),
        ("unknown bytes", b"hello world, not a binary", False),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, payload, expect_ok in cases:
            path = Path(tmp) / label.replace(" ", "_").replace("/", "_")
            path.write_bytes(payload)
            ok, message = check(path)
            status = "ok" if ok == expect_ok else "WRONG"
            if ok != expect_ok:
                failures += 1
            print(f"self-test {status}: {label}: {message}")
    if failures:
        print(f"self-test failed: {failures} case(s)", file=sys.stderr)
        return 1
    print("self-test passed")
    return 0


def main(argv: list) -> int:
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    if argv == ["--self-test"]:
        return self_test()
    failures = 0
    for name in argv:
        ok, message = check(Path(name))
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {message}")
        if not ok:
            failures += 1
    if failures:
        print(f"{failures} file(s) are not native executables", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
