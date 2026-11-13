#!/usr/bin/env python3
"""Verifies load-command insertion against a synthetic arm64 Mach-O."""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import inject  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print(f"FAIL {msg}")


def build_macho(section_offset):
    seg = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64, 72 + 80, b"__TEXT\x00",
        0x100000000, 0x1000, 0x0, section_offset,
        5, 5, 1, 0,
    )
    sect = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\x00", b"__TEXT\x00",
        0x100000000, 0x10, section_offset, 4, 0, 0, 0x80000400, 0, 0, 0,
    )
    sizeofcmds = len(seg) + len(sect)
    hdr = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2, 1, sizeofcmds, 0, 0)
    body = bytearray(max(section_offset, 32 + sizeofcmds))
    body[: len(hdr)] = hdr
    body[32: 32 + len(seg)] = seg
    body[32 + len(seg): 32 + sizeofcmds] = sect
    return bytes(body), sizeofcmds


def parse(buf):
    _magic, _cpu, _sub, _ft, ncmds, sizeofcmds, _fl, _r = struct.unpack_from("<IiiIIIII", buf, 0)
    names = []
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", buf, off)
        if cmd in (inject.LC_LOAD_DYLIB, inject.LC_RPATH):
            noff = struct.unpack_from("<I", buf, off + 8)[0]
            names.append(buf[off + noff: off + size].split(b"\x00")[0].decode())
        off += size
    return ncmds, sizeofcmds, names


def test_happy_path():
    data, sizeofcmds = build_macho(0x1000)
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "binary")
        with open(path, "wb") as f:
            f.write(data)

        inject.patch_binary(path)

        with open(path, "rb") as f:
            out = f.read()

        check(len(out) == len(data), "file size unchanged")
        ncmds, new_sizeofcmds, names = parse(out)
        check(ncmds == 3, f"ncmds 3 (got {ncmds})")
        check(new_sizeofcmds > sizeofcmds, "sizeofcmds grew")
        check(inject.DYLIB_INSTALL in names, "LC_LOAD_DYLIB present")
        check(inject.RPATH in names, "LC_RPATH present")
        check(out[0:4] == struct.pack("<I", MH_MAGIC_64), "magic intact")

        # Section data must not have been touched.
        check(out[0x1000:] == data[0x1000:], "section payload untouched")

        # Running it twice must not double the commands.
        inject.patch_binary(path)
        with open(path, "rb") as f:
            again = f.read()
        ncmds2, _, names2 = parse(again)
        check(ncmds2 == 3, f"idempotent ncmds (got {ncmds2})")
        check(len(names2) == 2, f"idempotent command count (got {len(names2)})")


def test_no_room():
    data, sizeofcmds = build_macho(32 + 152)
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "tight")
        with open(path, "wb") as f:
            f.write(data)
        try:
            inject.patch_binary(path)
        except SystemExit as exc:
            check("not enough header padding" in str(exc), "clear failure message")
        else:
            failures.append("tight binary should have been refused")
            print("FAIL tight binary accepted")


if __name__ == "__main__":
    test_happy_path()
    test_no_room()
    if failures:
        print(f"\n{len(failures)} failure(s)")
        sys.exit(1)
    print("injector checks passed")
