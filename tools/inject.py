#!/usr/bin/env python3
"""
Inject FnPatch.dylib into a Fortnite IPA.

Copies the dylib to Frameworks/ and inserts LC_LOAD_DYLIB + LC_RPATH into the
main Mach-O. Every other zip entry is re-emitted with its original ZipInfo, so
symlinks, permissions and attributes survive untouched.

Sign straight after with Sideloadly / AltStore / SideStore: adding the load
command invalidates the existing signature by design.

Usage:
    python tools/inject.py --ipa Fortnite_43.10.ipa --dylib FnPatch.dylib \
                           --out Fortnite_FnPatch.ipa
"""

import argparse
import os
import plistlib
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_RPATH = 0x8000001C

DYLIB_NAME = "FnPatch.dylib"
DYLIB_INSTALL = "@rpath/" + DYLIB_NAME
RPATH = "@executable_path/Frameworks"

S_IFLNK = 0o120000


def align8(n):
    return (n + 7) & ~7


def iter_commands(buf, ncmds):
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", buf, off)
        if size < 8:
            raise ValueError(f"corrupt load command at {off:#x}")
        yield off, cmd, size
        off += size


def macho_metrics(buf):
    if len(buf) < 32:
        raise ValueError("file too small to be Mach-O")
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic != MH_MAGIC_64:
        raise ValueError(f"not a 64-bit Mach-O (magic {magic:#x})")
    _cpu, _sub, _ft, ncmds, sizeofcmds, _flags, _res = struct.unpack_from("<iiIIIII", buf, 4)
    lc_end = 32 + sizeofcmds

    min_data = None
    for off, cmd, _size in iter_commands(buf, ncmds):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from("<I", buf, off + 64)[0]
        for i in range(nsects):
            s = off + 72 + i * 80
            sect_off = struct.unpack_from("<I", buf, s + 48)[0]
            if sect_off and (min_data is None or sect_off < min_data):
                min_data = sect_off
    return ncmds, sizeofcmds, lc_end, min_data


def existing_paths(buf, ncmds):
    found = set()
    for off, cmd, size in iter_commands(buf, ncmds):
        if cmd in (LC_LOAD_DYLIB, LC_RPATH):
            name_off = struct.unpack_from("<I", buf, off + 8)[0]
            raw = buf[off + name_off: off + size].split(b"\x00")[0]
            found.add(raw.decode("utf-8", "replace"))
    return found


def build_load_dylib(path):
    raw = path.encode() + b"\x00"
    size = align8(24 + len(raw))
    out = struct.pack("<IIIIII", LC_LOAD_DYLIB, size, 24, 2, 0x10000, 0x10000)
    return out + raw.ljust(size - 24, b"\x00")


def build_rpath(path):
    raw = path.encode() + b"\x00"
    size = align8(12 + len(raw))
    out = struct.pack("<III", LC_RPATH, size, 12)
    return out + raw.ljust(size - 12, b"\x00")


def patch_bytes(buf):
    """Returns (patched bytes, list of added load command descriptions)."""
    ba = bytearray(buf)
    ncmds, sizeofcmds, lc_end, min_data = macho_metrics(ba)
    present = existing_paths(ba, ncmds)

    cmds = b""
    added = []
    if DYLIB_INSTALL not in present:
        cmds += build_load_dylib(DYLIB_INSTALL)
        added.append(f"LC_LOAD_DYLIB {DYLIB_INSTALL}")
    if RPATH not in present:
        cmds += build_rpath(RPATH)
        added.append(f"LC_RPATH {RPATH}")

    if not cmds:
        return bytes(ba), added

    if min_data is None:
        raise SystemExit("cannot determine first section offset")
    space = min_data - lc_end
    if space < len(cmds):
        raise SystemExit(
            f"not enough header padding: need {len(cmds)} bytes at {lc_end:#x}, "
            f"have {space} before first section {min_data:#x}"
        )

    ba[lc_end:lc_end + len(cmds)] = cmds
    struct.pack_into("<II", ba, 16, ncmds + len(added), sizeofcmds + len(cmds))
    return bytes(ba), added


def patch_binary(path):
    with open(path, "rb") as f:
        buf = f.read()
    out, added = patch_bytes(buf)
    if added:
        with open(path, "wb") as f:
            f.write(out)
    for entry in added:
        print(f"  + {entry}")
    if not added:
        print("  load commands already present, binary untouched")


def find_app_prefix(names):
    apps = set()
    for name in names:
        parts = name.split("/")
        if len(parts) >= 2 and parts[0].lower() == "payload" and parts[1].endswith(".app"):
            apps.add("Payload/" + parts[1])
    if len(apps) != 1:
        raise SystemExit(f"expected one .app in Payload/, found {sorted(apps) or 'none'}")
    return apps.pop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, help="source .ipa")
    ap.add_argument("--dylib", required=True, help="built FnPatch.dylib")
    ap.add_argument("--out", required=True, help="output .ipa")
    args = ap.parse_args()

    if not os.path.isfile(args.dylib):
        raise SystemExit(f"dylib not found: {args.dylib}")
    if os.path.abspath(args.ipa) == os.path.abspath(args.out):
        raise SystemExit("--out must differ from --ipa")

    with open(args.dylib, "rb") as f:
        dylib_bytes = f.read()

    if os.path.exists(args.out):
        os.remove(args.out)

    with zipfile.ZipFile(args.ipa) as src:
        infos = src.infolist()
        app = find_app_prefix([i.filename for i in infos])

        plist = plistlib.loads(src.read(app + "/Info.plist"))
        exe_name = plist.get("CFBundleExecutable")
        if not exe_name:
            raise SystemExit("Info.plist has no CFBundleExecutable")
        exe_entry = f"{app}/{exe_name}"

        if exe_entry not in src.namelist():
            raise SystemExit(f"executable entry missing: {exe_entry}")

        print(f"app bundle : {app}")
        print(f"executable : {exe_name}")
        print(f"entries    : {len(infos)}")

        total = len(infos)
        added_report = []

        with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as dst:
            for n, info in enumerate(infos, 1):
                data = src.read(info.filename)

                if info.filename == exe_entry:
                    data, added = patch_bytes(data)
                    added_report = added

                out_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                out_info.external_attr = info.external_attr
                out_info.internal_attr = info.internal_attr
                out_info.create_system = info.create_system
                out_info.compress_type = info.compress_type

                is_link = (info.external_attr >> 16) & 0o170000 == S_IFLNK
                if is_link:
                    out_info.compress_type = zipfile.ZIP_STORED

                dst.writestr(out_info, data)

                if n % 100 == 0 or n == total:
                    print(f"  packed {n}/{total}", end="\r")
            print()

            dest = f"{app}/Frameworks/{DYLIB_NAME}"
            link = zipfile.ZipInfo(dest)
            link.date_time = (2024, 1, 1, 0, 0, 0)
            link.external_attr = 0o100755 << 16
            link.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(link, dylib_bytes)

    for entry in added_report:
        print(f"  + {entry}")
    if not added_report:
        print("  load commands already present, binary untouched")
    print(f"  + {app}/Frameworks/{DYLIB_NAME}")

    verify(args.out, exe_entry, len(infos), app)

    size = os.path.getsize(args.out) / (1024 ** 3)
    print(f"\ndone: {args.out} ({size:.2f} GB)")
    print("Next: sign with Sideloadly / AltStore / SideStore. Do not pre-sign with")
    print("a different identity, or the inserted load command is rejected.")


def verify(path, exe_entry, expected_entries, app):
    print("\nverifying output")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        ok = True

        def check(cond, msg):
            nonlocal ok
            print(("  PASS " if cond else "  FAIL ") + msg)
            ok = ok and cond

        check(len(names) == expected_entries + 1, "entry count +1 (dylib)")
        check(f"{app}/Frameworks/{DYLIB_NAME}" in names, "dylib entry present")
        check(exe_entry in names, "executable entry present")

        data = zf.read(exe_entry)
        ncmds, _, lc_end, min_data = macho_metrics(data)
        paths = existing_paths(data, ncmds)
        check(DYLIB_INSTALL in paths, "LC_LOAD_DYLIB parses back")
        check(lc_end <= min_data, "load commands fit before section data")

        bad = zf.testzip()
        check(bad is None, f"zip integrity ({bad})")

        if not ok:
            raise SystemExit("output verification failed")


if __name__ == "__main__":
    main()
