#!/usr/bin/env python3
"""
Inject FnPatch.dylib into a Fortnite IPA.

Adds Frameworks/FnPatch.dylib and inserts LC_LOAD_DYLIB + LC_RPATH into the main
Mach-O. Sign straight after with Sideloadly / AltStore / ldid -- the existing
signature is invalidated by design.

Usage:
    python tools/inject.py --ipa Fortnite_43.10.ipa --dylib FnPatch.dylib \
                           --out Fortnite_FnPatch.ipa
"""

import argparse
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_RPATH = 0x8000001C

DYLIB_NAME = "FnPatch.dylib"
DYLIB_INSTALL = "@rpath/" + DYLIB_NAME
RPATH = "@executable_path/Frameworks"


def align8(n):
    return (n + 7) & ~7


def iter_commands(buf, ncmds):
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", buf, off)
        yield off, cmd, size
        if size < 8:
            raise ValueError(f"corrupt load command at {off:#x}")
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


def build_load_dylib(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    size = align8(24 + len(raw))
    out = struct.pack("<IIIIII", LC_LOAD_DYLIB, size, 24, 2, 0x10000, 0x10000)
    return out + raw.ljust(size - 24, b"\x00")


def build_rpath(path: str) -> bytes:
    raw = path.encode() + b"\x00"
    size = align8(12 + len(raw))
    out = struct.pack("<III", LC_RPATH, size, 12)
    return out + raw.ljust(size - 12, b"\x00")


def patch_binary(path: str) -> None:
    with open(path, "rb") as f:
        buf = bytearray(f.read())

    ncmds, sizeofcmds, lc_end, min_data = macho_metrics(buf)
    present = existing_paths(buf, ncmds)

    cmds = b""
    added = []
    if DYLIB_INSTALL not in present:
        cmds += build_load_dylib(DYLIB_INSTALL)
        added.append(f"LC_LOAD_DYLIB {DYLIB_INSTALL}")
    if RPATH not in present:
        cmds += build_rpath(RPATH)
        added.append(f"LC_RPATH {RPATH}")

    if not cmds:
        print("  load commands already present, binary untouched")
        return

    if min_data is None:
        raise SystemExit("cannot determine first section offset")
    space = min_data - lc_end
    if space < len(cmds):
        raise SystemExit(
            f"not enough header padding: need {len(cmds)} bytes at {lc_end:#x}, "
            f"have {space} before first section {min_data:#x}"
        )

    buf[lc_end:lc_end + len(cmds)] = cmds
    struct.pack_into("<II", buf, 16, ncmds + len(added), sizeofcmds + len(cmds))

    with open(path, "wb") as f:
        f.write(buf)

    for entry in added:
        print(f"  + {entry}")


def find_app_root(root: str) -> str:
    payload = os.path.join(root, "Payload")
    if not os.path.isdir(payload):
        raise SystemExit("Payload/ missing -- not an IPA")
    apps = [d for d in os.listdir(payload) if d.endswith(".app")]
    if len(apps) != 1:
        raise SystemExit(f"expected one .app in Payload, found {apps}")
    return os.path.join(payload, apps[0])


def bundle_executable(app_dir: str) -> str:
    with open(os.path.join(app_dir, "Info.plist"), "rb") as f:
        plist = plistlib.load(f)
    exe = plist.get("CFBundleExecutable")
    if not exe:
        raise SystemExit("Info.plist has no CFBundleExecutable")
    return os.path.join(app_dir, exe)


def repack(root: str, out_path: str) -> None:
    if os.path.exists(out_path):
        os.remove(out_path)
    names = []
    for base, _dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            names.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    names.sort(key=lambda x: (not x[0].endswith(".app/Info.plist"), x[0]))

    total = len(names)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for i, (arc, full) in enumerate(names, 1):
            z.write(full, arc)
            if i % 50 == 0 or i == total:
                print(f"  packed {i}/{total}", end="\r")
    print()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, help="source .ipa")
    ap.add_argument("--dylib", required=True, help="built FnPatch.dylib")
    ap.add_argument("--out", required=True, help="output .ipa")
    ap.add_argument("--keep", action="store_true", help="keep the extracted tree")
    args = ap.parse_args()

    if not os.path.isfile(args.dylib):
        raise SystemExit(f"dylib not found: {args.dylib}")

    work = tempfile.mkdtemp(prefix="fnpatch_")
    try:
        print(f"[1/5] extracting {os.path.basename(args.ipa)}")
        with zipfile.ZipFile(args.ipa) as z:
            z.extractall(work)

        app = find_app_root(work)
        exe = bundle_executable(app)
        print(f"[2/5] app bundle: {os.path.basename(app)}")
        print(f"      executable: {os.path.basename(exe)}")

        fw = os.path.join(app, "Frameworks")
        os.makedirs(fw, exist_ok=True)
        dest = os.path.join(fw, DYLIB_NAME)
        shutil.copy2(args.dylib, dest)
        print(f"[3/5] copied dylib -> Frameworks/{DYLIB_NAME}")

        print("[4/5] patching load commands")
        patch_binary(exe)

        print(f"[5/5] repacking -> {args.out}")
        repack(work, args.out)
    finally:
        if args.keep:
            print(f"extracted tree kept at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    size = os.path.getsize(args.out) / (1024 ** 3)
    print(f"done: {args.out} ({size:.2f} GB)")
    print()
    print("Next: sign it with Sideloadly / AltStore / SideStore.")
    print("Sideloadly signs the main binary and every nested dylib; do not")
    print("pre-sign with a different identity or the load will be rejected.")


if __name__ == "__main__":
    main()
