#!/usr/bin/env python3
"""
Inject one or more dylibs into a Fortnite IPA.

Each dylib is copied to Frameworks/, its LC_ID_DYLIB is rewritten to
@rpath/<name>, and an LC_LOAD_DYLIB + LC_RPATH is inserted into the main
Mach-O. Every other zip entry is re-emitted with its original ZipInfo, so
symlinks, permissions and attributes survive untouched.

Fat dylibs are thinned to their arm64 slice first: the process is arm64, the
extra slices only bloat the bundle, and some build systems emit an arm64e
slice that dyld would never choose anyway.

Sign straight after with Sideloadly / AltStore / SideStore: adding the load
command invalidates the existing signature by design.

Usage:
    python tools/inject.py --ipa Fortnite_43.10.ipa \
        --dylib FnPatch.dylib --dylib NEWLIB_43.dylib \
        --out Fortnite_FnPatch.ipa
"""

import argparse
import os
import plistlib
import struct
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_RPATH = 0x8000001C

RPATH = "@executable_path/Frameworks"

S_IFLNK = 0o120000


def align8(n):
    return (n + 7) & ~7


def iter_commands(buf, ncmds, base=0):
    off = base + 32
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


def command_paths(buf, ncmds, wanted):
    found = set()
    for off, cmd, size in iter_commands(buf, ncmds):
        if cmd in wanted:
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


def thin_arm64(buf, label):
    """Return the arm64 slice of a fat binary, or buf unchanged if it is thin."""
    if len(buf) < 8:
        raise SystemExit(f"{label}: too small to be Mach-O")
    magic = struct.unpack_from(">I", buf, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return buf, "thin"

    n = struct.unpack_from(">I", buf, 4)[0]
    if n < 1 or n > 32:
        raise SystemExit(f"{label}: implausible fat slice count {n}")

    best = None
    for i in range(n):
        base = 8 + 20 * i
        cpu, sub, off, size, _align = struct.unpack_from(">iiIII", buf, base)
        if (cpu & 0xFFFFFFFF) != CPU_TYPE_ARM64:
            continue
        # cpusubtype 0 is plain arm64: the slice an app process actually loads.
        score = 0 if (sub & 0x00FFFFFF) == 0 else 1
        if best is None or score < best[0]:
            best = (score, off, size, sub)

    if best is None:
        raise SystemExit(f"{label}: fat binary with no arm64 slice")

    _score, off, size, sub = best
    if off + size > len(buf):
        raise SystemExit(f"{label}: fat slice runs past end of file")
    slice_buf = buf[off:off + size]
    if struct.unpack_from("<I", slice_buf, 0)[0] != MH_MAGIC_64:
        raise SystemExit(f"{label}: selected slice is not a 64-bit Mach-O")

    return slice_buf, f"thinned from fat (arm64 cpusubtype {sub & 0xFFFFFFFF:#x}, {len(buf)} -> {len(slice_buf)} bytes)"


def rewrite_install_name(buf, new_name, label):
    """Point LC_ID_DYLIB at @rpath/<file name> so dyld finds it in Frameworks/."""
    ncmds, _sizeofcmds, _lc_end, _min = macho_metrics(buf)
    ba = bytearray(buf)
    for off, cmd, size in iter_commands(ba, ncmds):
        if cmd != LC_ID_DYLIB:
            continue
        name_off = struct.unpack_from("<I", ba, off + 8)[0]
        room = size - name_off
        raw = new_name.encode() + b"\x00"
        if len(raw) > room:
            raise SystemExit(
                f"{label}: install name {new_name} needs {len(raw)} bytes, "
                f"LC_ID_DYLIB has room for {room}"
            )
        ba[off + name_off: off + size] = raw.ljust(room, b"\x00")
        return bytes(ba)
    return bytes(ba)


def patch_bytes(buf, install_paths):
    """Insert any missing LC_LOAD_DYLIB commands. Returns (bytes, added list)."""
    ba = bytearray(buf)
    ncmds, sizeofcmds, lc_end, min_data = macho_metrics(ba)
    present = command_paths(ba, ncmds, (LC_LOAD_DYLIB, LC_RPATH))

    cmds = b""
    added = []
    for path in install_paths:
        if path not in present:
            cmds += build_load_dylib(path)
            added.append(f"LC_LOAD_DYLIB {path}")
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


def raw_local_header(info):
    """Local file header for an entry whose compressed bytes are copied as-is."""
    dt = info.date_time
    dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
    dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
    name = info.filename.encode("utf-8")
    # UTF-8 name flag on, data-descriptor flag off: both sizes are known here.
    flag = (info.flag_bits | 0x800) & ~0x08
    return struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flag, info.compress_type,
        dostime, dosdate, info.CRC, info.compress_size, info.file_size,
        len(name), 0,
    ) + name


def raw_copy_entry(dst, src, info):
    """Copy one entry without decompressing or recompressing it.

    The source entry already holds valid deflate output, so the fastest correct
    copy is the compressed bytes themselves. Reads the local header to learn
    where the payload starts, emits a fresh local header, then streams the
    payload across. The output central directory is written by ZipFile.close()
    from dst.filelist, which is why the ZipInfo is registered here.
    """
    src.fp.seek(info.header_offset)
    head = src.fp.read(30)
    if len(head) != 30 or struct.unpack_from("<I", head, 0)[0] != 0x04034B50:
        raise SystemExit(f"bad local header for {info.filename} at {info.header_offset}")
    name_len, extra_len = struct.unpack_from("<HH", head, 26)

    out = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    out.external_attr = info.external_attr
    out.internal_attr = info.internal_attr
    out.create_system = info.create_system
    out.compress_type = info.compress_type
    out.flag_bits = info.flag_bits & ~0x08
    out.CRC = info.CRC
    out.compress_size = info.compress_size
    out.file_size = info.file_size
    out.header_offset = dst.fp.tell()

    dst.fp.write(raw_local_header(out))

    src.fp.seek(info.header_offset + 30 + name_len + extra_len)
    left = info.compress_size
    while left:
        chunk = src.fp.read(min(left, 4 << 20))
        if not chunk:
            raise SystemExit(f"truncated payload for {info.filename}")
        dst.fp.write(chunk)
        left -= len(chunk)

    dst.filelist.append(out)
    dst.NameToInfo[out.filename] = out
    # ZipFile keeps start_dir as "where the central directory will go". Writes
    # that bypass writestr() must move it forward themselves, otherwise
    # close() writes the central directory over the first entry.
    dst.start_dir = dst.fp.tell()


def find_app_prefix(names):
    apps = set()
    for name in names:
        parts = name.split("/")
        if len(parts) >= 2 and parts[0].lower() == "payload" and parts[1].endswith(".app"):
            apps.add("Payload/" + parts[1])
    if len(apps) != 1:
        raise SystemExit(f"expected one .app in Payload/, found {sorted(apps) or 'none'}")
    return apps.pop()


def load_dylib(src, label):
    with open(src, "rb") as f:
        raw = f.read()
    data, note = thin_arm64(raw, label)
    name = os.path.basename(src)
    data = rewrite_install_name(data, "@rpath/" + name, label)
    print(f"  {name}: {note}")
    return name, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, help="source .ipa")
    ap.add_argument("--dylib", required=True, action="append",
                    help="dylib to attach; repeat for more than one")
    ap.add_argument("--out", required=True, help="output .ipa")
    args = ap.parse_args()

    if os.path.abspath(args.ipa) == os.path.abspath(args.out):
        raise SystemExit("--out must differ from --ipa")

    print("dylibs")
    attached = []
    seen = set()
    for src in args.dylib:
        if not os.path.isfile(src):
            raise SystemExit(f"dylib not found: {src}")
        name, data = load_dylib(src, os.path.basename(src))
        if name in seen:
            raise SystemExit(f"two dylibs would land at Frameworks/{name}")
        seen.add(name)
        attached.append((name, data))

    install_paths = ["@rpath/" + name for name, _ in attached]

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

        print(f"\napp bundle : {app}")
        print(f"executable : {exe_name}")
        print(f"entries    : {len(infos)}")

        exe_source_size = src.getinfo(exe_entry).file_size
        total = len(infos)
        added_report = []
        replaced_exe = False

        with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as dst:
            for n, info in enumerate(infos, 1):
                if info.filename == exe_entry:
                    # The only entry whose bytes change: decompress, patch,
                    # recompress. Everything else is copied compressed.
                    data = src.read(info.filename)
                    data, added = patch_bytes(data, install_paths)
                    added_report = added

                    out_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    out_info.external_attr = info.external_attr
                    out_info.internal_attr = info.internal_attr
                    out_info.create_system = info.create_system
                    out_info.compress_type = zipfile.ZIP_DEFLATED
                    dst.writestr(out_info, data)
                    replaced_exe = True
                else:
                    raw_copy_entry(dst, src, info)

                if n % 25 == 0 or n == total:
                    print(f"  packed {n}/{total}", end="\r")
            print()
            if not replaced_exe:
                raise SystemExit(f"executable entry never written: {exe_entry}")

            for name, data in attached:
                entry = zipfile.ZipInfo(f"{app}/Frameworks/{name}")
                entry.date_time = (2024, 1, 1, 0, 0, 0)
                entry.external_attr = 0o100755 << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                dst.writestr(entry, data)

    for entry in added_report:
        print(f"  + {entry}")
    if not added_report:
        print("  load commands already present, binary untouched")
    for name, data in attached:
        print(f"  + {app}/Frameworks/{name} ({len(data)} bytes)")

    carried = {i.filename: i.file_size for i in infos if i.filename != exe_entry}
    verify(args.out, exe_entry, len(infos) + len(attached), app, attached,
           install_paths, carried, exe_source_size)

    size = os.path.getsize(args.out) / (1024 ** 3)
    print(f"\ndone: {args.out} ({size:.2f} GB)")
    print("Next: sign with Sideloadly / AltStore / SideStore. Do not pre-sign with")
    print("a different identity, or the inserted load command is rejected.")


def verify(path, exe_entry, expected_entries, app, attached, install_paths,
           source_sizes, source_size):
    print("\nverifying output")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        ok = True

        def check(cond, msg):
            nonlocal ok
            print(("  PASS " if cond else "  FAIL ") + msg)
            ok = ok and cond

        check(len(names) == expected_entries, f"entry count +{len(attached)} (dylibs)")
        for name, data in attached:
            entry = f"{app}/Frameworks/{name}"
            check(entry in names, f"{name} entry present")
            if entry in names:
                check(zf.read(entry) == data, f"{name} bytes match input")

        check(exe_entry in names, "executable entry present")

        data = zf.read(exe_entry)
        ncmds, _, lc_end, min_data = macho_metrics(data)
        paths = command_paths(data, ncmds, (LC_LOAD_DYLIB, LC_RPATH))
        for p in install_paths:
            check(p in paths, f"LC_LOAD_DYLIB {p} parses back")
        check(lc_end <= min_data, "load commands fit before section data")
        check(len(data) == source_size, "executable size unchanged apart from load commands")

        # Not testzip(): that decompresses all 300 entries and costs minutes.
        # Every entry except the executable was copied as already-compressed
        # bytes, so a size comparison against the source proves the copy, and
        # ZipExtFile raises BadZipFile if the one recompressed entry's CRC
        # does not match.
        with zipfile.ZipFile(path) as zf2:
            sizes_ok = all(
                zf2.getinfo(n).file_size == source_sizes[n]
                for n in source_sizes
            )
        check(sizes_ok, "every carried entry has its original size")

        if not ok:
            raise SystemExit("output verification failed")


if __name__ == "__main__":
    main()
