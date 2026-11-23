"""
Hand-packed Mach-O fixtures used by the slice pairing tests.

The fixtures are deliberately small.  They are assembled with ``struct.pack``
instead of invoking ``lipo``, ``otool`` or any other system tool, which keeps
the audit tests independent from the host platform.
"""

from __future__ import absolute_import

import os
import struct
import uuid

from macholib import mach_o

CPU_TYPE_ARM = 0x0000000C
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_POWERPC = 0x00000012

SUBTYPE_ARM_ALL = 0
SUBTYPE_ARM64_ALL = 0
SUBTYPE_X86_64_ALL = 3
SUBTYPE_POWERPC_ALL = 0

MH_EXECUTE = 0x2
MH_DSYM = 0xA

UUID_ARM64 = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes
UUID_X86_64 = uuid.UUID("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE").bytes
UUID_REPLACEMENT = uuid.UUID("99999999-8888-7777-6666-555555555555").bytes


def _align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def lc_uuid(raw_uuid, endian="<"):
    """Pack one LC_UUID command."""

    return struct.pack(endian + "II16s", mach_o.LC_UUID, 24, raw_uuid)


def lc_unknown(endian="<", payload=b"\x2a\x00\x00\x00"):
    """Pack a small unknown load command, useful for command offsets."""

    cmd = 0x707A11ED
    return struct.pack(
        endian + "II", cmd, 8 + len(payload)
    ) + payload


def pack_thin_macho(
    raw_uuid=None,
    cputype=CPU_TYPE_ARM64,
    cpusubtype=SUBTYPE_ARM64_ALL,
    commands=None,
    endian="<",
    bits=64,
    filetype=MH_EXECUTE,
    ncmds=None,
    sizeofcmds=None,
    trailing=b"",
):
    """
    Return a thin Mach-O byte string.

    ``ncmds`` and ``sizeofcmds`` can be overridden to create malformed
    material without changing the command bytes.  ``commands`` can be used
    when a test needs a command before LC_UUID.
    """

    if commands is None:
        commands = []
        if raw_uuid is not None:
            commands.append(lc_uuid(raw_uuid, endian))

    command_blob = b"".join(commands)
    actual_ncmds = len(commands)
    actual_sizeofcmds = len(command_blob)
    if ncmds is None:
        ncmds = actual_ncmds
    if sizeofcmds is None:
        sizeofcmds = actual_sizeofcmds

    if bits == 64:
        magic = mach_o.MH_MAGIC_64
        header_format = endian + "IiIIIIII"
        header_args = (
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            0,
            0,
        )
    else:
        magic = mach_o.MH_MAGIC
        header_format = endian + "IiIIIII"
        header_args = (
            magic,
            cputype,
            cpusubtype,
            filetype,
            ncmds,
            sizeofcmds,
            0,
        )

    return struct.pack(header_format, *header_args) + command_blob + trailing


def pack_fat_macho(architectures, fat64=False, align=4, endian=">"):
    """
    Return a fat Mach-O byte string.

    ``architectures`` is a list of mappings with ``cputype``, ``cpusubtype``
    and ``blob`` keys.  The fat_arch values are intentionally independent from
    the embedded header so that tests can build CPU mismatch cases.
    """

    arch_size = 32 if fat64 else 20
    magic = mach_o.FAT_MAGIC_64 if fat64 else mach_o.FAT_MAGIC
    header = struct.pack(endian + "II", magic, len(architectures))
    table_size = len(architectures) * arch_size
    cursor = _align_up(len(header) + table_size, 1 << align)

    entries = []
    placements = []
    for architecture in architectures:
        blob = architecture["blob"]
        offset = architecture.get("offset", cursor)
        size = architecture.get("size", len(blob))
        entry_align = architecture.get("align", align)
        entries.append(
            struct.pack(
                endian + ("iIQQII" if fat64 else "iIIII"),
                architecture["cputype"],
                architecture["cpusubtype"],
                offset,
                size,
                entry_align,
                *( (0,) if fat64 else () )
            )
        )
        placements.append((offset, blob))
        cursor = _align_up(offset + len(blob), 1 << align)

    out = bytearray(header + b"".join(entries))
    for offset, blob in placements:
        if len(out) < offset:
            out.extend(b"\x00" * (offset - len(out)))
        end = offset + len(blob)
        if len(out) < end:
            out.extend(b"\x00" * (end - len(out)))
        out[offset:end] = blob
    return bytes(out)


def _write(path, data):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "wb") as fp:
        fp.write(data)


def build_release_materials(
    root,
    swap=None,
    duplicate_archives=False,
    fat64=False,
):
    """
    Create a complete universal/archive/debug material set below *root*.

    ``swap`` can be ``"uuid"``, ``"truncate"``, ``"cpu"``, ``"no_uuid"`` or
    ``"fat_arch_cpu"``.  The returned mapping contains the created paths.
    """

    root = os.path.abspath(root)
    slice_specs = [
        {
            "name": "arm64",
            "uuid": UUID_ARM64,
            "cputype": CPU_TYPE_ARM64,
            "cpusubtype": SUBTYPE_ARM64_ALL,
        },
        {
            "name": "x86_64",
            "uuid": UUID_X86_64,
            "cputype": CPU_TYPE_X86_64,
            "cpusubtype": SUBTYPE_X86_64_ALL,
        },
    ]

    thin = {}
    for spec in slice_specs:
        thin[spec["name"]] = pack_thin_macho(
            spec["uuid"], spec["cputype"], spec["cpusubtype"]
        )

    fat_architectures = [
        {
            "cputype": spec["cputype"],
            "cpusubtype": spec["cpusubtype"],
            "blob": thin[spec["name"]],
        }
        for spec in slice_specs
    ]

    archive = {}
    for spec in slice_specs:
        archive[spec["name"]] = thin[spec["name"]]

    if swap == "uuid":
        archive["arm64"] = pack_thin_macho(
            UUID_REPLACEMENT,
            CPU_TYPE_ARM64,
            SUBTYPE_ARM64_ALL,
        )
    elif swap == "truncate":
        archive["arm64"] = thin["arm64"][:-8]
    elif swap == "cpu":
        archive["arm64"] = pack_thin_macho(
            UUID_ARM64,
            CPU_TYPE_ARM,
            SUBTYPE_ARM_ALL,
        )
    elif swap == "no_uuid":
        archive["arm64"] = pack_thin_macho(
            None,
            CPU_TYPE_ARM64,
            SUBTYPE_ARM64_ALL,
        )
    elif swap == "fat_arch_cpu":
        for architecture in fat_architectures:
            if architecture["cputype"] == CPU_TYPE_ARM64:
                architecture["cputype"] = CPU_TYPE_X86_64
    elif swap == "uuid_conflict":
        archive["x86_64"] = pack_thin_macho(
            UUID_ARM64,
            CPU_TYPE_X86_64,
            SUBTYPE_X86_64_ALL,
        )
    elif swap == "universal_uuid":
        for architecture in fat_architectures:
            if architecture["cputype"] == CPU_TYPE_ARM64:
                architecture["blob"] = pack_thin_macho(
                    UUID_REPLACEMENT,
                    CPU_TYPE_ARM64,
                    SUBTYPE_ARM64_ALL,
                )
    elif swap is not None:
        raise ValueError("unknown swap mode: %r" % (swap,))

    universal_path = os.path.join(root, "Universal.bin")
    _write(universal_path, pack_fat_macho(fat_architectures, fat64=fat64))

    archive_paths = []
    for spec in slice_specs:
        path = os.path.join(root, "archive", spec["name"] + ".bin")
        _write(path, archive[spec["name"]])
        archive_paths.append(path)
    if duplicate_archives:
        path = os.path.join(root, "archive", "arm64-copy.bin")
        _write(path, archive["arm64"])
        archive_paths.append(path)

    debug_paths = []
    for spec in slice_specs:
        path = os.path.join(root, "debug", spec["name"] + ".dSYM")
        _write(
            path,
            pack_thin_macho(
                spec["uuid"],
                spec["cputype"],
                spec["cpusubtype"],
                filetype=MH_DSYM,
            ),
        )
        debug_paths.append(path)

    return {
        "universal": universal_path,
        "archive": archive_paths,
        "debug": debug_paths,
        "thin": thin,
    }
