
"""Pure-Python synthetic fat Mach-O generator for slice_diff tests.

The samples are deliberately minimal but parse with the real
:mod:`macholib` parser: a fat header, per-architecture slices containing a
mach_header_64, two LC_SEGMENT_64 commands, an LC_LOAD_DYLIB whose path the
packaging step rewrites and an LC_CODE_SIGNATURE anchor.  No native tooling
is involved, so the tests are platform independent.
"""

import struct

from macholib import mach_o

CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
SUBTYPE_ALL = 0

FAT_MAGIC = mach_o.FAT_MAGIC
MH_MAGIC_64 = mach_o.MH_MAGIC_64
LC_SEGMENT_64 = mach_o.LC_SEGMENT_64
LC_LOAD_DYLIB = mach_o.LC_LOAD_DYLIB
LC_CODE_SIGNATURE = mach_o.LC_CODE_SIGNATURE

_HEADER_64_SIZE = 32
_SEGMENT_64_SIZE = 72  # 8-byte load_command + 64-byte body
_SIGNATURE_SIZE = 16
FAT_ARCH_SIZE = 20
FAT_HEADER_SIZE = 8
FAT_ALIGN_SHIFT = 4  # 2**4 == 16 byte slice alignment
SLICE_ALIGNMENT = 1 << FAT_ALIGN_SHIFT


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _segment_command(name, vmaddr, vmsize, fileoff, filesize):
    raw = struct.pack(
        "=II16sQQQQiiII",
        LC_SEGMENT_64,
        _SEGMENT_64_SIZE,
        name.encode("ascii").ljust(16, b"\x00"),
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        7,
        5,
        0,
        0,
    )
    assert len(raw) == _SEGMENT_64_SIZE
    return raw


def _dylib_command(path):
    payload = path.encode("ascii") + b"\x00"
    fixed = 24
    cmdsize = _align(fixed + len(payload), 8)
    payload = payload.ljust(cmdsize - fixed, b"\x00")
    raw = struct.pack(
        "=IIIIII",
        LC_LOAD_DYLIB,
        cmdsize,
        fixed,
        2,
        0x10000,
        0x10000,
    )
    return raw + payload, cmdsize


def _signature_command(dataoff, datasize):
    return struct.pack(
        "=IIII",
        LC_CODE_SIGNATURE,
        _SIGNATURE_SIZE,
        dataoff,
        datasize,
    )


def build_slice(
    cputype,
    dylib_path,
    data_payload,
    signature_bytes,
    data_offset=None,
):
    """Build one little-endian 64-bit Mach-O slice.

    Layout: mach header + load commands, then a __TEXT segment covering the
    header area, a __DATA segment holding ``data_payload`` and finally the
    code signature blob.  When ``data_offset`` is given it overrides the
    natural placement to model an unexplained layout change.
    """
    dylib_raw, dylib_size = _dylib_command(dylib_path)
    commands_size = (
        _SEGMENT_64_SIZE * 2 + dylib_size + _SIGNATURE_SIZE
    )
    header_end = _HEADER_64_SIZE + commands_size

    natural_data_offset = _align(header_end, SLICE_ALIGNMENT)
    if data_offset is None:
        data_offset = natural_data_offset
    signature_offset = _align(
        data_offset + len(data_payload), SLICE_ALIGNMENT
    )
    slice_size = signature_offset + len(signature_bytes)

    text_size = natural_data_offset
    text_segment = _segment_command(
        "__TEXT", 0x100000000, text_size, 0, text_size
    )
    data_segment = _segment_command(
        "__DATA",
        0x100000000 + text_size,
        len(data_payload),
        data_offset,
        len(data_payload),
    )
    signature_command = _signature_command(
        signature_offset, len(signature_bytes)
    )

    header = struct.pack(
        "=IiiIIIII",
        MH_MAGIC_64,
        cputype,
        SUBTYPE_ALL,
        mach_o.MH_EXECUTE,
        4,
        commands_size,
        0,
        0,
    )
    assert len(header) == _HEADER_64_SIZE

    blob = bytearray(slice_size)
    cursor = 0
    for part in (
        header,
        text_segment,
        data_segment,
        dylib_raw,
        signature_command,
    ):
        blob[cursor : cursor + len(part)] = part
        cursor += len(part)
    blob[data_offset : data_offset + len(data_payload)] = data_payload
    blob[
        signature_offset : signature_offset + len(signature_bytes)
    ] = signature_bytes
    return bytes(blob), {
        "data_offset": data_offset,
        "natural_data_offset": natural_data_offset,
        "signature_offset": signature_offset,
        "header_end": header_end,
        "dylib_cmdsize": dylib_size,
        "slice_size": slice_size,
    }


def build_fat(slices):
    """Assemble (cputype, slice_bytes) pairs into a 32-bit fat file."""
    count = len(slices)
    header = struct.pack(">II", FAT_MAGIC, count)
    arch_table = bytearray(count * FAT_ARCH_SIZE)
    table_end = FAT_HEADER_SIZE + count * FAT_ARCH_SIZE
    first_offset = _align(table_end, SLICE_ALIGNMENT)
    body = bytearray(b"\x00" * (first_offset - table_end))
    cursor = first_offset
    for index, (cputype, slice_bytes) in enumerate(slices):
        offset = _align(cursor, SLICE_ALIGNMENT)
        padding = offset - cursor
        body.extend(b"\x00" * padding)
        body.extend(slice_bytes)
        entry = struct.pack(
            ">IIIII",
            cputype,
            SUBTYPE_ALL,
            offset,
            len(slice_bytes),
            FAT_ALIGN_SHIFT,
        )
        arch_table[
            index * FAT_ARCH_SIZE : (index + 1) * FAT_ARCH_SIZE
        ] = entry
        cursor = offset + len(slice_bytes)
    return bytes(header) + bytes(arch_table) + bytes(body)
