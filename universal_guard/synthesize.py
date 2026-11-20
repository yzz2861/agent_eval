"""Synthetic Mach-O / universal artifact builder and min-os rewriter.

The builder emits minimal but spec-conformant 64-bit Mach-O images: a
mach_header_64, one unreadable __TEXT segment, LC_BUILD_VERSION and an
LC_CODE_SIGNATURE pointing at a hand-built SuperBlob + CodeDirectory.
macholib parses these images exactly like a real release artifact, which
makes them deterministic fixtures for release-gate tests.
"""

import struct

from macholib import mach_o

from .models import OSVersion
from .parsing import parse_artifact

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = mach_o.LC_SEGMENT_64
LC_BUILD_VERSION = mach_o.LC_BUILD_VERSION
LC_CODE_SIGNATURE = mach_o.LC_CODE_SIGNATURE
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSSLOT_CODEDIRECTORY = 0
CS_ADHOC = 0x2
CS_RUNTIME = 0x4000
CS_KILL = 0x100000
FAT_MAGIC = mach_o.FAT_MAGIC


def _pack_version(version):
    version = OSVersion.parse(version)
    return version.packed


def _build_code_directory(flags, team_id=None):
    # 0x20400 scalar header is 52 bytes (nine uint32 fields, four hash
    # descriptor bytes, then spare2/spare3/teamOffset uint32 fields).
    # The string area with identifier and optional team id follows at 52.
    identifier = b"com.universal-guard.synthetic\x00"
    team_bytes = (team_id.encode("utf-8") + b"\x00") if team_id else b""
    string_area = identifier + team_bytes
    ident_offset = 52
    team_offset = ident_offset + len(identifier) if team_id else 0
    header = struct.pack(
        ">IIIIIIIIIBBBBIII",
        CSMAGIC_CODEDIRECTORY,
        0,                      # length, patched below
        0x20400,
        flags,
        0,                      # hashOffset
        ident_offset,
        0,                      # nSpecialSlots
        0,                      # nCodeSlots
        0,                      # codeLimit
        0,                      # hashSize (no code slots)
        2,                      # hashType = SHA-256
        0,                      # platform
        0,                      # pageSize
        0,                      # spare2 at byte 40
        0,                      # spare3 at byte 44
        team_offset,            # teamOffset at byte 48
    )
    body = header + string_area
    body = body[:4] + struct.pack(">I", len(body)) + body[8:]
    return body


def _build_signature_blob(flags, team_id=None):
    codedirectory = _build_code_directory(flags, team_id=team_id)
    super_header = struct.pack(
        ">III", CSMAGIC_EMBEDDED_SIGNATURE, 0, 1
    )
    cd_offset = len(super_header) + 8
    blob_index = struct.pack(
        ">II", CSSLOT_CODEDIRECTORY, cd_offset
    )
    blob = super_header + blob_index + codedirectory
    blob = blob[:4] + struct.pack(">I", len(blob)) + blob[8:]
    return blob



def build_slice(
    cpu_type,
    cpu_subtype,
    platform,
    min_os,
    sdk=None,
    code_signature_flags=None,
    include_signature=True,
    team_id=None,
):
    sdk = sdk or min_os
    signature = (
        _build_signature_blob(code_signature_flags or 0, team_id=team_id)
        if include_signature
        else b""
    )

    ncmds = 3 if include_signature else 2
    mach_header = struct.pack(
        ">IiiIIIII",
        MH_MAGIC_64,
        cpu_type,
        cpu_subtype,
        mach_o.MH_EXECUTE,
        ncmds,
        0,                          # sizeofcmds, patched below
        mach_o.MH_PIE | mach_o.MH_NO_HEAP_EXECUTION,
        0,                          # reserved
    )
    segment = struct.pack(
        ">II16sQQQQiiII",
        LC_SEGMENT_64,
        72,                         # cmdsize
        b"__TEXT\x00" + b"\x00" * 9,
        0,                          # vmaddr
        0x1000,                     # vmsize
        0,                          # fileoff
        0,                          # filesize
        0x5,                        # maxprot r-x
        0x5,                        # initprot r-x
        0,                          # nsects
        0,                          # flags
    )
    build_version = struct.pack(
        ">IIIIII",
        LC_BUILD_VERSION,
        32,                         # cmdsize incl. one build_tool_version
        platform,
        _pack_version(min_os),
        _pack_version(sdk),
        1,                          # ntools
    ) + struct.pack(">II", 0, 0)
    if include_signature:
        # Place the signature at the next 16-byte boundary after the header.
        header_size = len(mach_header) + len(segment) + len(build_version) + 16
        dataoff = (header_size + 15) & ~15  # noqa: E501
        code_signature = struct.pack(
            ">IIII", LC_CODE_SIGNATURE, 16, dataoff, len(signature)
        )
    else:
        dataoff = 0
        code_signature = b""

    commands = segment + build_version + code_signature
    sizeofcmds = len(commands)
    mach_header = mach_header[:20] + struct.pack(
        ">I", sizeofcmds
    ) + mach_header[24:]
    image = mach_header + commands
    if include_signature:
        image = image.ljust(dataoff, b"\x00") + signature
    return image



def _align_shift(size):
    shift = 0
    alignment = 1
    while alignment < size and shift < 15:
        alignment <<= 1
        shift += 1
    return shift


def build_fat(slice_specs):
    slices = [build_slice(**spec) for spec in slice_specs]
    count = len(slices)
    header_size = 8 + count * 20
    offset = header_size
    entries = []
    bodies = []
    for spec, image in zip(slice_specs, slices):
        align = _align_shift(len(image))
        aligned_offset = (offset + (1 << align) - 1) & ~((1 << align) - 1)
        padding = aligned_offset - offset
        if padding:
            bodies.append(b"\x00" * padding)
        entries.append(
            struct.pack(
                ">IIIII",
                spec["cpu_type"],
                spec["cpu_subtype"],
                aligned_offset,
                len(image),
                align,
            )
        )
        bodies.append(image)
        offset = aligned_offset + len(image)
    fat_header = struct.pack(">II", FAT_MAGIC, count)
    return fat_header + b"".join(entries) + b"".join(bodies)


def write_synthetic_universal(path, slice_specs):
    data = build_fat(slice_specs)
    with open(path, "wb") as handle:
        handle.write(data)
    return data


def build_synthetic_universal(slice_specs):
    return build_fat(slice_specs)



def rewrite_minimum_os(
    image,
    new_min_os,
    cpu_type=None,
    cpu_subtype=None,
):
    """Rewrite the minimum OS declaration of one or every slice.

    Returns a new byte string. Raises ValueError when the target slice
    uses a legacy LC_VERSION_MIN_* command or no matching slice is found.
    """
    artifact = parse_artifact(image)
    data = bytearray(image)
    packed = _pack_version(new_min_os)
    matched = False

    for slc in artifact.slices:
        if cpu_type is not None and slc.cpu_type != cpu_type:
            continue
        if (
            cpu_subtype is not None
            and slc.architecture.masked_subtype
            != (cpu_subtype & 0x0FFFFFFF)
        ):
            continue
        if slc.platform is None:
            raise ValueError(
                "slice %d has no platform declaration" % slc.index
            )
        if slc.platform.source_command != "LC_BUILD_VERSION":
            raise ValueError(
                "slice %d uses %s; only LC_BUILD_VERSION is rewritable"
                % (slc.index, slc.platform.source_command)
            )
        command_offset = _find_build_version_offset(data, slc.fat_offset)
        # build_version_command: cmd(0) cmdsize(4) platform(8) minos(12)
        field_offset = slc.fat_offset + command_offset + 12
        struct.pack_into(">I", data, field_offset, packed)
        matched = True

    if not matched:
        raise ValueError("no slice matched the requested architecture")
    return bytes(data)




def _find_build_version_offset(data, slice_offset):
    magic = int.from_bytes(data[slice_offset:slice_offset + 4], "big")
    if magic in (mach_o.MH_MAGIC_64, mach_o.MH_CIGAM_64):
        header_size = 32
    else:
        header_size = 28
    ncmds = struct.unpack_from(">I", data, slice_offset + 16)[0]
    position = slice_offset + header_size
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(">II", data, position)
        if cmd == LC_BUILD_VERSION:
            return position - slice_offset
        position += cmdsize
    raise ValueError("LC_BUILD_VERSION not found in slice")


def rewrite_file_minimum_os(
    input_path,
    output_path,
    new_min_os,
    cpu_type=None,
    cpu_subtype=None,
):
    with open(input_path, "rb") as handle:
        image = handle.read()
    rewritten = rewrite_minimum_os(
        image,
        new_min_os,
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
    )
    with open(output_path, "wb") as handle:
        handle.write(rewritten)
    return rewritten
