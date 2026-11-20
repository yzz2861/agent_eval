"""Mach-O / fat binary parsing built on top of macholib.

Parsing runs from an in-memory buffer and drives the structure classes and
``LC_REGISTRY`` shipped with :mod:macholib, so the same code path handles
files on disk, synthesized bytes and unit-test fixtures.
"""

import dataclasses
import hashlib
import io

from macholib import mach_o
from macholib.ptypes import sizeof

from . import codesig
from .models import (
    Architecture,
    OSVersion,
    CodeSignatureInfo,
    PlatformDeclaration,
    SliceInfo,
    UniversalArtifact,
)

VERSION_MIN_PLATFORMS = {
    mach_o.LC_VERSION_MIN_MACOSX: mach_o.PLATFORM_MACOS,
    mach_o.LC_VERSION_MIN_IPHONEOS: mach_o.PLATFORM_IOS,
    mach_o.LC_VERSION_MIN_TVOS: mach_o.PLATFORM_TVOS,
    mach_o.LC_VERSION_MIN_WATCHOS: mach_o.PLATFORM_WATCHOS,
}


def _decode_packed_version(value):
    value = int(value)
    return (
        (value >> 16) & 0xFFFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
    )


class _BufferReader(io.BytesIO):
    def read_exact(self, size):
        chunk = self.read(size)
        if len(chunk) != size:
            raise ValueError("truncated Mach-O image")
        return chunk

    def read_struct(self, structure, endian):
        return structure.from_fileobj(self, _endian_=endian)


def _parse_fat_entries(data):
    magic_value = int.from_bytes(data[:4], "big")
    if magic_value == mach_o.FAT_MAGIC:
        header = mach_o.fat_header.from_str(data[:8], _endian_=">")
        reader = _BufferReader(data)
        reader.seek(8)
        entries = [
            mach_o.fat_arch.from_fileobj(reader, _endian_=">")
            for _ in range(header.nfat_arch)
        ]
    elif magic_value == mach_o.FAT_MAGIC_64:
        header = mach_o.fat_header.from_str(data[:8], _endian_=">")
        reader = _BufferReader(data)
        reader.seek(8)
        entries = [
            mach_o.fat_arch64.from_fileobj(reader, _endian_=">")
            for _ in range(header.nfat_arch)
        ]
    else:
        return None
    return [
        (
            int(entry.cputype),
            int(entry.cpusubtype),
            int(entry.offset),
            int(entry.size),
            int(entry.align),
        )
        for entry in entries
    ]



def _parse_mach_header(slice_data):
    magic_bytes = slice_data[:4]
    big_magic = int.from_bytes(magic_bytes, "big")
    little_magic = int.from_bytes(magic_bytes, "little")
    if big_magic in (mach_o.MH_MAGIC, mach_o.MH_MAGIC_64):
        endian = ">"
        magic = big_magic
    elif little_magic in (mach_o.MH_MAGIC, mach_o.MH_MAGIC_64):
        # MH_CIGAM / MH_CIGAM_64 are the byte-swapped magic numbers, so a
        # little-endian slice reads as a normal magic under little endian.
        endian = "<"
        magic = little_magic
    else:
        raise ValueError(
            "not a Mach-O slice: magic=0x%08x" % big_magic
        )

    if magic in (mach_o.MH_MAGIC_64, mach_o.MH_CIGAM_64):
        header_class = mach_o.mach_header_64
    else:
        header_class = mach_o.mach_header
    header_size = sizeof(header_class)
    header = header_class.from_str(
        slice_data[:header_size], _endian_=endian
    )

    reader = _BufferReader(slice_data)
    reader.seek(header_size)
    commands = []
    for _ in range(header.ncmds):
        load = reader.read_struct(mach_o.load_command, endian)
        klass = mach_o.LC_REGISTRY.get(load.cmd)
        if klass is None:
            reader.read_exact(
                load.cmdsize - sizeof(mach_o.load_command)
            )
            continue
        command = reader.read_struct(klass, endian)
        consumed = sizeof(mach_o.load_command) + sizeof(klass)
        payload = reader.read_exact(load.cmdsize - consumed)
        commands.append((load, command, payload))
    return header, endian, commands


def _parse_platform_declaration(commands):
    for load, command, _payload in commands:
        if load.cmd == mach_o.LC_BUILD_VERSION:
            return PlatformDeclaration(
                platform=int(command.platform),
                platform_name=mach_o.PLATFORM_NAMES.get(
                    int(command.platform), str(int(command.platform))
                ),
                min_os=OSVersion(*_decode_packed_version(command.minos)),
                sdk=OSVersion(*_decode_packed_version(command.sdk)),
                source_command="LC_BUILD_VERSION",
            )
    for load, command, _payload in commands:
        if load.cmd in VERSION_MIN_PLATFORMS:
            platform = VERSION_MIN_PLATFORMS[load.cmd]
            return PlatformDeclaration(
                platform=platform,
                platform_name=mach_o.PLATFORM_NAMES.get(
                    platform, str(platform)
                ),
                min_os=OSVersion(*_decode_packed_version(command.version)),
                sdk=OSVersion(*_decode_packed_version(command.sdk)),
                source_command=mach_o.LC_NAMES.get(
                    load.cmd, "LC_VERSION_MIN_*"
                ),
            )
    return None


def _parse_encryption(commands):
    for load, command, _payload in commands:
        if load.cmd in (
            mach_o.LC_ENCRYPTION_INFO,
            mach_o.LC_ENCRYPTION_INFO_64,
        ):
            return {
                "cryptoff": int(command.cryptoff),
                "cryptsize": int(command.cryptsize),
                "cryptid": int(command.cryptid),
            }
    return None


def _parse_signature(slice_data, commands, encryption):
    for load, command, _payload in commands:
        if load.cmd != mach_o.LC_CODE_SIGNATURE:
            continue
        dataoff = int(command.dataoff)
        datasize = int(command.datasize)
        blob = slice_data[dataoff:dataoff + datasize]
        info = codesig.parse_code_signature(
            blob, dataoff=dataoff, datasize=datasize
        )
        if encryption is not None:
            info = dataclasses.replace(
                info, encryption_info=encryption
            )
        return info
    if encryption is not None:
        return CodeSignatureInfo(
            present=False, encryption_info=encryption
        )
    return CodeSignatureInfo(present=False, encryption_info=encryption)



def _parse_segments(commands):
    segments = []
    for load, command, _payload in commands:
        if load.cmd not in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
            continue
        segments.append(
            {
                "name": command.segname.rstrip(b"\x00").decode("utf-8"),
                "fileoff": int(command.fileoff),
                "filesize": int(command.filesize),
                "initprot": int(command.initprot),
                "maxprot": int(command.maxprot),
                "nsects": int(command.nsects),
            }
        )
    return tuple(segments)


def _header_flag_names(flags):
    return tuple(
        mach_o.MH_FLAGS_NAMES.get(bit, str(bit))
        for bit in (1 << shift for shift in range(32))
        if flags & bit
    )


def _parse_slice(slice_data, index, fat_offset):
    header, _endian, commands = _parse_mach_header(slice_data)
    platform = _parse_platform_declaration(commands)
    encryption = _parse_encryption(commands)
    signature = _parse_signature(slice_data, commands, encryption)
    segments = _parse_segments(commands)
    flags = int(header.flags)
    cpu_type = int(header.cputype)
    cpu_subtype = int(header.cpusubtype)
    architecture = Architecture(
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
        name=mach_o.CPU_TYPE_NAMES.get(cpu_type, str(cpu_type)),
        subtype_name=mach_o.get_cpu_subtype(cpu_type, cpu_subtype),
    )
    digests = {
        "sha256": hashlib.sha256(slice_data).hexdigest(),
        "sha1": hashlib.sha1(slice_data).hexdigest(),
    }
    return SliceInfo(
        index=index,
        fat_offset=fat_offset,
        fat_size=len(slice_data),
        architecture=architecture,
        platform=platform,
        filetype=int(header.filetype),
        filetype_name=mach_o.MH_FILETYPE_NAMES.get(
            int(header.filetype), str(int(header.filetype))
        ),
        header_flags=flags,
        header_flag_names=_header_flag_names(flags),
        segments=segments,
        code_signature=signature,
        digests=digests,
    )


def parse_artifact(source):
    if isinstance(source, str):
        with open(source, "rb") as handle:
            data = handle.read()
        source_name = source
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        source_name = "<bytes>"
    else:
        raise TypeError("source must be bytes or a filesystem path")
    if not data:
        raise ValueError("empty Mach-O image")

    entries = _parse_fat_entries(data)
    if entries is None:
        slice_info = _parse_slice(data, 0, 0)
        return UniversalArtifact(
            source=source_name, is_fat=False, slices=(slice_info,)
        )

    slices = []
    for index, (_cpu, _sub, offset, size, align) in enumerate(entries):
        slice_data = data[offset:offset + size]
        if len(slice_data) != size:
            raise ValueError(
                "slice %d extends past the universal image" % index
            )
        slices.append(_parse_slice(slice_data, index, offset))
    return UniversalArtifact(
        source=source_name,
        is_fat=True,
        slices=tuple(slices),
        fat_alignment=min(entry[4] for entry in entries),
    )
