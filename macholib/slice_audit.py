"""
Read-only pairing audit for Mach-O release slices.

A release audit typically receives a universal (fat) Mach-O, an archive of
per-architecture slices extracted from it, and a number of standalone debug
files.  This module parses every artifact with the structure definitions
from :mod:`macholib.mach_o` -- without ever modifying the files -- and pairs
slices across the sources by their identity: the CPU type, CPU subtype and
the ``LC_UUID`` load command.

Every load command that is read keeps its provenance: the file it came from
and its absolute offset in that file.  Slices are then classified into four
disjoint buckets:

* ``uniques``     -- identities with enough evidence that correspond
                     one-to-one across all required sources,
* ``duplicates``  -- identities that occur more than once in a single source,
* ``incompletes`` -- slices whose load commands could not be read completely,
* ``unmatcheds``  -- slices that have no counterpart in another source.

Matching is computed from identity multisets, never by consuming candidates
in input order, so the classification does not change when the order of the
input files changes.
"""

from __future__ import absolute_import, print_function

import binascii
import os
import struct

from .mach_o import (
    CPU_TYPE_NAMES,
    FAT_MAGIC,
    FAT_MAGIC_64,
    LC_UUID,
    MH_CIGAM,
    MH_CIGAM_64,
    MH_MAGIC,
    MH_MAGIC_64,
    fat_arch,
    fat_arch64,
    fat_header,
    get_cpu_subtype,
    load_command,
    mach_header,
    mach_header_64,
    uuid_command,
)
from .ptypes import sizeof

__all__ = [
    "SliceCommand",
    "Slice",
    "Pairing",
    "Unmatched",
    "AuditReport",
    "read_slices",
    "audit_slices",
    "audit_release",
]

ROLE_UNIVERSAL = "universal"
ROLE_ARCHIVE = "archive"
ROLE_DEBUG = "debug"

DEFAULT_REQUIRE = (ROLE_UNIVERSAL, ROLE_ARCHIVE, ROLE_DEBUG)

_THIN_MAGICS = {
    MH_MAGIC: (mach_header, ">"),
    MH_CIGAM: (mach_header, "<"),
    MH_MAGIC_64: (mach_header_64, ">"),
    MH_CIGAM_64: (mach_header_64, "<"),
}


def _uuid_string(raw):
    """
    Format the 16 raw bytes of an LC_UUID payload as a canonical UUID string.
    """
    raw = bytes(raw)
    hexed = binascii.hexlify(raw).decode("ascii")
    return "%s-%s-%s-%s-%s" % (
        hexed[0:8],
        hexed[8:12],
        hexed[12:16],
        hexed[16:20],
        hexed[20:32],
    )


def cpu_type_name(cputype):
    return CPU_TYPE_NAMES.get(cputype, str(cputype))


def cpu_subtype_name(cputype, cpusubtype):
    subtype = get_cpu_subtype(cputype, cpusubtype)
    if isinstance(subtype, str):
        return subtype
    return str(subtype)


class SliceCommand(object):
    """
    Provenance of a single load command: the file it belongs to and its
    absolute offset in that file.
    """

    def __init__(self, source, slice_offset, command_offset, cmd, cmdsize, uuid=None):
        self.source = source
        self.slice_offset = slice_offset
        self.command_offset = command_offset
        self.cmd = cmd
        self.cmdsize = cmdsize
        self.uuid = uuid

    def __repr__(self):
        return "<SliceCommand source=%r offset=%d cmd=0x%x size=%d>" % (
            self.source,
            self.command_offset,
            self.cmd,
            self.cmdsize,
        )


class Slice(object):
    """
    One architecture slice of a Mach-O artifact, with the load commands that
    could be read from it.
    """

    def __init__(self, source, role, slice_offset, cputype, cpusubtype):
        self.source = source
        self.role = role
        self.slice_offset = slice_offset
        self.cputype = cputype
        self.cpusubtype = cpusubtype
        self.commands = []
        self.complete = True
        self.error = None

    @property
    def uuid(self):
        for command in self.commands:
            if command.uuid is not None:
                return command.uuid
        return None

    @property
    def identity(self):
        """
        The pairing identity of this slice, or None when the slice does not
        carry enough evidence (a readable LC_UUID) to be paired.
        """
        if not self.complete or self.uuid is None:
            return None
        return (self.cputype, self.cpusubtype, _uuid_string(self.uuid))

    def describe_cpu(self):
        return "%s (%s)" % (
            cpu_type_name(self.cputype),
            cpu_subtype_name(self.cputype, self.cpusubtype),
        )

    def __repr__(self):
        return "<Slice source=%r role=%r offset=%d cputype=%r subtype=%r>" % (
            self.source,
            self.role,
            self.slice_offset,
            self.cputype,
            self.cpusubtype,
        )


class Pairing(object):
    """
    A set of slices, one per source role, that share a single identity.
    """

    def __init__(self, identity, slices):
        self.identity = identity
        self.slices = list(slices)

    @property
    def roles(self):
        return sorted(set(slice_.role for slice_ in self.slices))

    def __repr__(self):
        return "<Pairing identity=%r slices=%d>" % (
            self.identity,
            len(self.slices),
        )


class Unmatched(object):
    """
    A slice for which no counterpart could be established, with the reason.
    """

    def __init__(self, slice_, reason):
        self.slice = slice_
        self.reason = reason

    def __repr__(self):
        return "<Unmatched source=%r reason=%r>" % (
            self.slice.source,
            self.reason,
        )


class AuditReport(object):
    """
    Result of a slice pairing audit.
    """

    def __init__(self, uniques, duplicates, incompletes, unmatcheds):
        self.uniques = uniques
        self.duplicates = duplicates
        self.incompletes = incompletes
        self.unmatcheds = unmatcheds

    @property
    def ok(self):
        return not (self.duplicates or self.incompletes or self.unmatcheds)

    def summary(self):
        lines = []
        for pairing in self.uniques:
            lines.append(
                "unique %s: %s"
                % (
                    _format_identity(pairing.identity),
                    ", ".join(
                        "%s[%s]@0x%x"
                        % (slice_.source, slice_.role, slice_.slice_offset)
                        for slice_ in pairing.slices
                    ),
                )
            )
        for pairing in self.duplicates:
            lines.append(
                "duplicate %s: %s"
                % (
                    _format_identity(pairing.identity),
                    ", ".join(
                        "%s[%s]@0x%x"
                        % (slice_.source, slice_.role, slice_.slice_offset)
                        for slice_ in pairing.slices
                    ),
                )
            )
        for slice_ in self.incompletes:
            lines.append(
                "incomplete %s[%s]@0x%x: %s"
                % (
                    slice_.source,
                    slice_.role,
                    slice_.slice_offset,
                    slice_.error,
                )
            )
        for unmatched in self.unmatcheds:
            slice_ = unmatched.slice
            lines.append(
                "unmatched %s[%s]@0x%x: %s"
                % (
                    slice_.source,
                    slice_.role,
                    slice_.slice_offset,
                    unmatched.reason,
                )
            )
        return "\n".join(lines)


def _format_identity(identity):
    cputype, cpusubtype, uuid_string = identity
    return "%s/%s uuid=%s" % (
        cpu_type_name(cputype),
        cpu_subtype_name(cputype, cpusubtype),
        uuid_string,
    )


def _read_thin(fh, source, role, offset, size):
    """
    Read a single Mach-O slice at ``offset`` in ``fh``.  Never raises for
    malformed content; the returned slice is flagged incomplete instead.
    """
    slice_ = Slice(source, role, offset, None, None)
    end = offset + size
    try:
        fh.seek(offset)
        magic_bytes = fh.read(4)
        if len(magic_bytes) < 4:
            raise ValueError("short read on mach header magic")
        magic = struct.unpack(">I", magic_bytes)[0]
        if magic not in _THIN_MAGICS:
            raise ValueError("unknown Mach-O magic 0x%08x" % (magic,))
        header_cls, endian = _THIN_MAGICS[magic]

        fh.seek(offset)
        header = header_cls.from_fileobj(fh, _endian_=endian)
        slice_.cputype = int(header.cputype)
        slice_.cpusubtype = int(header.cpusubtype)

        command_offset = offset + sizeof(header_cls)
        for _index in range(header.ncmds):
            if command_offset + sizeof(load_command) > end:
                raise ValueError("load command extends past end of slice")
            fh.seek(command_offset)
            try:
                cmd_load = load_command.from_fileobj(fh, _endian_=endian)
            except struct.error:
                raise ValueError("short read on load command")
            cmdsize = int(cmd_load.cmdsize)
            if cmdsize < sizeof(load_command):
                raise ValueError("invalid load command size %d" % (cmdsize,))
            if command_offset + cmdsize > end:
                raise ValueError("load command extends past end of slice")

            uuid = None
            if int(cmd_load.cmd) == LC_UUID:
                if cmdsize < sizeof(load_command) + sizeof(uuid_command):
                    raise ValueError("short LC_UUID command")
                try:
                    cmd_uuid = uuid_command.from_fileobj(fh, _endian_=endian)
                except struct.error:
                    raise ValueError("short read on LC_UUID payload")
                uuid = bytes(cmd_uuid.uuid)

            slice_.commands.append(
                SliceCommand(
                    source=source,
                    slice_offset=offset,
                    command_offset=command_offset,
                    cmd=int(cmd_load.cmd),
                    cmdsize=cmdsize,
                    uuid=uuid,
                )
            )
            command_offset += cmdsize
    except (ValueError, struct.error) as exc:
        slice_.complete = False
        slice_.error = str(exc)
    return slice_


def read_slices(path, role):
    """
    Read every architecture slice of the Mach-O file at ``path`` (fat or
    thin) without modifying it, tagging each slice with ``role``.
    """
    slices = []
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        file_size = fh.tell()
        fh.seek(0)
        magic_bytes = fh.read(4)
        if len(magic_bytes) < 4:
            slice_ = Slice(path, role, 0, None, None)
            slice_.complete = False
            slice_.error = "short read on file magic"
            return [slice_]
        magic = struct.unpack(">I", magic_bytes)[0]

        if magic in (FAT_MAGIC, FAT_MAGIC_64):
            arch_cls = fat_arch if magic == FAT_MAGIC else fat_arch64
            fh.seek(0)
            try:
                header = fat_header.from_fileobj(fh)
                archs = [
                    arch_cls.from_fileobj(fh) for _index in range(header.nfat_arch)
                ]
            except struct.error:
                slice_ = Slice(path, role, 0, None, None)
                slice_.complete = False
                slice_.error = "short read on fat header"
                return [slice_]
            for arch in archs:
                slices.append(
                    _read_thin(fh, path, role, int(arch.offset), int(arch.size))
                )
        else:
            slices.append(_read_thin(fh, path, role, 0, file_size))
    return slices


def audit_slices(slices, require=DEFAULT_REQUIRE):
    """
    Classify ``slices`` into an :class:`AuditReport`.  The result depends
    only on the identity multisets, never on the order of ``slices``.
    """
    require = tuple(require)
    incompletes = []
    unmatcheds = []
    groups = {}

    for slice_ in slices:
        if not slice_.complete:
            incompletes.append(slice_)
            continue
        identity = slice_.identity
        if identity is None:
            unmatcheds.append(Unmatched(slice_, "missing LC_UUID load command"))
            continue
        groups.setdefault(identity, []).append(slice_)

    uniques = []
    duplicates = []
    for identity in sorted(groups):
        group = groups[identity]
        by_role = {}
        for slice_ in group:
            by_role.setdefault(slice_.role, []).append(slice_)

        if any(len(by_role[role]) > 1 for role in by_role):
            duplicates.append(Pairing(identity, group))
            continue

        missing = [role for role in require if role not in by_role]
        if missing:
            for slice_ in group:
                unmatcheds.append(
                    Unmatched(
                        slice_,
                        "no counterpart in source(s): %s" % (", ".join(missing),),
                    )
                )
            continue

        uniques.append(Pairing(identity, group))

    def sort_key(slice_):
        return (slice_.source, slice_.slice_offset)

    incompletes.sort(key=sort_key)
    unmatcheds.sort(key=lambda unmatched: sort_key(unmatched.slice))
    for pairing in uniques + duplicates:
        pairing.slices.sort(key=sort_key)

    return AuditReport(uniques, duplicates, incompletes, unmatcheds)


def _archive_members(archive):
    if isinstance(archive, (str, bytes)):
        if os.path.isdir(archive):
            return [
                os.path.join(archive, name)
                for name in sorted(os.listdir(archive))
                if not name.startswith(".")
            ]
        return [archive]
    return list(archive)


def audit_release(universal, archive, debug_files=(), require=DEFAULT_REQUIRE):
    """
    Audit a release set: the universal Mach-O at ``universal``, the per-arch
    slice archive ``archive`` (a directory or an iterable of member files)
    and the standalone debug files in ``debug_files``.
    """
    slices = []
    slices.extend(read_slices(universal, ROLE_UNIVERSAL))
    for member in _archive_members(archive):
        slices.extend(read_slices(member, ROLE_ARCHIVE))
    for path in debug_files:
        slices.extend(read_slices(path, ROLE_DEBUG))
    return audit_slices(slices, require=require)
