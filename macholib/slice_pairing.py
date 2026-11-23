"""
Read-only pairing audit for Mach-O slices.

The audit is meant for release material such as:

* one universal (fat) Mach-O binary,
* the same binary split into one thin archive per architecture,
* standalone debug Mach-O files.

A slice is identified by the tuple ``(LC_UUID, cputype, cpusubtype)``.
Every load command is kept together with the file it came from, the slice
index and its byte position.  The input files are only opened for reading;
no Mach-O file is modified and no external tool (``lipo``, ``otool``,
``file``, ...) is used.

The public entry point is :func:`build_pairing_report`.  The report has four
separate result buckets:

``unique``
    Exactly one readable material per present kind claims the identity and
    at least two kinds agree.  These are safe one-to-one correspondences.

``duplicates``
    More than one material of the same kind claims the identity, or one slice
    carries several UUID commands.  No candidate is consumed by input order.

``incomplete``
    A command was truncated or otherwise could not be read completely, so the
    identity is not strong enough to be called a match.

``unmatched``
    A readable material has no counterpart (or a required kind is absent).
"""

from __future__ import absolute_import, print_function

import argparse
import json
import os
import struct
import sys
import uuid as _uuid
from collections import OrderedDict

from .mach_o import (
    CPU_TYPE_NAMES,
    FAT_CIGAM,
    FAT_CIGAM_64,
    FAT_MAGIC,
    FAT_MAGIC_64,
    LC_NAMES,
    LC_UUID,
    MH_CIGAM,
    MH_CIGAM_64,
    MH_MAGIC,
    MH_MAGIC_64,
    fat_arch,
    fat_arch64,
    fat_header,
    get_cpu_subtype,
    mach_header,
    mach_header_64,
)
from .ptypes import sizeof

__all__ = [
    "KIND_ARCHIVE",
    "KIND_DEBUG",
    "KIND_UNIVERSAL",
    "MATERIAL_KINDS",
    "SCHEMA_VERSION",
    "SliceAuditor",
    "SlicePairingAudit",
    "audit_macho_slices",
    "audit_slices",
    "build_pairing_report",
    "build_slice_pairing_report",
    "main",
    "pair_macho_slices",
    "pair_slices",
    "read_slices",
]

SCHEMA_VERSION = "macholib.slice_pairing/1"

KIND_UNIVERSAL = "universal"
KIND_ARCHIVE = "archive"
KIND_DEBUG = "debug"

MATERIAL_KINDS = (KIND_UNIVERSAL, KIND_ARCHIVE, KIND_DEBUG)
_KIND_ORDER = {kind: index for index, kind in enumerate(MATERIAL_KINDS)}

_KIND_ALIASES = {
    "universal": KIND_UNIVERSAL,
    "universal_macho": KIND_UNIVERSAL,
    "generic": KIND_UNIVERSAL,
    "generic_macho": KIND_UNIVERSAL,
    "fat": KIND_UNIVERSAL,
    "archive": KIND_ARCHIVE,
    "archives": KIND_ARCHIVE,
    "split": KIND_ARCHIVE,
    "splits": KIND_ARCHIVE,
    "split_archive": KIND_ARCHIVE,
    "thin": KIND_ARCHIVE,
    "per_arch": KIND_ARCHIVE,
    "debug": KIND_DEBUG,
    "debugs": KIND_DEBUG,
    "debug_file": KIND_DEBUG,
    "debug_files": KIND_DEBUG,
    "dsym": KIND_DEBUG,
    "dwarf": KIND_DEBUG,
}

try:
    _STRING_TYPES = (basestring,)  # noqa: F821
except NameError:
    _STRING_TYPES = (str,)

try:
    _PATH_TYPES = _STRING_TYPES + (os.PathLike,)
except AttributeError:
    _PATH_TYPES = _STRING_TYPES

_FAT_MAGICS = (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64)
_THIN_MAGICS = (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64)


def _normalise_kind(kind):
    if kind is None:
        return KIND_ARCHIVE
    key = str(kind).strip().lower().replace("-", "_").replace(" ", "_")
    try:
        return _KIND_ALIASES[key]
    except KeyError:
        raise ValueError(
            "unknown material kind %r (expected one of %s)"
            % (kind, ", ".join(MATERIAL_KINDS))
        )


def _as_paths(value):
    if value is None:
        return []
    if isinstance(value, _PATH_TYPES):
        return [value]
    paths = []
    for item in value:
        paths.extend(_as_paths(item))
    return paths


def _as_kind_list(value):
    if value is None:
        return None
    if isinstance(value, _STRING_TYPES) and "," in value:
        value = [item.strip() for item in value.split(",") if item.strip()]
    kinds = []
    for item in _as_paths(value):
        kind = _normalise_kind(item)
        if kind not in kinds:
            kinds.append(kind)
    return tuple(sorted(kinds, key=lambda item: _KIND_ORDER[item]))


def _read_magic(fh):
    fh.seek(0)
    raw = fh.read(4)
    if len(raw) != 4:
        return None
    return struct.unpack(">I", raw)[0]


def _looks_like_macho(path):
    try:
        with open(path, "rb") as fh:
            magic = _read_magic(fh)
    except (IOError, OSError):
        return False
    return magic in _FAT_MAGICS or magic in _THIN_MAGICS


def _issue(code, message, **details):
    issue = OrderedDict()
    issue["code"] = code
    issue["message"] = message
    for key in sorted(details):
        issue[key] = details[key]
    return issue


def _slice_id(kind, path, slice_index):
    return "%s:%s#%d" % (kind, path, slice_index)


def _uuid_details(raw_uuid):
    if raw_uuid is None:
        return {"uuid": None, "uuid_hex": None}
    value = _uuid.UUID(bytes=raw_uuid)
    return {"uuid": str(value).upper(), "uuid_hex": value.hex}


def _cpu_type_name(cputype):
    if cputype is None:
        return None
    value = CPU_TYPE_NAMES.get(cputype, cputype)
    return str(value)


def _cpu_subtype_name(cputype, cpusubtype):
    if cputype is None or cpusubtype is None:
        return None
    return str(get_cpu_subtype(cputype, cpusubtype))


def _base_slice(path, kind, slice_index, container):
    record = OrderedDict()
    record["slice_id"] = _slice_id(kind, path, slice_index)
    record["path"] = path
    record["kind"] = kind
    record["container"] = container
    record["slice_index"] = slice_index
    record["file_offset"] = 0
    record["declared_size"] = None
    record["slice_size"] = None
    record["bits"] = None
    record["endian"] = None
    record["cputype"] = None
    record["cpusubtype"] = None
    record["cputype_name"] = None
    record["cpusubtype_name"] = None
    record["fat_arch"] = None
    record["uuid"] = None
    record["uuid_hex"] = None
    record["uuid_candidates"] = []
    record["status"] = "incomplete"
    record["issues"] = []
    record["commands"] = []
    record["command_count"] = 0
    record["uuid_command_count"] = 0
    return record


def _error_slice(path, kind, reason, message, slice_index=0, container="thin"):
    record = _base_slice(path, kind, slice_index, container)
    record["issues"].append(_issue(reason, message))
    return record


def _command_record(
    path, kind, slice_index, command_index, cmd, cmdsize, slice_offset, file_offset
):
    command = OrderedDict()
    command["path"] = path
    command["kind"] = kind
    command["slice_id"] = _slice_id(kind, path, slice_index)
    command["slice_index"] = slice_index
    command["command_index"] = command_index
    command["cmd"] = cmd
    command["name"] = LC_NAMES.get(cmd, "0x%08X" % (cmd,))
    command["cmdsize"] = cmdsize
    command["slice_offset"] = slice_offset
    command["file_offset"] = file_offset
    command["uuid"] = None
    command["uuid_hex"] = None
    command["uuid_slice_offset"] = None
    command["uuid_file_offset"] = None
    return command


def _load_slice(
    fh,
    file_size,
    path,
    kind,
    base_offset,
    declared_size,
    container,
    slice_index,
    fat_arch_info=None,
):
    record = _base_slice(path, kind, slice_index, container)
    record["file_offset"] = base_offset
    record["declared_size"] = declared_size

    if fat_arch_info is not None:
        record["fat_arch"] = fat_arch_info

    slice_end = file_size
    if declared_size is not None:
        slice_end = min(file_size, base_offset + declared_size)
    record["slice_size"] = max(0, slice_end - base_offset)

    if base_offset < 0 or base_offset >= file_size:
        record["issues"].append(
            _issue(
                "slice_out_of_range",
                "slice offset is outside the file",
                slice_offset=base_offset,
                file_size=file_size,
            )
        )
        return record

    fh.seek(base_offset)
    raw_magic = fh.read(4)
    if len(raw_magic) != 4:
        record["issues"].append(
            _issue(
                "truncated_header",
                "slice is too short to contain a Mach-O magic",
                available=len(raw_magic),
            )
        )
        return record

    magic = struct.unpack(">I", raw_magic)[0]
    if magic == MH_MAGIC:
        bits, endian = 32, ">"
    elif magic == MH_CIGAM:
        bits, endian = 32, "<"
    elif magic == MH_MAGIC_64:
        bits, endian = 64, ">"
    elif magic == MH_CIGAM_64:
        bits, endian = 64, "<"
    else:
        record["issues"].append(
            _issue(
                "not_macho",
                "slice does not start with a Mach-O magic",
                magic="0x%08X" % (magic,),
            )
        )
        return record

    record["bits"] = bits
    record["endian"] = endian
    header_class = mach_header_64 if bits == 64 else mach_header
    header_size = sizeof(header_class)

    if base_offset + header_size > slice_end:
        record["issues"].append(
            _issue(
                "truncated_header",
                "slice is too short to contain the Mach-O header",
                expected=header_size,
                available=max(0, slice_end - base_offset),
            )
        )
        return record

    fh.seek(base_offset)
    header = header_class.from_fileobj(fh, _endian_=endian)
    cputype = int(header.cputype)
    cpusubtype = int(header.cpusubtype)
    record["cputype"] = cputype
    record["cpusubtype"] = cpusubtype
    record["cputype_name"] = _cpu_type_name(cputype)
    record["cpusubtype_name"] = _cpu_subtype_name(cputype, cpusubtype)

    if fat_arch_info is not None:
        if (
            fat_arch_info["cputype"] != cputype
            or fat_arch_info["cpusubtype"] != cpusubtype
        ):
            record["issues"].append(
                _issue(
                    "fat_arch_cpu_mismatch",
                    "fat_arch CPU type/subtype does not match the embedded header",
                    fat_arch_cputype=fat_arch_info["cputype"],
                    fat_arch_cpusubtype=fat_arch_info["cpusubtype"],
                    header_cputype=cputype,
                    header_cpusubtype=cpusubtype,
                )
            )

    sizeofcmds = int(header.sizeofcmds)
    ncmds = int(header.ncmds)
    commands_start = base_offset + header_size
    declared_commands_end = commands_start + sizeofcmds
    if declared_commands_end > slice_end:
        record["issues"].append(
            _issue(
                "truncated_load_commands",
                "sizeofcmds extends beyond the available slice bytes",
                sizeofcmds=sizeofcmds,
                available=max(0, slice_end - commands_start),
            )
        )
    commands_region_end = min(slice_end, declared_commands_end)

    commands = []
    consumed = 0
    command_offset = header_size
    uuid_commands = []
    uuid_command_seen = False

    for command_index in range(ncmds):
        absolute_command_offset = base_offset + command_offset
        if absolute_command_offset + 8 > commands_region_end:
            record["issues"].append(
                _issue(
                    "truncated_load_command_header",
                    "load command header is truncated",
                    command_index=command_index,
                    slice_offset=command_offset,
                    file_offset=absolute_command_offset,
                )
            )
            break

        fh.seek(absolute_command_offset)
        raw_command = fh.read(8)
        cmd, cmdsize = struct.unpack(endian + "II", raw_command)
        command = _command_record(
            path,
            kind,
            slice_index,
            command_index,
            cmd,
            cmdsize,
            command_offset,
            absolute_command_offset,
        )

        if cmdsize < 8:
            record["issues"].append(
                _issue(
                    "invalid_cmdsize",
                    "load command size is smaller than the command header",
                    command_index=command_index,
                    cmd=cmd,
                    cmdsize=cmdsize,
                    slice_offset=command_offset,
                    file_offset=absolute_command_offset,
                )
            )
            commands.append(command)
            break

        if consumed + cmdsize > sizeofcmds:
            record["issues"].append(
                _issue(
                    "command_exceeds_sizeofcmds",
                    "load command extends beyond sizeofcmds",
                    command_index=command_index,
                    cmd=cmd,
                    cmdsize=cmdsize,
                    consumed=consumed,
                    sizeofcmds=sizeofcmds,
                )
            )

        command_end = absolute_command_offset + cmdsize
        available_end = min(command_end, commands_region_end)
        if command_end > commands_region_end:
            record["issues"].append(
                _issue(
                    "truncated_load_command",
                    "load command extends beyond the available slice bytes",
                    command_index=command_index,
                    cmd=cmd,
                    cmdsize=cmdsize,
                    slice_offset=command_offset,
                    file_offset=absolute_command_offset,
                    available=max(0, commands_region_end - absolute_command_offset),
                )
            )

        if cmd == LC_UUID:
            uuid_command_seen = True
            command["uuid_command"] = True
            command["uuid_slice_offset"] = command_offset + 8
            command["uuid_file_offset"] = absolute_command_offset + 8
            if cmdsize < 24:
                record["issues"].append(
                    _issue(
                        "uuid_command_too_small",
                        "LC_UUID is too small to contain a 16 byte UUID",
                        command_index=command_index,
                        cmdsize=cmdsize,
                    )
                )
            elif absolute_command_offset + 24 > available_end:
                record["issues"].append(
                    _issue(
                        "truncated_uuid",
                        "LC_UUID payload is truncated",
                        command_index=command_index,
                        slice_offset=command_offset + 8,
                        file_offset=absolute_command_offset + 8,
                        available=max(0, available_end - (absolute_command_offset + 8)),
                    )
                )
            else:
                fh.seek(absolute_command_offset + 8)
                raw_uuid = fh.read(16)
                if len(raw_uuid) != 16:
                    record["issues"].append(
                        _issue(
                            "truncated_uuid",
                            "LC_UUID payload is truncated",
                            command_index=command_index,
                            slice_offset=command_offset + 8,
                            file_offset=absolute_command_offset + 8,
                            available=len(raw_uuid),
                        )
                    )
                else:
                    details = _uuid_details(raw_uuid)
                    command.update(details)
                    uuid_commands.append(command)

        commands.append(command)
        consumed += cmdsize
        command_offset += cmdsize

        if command_end > commands_region_end:
            break

    record["commands"] = commands
    record["command_count"] = len(commands)

    if not any(
        issue["code"]
        in (
            "truncated_load_commands",
            "truncated_load_command_header",
            "truncated_load_command",
            "invalid_cmdsize",
            "command_exceeds_sizeofcmds",
        )
        for issue in record["issues"]
    ) and consumed != sizeofcmds:
        record["issues"].append(
            _issue(
                "sizeofcmds_mismatch",
                "read load command bytes do not match sizeofcmds",
                consumed=consumed,
                sizeofcmds=sizeofcmds,
                ncmds=ncmds,
                read_ncmds=len(commands),
            )
        )

    record["uuid_command_count"] = sum(
        1 for command in commands if command["cmd"] == LC_UUID
    )
    record["uuid_candidates"] = [
        command["uuid"] for command in uuid_commands if command["uuid"] is not None
    ]

    if record["uuid_command_count"] == 1 and len(uuid_commands) == 1:
        command = uuid_commands[0]
        record["uuid"] = command["uuid"]
        record["uuid_hex"] = command["uuid_hex"]
    elif record["uuid_command_count"] > 1:
        record["issues"].append(
            _issue(
                "multiple_lc_uuid_commands",
                "slice contains more than one LC_UUID command; no command is selected",
                command_indices=[
                    command["command_index"]
                    for command in commands
                    if command["cmd"] == LC_UUID
                ],
                uuids=list(record["uuid_candidates"]),
            )
        )

    if not uuid_command_seen and not any(
        issue["code"] == "missing_lc_uuid" for issue in record["issues"]
    ):
        record["issues"].append(
            _issue(
                "missing_lc_uuid",
                "slice has no readable LC_UUID command",
            )
        )

    incomplete_codes = {
        "slice_out_of_range",
        "truncated_header",
        "not_macho",
        "fat_arch_cpu_mismatch",
        "truncated_load_commands",
        "truncated_load_command_header",
        "truncated_load_command",
        "invalid_cmdsize",
        "command_exceeds_sizeofcmds",
        "uuid_command_too_small",
        "truncated_uuid",
        "sizeofcmds_mismatch",
    }
    issue_codes = {issue["code"] for issue in record["issues"]}

    if issue_codes & incomplete_codes:
        record["status"] = "incomplete"
    elif "missing_lc_uuid" in issue_codes:
        record["status"] = "unidentified"
    elif "multiple_lc_uuid_commands" in issue_codes:
        record["status"] = "ambiguous"
    elif record["uuid"] is None:
        record["status"] = "incomplete"
    else:
        record["status"] = "ok"

    return record


def _load_fat(fh, file_size, path, kind):
    magic = _read_magic(fh)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        endian = ">"
        arch_class = fat_arch64 if magic == FAT_MAGIC_64 else fat_arch
        is_64 = magic == FAT_MAGIC_64
    elif magic in (FAT_CIGAM, FAT_CIGAM_64):
        endian = "<"
        arch_class = fat_arch64 if magic == FAT_CIGAM_64 else fat_arch
        is_64 = magic == FAT_CIGAM_64
    else:
        return None

    if file_size < sizeof(fat_header):
        return [
            _error_slice(
                path,
                kind,
                "truncated_fat_header",
                "fat header is truncated",
                container="fat",
            )
        ]

    fh.seek(0)
    try:
        header = fat_header.from_fileobj(fh, _endian_=endian)
    except (struct.error, ValueError) as exc:
        return [
            _error_slice(
                path,
                kind,
                "invalid_fat_header",
                "fat header could not be read: %s" % (exc,),
                container="fat",
            )
        ]
    nfat_arch = int(header.nfat_arch)
    if nfat_arch == 0:
        return [
            _error_slice(
                path,
                kind,
                "empty_fat_container",
                "fat container declares no architectures",
                container="fat",
            )
        ]
    arch_size = sizeof(arch_class)
    records = []

    for slice_index in range(nfat_arch):
        entry_offset = sizeof(fat_header) + slice_index * arch_size
        if entry_offset + arch_size > file_size:
            records.append(
                _error_slice(
                    path,
                    kind,
                    "truncated_fat_arch",
                    "fat architecture table is truncated",
                    slice_index=slice_index,
                    container="fat",
                )
            )
            break
        try:
            fh.seek(entry_offset)
            arch = arch_class.from_fileobj(fh, _endian_=endian)
        except (struct.error, ValueError) as exc:
            records.append(
                _error_slice(
                    path,
                    kind,
                    "truncated_fat_arch",
                    "fat architecture entry could not be read: %s" % (exc,),
                    slice_index=slice_index,
                    container="fat",
                )
            )
            break
        arch_info = OrderedDict()
        arch_info["table_offset"] = entry_offset
        arch_info["cputype"] = int(arch.cputype)
        arch_info["cpusubtype"] = int(arch.cpusubtype)
        arch_info["offset"] = int(arch.offset)
        arch_info["size"] = int(arch.size)
        arch_info["align"] = int(arch.align)
        arch_info["is_64"] = is_64

        record = _load_slice(
            fh,
            file_size,
            path,
            kind,
            arch_info["offset"],
            arch_info["size"],
            "fat",
            slice_index,
            fat_arch_info=arch_info,
        )
        records.append(record)

    return records


def read_slices(path, kind=KIND_ARCHIVE):
    """
    Read all slices from *path* without modifying it.

    A fat container produces one record per ``fat_arch``.  A thin Mach-O
    produces one record with ``slice_index`` 0.  Parse problems are returned
    as records instead of exceptions so that an audit can report them next to
    the healthy material.
    """

    kind = _normalise_kind(kind)
    path = os.path.abspath(os.path.expanduser(str(path)))

    if not os.path.exists(path):
        return [
            _error_slice(
                path,
                kind,
                "no_such_file",
                "input path does not exist",
            )
        ]
    if not os.path.isfile(path):
        return [
            _error_slice(
                path,
                kind,
                "not_a_file",
                "input path is not a regular file",
            )
        ]

    try:
        with open(path, "rb") as fh:
            file_size = os.fstat(fh.fileno()).st_size
            records = _load_fat(fh, file_size, path, kind)
            if records is not None:
                return records
            return [
                _load_slice(
                    fh,
                    file_size,
                    path,
                    kind,
                    0,
                    file_size,
                    "thin",
                    0,
                )
            ]
    except (IOError, OSError, struct.error, ValueError) as exc:
        return [
            _error_slice(
                path,
                kind,
                "read_error",
                "could not read input file: %s" % (exc,),
            )
        ]


def _expand_paths(paths, kind):
    expanded = OrderedDict()
    for raw_path in paths:
        path = os.path.abspath(os.path.expanduser(str(raw_path)))
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs.sort()
                for filename in sorted(files):
                    candidate = os.path.join(root, filename)
                    if _looks_like_macho(candidate):
                        expanded.setdefault(os.path.realpath(candidate), candidate)
        else:
            expanded.setdefault(os.path.realpath(path), path)
    return [(kind, path) for path in expanded.values()]


def _collect_materials(universal, archive, debug, materials):
    grouped = OrderedDict((kind, []) for kind in MATERIAL_KINDS)

    for kind, value in (
        (KIND_UNIVERSAL, universal),
        (KIND_ARCHIVE, archive),
        (KIND_DEBUG, debug),
    ):
        grouped[kind].extend(_as_paths(value))

    if materials is None:
        return grouped

    if isinstance(materials, dict):
        items = materials.items()
    elif isinstance(materials, _PATH_TYPES):
        items = [(KIND_ARCHIVE, materials)]
    else:
        items = materials

    for item in items:
        if isinstance(item, _PATH_TYPES):
            grouped[KIND_ARCHIVE].append(item)
            continue
        try:
            kind, value = item
        except (TypeError, ValueError):
            raise ValueError(
                "materials must contain (kind, path) pairs or path strings"
            )
        grouped[_normalise_kind(kind)].extend(_as_paths(value))

    return grouped


def _slice_sort_key(record):
    return (
        _KIND_ORDER[record["kind"]],
        record["path"],
        record["slice_index"],
    )


def _command_sort_key(command):
    return (
        _KIND_ORDER[command["kind"]],
        command["path"],
        command["slice_index"],
        command["command_index"],
    )


def _slice_ref(record):
    reference = OrderedDict()
    for key in (
        "slice_id",
        "path",
        "kind",
        "container",
        "slice_index",
        "file_offset",
        "declared_size",
        "slice_size",
        "bits",
        "endian",
        "cputype",
        "cpusubtype",
        "cputype_name",
        "cpusubtype_name",
        "uuid",
        "uuid_hex",
        "status",
        "command_count",
        "uuid_command_count",
    ):
        reference[key] = record[key]
    reference["issues"] = [dict(issue) for issue in record["issues"]]
    return reference


def _identity_dict(uuid, cputype, cpusubtype):
    identity = OrderedDict()
    identity["uuid"] = uuid
    identity["cputype"] = cputype
    identity["cpusubtype"] = cpusubtype
    identity["cputype_name"] = _cpu_type_name(cputype)
    identity["cpusubtype_name"] = _cpu_subtype_name(cputype, cpusubtype)
    return identity


def _group_identity(record):
    return (record["uuid_hex"], record["cputype"], record["cpusubtype"])


def _build_group(key, members, required_kinds, conflicted_uuids=None):
    members = sorted(members, key=_slice_sort_key)
    per_kind = OrderedDict((kind, []) for kind in MATERIAL_KINDS)
    for member in members:
        per_kind[member["kind"]].append(member)

    counts = OrderedDict((kind, len(per_kind[kind])) for kind in MATERIAL_KINDS)
    present_kinds = [kind for kind in MATERIAL_KINDS if counts[kind]]
    absent_kinds = [kind for kind in MATERIAL_KINDS if not counts[kind]]
    duplicate_kinds = [kind for kind in present_kinds if counts[kind] > 1]
    missing_required = (
        [kind for kind in required_kinds if kind not in present_kinds]
        if required_kinds is not None
        else []
    )

    if duplicate_kinds:
        status = "duplicate"
        reason = "duplicate_material_kind"
    elif conflicted_uuids and key[0] in conflicted_uuids:
        status = "duplicate"
        reason = "uuid_with_multiple_cpu_identities"
    elif missing_required:
        status = "unmatched"
        reason = "missing_required_kind"
    elif len(present_kinds) < 2:
        status = "unmatched"
        reason = "no_counterpart"
    else:
        status = "unique"
        reason = None

    group = OrderedDict()
    group["status"] = status
    group["reason"] = reason
    group["identity"] = _identity_dict(
        members[0]["uuid"], members[0]["cputype"], members[0]["cpusubtype"]
    )
    group["counts"] = counts
    group["present_kinds"] = present_kinds
    group["absent_kinds"] = absent_kinds
    group["duplicate_kinds"] = duplicate_kinds
    group["missing_required_kinds"] = missing_required
    group["members"] = [_slice_ref(member) for member in members]
    return group


def _ambiguous_entry(record):
    entry = OrderedDict()
    entry["status"] = "duplicate"
    entry["reason"] = "multiple_lc_uuid_commands"
    entry["path"] = record["path"]
    entry["kind"] = record["kind"]
    entry["slice_index"] = record["slice_index"]
    entry["uuid_candidates"] = list(record["uuid_candidates"])
    entry["issues"] = [dict(issue) for issue in record["issues"]]
    return entry


def _incomplete_entry(record):
    entry = OrderedDict()
    entry["status"] = record["status"]
    entry["path"] = record["path"]
    entry["kind"] = record["kind"]
    entry["slice_index"] = record["slice_index"]
    entry["file_offset"] = record["file_offset"]
    entry["declared_size"] = record["declared_size"]
    entry["slice_size"] = record["slice_size"]
    entry["cputype"] = record["cputype"]
    entry["cpusubtype"] = record["cpusubtype"]
    entry["uuid"] = record["uuid"]
    entry["command_count"] = record["command_count"]
    entry["issues"] = [dict(issue) for issue in record["issues"]]
    entry["commands"] = [
        dict(command) for command in record["commands"] if command["cmd"] == LC_UUID
    ]
    return entry


def _finding(
    code,
    severity,
    message,
    path=None,
    kind=None,
    slice_index=None,
    command_index=None,
    related=None,
    **details
):
    finding = OrderedDict()
    finding["code"] = code
    finding["severity"] = severity
    finding["message"] = message
    finding["path"] = path
    finding["kind"] = kind
    finding["slice_index"] = slice_index
    finding["command_index"] = command_index
    finding["related"] = related or []
    for key in sorted(details):
        finding[key] = details[key]
    return finding


def _findings_for_groups(unique, duplicates, unmatched):
    findings = []

    for group in duplicates:
        if "identity" not in group:
            if group.get("reason") == "multiple_lc_uuid_commands":
                findings.append(
                    _finding(
                        "ambiguous_uuid_commands",
                        "error",
                        "slice carries several LC_UUID commands; "
                        "first result was not used",
                        path=group["path"],
                        kind=group["kind"],
                        slice_index=group["slice_index"],
                        uuid_candidates=group["uuid_candidates"],
                    )
                )
            continue

        if group.get("reason") == "uuid_with_multiple_cpu_identities":
            continue

        findings.append(
            _finding(
                "duplicate_identity",
                "error",
                "identity is claimed by more than one material of the same kind",
                kind=group["duplicate_kinds"][0] if group["duplicate_kinds"] else None,
                related=group["members"],
                paths=[
                    member["path"]
                    for member in group["members"]
                    if member["kind"] in group["duplicate_kinds"]
                ],
                identity=group["identity"],
                duplicate_kinds=group["duplicate_kinds"],
            )
        )

    for group in unmatched:
        if group["reason"] == "missing_required_kind":
            message = "required material kind is absent: %s" % (
                ", ".join(group["missing_required_kinds"]),
            )
        else:
            message = "material has no counterpart in another input kind"
        member = group["members"][0]
        findings.append(
            _finding(
                "missing_counterpart",
                "error",
                message,
                path=member["path"],
                kind=member["kind"],
                slice_index=member["slice_index"],
                related=group["members"][1:],
                paths=[item["path"] for item in group["members"]],
                identity=group["identity"],
                missing_required_kinds=group["missing_required_kinds"],
            )
        )

    return findings


def _findings_for_incomplete(records):
    findings = []
    for record in records:
        findings.append(
            _finding(
                "incomplete_slice",
                "error",
                "slice identity is incomplete; see issues for the failed command",
                path=record["path"],
                kind=record["kind"],
                slice_index=record["slice_index"],
                issues=record["issues"],
            )
        )
    return findings


def _findings_for_uuid_conflicts(ok_records):
    by_uuid = OrderedDict()
    for record in ok_records:
        by_uuid.setdefault(record["uuid_hex"], []).append(record)

    findings = []
    for uuid_hex in sorted(by_uuid):
        members = by_uuid[uuid_hex]
        identities = {
            (member["cputype"], member["cpusubtype"]) for member in members
        }
        if len(identities) < 2:
            continue
        groups = OrderedDict()
        for member in members:
            identity = (member["cputype"], member["cpusubtype"])
            groups.setdefault(identity, []).append(member)
        identity_details = [
            _identity_dict(members[0]["uuid"], cputype, cpusubtype)
            for cputype, cpusubtype in sorted(groups)
        ]
        findings.append(
            _finding(
                "uuid_cpu_conflict",
                "error",
                "one UUID is claimed with more than one CPU type/subtype",
                related=[_slice_ref(member) for member in members],
                paths=[member["path"] for member in members],
                uuid=members[0]["uuid"],
                identities=identity_details,
            )
        )
    return findings


def _findings_for_cpu_comparison(records):
    by_cpu = OrderedDict()
    for record in records:
        if record["cputype"] is None or record["cpusubtype"] is None:
            continue
        key = (record["cputype"], record["cpusubtype"])
        per_kind = by_cpu.setdefault(
            key, OrderedDict((kind, []) for kind in MATERIAL_KINDS)
        )
        per_kind[record["kind"]].append(record)

    findings = []
    for key in sorted(by_cpu):
        per_kind = by_cpu[key]
        counts = {kind: len(per_kind[kind]) for kind in MATERIAL_KINDS}
        present_kinds = [kind for kind in MATERIAL_KINDS if counts[kind]]
        if len(present_kinds) < 2:
            continue
        if any(counts[kind] > 1 for kind in present_kinds):
            continue

        members = [per_kind[kind][0] for kind in present_kinds]
        ok_members = [member for member in members if member["status"] == "ok"]
        incomplete_members = [
            member
            for member in members
            if member["status"] in ("incomplete", "unidentified")
        ]

        reference = ok_members[0] if ok_members else None
        mismatch_members = []
        if len(ok_members) >= 2:
            uuid_counts = OrderedDict()
            for member in ok_members:
                uuid_counts[member["uuid_hex"]] = (
                    uuid_counts.get(member["uuid_hex"], 0) + 1
                )
            majority_uuid = max(uuid_counts, key=uuid_counts.get)
            majority_members = [
                member
                for member in ok_members
                if member["uuid_hex"] == majority_uuid
            ]
            if len(majority_members) * 2 > len(ok_members):
                reference = majority_members[0]
                mismatch_members = [
                    member
                    for member in ok_members
                    if member["uuid_hex"] != majority_uuid
                ]
            else:
                reference = ok_members[0]
                mismatch_members = [
                    member
                    for member in ok_members[1:]
                    if member["uuid_hex"] != reference["uuid_hex"]
                ]

            for member in mismatch_members:
                findings.append(
                    _finding(
                        "identity_mismatch",
                        "error",
                        "same CPU type/subtype reports different LC_UUID values",
                        path=member["path"],
                        kind=member["kind"],
                        slice_index=member["slice_index"],
                        related=[_slice_ref(reference)],
                        paths=[member["path"], reference["path"]],
                        cputype=key[0],
                        cpusubtype=key[1],
                        expected_uuid=reference["uuid"],
                        actual_uuid=member["uuid"],
                    )
                )

        if reference is not None:
            for member in incomplete_members:
                findings.append(
                    _finding(
                        "incomplete_counterpart",
                        "error",
                        "same CPU type/subtype has a readable counterpart "
                        "but this slice is incomplete",
                        path=member["path"],
                        kind=member["kind"],
                        slice_index=member["slice_index"],
                        related=[_slice_ref(reference)],
                        paths=[member["path"], reference["path"]],
                        cputype=key[0],
                        cpusubtype=key[1],
                        expected_uuid=reference["uuid"],
                        actual_uuid=member["uuid"],
                    )
                )

    return findings


def _finding_sort_key(finding):
    kind = finding.get("kind")
    return (
        finding.get("code") or "",
        _KIND_ORDER.get(kind, len(MATERIAL_KINDS)),
        finding.get("path") or "",
        finding.get("slice_index")
        if finding.get("slice_index") is not None
        else -1,
        finding.get("command_index")
        if finding.get("command_index") is not None
        else -1,
    )


def _prepare_kwargs(kwargs):
    aliases = {
        "archives": "archive",
        "splits": "archive",
        "split_archive": "archive",
        "thin": "archive",
        "per_arch": "archive",
        "slices": "archive",
        "debugs": "debug",
        "dsym": "debug",
        "dsyms": "debug",
        "dwarf": "debug",
        "debug_file": "debug",
        "debug_files": "debug",
        "generic": "universal",
        "fat": "universal",
        "universal_macho": "universal",
        "universal_files": "universal",
    }
    accepted = {}
    for key, value in kwargs.items():
        if key in aliases:
            accepted.setdefault(aliases[key], []).append(value)
        elif key in ("required_kinds", "expected_kinds", "expected", "require_kinds"):
            accepted["expected_kinds"] = value
        elif key == "include_commands":
            accepted["include_commands"] = value
        else:
            raise TypeError("unexpected keyword argument %r" % (key,))
    return accepted


def build_pairing_report(
    universal=None,
    archive=None,
    debug=None,
    materials=None,
    expected_kinds=None,
    include_commands=True,
    **kwargs
):
    """
    Build a read-only slice pairing report.

    ``universal``, ``archive`` and ``debug`` accept a path, a directory or an
    iterable of paths.  Directories are walked in sorted order and filtered to
    files that start with a Mach-O or fat magic.  Explicit file paths are
    always inspected, even when they are malformed.

    ``materials`` may be a mapping ``{kind: path_or_paths}`` or an iterable of
    ``(kind, path_or_paths)`` pairs.

    ``expected_kinds`` optionally requires every identity to be present in the
    listed kinds.  Without it, a complete pair is enough: a group with a
    universal slice and its archive slice is unique even when no debug file
    was supplied.
    """

    prepared = _prepare_kwargs(kwargs)
    if "expected_kinds" in prepared:
        expected_kinds = prepared["expected_kinds"]
    if "include_commands" in prepared:
        include_commands = prepared["include_commands"]
    for alias_key in ("universal", "archive", "debug"):
        if alias_key in prepared:
            extra = _as_paths(prepared[alias_key])
            if alias_key == "universal":
                universal = _as_paths(universal) + extra
            elif alias_key == "archive":
                archive = _as_paths(archive) + extra
            else:
                debug = _as_paths(debug) + extra

    grouped = _collect_materials(universal, archive, debug, materials)
    required_kinds = _as_kind_list(expected_kinds)

    inputs = []
    all_records = []
    for kind in MATERIAL_KINDS:
        for input_kind, path in _expand_paths(grouped[kind], kind):
            inputs.append(OrderedDict((("kind", input_kind), ("path", path))))
            all_records.extend(read_slices(path, input_kind))

    all_records.sort(key=_slice_sort_key)
    inputs.sort(key=lambda item: (_KIND_ORDER[item["kind"]], item["path"]))

    commands = []
    for record in all_records:
        commands.extend(record["commands"])
    commands.sort(key=_command_sort_key)

    ok_records = [record for record in all_records if record["status"] == "ok"]
    ambiguous_records = [
        record for record in all_records if record["status"] == "ambiguous"
    ]
    incomplete_records = [
        record
        for record in all_records
        if record["status"] in ("incomplete", "unidentified")
    ]

    by_identity = OrderedDict()
    for record in ok_records:
        by_identity.setdefault(_group_identity(record), []).append(record)

    uuid_identities = OrderedDict()
    for record in ok_records:
        uuid_identities.setdefault(record["uuid_hex"], set()).add(
            (record["cputype"], record["cpusubtype"])
        )
    conflicted_uuids = {
        uuid_hex
        for uuid_hex, identities in uuid_identities.items()
        if len(identities) > 1
    }

    groups = []
    for key in sorted(by_identity):
        groups.append(
            _build_group(
                key,
                by_identity[key],
                required_kinds,
                conflicted_uuids=conflicted_uuids,
            )
        )

    unique = [group for group in groups if group["status"] == "unique"]
    duplicates = [group for group in groups if group["status"] == "duplicate"]
    unmatched = [group for group in groups if group["status"] == "unmatched"]
    duplicates.extend(_ambiguous_entry(record) for record in ambiguous_records)

    uuid_findings = _findings_for_uuid_conflicts(ok_records)

    incomplete = [_incomplete_entry(record) for record in incomplete_records]

    problems = []
    problems.extend(_findings_for_incomplete(incomplete_records))
    problems.extend(_findings_for_groups(unique, duplicates, unmatched))
    problems.extend(uuid_findings)
    problems.extend(_findings_for_cpu_comparison(all_records))
    problems.sort(key=_finding_sort_key)

    summary = OrderedDict()
    summary["material_count"] = len(inputs)
    summary["slice_count"] = len(all_records)
    summary["command_count"] = len(commands)
    summary["uuid_command_count"] = sum(
        1 for command in commands if command["cmd"] == LC_UUID
    )
    summary["unique_count"] = len(unique)
    summary["duplicate_count"] = len(duplicates)
    summary["incomplete_count"] = len(incomplete)
    summary["unmatched_count"] = len(unmatched)
    summary["problem_count"] = len(problems)
    summary["expected_kinds"] = list(required_kinds) if required_kinds else []
    summary["all_complete"] = (
        bool(inputs)
        and not duplicates
        and not incomplete
        and not unmatched
        and not problems
    )

    report = OrderedDict()
    report["schema"] = SCHEMA_VERSION
    report["inputs"] = inputs
    report["summary"] = summary
    report["slices"] = all_records if include_commands else [
        _slice_ref(record) for record in all_records
    ]
    report["commands"] = commands if include_commands else []
    report["uuid_commands"] = [
        command for command in commands if command["cmd"] == LC_UUID
    ] if include_commands else []
    report["unique"] = unique
    report["duplicates"] = duplicates
    report["incomplete"] = incomplete
    report["unmatched"] = unmatched
    report["problems"] = problems
    return report


def audit_slices(*args, **kwargs):
    """Alias for :func:`build_pairing_report`."""

    return build_pairing_report(*args, **kwargs)


pair_slices = audit_slices
audit_macho_slices = build_pairing_report
pair_macho_slices = build_pairing_report
build_slice_pairing_report = build_pairing_report


class SlicePairingAudit(object):
    """Small object wrapper around :func:`build_pairing_report`."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def run(self):
        return build_pairing_report(*self.args, **self.kwargs)

    report = run


SliceAuditor = SlicePairingAudit


def _print_human(report, fp):
    summary = report["summary"]
    print(
        "Mach-O slices: %d unique, %d duplicate, %d incomplete, %d unmatched"
        % (
            summary["unique_count"],
            summary["duplicate_count"],
            summary["incomplete_count"],
            summary["unmatched_count"],
        ),
        file=fp,
    )
    for finding in report["problems"]:
        locations = finding.get("paths") or []
        location = finding.get("path") or (
            ", ".join(locations) if locations else "<multiple>"
        )
        if finding.get("path") and finding.get("slice_index") is not None:
            location += "#slice=%d" % (finding["slice_index"],)
        print(
            "%s [%s] %s: %s"
            % (finding["severity"], finding["code"], location, finding["message"]),
            file=fp,
        )


def _split_material_argument(value):
    for separator in ("=", ":"):
        if separator not in value:
            continue
        prefix, rest = value.split(separator, 1)
        try:
            return _normalise_kind(prefix), rest
        except ValueError:
            continue
    return KIND_ARCHIVE, value


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="macholib.slice_pairing",
        description="Read-only LC_UUID/CPU slice pairing audit for Mach-O files.",
    )
    parser.add_argument(
        "materials",
        nargs="*",
        help="KIND=PATH pairs or paths (default kind: archive)",
    )
    parser.add_argument("--universal", action="append", default=[])
    parser.add_argument("--archive", action="append", default=[])
    parser.add_argument("--debug", action="append", default=[])
    parser.add_argument(
        "--expected",
        default=None,
        help="comma separated kinds that every identity must contain",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--pretty", action="store_true", help="indent JSON")
    parser.add_argument(
        "--no-commands",
        action="store_true",
        help="omit the flat command list from the report",
    )
    parser.add_argument(
        "--fail-on-problems",
        action="store_true",
        help="exit with status 2 when the report is not fully paired",
    )
    args = parser.parse_args(argv)

    grouped = OrderedDict((kind, []) for kind in MATERIAL_KINDS)
    grouped[KIND_UNIVERSAL].extend(args.universal)
    grouped[KIND_ARCHIVE].extend(args.archive)
    grouped[KIND_DEBUG].extend(args.debug)
    for value in args.materials:
        kind, path = _split_material_argument(value)
        grouped[kind].append(path)

    if not any(grouped.values()):
        parser.error("at least one input path is required")

    expected = args.expected.split(",") if args.expected else None
    try:
        report = build_pairing_report(
            universal=grouped[KIND_UNIVERSAL],
            archive=grouped[KIND_ARCHIVE],
            debug=grouped[KIND_DEBUG],
            expected_kinds=expected,
            include_commands=not args.no_commands,
        )
    except ValueError as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=False))
    else:
        _print_human(report, sys.stdout)

    if args.fail_on_problems and not report["summary"]["all_complete"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
