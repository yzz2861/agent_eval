"""
Read-only evidence extraction for offline Mach-O disassembly.

The manifest built by this module keeps every Mach-O slice separate and uses
LC_DATA_IN_CODE, section attributes and symbol locations as independent clues.
It deliberately does not decode instructions or overwrite the file.
"""

from __future__ import absolute_import, print_function

import json
import os
import sys

from macholib.mach_o import (
    DATA_IN_CODE_KINDS,
    LC_DATA_IN_CODE,
    LC_SEGMENT,
    LC_SEGMENT_64,
    LC_SYMTAB,
    MH_CIGAM_64,
    MH_MAGIC_64,
    N_SECT,
    N_STAB,
    N_TYPE,
    N_UNDF,
    S_ATTR_PURE_INSTRUCTIONS,
    S_ATTR_SELF_MODIFYING_CODE,
    S_ATTR_SOME_INSTRUCTIONS,
    S_GB_ZEROFILL,
    S_SYMBOL_STUBS,
    S_THREAD_LOCAL_ZEROFILL,
    S_ZEROFILL,
    SECTION_TYPE,
    data_in_code_entry,
    nlist,
    nlist_64,
)
from macholib.ptypes import sizeof

MANIFEST_FORMAT = "macholib.data-in-code-evidence"
MANIFEST_VERSION = 1

STATUS_DATA = "data"
STATUS_INSTRUCTION_CANDIDATE = "instruction_candidate"
STATUS_CONFLICT = "conflict"
STATUS_UNRESOLVED = "unresolved"

EVIDENCE_DATA = STATUS_DATA
EVIDENCE_INSTRUCTION_CANDIDATE = STATUS_INSTRUCTION_CANDIDATE
EVIDENCE_CONFLICT = STATUS_CONFLICT
EVIDENCE_UNRESOLVED = STATUS_UNRESOLVED

__all__ = [
    "EVIDENCE_CONFLICT",
    "EVIDENCE_DATA",
    "EVIDENCE_INSTRUCTION_CANDIDATE",
    "EVIDENCE_UNRESOLVED",
    "EvidenceManifest",
    "MANIFEST_FORMAT",
    "MANIFEST_VERSION",
    "STATUS_CONFLICT",
    "STATUS_DATA",
    "STATUS_INSTRUCTION_CANDIDATE",
    "STATUS_UNRESOLVED",
    "build_data_in_code_evidence",
    "build_evidence_manifest",
    "data_in_code_evidence",
    "data_in_code_kind_name",
    "main",
    "manifest_for_macho",
]


class EvidenceManifest(dict):
    """Dictionary manifest with convenient attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def to_dict(self):
        return dict(self)

    def to_json(self, indent=2):
        return json.dumps(self, indent=indent, sort_keys=True)


def data_in_code_kind_name(kind):
    return DATA_IN_CODE_KINDS.get(int(kind))


def _is_zerofill(section):
    section_type = int(section.flags) & SECTION_TYPE
    return section_type in (
        S_ZEROFILL,
        S_GB_ZEROFILL,
        S_THREAD_LOCAL_ZEROFILL,
    )


def _is_code_section(section, segment):
    flags = int(section.flags)
    if flags & (
        S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_SELF_MODIFYING_CODE
    ):
        return True

    section_type = flags & SECTION_TYPE
    if section_type == S_SYMBOL_STUBS:
        return True

    sectname = section.sectname.rstrip(b"\x00")
    segname = section.segname.rstrip(b"\x00")
    if sectname == b"__text" and segname == b"__TEXT":
        return True

    return bool(int(segment.initprot) & 4 and section_type == 0)


def _section_name(section):
    return section.sectname.rstrip(b"\x00").decode("ascii", "replace")


def _segment_name(section):
    return section.segname.rstrip(b"\x00").decode("ascii", "replace")


def _section_brief(section):
    if section is None:
        return None
    return {
        "index": section["index"],
        "sectname": section["sectname"],
        "segname": section["segname"],
        "addr": section["virtual_address"],
        "size": section["size"],
        "offset": section["slice_file_offset"],
        "file_offset": section["file_offset"],
    }


def _segment_brief(segment):
    if segment is None:
        return None
    return {
        "index": segment["index"],
        "segname": segment["segname"],
        "vmaddr": segment["vmaddr"],
        "vmsize": segment["vmsize"],
        "fileoff": segment["fileoff"],
        "filesize": segment["filesize"],
        "initprot": segment["initprot"],
    }


def _command_offsets(header):
    offsets = []
    offset = sizeof(header.mach_header)
    for load_command, _command, _data in header.commands:
        offsets.append(offset)
        offset += int(load_command.cmdsize)
    return offsets


def _collect_segments_and_sections(header):
    segments = []
    sections = []
    section_index = 0

    for command_index, (load_command, command, data) in enumerate(header.commands):
        if load_command.cmd not in (LC_SEGMENT, LC_SEGMENT_64):
            continue

        segment = {
            "index": len(segments),
            "command_index": command_index,
            "segname": command.segname.rstrip(b"\x00").decode("ascii", "replace"),
            "vmaddr": int(command.vmaddr),
            "vmsize": int(command.vmsize),
            "fileoff": int(command.fileoff),
            "filesize": int(command.filesize),
            "maxprot": int(command.maxprot),
            "initprot": int(command.initprot),
            "nsects": int(command.nsects),
            "flags": int(command.flags),
            "sections": [],
        }

        for section in data:
            section_index += 1
            section_type = int(section.flags) & SECTION_TYPE
            file_backed = not _is_zerofill(section)
            section_data = {
                "index": section_index,
                "command_index": command_index,
                "segment_index": segment["index"],
                "section_type": section_type,
                "sectname": _section_name(section),
                "segname": _segment_name(section),
                "virtual_address": int(section.addr),
                "size": int(section.size),
                "slice_file_offset": int(section.offset),
                "file_offset": int(header.offset) + int(section.offset),
                "align": int(section.align),
                "reloff": int(section.reloff),
                "nreloc": int(section.nreloc),
                "flags": int(section.flags),
                "file_backed": file_backed,
                "code_candidate": file_backed
                and int(section.size) > 0
                and _is_code_section(section, command),
            }
            sections.append(section_data)
            segment["sections"].append(section_data)

        segments.append(segment)

    return segments, sections


def _find_section_by_file_offset(sections, slice_file_offset):
    matches = []
    for section in sections:
        if not section["file_backed"]:
            continue
        start = section["slice_file_offset"]
        end = start + section["size"]
        if start <= slice_file_offset < end:
            matches.append(section)
    if not matches:
        return None
    return min(matches, key=lambda item: item["size"])


def _find_segment_by_file_offset(segments, slice_file_offset):
    matches = []
    for segment in segments:
        start = segment["fileoff"]
        end = start + segment["filesize"]
        if start <= slice_file_offset < end:
            matches.append(segment)
    if not matches:
        return None
    return min(matches, key=lambda item: item["filesize"])


def _find_section_by_vmaddr(sections, virtual_address):
    matches = []
    for section in sections:
        start = section["virtual_address"]
        end = start + section["size"]
        if start <= virtual_address < end:
            matches.append(section)
    if not matches:
        return None
    return min(matches, key=lambda item: item["size"])


def _map_file_offset(sections, segments, slice_file_offset):
    section = _find_section_by_file_offset(sections, slice_file_offset)
    segment = _find_segment_by_file_offset(segments, slice_file_offset)

    virtual_address = None
    if section is not None:
        virtual_address = section["virtual_address"] + (
            slice_file_offset - section["slice_file_offset"]
        )
    elif segment is not None:
        virtual_address = segment["vmaddr"] + (slice_file_offset - segment["fileoff"])

    return section, segment, virtual_address


def _map_virtual_address(sections, segments, virtual_address, section_index=None):
    if section_index and 1 <= section_index <= len(sections):
        section = sections[section_index - 1]
        start = section["virtual_address"]
        end = start + section["size"]
        if start <= virtual_address < end and section["file_backed"]:
            return (
                section["slice_file_offset"] + (virtual_address - start),
                section,
            )

    section = _find_section_by_vmaddr(sections, virtual_address)
    if section is not None and section["file_backed"]:
        return (
            section["slice_file_offset"]
            + (virtual_address - section["virtual_address"]),
            section,
        )

    for segment in segments:
        start = segment["vmaddr"]
        end = start + segment["vmsize"]
        if start <= virtual_address < end:
            file_offset = segment["fileoff"] + (virtual_address - start)
            if 0 <= file_offset < segment["filesize"]:
                return file_offset, None

    return None, None


def _record_source(record):
    keys = (
        "record_id",
        "record_index",
        "command_index",
        "table_index",
        "record_file_offset",
        "record_slice_file_offset",
        "offset",
        "length",
        "kind",
        "kind_name",
        "known_kind",
        "status",
        "reason",
        "file_offset",
        "slice_file_offset",
        "virtual_address",
        "section",
    )
    return dict((key, record.get(key)) for key in keys)


def _add_conflict(
    conflicts,
    header,
    sections,
    segments,
    category,
    slice_file_offset,
    length,
    detail,
    record_ids=None,
    records=None,
    symbol_id=None,
):
    virtual_address = None
    if slice_file_offset is not None:
        _section, _segment, virtual_address = _map_file_offset(
            sections, segments, slice_file_offset
        )

    conflict = {
        "status": STATUS_CONFLICT,
        "category": category,
        "slice_index": header._evidence_slice_index,
        "slice_file_offset": slice_file_offset,
        "file_offset": (
            None
            if slice_file_offset is None
            else int(header.offset) + slice_file_offset
        ),
        "virtual_address": virtual_address,
        "length": length,
        "end_file_offset": (
            None
            if slice_file_offset is None
            else int(header.offset) + slice_file_offset + length
        ),
        "end_virtual_address": (
            None if virtual_address is None else virtual_address + length
        ),
        "detail": detail,
        "record_ids": list(record_ids or ()),
        "records": list(records or ()),
        "symbol_id": symbol_id,
    }
    conflicts.append(conflict)


def _record_region(record, status):
    return {
        "status": status,
        "record_id": record["record_id"],
        "record_ids": [record["record_id"]],
        "slice_index": record["slice_index"],
        "slice_file_offset": record["slice_file_offset"],
        "file_offset": record["file_offset"],
        "virtual_address": record["virtual_address"],
        "length": record["length"],
        "end_slice_file_offset": (
            None
            if record["slice_file_offset"] is None
            else record["slice_file_offset"] + record["length"]
        ),
        "end_file_offset": (
            None
            if record["file_offset"] is None
            else record["file_offset"] + record["length"]
        ),
        "end_virtual_address": (
            None
            if record["virtual_address"] is None
            else record["virtual_address"] + record["length"]
        ),
        "kind": record["kind"],
        "kind_name": record["kind_name"],
        "known_kind": record["known_kind"],
        "section": record["section"],
        "symbol_ids": [],
        "record": _record_source(record),
    }


def _parse_data_in_code(
    header,
    file_object,
    file_size,
    command_offsets,
    sections,
    segments,
):
    records = []
    conflicts = []
    command_summaries = []
    slice_size = int(header.size)
    slice_offset = int(header.offset)
    available_slice_size = max(0, min(slice_size, file_size - slice_offset))
    entry_size = sizeof(data_in_code_entry)

    for command_index, (load_command, command, _data) in enumerate(header.commands):
        if load_command.cmd != LC_DATA_IN_CODE:
            continue

        dataoff = int(command.dataoff)
        datasize = int(command.datasize)
        command_file_offset = slice_offset + command_offsets[command_index]
        table_file_offset = slice_offset + dataoff
        available_size = max(0, min(datasize, available_slice_size - dataoff))
        summary = {
            "command_index": command_index,
            "command_file_offset": command_file_offset,
            "command_slice_file_offset": command_offsets[command_index],
            "dataoff": dataoff,
            "datasize": datasize,
            "table_file_offset": table_file_offset,
            "table_slice_file_offset": dataoff,
            "available_size": available_size,
            "entry_size": entry_size,
            "entry_count": available_size // entry_size,
            "declared_entry_count": datasize // entry_size,
        }
        command_summaries.append(summary)

        if dataoff > available_slice_size:
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "data_in_code_table_out_of_bounds",
                None,
                0,
                "LC_DATA_IN_CODE table is outside the Mach-O slice",
            )
            summary["error"] = "out_of_bounds"
            continue

        if datasize % entry_size:
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "data_in_code_table_truncated_entry",
                dataoff + (datasize - (datasize % entry_size)),
                datasize % entry_size,
                "LC_DATA_IN_CODE datasize is not a multiple of the entry size",
            )
            summary["error"] = "truncated_entry"

        if dataoff + datasize > available_slice_size:
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "data_in_code_table_truncated",
                dataoff,
                available_size,
                "LC_DATA_IN_CODE table extends beyond the Mach-O slice",
            )
            summary["error"] = summary.get("error") or "truncated"

        if available_size <= 0:
            continue

        file_object.seek(table_file_offset)
        table_data = file_object.read(available_size)

        for entry_index in range(len(table_data) // entry_size):
            entry_offset = entry_index * entry_size
            entry = data_in_code_entry.from_str(
                table_data[entry_offset : entry_offset + entry_size],  # noqa: E203
                _endian_=header.endian,
            )
            record_offset = int(entry.offset)
            record_length = int(entry.length)
            kind = int(entry.kind)
            known_kind = kind in DATA_IN_CODE_KINDS
            record_file_offset = table_file_offset + entry_offset
            record_file_start = slice_offset + record_offset
            record_file_end = record_file_start + record_length
            within_slice = (
                record_length > 0
                and record_offset >= 0
                and record_offset + record_length <= available_slice_size
            )
            within_file = (
                record_length > 0
                and record_file_start >= 0
                and record_file_end <= file_size
            )
            valid = within_slice and within_file
            section, segment, virtual_address = _map_file_offset(
                sections, segments, record_offset
            )

            record_id = "slice:%d/data-in-code:%d/entry:%d" % (
                header._evidence_slice_index,
                command_index,
                entry_index,
            )
            record = {
                "record_id": record_id,
                "record_index": len(records),
                "table_index": len(command_summaries) - 1,
                "entry_index": entry_index,
                "command_index": command_index,
                "record_file_offset": record_file_offset,
                "record_slice_file_offset": record_file_offset - slice_offset,
                "slice_index": header._evidence_slice_index,
                "offset": record_offset,
                "length": record_length,
                "kind": kind,
                "kind_name": data_in_code_kind_name(kind),
                "known_kind": known_kind,
                "valid_bounds": valid,
                "slice_file_offset": record_offset,
                "file_offset": record_file_start,
                "virtual_address": virtual_address,
                "section": _section_brief(section),
                "segment": _segment_brief(segment),
                "status": STATUS_UNRESOLVED,
                "reason": None,
                "symbol_ids": [],
            }

            if not known_kind:
                record["reason"] = "unknown data-in-code kind"
            elif record_length == 0:
                record["status"] = STATUS_CONFLICT
                record["reason"] = "zero length"
            elif not valid:
                record["status"] = STATUS_CONFLICT
                record["reason"] = "record is outside file/slice bounds"
            else:
                record["status"] = STATUS_DATA

            if record["status"] == STATUS_CONFLICT:
                _add_conflict(
                    conflicts,
                    header,
                    sections,
                    segments,
                    "invalid_data_in_code_record",
                    record_offset,
                    max(0, record_length),
                    record["reason"],
                    record_ids=[record_id],
                    records=[_record_source(record)],
                )

            if (
                record["status"] == STATUS_DATA
                and section is not None
                and record_offset + record_length
                > section["slice_file_offset"] + section["size"]
            ):
                _add_conflict(
                    conflicts,
                    header,
                    sections,
                    segments,
                    "record_crosses_section_boundary",
                    record_offset,
                    record_length,
                    "LC_DATA_IN_CODE record crosses a section boundary",
                    record_ids=[record_id],
                    records=[_record_source(record)],
                )

            records.append(record)

    summary = {
        "present": bool(command_summaries),
        "command_indices": [item["command_index"] for item in command_summaries],
        "commands": command_summaries,
        "entry_count": len(records),
        "unknown_kind_count": sum(1 for record in records if not record["known_kind"]),
    }
    if not command_summaries:
        summary["missing"] = True

    return summary, records, conflicts


def _symbol_name(string_table, name_offset):
    if name_offset <= 0 or name_offset >= len(string_table):
        return ""
    end = string_table.find(b"\x00", name_offset)
    if end < 0:
        end = len(string_table)
    return string_table[name_offset:end].decode("utf-8", "replace")


def _parse_symbols(
    header,
    file_object,
    file_size,
    command_offsets,
    sections,
    segments,
):
    symbols = []
    conflicts = []
    slice_offset = int(header.offset)
    available_slice_size = max(0, min(int(header.size), file_size - slice_offset))

    if header.MH_MAGIC in (MH_MAGIC_64, MH_CIGAM_64):
        symbol_class = nlist_64
    else:
        symbol_class = nlist
    symbol_size = sizeof(symbol_class)

    for command_index, (load_command, command, _data) in enumerate(header.commands):
        if load_command.cmd != LC_SYMTAB:
            continue

        symoff = int(command.symoff)
        nsyms = int(command.nsyms)
        stroff = int(command.stroff)
        strsize = int(command.strsize)
        symbol_table_size = nsyms * symbol_size
        available_symbols_size = max(
            0, min(symbol_table_size, available_slice_size - symoff)
        )
        available_string_size = max(0, min(strsize, available_slice_size - stroff))

        if (
            symoff > available_slice_size
            or symbol_table_size > available_slice_size - symoff
        ):
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "symbol_table_out_of_bounds",
                symoff,
                symbol_table_size,
                "LC_SYMTAB symbol table extends beyond the Mach-O slice",
            )

        if stroff > available_slice_size or strsize > available_slice_size - stroff:
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "string_table_out_of_bounds",
                stroff,
                strsize,
                "LC_SYMTAB string table extends beyond the Mach-O slice",
            )

        file_object.seek(slice_offset + stroff)
        string_table = file_object.read(available_string_size)
        file_object.seek(slice_offset + symoff)
        symbol_data = file_object.read(available_symbols_size)

        for symbol_index in range(len(symbol_data) // symbol_size):
            start = symbol_index * symbol_size
            symbol = symbol_class.from_str(
                symbol_data[start : start + symbol_size],  # noqa: E203
                _endian_=header.endian,
            )
            name = _symbol_name(string_table, int(symbol.n_un))
            if not name:
                continue

            symbol_type = int(symbol.n_type)
            section_index = int(symbol.n_sect)
            virtual_address = int(symbol.n_value)
            file_offset, section = _map_virtual_address(
                sections,
                segments,
                virtual_address,
                section_index=section_index,
            )
            symbol_id = "slice:%d/symtab:%d/symbol:%d" % (
                header._evidence_slice_index,
                command_index,
                symbol_index,
            )
            symbol_entry = {
                "symbol_id": symbol_id,
                "symbol_index": symbol_index,
                "command_index": command_index,
                "symbol_record_file_offset": (slice_offset + symoff + start),
                "name": name,
                "type": symbol_type,
                "type_kind": symbol_type & N_TYPE,
                "is_stab": bool(symbol_type & N_STAB),
                "is_undefined": (symbol_type & N_TYPE) == N_UNDF,
                "is_section": (symbol_type & N_TYPE) == N_SECT,
                "section_index": section_index,
                "section": _section_brief(section),
                "slice_file_offset": file_offset,
                "file_offset": (
                    None if file_offset is None else slice_offset + file_offset
                ),
                "virtual_address": virtual_address,
            }
            symbols.append(symbol_entry)

    return symbols, conflicts


def _merge_intervals(intervals):
    merged = []
    for start, end in sorted(intervals):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        elif end > merged[-1][1]:
            merged[-1][1] = end
    return merged


def _build_candidates(header, sections, segments, records, symbols, data_in_code):
    candidates = []
    conflicts = []
    slice_limit = int(header.size)
    claimed_intervals = [
        (
            record["slice_file_offset"],
            record["slice_file_offset"] + record["length"],
        )
        for record in records
        if record["length"] > 0 and record["slice_file_offset"] is not None
    ]

    for section in sections:
        if not section["code_candidate"]:
            continue

        start = section["slice_file_offset"]
        end = start + section["size"]
        bounded_end = min(end, slice_limit)
        if start < 0 or start >= bounded_end:
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "code_section_out_of_bounds",
                start,
                section["size"],
                "Executable section is outside the Mach-O slice",
            )
            continue
        if bounded_end < end:
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                "code_section_truncated",
                start,
                section["size"],
                "Executable section extends beyond the Mach-O slice",
            )

        blocked = []
        for claim_start, claim_end in claimed_intervals:
            overlap_start = max(start, claim_start)
            overlap_end = min(bounded_end, claim_end)
            if overlap_start < overlap_end:
                blocked.append((overlap_start, overlap_end))

        cursor = start
        for blocked_start, blocked_end in _merge_intervals(blocked):
            if cursor < blocked_start:
                candidates.append(
                    _candidate_interval(
                        header,
                        section,
                        symbols,
                        data_in_code,
                        cursor,
                        blocked_start,
                    )
                )
            cursor = max(cursor, blocked_end)
        if cursor < bounded_end:
            candidates.append(
                _candidate_interval(
                    header,
                    section,
                    symbols,
                    data_in_code,
                    cursor,
                    bounded_end,
                )
            )

    return candidates, conflicts


def _candidate_interval(header, section, symbols, data_in_code, start, end):
    length = end - start
    virtual_address = section["virtual_address"] + (
        start - section["slice_file_offset"]
    )
    symbol_clues = [
        {
            "symbol_id": symbol["symbol_id"],
            "name": symbol["name"],
            "file_offset": symbol["file_offset"],
            "virtual_address": symbol["virtual_address"],
        }
        for symbol in symbols
        if symbol["slice_file_offset"] is not None
        and start <= symbol["slice_file_offset"] < end
    ]
    evidence = ["executable_section"]
    if data_in_code["present"]:
        evidence.append("no_data_in_code_record_covers_interval")
        reason = "LC_DATA_IN_CODE does not classify this interval as data"
    else:
        evidence.append("data_in_code_table_missing")
        reason = (
            "LC_DATA_IN_CODE is missing; interval remains an instruction "
            "candidate only"
        )

    return {
        "status": STATUS_INSTRUCTION_CANDIDATE,
        "slice_index": header._evidence_slice_index,
        "section_index": section["index"],
        "sectname": section["sectname"],
        "segname": section["segname"],
        "slice_file_offset": start,
        "file_offset": int(header.offset) + start,
        "virtual_address": virtual_address,
        "length": length,
        "end_slice_file_offset": end,
        "end_file_offset": int(header.offset) + end,
        "end_virtual_address": virtual_address + length,
        "confirmed_instruction": False,
        "is_instruction": False,
        "evidence": evidence,
        "reason": reason,
        "symbol_clues": symbol_clues,
    }


def _add_symbol_conflicts(
    conflicts,
    header,
    sections,
    segments,
    records,
    regions,
    symbols,
):
    by_record_id = dict((region["record_id"], region) for region in regions)
    for symbol in symbols:
        if symbol["is_stab"] or symbol["slice_file_offset"] is None:
            continue
        symbol_offset = symbol["slice_file_offset"]
        for record in records:
            if record["length"] <= 0 or record["slice_file_offset"] is None:
                continue
            start = record["slice_file_offset"]
            end = start + record["length"]
            if start <= symbol_offset < end:
                record["symbol_ids"].append(symbol["symbol_id"])
                region = by_record_id.get(record["record_id"])
                if (
                    region is not None
                    and symbol["symbol_id"] not in region["symbol_ids"]
                ):
                    region["symbol_ids"].append(symbol["symbol_id"])
                if start < symbol_offset < end:
                    _add_conflict(
                        conflicts,
                        header,
                        sections,
                        segments,
                        "symbol_inside_data_region",
                        symbol_offset,
                        0,
                        "Symbol points inside an LC_DATA_IN_CODE interval",
                        record_ids=[record["record_id"]],
                        records=[_record_source(record)],
                        symbol_id=symbol["symbol_id"],
                    )


def _add_record_overlap_conflicts(
    conflicts,
    header,
    sections,
    segments,
    records,
):
    for left_index, left in enumerate(records):
        if left["length"] <= 0 or left["slice_file_offset"] is None:
            continue
        left_start = left["slice_file_offset"]
        left_end = left_start + left["length"]
        for right in records[left_index + 1 :]:  # noqa: E203
            if right["length"] <= 0 or right["slice_file_offset"] is None:
                continue
            right_start = right["slice_file_offset"]
            right_end = right_start + right["length"]
            overlap_start = max(left_start, right_start)
            overlap_end = min(left_end, right_end)
            if overlap_start >= overlap_end:
                continue
            if (
                left_start == right_start
                and left_end == right_end
                and left["kind"] == right["kind"]
            ):
                continue
            category = "overlapping_data_in_code_records"
            if not left["known_kind"] or not right["known_kind"]:
                category = "unknown_kind_overlaps_record"
            _add_conflict(
                conflicts,
                header,
                sections,
                segments,
                category,
                overlap_start,
                overlap_end - overlap_start,
                "LC_DATA_IN_CODE intervals overlap with different evidence",
                record_ids=[left["record_id"], right["record_id"]],
                records=[
                    _record_source(left),
                    _record_source(right),
                ],
            )


def _deduplicate_conflicts(conflicts):
    result = []
    seen = set()
    for conflict in conflicts:
        key = (
            conflict["category"],
            conflict["slice_index"],
            conflict["slice_file_offset"],
            conflict["length"],
            tuple(conflict["record_ids"]),
            conflict["symbol_id"],
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(conflict)
    return result


def _build_slice(header, file_object, file_size, slice_index):
    header._evidence_slice_index = slice_index
    command_offsets = _command_offsets(header)
    segments, sections = _collect_segments_and_sections(header)
    data_in_code, records, conflicts = _parse_data_in_code(
        header,
        file_object,
        file_size,
        command_offsets,
        sections,
        segments,
    )
    symbols, symbol_conflicts = _parse_symbols(
        header,
        file_object,
        file_size,
        command_offsets,
        sections,
        segments,
    )
    conflicts.extend(symbol_conflicts)

    data_regions = [
        _record_region(record, STATUS_DATA)
        for record in records
        if record["status"] == STATUS_DATA
    ]
    unresolved = [
        _record_region(record, STATUS_UNRESOLVED)
        for record in records
        if record["status"] == STATUS_UNRESOLVED
    ]

    _add_record_overlap_conflicts(conflicts, header, sections, segments, records)
    _add_symbol_conflicts(
        conflicts,
        header,
        sections,
        segments,
        records,
        data_regions + unresolved,
        symbols,
    )
    candidates, candidate_conflicts = _build_candidates(
        header,
        sections,
        segments,
        records,
        symbols,
        data_in_code,
    )
    conflicts.extend(candidate_conflicts)
    conflicts = _deduplicate_conflicts(conflicts)

    notes = []
    if not data_in_code["present"]:
        notes.append(
            "LC_DATA_IN_CODE is absent; executable ranges are instruction "
            "candidates, not confirmed instructions."
        )
    if data_in_code["unknown_kind_count"]:
        notes.append(
            "Unknown LC_DATA_IN_CODE kinds remain unresolved and are not "
            "promoted to confirmed instructions."
        )

    return {
        "slice_index": slice_index,
        "offset": int(header.offset),
        "file_offset": int(header.offset),
        "size": int(header.size),
        "end_file_offset": int(header.offset) + int(header.size),
        "endian": header.endian,
        "is_64_bit": header.MH_MAGIC in (MH_MAGIC_64, MH_CIGAM_64),
        "magic": int(header.header.magic),
        "cputype": int(header.header.cputype),
        "cpusubtype": int(header.header.cpusubtype),
        "filetype": int(header.header.filetype),
        "header_size": sizeof(header.mach_header),
        "data_in_code": data_in_code,
        "records": records,
        "sections": [_section_brief(section) for section in sections],
        "segments": [_segment_brief(segment) for segment in segments],
        "symbols": symbols,
        "data_regions": data_regions,
        "instruction_candidates": candidates,
        "conflicts": conflicts,
        "unresolved": unresolved,
        "unresolved_regions": unresolved,
        "notes": notes,
    }


def build_evidence_manifest(source, headers=None):
    """
    Build a read-only, per-slice LC_DATA_IN_CODE evidence manifest.

    *source* can be a filename or an existing :class:`macholib.MachO.MachO`.
    """

    if hasattr(source, "headers") and hasattr(source, "filename"):
        macho = source
        filename = macho.filename
    else:
        from macholib.MachO import MachO

        filename = source
        macho = MachO(filename, allow_unknown_load_commands=True)

    selected_headers = list(macho.headers if headers is None else headers)
    file_size = os.path.getsize(filename)
    slices = []

    with open(filename, "rb") as file_object:
        for header in selected_headers:
            try:
                slice_index = macho.headers.index(header)
            except ValueError:
                slice_index = len(slices)
            slices.append(_build_slice(header, file_object, file_size, slice_index))

    manifest = EvidenceManifest(
        {
            "format": MANIFEST_FORMAT,
            "version": MANIFEST_VERSION,
            "filename": filename,
            "read_only": True,
            "slice_count": len(slices),
            "slices": slices,
            "data_regions": [],
            "instruction_candidates": [],
            "conflicts": [],
            "unresolved": [],
            "summary": {
                "records": 0,
                "data_regions": 0,
                "instruction_candidates": 0,
                "conflicts": 0,
                "unresolved": 0,
            },
        }
    )

    for slice_data in slices:
        manifest["data_regions"].extend(slice_data["data_regions"])
        manifest["instruction_candidates"].extend(slice_data["instruction_candidates"])
        manifest["conflicts"].extend(slice_data["conflicts"])
        manifest["unresolved"].extend(slice_data["unresolved"])

    manifest["summary"] = {
        "records": sum(len(item["records"]) for item in slices),
        "data_regions": len(manifest["data_regions"]),
        "instruction_candidates": len(manifest["instruction_candidates"]),
        "conflicts": len(manifest["conflicts"]),
        "unresolved": len(manifest["unresolved"]),
    }
    return manifest


def build_data_in_code_evidence(source, headers=None):
    return build_evidence_manifest(source, headers=headers)


def data_in_code_evidence(source, headers=None):
    return build_evidence_manifest(source, headers=headers)


def manifest_for_macho(source, headers=None):
    return build_evidence_manifest(source, headers=headers)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 1:
        print("Usage: python -m macholib data-in-code FILE", file=sys.stderr)
        return 1

    try:
        manifest = build_evidence_manifest(argv[0])
    except (IOError, OSError, ValueError) as error:
        print("%s: %s" % (argv[0], error), file=sys.stderr)
        return 1

    print(manifest.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
