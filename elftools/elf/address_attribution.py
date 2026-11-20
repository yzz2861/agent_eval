# -------------------------------------------------------------------------------
# elftools: elf/address_attribution.py
#
# Offline attribution of runtime addresses to DWARF file/line rows.
#
# The caller supplies the module ELF, every external debug ELF that should be
# considered, and one or more instance load mappings.  The module deliberately
# does not discover debug files or mappings on its own: an address from a crash
# report must be attributed only against inputs that the caller selected.
# -------------------------------------------------------------------------------
from __future__ import annotations

import json
import os
from bisect import bisect_right
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, Sequence

from ..dwarf.dwarf_util import _file_crc32
from ..dwarf.dwarfinfo import DebugSectionDescriptor, DwarfConfig, DWARFInfo
from ..dwarf.structs import DWARFStructs
from .elffile import ELFFile
from .sections import NoteSection
from .segments import NoteSegment

if TYPE_CHECKING:
    from collections.abc import Iterator
    from .sections import Section


SCHEMA_VERSION = 1

VERIFIED = "verified"
UNVERIFIED = "unverified"
CONFLICT = "conflict"

_DEBUG_SECTION_BASES = (
    ".debug_info",
    ".debug_aranges",
    ".debug_abbrev",
    ".debug_str",
    ".debug_line",
    ".debug_frame",
    ".debug_loc",
    ".debug_ranges",
    ".debug_pubtypes",
    ".debug_pubnames",
    ".debug_addr",
    ".debug_str_offsets",
    ".debug_line_str",
    ".debug_loclists",
    ".debug_rnglists",
    ".debug_sup",
    ".gnu_debugaltlink",
    ".debug_types",
)


class AttributionInputError(ValueError):
    """Raised when the caller's request cannot be interpreted."""


@dataclass(frozen=True, slots=True)
class DebugFile:
    """One explicitly supplied external debug ELF.

    ``id`` is optional; it is used in source and conflict records so a crash
    platform can keep package-based names stable across runs.
    """

    path: str
    id: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        try:
            path = os.fspath(self.path)
        except TypeError as exc:
            raise AttributionInputError("debug file path must be a path") from exc
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if not path:
            raise AttributionInputError("debug file path must not be empty")
        object.__setattr__(self, "path", path)


@dataclass(frozen=True, slots=True)
class MappingRegion:
    """A runtime-to-ELF virtual-address translation region.

    Runtime addresses in ``[runtime_start, runtime_end)`` are translated by
    adding ``elf_start - runtime_start``.  ``elf_size``, when supplied, limits
    the mapped ELF-side span.  It is useful for a mapping harvested from a
    loader table whose runtime extent is not the same as the ELF segment size.
    """

    runtime_start: int
    runtime_end: int
    elf_start: int
    elf_size: int | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        if self.runtime_start < 0 or self.runtime_end < 0 or self.elf_start < 0:
            raise AttributionInputError("mapping addresses must be non-negative")
        if self.runtime_end <= self.runtime_start:
            raise AttributionInputError(
                "mapping region runtime_end must be greater than runtime_start"
            )
        if self.elf_size is not None and self.elf_size <= 0:
            raise AttributionInputError("mapping region elf_size must be positive")


@dataclass(frozen=True, slots=True)
class LoadMapping:
    """One plausible instance load mapping.

    Exactly one of ``bias`` and ``regions`` must be provided.

    * ``bias`` means ``elf_vaddr = runtime_address - bias``.  By default the
      translation is restricted to the main ELF's PT_LOAD spans, so an address
      from an unrelated module is not silently attributed.
    * ``regions`` is an explicit runtime-to-vaddr table.  This is the form to
      use for firmware whose segments are not loaded with one uniform bias.

    Multiple LoadMapping objects are intentionally allowed.  Each produces its
    own provenance in the report, so two plausible mappings are never folded
    into one answer.
    """

    name: str
    bias: int | None = None
    regions: tuple[MappingRegion, ...] = ()
    restrict_to_load_segments: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise AttributionInputError("mapping name must not be empty")
        if (self.bias is None) == (not self.regions):
            raise AttributionInputError(
                f"mapping {self.name!r} must provide exactly one of bias or regions"
            )
        if self.bias is not None and self.bias < 0:
            raise AttributionInputError("mapping bias must be non-negative")

    @classmethod
    def from_bias(
        cls,
        name: str,
        bias: int | str,
        *,
        restrict_to_load_segments: bool = True,
    ) -> LoadMapping:
        return cls(
            name=name,
            bias=parse_int(bias, what="mapping bias"),
            restrict_to_load_segments=restrict_to_load_segments,
        )

    @classmethod
    def from_regions(
        cls,
        name: str,
        regions: Iterable[MappingRegion | dict[str, Any] | Sequence[int | str]],
    ) -> LoadMapping:
        return cls(name=name, regions=tuple(_coerce_region(r) for r in regions))

    @classmethod
    def from_dict(
        cls, value: dict[str, Any], *, default_name: str | None = None
    ) -> LoadMapping:
        if not isinstance(value, dict):
            raise AttributionInputError("mapping must be an object")
        name = str(value.get("name") or value.get("id") or default_name or "")
        if not name:
            raise AttributionInputError("mapping needs a name")
        raw_regions = value.get("regions", value.get("map", value.get("segments")))
        bias = value.get("bias", value.get("load_bias"))
        if bias is None and not raw_regions:
            raise AttributionInputError(f"mapping {name!r} needs bias or regions")
        regions = ()
        if raw_regions:
            if not isinstance(raw_regions, (list, tuple)):
                raise AttributionInputError(f"mapping {name!r} regions must be a list")
            regions = tuple(_coerce_region(r) for r in raw_regions)
        return cls(
            name=name,
            bias=parse_int(bias, what=f"mapping {name!r} bias")
            if bias is not None
            else None,
            regions=regions,
            restrict_to_load_segments=bool(
                value.get("restrict_to_load_segments", True)
            ),
        )

    def definition(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "kind": "bias" if self.bias is not None else "regions",
        }
        if self.bias is not None:
            result["bias"] = hex_int(self.bias)
            result["restrict_to_load_segments"] = self.restrict_to_load_segments
        else:
            result["regions"] = [_region_dict(r) for r in self.regions]
        return result


def _coerce_region(
    value: MappingRegion | dict[str, Any] | Sequence[int | str],
) -> MappingRegion:
    if isinstance(value, MappingRegion):
        return value
    if isinstance(value, dict):
        return MappingRegion(
            runtime_start=parse_int(
                value.get("runtime_start", value.get("start")), what="runtime_start"
            ),
            runtime_end=parse_int(
                value.get("runtime_end", value.get("end")), what="runtime_end"
            ),
            elf_start=parse_int(
                value.get("elf_start", value.get("vaddr", value.get("elf_address"))),
                what="elf_start",
            ),
            elf_size=(
                parse_int(value["elf_size"], what="elf_size")
                if value.get("elf_size") is not None
                else None
            ),
            label=(str(value["label"]) if value.get("label") is not None else None),
        )
    if isinstance(value, (list, tuple)) and len(value) in (3, 4):
        return MappingRegion(
            runtime_start=parse_int(value[0], what="runtime_start"),
            runtime_end=parse_int(value[1], what="runtime_end"),
            elf_start=parse_int(value[2], what="elf_start"),
            elf_size=(
                parse_int(value[3], what="elf_size") if len(value) == 4 else None
            ),
        )
    raise AttributionInputError(
        "mapping region must be an object or [runtime_start, runtime_end, elf_start, elf_size?]"
    )


def _region_dict(region: MappingRegion) -> dict[str, Any]:
    result = {
        "runtime_start": hex_int(region.runtime_start),
        "runtime_end": hex_int(region.runtime_end),
        "elf_start": hex_int(region.elf_start),
    }
    if region.elf_size is not None:
        result["elf_size"] = region.elf_size
    if region.label is not None:
        result["label"] = region.label
    return result


def parse_int(value: Any, *, what: str = "integer") -> int:
    if isinstance(value, bool):
        raise AttributionInputError(f"{what} must be an integer, not a boolean")
    if isinstance(value, int):
        if value < 0:
            raise AttributionInputError(f"{what} must be non-negative")
        return value
    if isinstance(value, str):
        try:
            result = int(value.strip(), 0)
        except ValueError as exc:
            raise AttributionInputError(f"{what} is not an integer: {value!r}") from exc
        if result < 0:
            raise AttributionInputError(f"{what} must be non-negative")
        return result
    raise AttributionInputError(f"{what} is not an integer: {value!r}")


def hex_int(value: int) -> str:
    return f"0x{value:x}"


def _decode_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1")
    return str(value)


def _base_name(path: str) -> str:
    return os.path.basename(path.rstrip(os.sep))


@dataclass(slots=True)
class _LoadSegment:
    index: int
    vaddr: int
    memsz: int
    offset: int
    flags: int

    def report_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "vaddr": hex_int(self.vaddr),
            "memsz": self.memsz,
            "offset": self.offset,
            "flags": self.flags,
        }


@dataclass(slots=True)
class _ElfInfo:
    id: str
    role: str
    path: str
    basename: str
    size: int
    elf_class: int
    little_endian: bool
    machine: str | int
    elf_type: str | int
    build_ids: tuple[str, ...]
    dwo_ids: tuple[int, ...]
    debuglink_name: str | None
    debuglink_crc: int | None
    crc32: int | None
    has_debug_info: bool
    has_debug_line: bool
    line_sections: tuple[str, ...]
    load_segments: tuple[_LoadSegment, ...]

    @property
    def build_id(self) -> str | None:
        return self.build_ids[0] if self.build_ids else None

    def report_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "role": self.role,
            "path": self.path,
            "basename": self.basename,
            "size": self.size,
            "elf": {
                "class": self.elf_class,
                "endianness": "little" if self.little_endian else "big",
                "machine": self.machine,
                "type": self.elf_type,
            },
            "build_id": self.build_id,
            "build_ids": list(self.build_ids),
            "dwo_ids": [hex_int(v) for v in self.dwo_ids],
            "crc32": hex_int(self.crc32) if self.crc32 is not None else None,
            "has_debug_info": self.has_debug_info,
            "has_debug_line": self.has_debug_line,
            "line_sections": list(self.line_sections),
        }
        if self.debuglink_name is not None:
            result["gnu_debuglink"] = {
                "filename": self.debuglink_name,
                "crc32": hex_int(self.debuglink_crc)
                if self.debuglink_crc is not None
                else None,
            }
        if self.load_segments:
            result["load_segments"] = [s.report_dict() for s in self.load_segments]
        return result


@dataclass(slots=True)
class _LineRow:
    address: int
    file_name: str
    file_path: str | None
    file_index: int
    line: int
    column: int
    discriminator: int
    is_stmt: bool


@dataclass(slots=True)
class _LineSequence:
    groups: list[tuple[int, list[_LineRow]]]
    starts: list[int]
    end_address: int | None
    complete: bool

    def candidates_at(self, address: int) -> Iterator[tuple[_LineRow, bool]]:
        if not self.starts:
            return
        if self.end_address is not None and address >= self.end_address:
            return
        position = bisect_right(self.starts, address) - 1
        if position < 0:
            return
        group_address, rows = self.groups[position]
        if group_address > address:
            return
        for row in rows:
            yield row, not self.complete


@dataclass(slots=True)
class _LineTable:
    artifact_id: str
    section: str
    program_offset: int
    cu_offset: int | None
    unit_index: int
    version: int
    compilation_directory: str | None
    sequences: list[_LineSequence]
    standalone: bool
    row_count: int

    def candidates_at(self, address: int) -> Iterator[tuple[_LineRow, int, bool]]:
        for sequence_index, sequence in enumerate(self.sequences):
            for row, unterminated in sequence.candidates_at(address):
                yield row, sequence_index, unterminated

    def report_dict(self) -> dict[str, Any]:
        min_address = None
        max_address = None
        covered = 0
        files: set[str] = set()
        complete_sequences = 0
        coverage: list[dict[str, Any]] = []
        for sequence in self.sequences:
            if sequence.groups:
                first = sequence.groups[0][0]
                last = sequence.groups[-1][0]
                min_address = first if min_address is None else min(min_address, first)
                endpoint = (
                    sequence.end_address if sequence.end_address is not None else last
                )
                max_address = (
                    endpoint if max_address is None else max(max_address, endpoint)
                )
                if sequence.complete and sequence.end_address is not None:
                    complete_sequences += 1
                    if sequence.end_address > first:
                        covered += sequence.end_address - first
                    coverage.append(
                        {
                            "start": hex_int(first),
                            "end": hex_int(sequence.end_address),
                        }
                    )
                else:
                    coverage.append(
                        {
                            "start": hex_int(first),
                            "end": hex_int(last),
                            "unterminated": True,
                        }
                    )
            for _, rows in sequence.groups:
                files.update(row.file_name for row in rows)
        return {
            "section": self.section,
            "program_offset": hex_int(self.program_offset),
            "cu_offset": hex_int(self.cu_offset)
            if self.cu_offset is not None
            else None,
            "unit_index": self.unit_index,
            "version": self.version,
            "standalone": self.standalone,
            "rows": self.row_count,
            "sequences": len(self.sequences),
            "complete_sequences": complete_sequences,
            "min_address": hex_int(min_address) if min_address is not None else None,
            "max_address": hex_int(max_address) if max_address is not None else None,
            "covered_bytes": covered,
            "files": sorted(files),
            "coverage": coverage,
            "compilation_directory": self.compilation_directory,
        }


@dataclass(slots=True)
class _ArtifactScan:
    info: _ElfInfo
    line_tables: list[_LineTable] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    identity: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def status(self) -> str:
        return str(self.identity.get("status", UNVERIFIED))

    def line_stats(self) -> dict[str, Any]:
        rows = sum(t.row_count for t in self.line_tables)
        sequences = sum(len(t.sequences) for t in self.line_tables)
        complete_sequences = sum(
            1 for t in self.line_tables for s in t.sequences if s.complete
        )
        covered = 0
        min_address = None
        max_address = None
        files: set[str] = set()
        coverage: list[dict[str, Any]] = []
        standalone = 0
        sections: set[str] = set()
        for table in self.line_tables:
            table_report = table.report_dict()
            sections.add(table.section)
            standalone += int(table.standalone)
            covered += int(table_report["covered_bytes"])
            value = table_report["min_address"]
            if value is not None:
                address = int(value, 0)
                min_address = (
                    address if min_address is None else min(min_address, address)
                )
            value = table_report["max_address"]
            if value is not None:
                address = int(value, 0)
                max_address = (
                    address if max_address is None else max(max_address, address)
                )
            files.update(table_report["files"])
            coverage.extend(table_report["coverage"])
        return {
            "units": len(self.line_tables),
            "standalone_units": standalone,
            "has_debug_info": self.info.has_debug_info,
            "has_debug_line": self.info.has_debug_line,
            "rows": rows,
            "sequences": sequences,
            "complete_sequences": complete_sequences,
            "covered_bytes": covered,
            "min_address": hex_int(min_address) if min_address is not None else None,
            "max_address": hex_int(max_address) if max_address is not None else None,
            "files": sorted(files),
            "sections": sorted(sections),
            "line_sections": list(self.info.line_sections),
            "coverage": coverage,
        }

    def report_dict(self) -> dict[str, Any]:
        return {
            **self.info.report_dict(),
            "identity": self.identity,
            "line_table": self.line_stats(),
            "diagnostics": self.diagnostics,
        }


def _add_diagnostic(
    diagnostics: list[dict[str, Any]],
    code: str,
    message: str,
    *,
    level: str = "warning",
    artifact_id: str | None = None,
) -> None:
    item: dict[str, Any] = {
        "level": level,
        "code": code,
        "message": message,
    }
    if artifact_id is not None:
        item["artifact_id"] = artifact_id
    diagnostics.append(item)


def _read_build_ids(
    elf: ELFFile, diagnostics: list[dict[str, Any]], artifact_id: str
) -> tuple[str, ...]:
    found: list[str] = []
    seen: set[str] = set()

    def add_notes(notes: Iterable[Any], where: str) -> None:
        try:
            for note in notes:
                note_type = note.get("n_type")
                is_build_id = note_type == "NT_GNU_BUILD_ID" or (
                    note.get("n_name") == "GNU" and note_type == 3
                )
                if not is_build_id:
                    continue
                desc = note.get("n_descdata")
                if isinstance(desc, (bytes, bytearray)):
                    value = bytes(desc).hex()
                else:
                    value = _decode_name(note.get("n_desc"))
                if value and value not in seen:
                    seen.add(value)
                    found.append(value)
        except Exception as exc:
            _add_diagnostic(
                diagnostics,
                "build_id_note_parse_error",
                f"could not parse GNU build-ID notes in {where}: {exc}",
                artifact_id=artifact_id,
            )

    try:
        for section in elf.iter_sections():
            if isinstance(section, NoteSection):
                add_notes(section.iter_notes(), section.name)
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "note_section_scan_error",
            f"could not scan note sections: {exc}",
            artifact_id=artifact_id,
        )

    try:
        for segment in elf.iter_segments():
            if isinstance(segment, NoteSegment):
                add_notes(segment.iter_notes(), f"PT_NOTE[{segment.header.p_type}]")
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "note_segment_scan_error",
            f"could not scan note segments: {exc}",
            artifact_id=artifact_id,
        )

    return tuple(found)


def _read_debuglink(
    elf: ELFFile,
    diagnostics: list[dict[str, Any]],
    artifact_id: str,
) -> tuple[str | None, int | None]:
    try:
        link = elf.get_dwarf_link()
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "debuglink_parse_error",
            f"could not parse .gnu_debuglink: {exc}",
            artifact_id=artifact_id,
        )
        return None, None
    if not link:
        return None, None
    return _base_name(_decode_name(link.filename)), int(link.checksum)


def _read_load_segments(elf: ELFFile) -> tuple[_LoadSegment, ...]:
    result: list[_LoadSegment] = []
    try:
        for index, segment in enumerate(elf.iter_segments(type="PT_LOAD")):
            if segment["p_memsz"] <= 0:
                continue
            result.append(
                _LoadSegment(
                    index=index,
                    vaddr=int(segment["p_vaddr"]),
                    memsz=int(segment["p_memsz"]),
                    offset=int(segment["p_offset"]),
                    flags=int(segment["p_flags"]),
                )
            )
    except Exception:
        return ()
    return tuple(result)


def _find_section(elf: ELFFile, base: str, *, dwo: bool) -> tuple[Section, str] | None:
    """Find a debug section, including GNU compressed and split-DWARF names."""
    suffix = ".dwo" if dwo else ""
    names = (
        base + suffix,
        ".z" + base[1:] + suffix,
    )
    for name in names:
        section = elf.get_section_by_name(name)
        if section is not None:
            return section, name
    return None


def _read_debug_section(
    elf: ELFFile,
    section: Section,
    diagnostics: list[dict[str, Any]],
    artifact_id: str,
) -> DebugSectionDescriptor | None:
    try:
        return elf._read_dwarf_section(section, relocate_dwarf_sections=True)
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "dwarf_section_read_error",
            f"could not read {section.name}: {exc}",
            artifact_id=artifact_id,
        )
        return None


def _build_dwarf_view(
    elf: ELFFile,
    *,
    dwo: bool,
    artifact_id: str,
    diagnostics: list[dict[str, Any]],
) -> DWARFInfo | None:
    selected: dict[str, tuple[Section, str]] = {}
    for base in _DEBUG_SECTION_BASES:
        found = _find_section(elf, base, dwo=dwo)
        if found is not None:
            selected[base] = found

    if not selected:
        return None
    # A file that only has .debug_str/.debug_abbrev but no info/line is not
    # useful for attribution and only adds noise.
    if ".debug_info" not in selected and ".debug_line" not in selected:
        return None

    descriptors: dict[str, DebugSectionDescriptor | None] = {}
    for base in _DEBUG_SECTION_BASES:
        entry = selected.get(base)
        descriptors[base] = (
            _read_debug_section(elf, entry[0], diagnostics, artifact_id)
            if entry is not None
            else None
        )

    eh_frame = elf.get_section_by_name(".eh_frame")
    eh_descriptor = (
        _read_debug_section(elf, eh_frame, diagnostics, artifact_id)
        if eh_frame is not None
        else None
    )

    config = DwarfConfig(
        little_endian=elf.little_endian,
        machine_arch=elf.get_machine_arch(),
        default_address_size=elf.elfclass // 8,
    )
    try:
        return DWARFInfo(
            config=config,
            debug_info_sec=descriptors[".debug_info"],
            debug_aranges_sec=descriptors[".debug_aranges"],
            debug_abbrev_sec=descriptors[".debug_abbrev"],
            debug_frame_sec=descriptors[".debug_frame"],
            eh_frame_sec=eh_descriptor,
            debug_str_sec=descriptors[".debug_str"],
            debug_loc_sec=descriptors[".debug_loc"],
            debug_ranges_sec=descriptors[".debug_ranges"],
            debug_line_sec=descriptors[".debug_line"],
            debug_pubtypes_sec=descriptors[".debug_pubtypes"],
            debug_pubnames_sec=descriptors[".debug_pubnames"],
            debug_addr_sec=descriptors[".debug_addr"],
            debug_str_offsets_sec=descriptors[".debug_str_offsets"],
            debug_line_str_sec=descriptors[".debug_line_str"],
            debug_loclists_sec=descriptors[".debug_loclists"],
            debug_rnglists_sec=descriptors[".debug_rnglists"],
            debug_sup_sec=descriptors[".debug_sup"],
            gnu_debugaltlink_sec=descriptors[".gnu_debugaltlink"],
            debug_types_sec=descriptors[".debug_types"],
        )
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "dwarf_view_build_error",
            f"could not create a DWARF view: {exc}",
            artifact_id=artifact_id,
        )
        return None


def _line_structure_for_offset(
    info: DWARFInfo,
    elf: ELFFile,
    offset: int,
    *,
    diagnostics: list[dict[str, Any]],
    artifact_id: str,
) -> tuple[DWARFStructs, int] | None:
    """Read just enough of a line-unit header to construct its DWARFStructs."""
    section = info.debug_line_sec
    if section is None:
        return None
    stream = section.stream
    try:
        stream.seek(offset)
        first = stream.read(4)
        if len(first) != 4:
            return None
        first_value = int.from_bytes(first, "little" if elf.little_endian else "big")
        if first_value == 0xFFFFFFFF:
            raw_length = stream.read(8)
            if len(raw_length) != 8:
                return None
            unit_length = int.from_bytes(
                raw_length, "little" if elf.little_endian else "big"
            )
            dwarf_format = 64
            header_size = 12
        else:
            unit_length = first_value
            dwarf_format = 32
            header_size = 4
        if unit_length <= 0:
            return None
        end_offset = offset + header_size + unit_length
        if end_offset > section.size:
            _add_diagnostic(
                diagnostics,
                "truncated_line_unit",
                f"line unit at {hex_int(offset)} extends past .debug_line",
                artifact_id=artifact_id,
            )
            end_offset = section.size
        stream.seek(offset + header_size)
        raw_version = stream.read(2)
        if len(raw_version) != 2:
            return None
        version = int.from_bytes(raw_version, "little" if elf.little_endian else "big")
        address_size = elf.elfclass // 8
        if version >= 5:
            raw_address_size = stream.read(1)
            if len(raw_address_size) != 1:
                return None
            address_size = raw_address_size[0]
        if address_size not in (4, 8):
            _add_diagnostic(
                diagnostics,
                "unsupported_address_size",
                f"line unit at {hex_int(offset)} uses address size {address_size}",
                artifact_id=artifact_id,
            )
            return None
        return DWARFStructs(
            elf.little_endian, dwarf_format, address_size, version
        ), end_offset
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "line_unit_header_error",
            f"could not read line-unit header at {hex_int(offset)}: {exc}",
            artifact_id=artifact_id,
        )
        return None


def _resolve_file_entry(
    header: Any,
    file_index: int,
    compilation_directory: str | None,
    version: int,
) -> tuple[str, str | None]:
    file_entries = tuple(header.get("file_entry") or ())
    if not file_entries:
        return f"<file index {file_index}>", None
    index = file_index if version >= 5 else file_index - 1
    if index < 0 or index >= len(file_entries):
        return f"<file index {file_index}>", None
    entry = file_entries[index]
    name = _decode_name(entry.get("name"))
    if not name:
        return f"<file index {file_index}>", None
    directories = tuple(
        _decode_name(d) for d in (header.get("include_directory") or ())
    )
    directory_index = int(entry.get("dir_index") or 0)
    if version >= 5:
        if directory_index < len(directories):
            directory = directories[directory_index]
        else:
            directory = compilation_directory
    else:
        if directory_index == 0:
            directory = compilation_directory
        elif directory_index - 1 < len(directories):
            directory = directories[directory_index - 1]
        else:
            directory = None

    if os.path.isabs(name) or not directory:
        path = name
    else:
        path = os.path.join(directory, name)
    return name, path


def _make_line_table(
    *,
    artifact_id: str,
    section: str,
    program_offset: int,
    cu_offset: int | None,
    unit_index: int,
    lineprog: Any,
    compilation_directory: str | None,
    standalone: bool,
    diagnostics: list[dict[str, Any]],
) -> _LineTable:
    header = lineprog.header
    version = int(header.get("version") or 0)
    sequences: list[_LineSequence] = []
    pending: list[_LineRow] = []
    row_count = 0
    sequence_budget_diagnostics = 0

    def finish_sequence(end_address: int | None, complete: bool) -> None:
        nonlocal pending, row_count, sequence_budget_diagnostics
        if not pending:
            pending = []
            return
        rows = sorted(pending, key=lambda row: row.address)
        groups: list[tuple[int, list[_LineRow]]] = []
        for row in rows:
            if groups and groups[-1][0] == row.address:
                groups[-1][1].append(row)
            else:
                groups.append((row.address, [row]))
        if end_address is not None:
            filtered_groups: list[tuple[int, list[_LineRow]]] = []
            for address, group_rows in groups:
                if address < end_address:
                    filtered_groups.append((address, group_rows))
                elif sequence_budget_diagnostics < 3:
                    _add_diagnostic(
                        diagnostics,
                        "line_row_after_sequence_end",
                        f"line row at {hex_int(address)} is not before sequence end "
                        f"{hex_int(end_address)}",
                        artifact_id=artifact_id,
                    )
                    sequence_budget_diagnostics += 1
            groups = filtered_groups
        if groups:
            row_count += sum(len(group_rows) for _, group_rows in groups)
            sequences.append(
                _LineSequence(
                    groups=groups,
                    starts=[address for address, _ in groups],
                    end_address=end_address,
                    complete=complete,
                )
            )
        pending = []

    try:
        for entry in lineprog.get_entries():
            state = entry.state
            if state is None:
                continue
            if state.end_sequence:
                finish_sequence(int(state.address), True)
                continue
            file_name, file_path = _resolve_file_entry(
                header, int(state.file), compilation_directory, version
            )
            pending.append(
                _LineRow(
                    address=int(state.address),
                    file_name=file_name,
                    file_path=file_path,
                    file_index=int(state.file),
                    line=int(state.line),
                    column=int(state.column),
                    discriminator=int(state.discriminator),
                    is_stmt=bool(state.is_stmt),
                )
            )
        finish_sequence(None, False)
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "line_program_decode_error",
            f"could not decode line program at {hex_int(program_offset)}: {exc}",
            artifact_id=artifact_id,
        )

    return _LineTable(
        artifact_id=artifact_id,
        section=section,
        program_offset=program_offset,
        cu_offset=cu_offset,
        unit_index=unit_index,
        version=version,
        compilation_directory=compilation_directory,
        sequences=sequences,
        standalone=standalone,
        row_count=row_count,
    )


def _collect_dwo_ids(
    info: DWARFInfo, diagnostics: list[dict[str, Any]], artifact_id: str
) -> set[int]:
    result: set[int] = set()
    if info.debug_info_sec is None:
        return result
    try:
        cus = info.iter_CUs()
        for cu in cus:
            try:
                header_id = cu.header.get("dwo_id")
                if isinstance(header_id, int):
                    result.add(header_id)
                top = cu.get_top_DIE()
                attribute = top.attributes.get("DW_AT_GNU_dwo_id")
                if attribute is not None and isinstance(attribute.value, int):
                    result.add(attribute.value)
            except Exception as exc:
                _add_diagnostic(
                    diagnostics,
                    "dwo_identity_error",
                    f"could not read split-DWARF identity from CU "
                    f"{hex_int(cu.cu_offset)}: {exc}",
                    artifact_id=artifact_id,
                )
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "cu_scan_error",
            f"could not scan compilation units for split-DWARF identity: {exc}",
            artifact_id=artifact_id,
        )
    return result


def _scan_line_tables(
    info: DWARFInfo,
    elf: ELFFile,
    *,
    artifact_id: str,
    diagnostics: list[dict[str, Any]],
    first_unit_index: int,
) -> list[_LineTable]:
    if info.debug_line_sec is None:
        return []
    section_name = info.debug_line_sec.name
    tables: list[_LineTable] = []
    seen_offsets: set[int] = set()
    unit_index = first_unit_index

    def add_from_cu(cu: Any, lineprog: Any, stmt_offset: int | None) -> None:
        nonlocal unit_index
        try:
            top = cu.get_top_DIE()
            comp_dir_attr = top.attributes.get("DW_AT_comp_dir")
            comp_dir = (
                _decode_name(comp_dir_attr.value) if comp_dir_attr is not None else None
            )
        except Exception:
            comp_dir = None
        tables.append(
            _make_line_table(
                artifact_id=artifact_id,
                section=section_name,
                program_offset=(
                    stmt_offset
                    if stmt_offset is not None
                    else int(lineprog.program_start_offset)
                ),
                cu_offset=int(cu.cu_offset),
                unit_index=unit_index,
                lineprog=lineprog,
                compilation_directory=comp_dir,
                standalone=False,
                diagnostics=diagnostics,
            )
        )
        unit_index += 1

    if info.debug_info_sec is not None:
        try:
            for cu in info.iter_CUs():
                stmt_offset: int | None = None
                try:
                    top = cu.get_top_DIE()
                    stmt_attr = top.attributes.get("DW_AT_stmt_list")
                    if stmt_attr is not None:
                        stmt_offset = int(stmt_attr.value)
                    lineprog = info.line_program_for_CU(cu)
                except Exception as exc:
                    _add_diagnostic(
                        diagnostics,
                        "cu_line_program_error",
                        f"could not read line program for CU {hex_int(cu.cu_offset)}: {exc}",
                        artifact_id=artifact_id,
                    )
                    continue
                if lineprog is None:
                    continue
                if stmt_offset is not None:
                    seen_offsets.add(stmt_offset)
                add_from_cu(cu, lineprog, stmt_offset)
        except Exception as exc:
            _add_diagnostic(
                diagnostics,
                "cu_iteration_error",
                f"could not iterate compilation units: {exc}",
                artifact_id=artifact_id,
            )

    # A line table may be shipped without .debug_info (or a split unit may not
    # be referenced by the CU list).  Walk the section's unit records too, so
    # trimmed/split debug packages are still usable.
    offset = 0
    size = info.debug_line_sec.size
    while offset + 4 <= size:
        structure = _line_structure_for_offset(
            info, elf, offset, diagnostics=diagnostics, artifact_id=artifact_id
        )
        if structure is None:
            break
        structs, end_offset = structure
        if offset not in seen_offsets:
            try:
                lineprog = info._parse_line_program_at_offset(offset, structs)
            except Exception as exc:
                _add_diagnostic(
                    diagnostics,
                    "standalone_line_program_error",
                    f"could not decode standalone line program at "
                    f"{hex_int(offset)}: {exc}",
                    artifact_id=artifact_id,
                )
            else:
                tables.append(
                    _make_line_table(
                        artifact_id=artifact_id,
                        section=section_name,
                        program_offset=offset,
                        cu_offset=None,
                        unit_index=unit_index,
                        lineprog=lineprog,
                        compilation_directory=None,
                        standalone=True,
                        diagnostics=diagnostics,
                    )
                )
                unit_index += 1
        if end_offset <= offset:
            break
        offset = end_offset
    return tables


def _scan_artifact(
    path: str,
    artifact_id: str,
    *,
    role: str,
    diagnostics: list[dict[str, Any]],
) -> _ArtifactScan:
    path = os.path.abspath(path)
    try:
        with open(path, "rb") as stream:
            elf = ELFFile(stream)
            local_diagnostics: list[dict[str, Any]] = []
            build_ids = _read_build_ids(elf, local_diagnostics, artifact_id)
            debuglink_name, debuglink_crc = _read_debuglink(
                elf, local_diagnostics, artifact_id
            )
            load_segments = _read_load_segments(elf)
            normal_view = _build_dwarf_view(
                elf, dwo=False, artifact_id=artifact_id, diagnostics=local_diagnostics
            )
            dwo_view = _build_dwarf_view(
                elf, dwo=True, artifact_id=artifact_id, diagnostics=local_diagnostics
            )

            line_tables: list[_LineTable] = []
            dwo_ids: set[int] = set()
            next_unit_index = 0
            for view in (normal_view, dwo_view):
                if view is None:
                    continue
                dwo_ids.update(_collect_dwo_ids(view, local_diagnostics, artifact_id))
                new_tables = _scan_line_tables(
                    view,
                    elf,
                    artifact_id=artifact_id,
                    diagnostics=local_diagnostics,
                    first_unit_index=next_unit_index,
                )
                line_tables.extend(new_tables)
                next_unit_index += len(new_tables)

            line_sections = tuple(sorted({t.section for t in line_tables}))
            has_debug_info = any(
                elf.get_section_by_name(name) is not None
                for name in (
                    ".debug_info",
                    ".zdebug_info",
                    ".debug_info.dwo",
                    ".zdebug_info.dwo",
                )
            )
            has_debug_line = any(
                elf.get_section_by_name(name) is not None
                for name in (
                    ".debug_line",
                    ".zdebug_line",
                    ".debug_line.dwo",
                    ".zdebug_line.dwo",
                )
            )
            if not line_sections and has_debug_line:
                line_sections = tuple(
                    name
                    for name in (
                        ".debug_line",
                        ".zdebug_line",
                        ".debug_line.dwo",
                        ".zdebug_line.dwo",
                    )
                    if elf.get_section_by_name(name) is not None
                )

            stream.seek(0)
            crc32 = _file_crc32(stream)
            info = _ElfInfo(
                id=artifact_id,
                role=role,
                path=path,
                basename=_base_name(path),
                size=elf.stream_len,
                elf_class=elf.elfclass,
                little_endian=elf.little_endian,
                machine=elf["e_machine"],
                elf_type=elf["e_type"],
                build_ids=build_ids,
                dwo_ids=tuple(sorted(dwo_ids)),
                debuglink_name=debuglink_name,
                debuglink_crc=debuglink_crc,
                crc32=crc32,
                has_debug_info=has_debug_info,
                has_debug_line=has_debug_line,
                line_sections=line_sections,
                load_segments=load_segments,
            )
            return _ArtifactScan(
                info=info,
                line_tables=line_tables,
                diagnostics=local_diagnostics,
            )
    except Exception as exc:
        _add_diagnostic(
            diagnostics,
            "artifact_load_error",
            f"could not load {path}: {exc}",
            artifact_id=artifact_id,
            level="error",
        )
        return _ArtifactScan(
            info=_ElfInfo(
                id=artifact_id,
                role=role,
                path=path,
                basename=_base_name(path),
                size=0,
                elf_class=0,
                little_endian=True,
                machine="<unreadable>",
                elf_type="<unreadable>",
                build_ids=(),
                dwo_ids=(),
                debuglink_name=None,
                debuglink_crc=None,
                crc32=None,
                has_debug_info=False,
                has_debug_line=False,
                line_sections=(),
                load_segments=(),
            ),
            diagnostics=[
                {
                    "level": "error",
                    "code": "artifact_load_error",
                    "message": f"could not load {path}: {exc}",
                    "artifact_id": artifact_id,
                }
            ],
            error=str(exc),
        )


def _compare_identity(main: _ElfInfo, candidate: _ElfInfo) -> dict[str, Any]:
    if candidate.role == "main":
        return {
            "status": VERIFIED,
            "matching": [],
            "strong_matches": ["main_elf"],
            "weak_matches": [],
            "missing": [],
            "contradictions": [],
            "materials_available": {
                "main_elf": True,
                "build_id": candidate.build_id is not None,
                "gnu_debuglink_crc": False,
                "dwo_id": bool(candidate.dwo_ids),
            },
        }

    matching: list[str] = []
    strong: list[str] = []
    weak: list[str] = []
    missing: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []

    def match(
        name: str, *, strong_match: bool = False, weak_match: bool = False
    ) -> None:
        matching.append(name)
        if strong_match:
            strong.append(name)
        if weak_match:
            weak.append(name)

    def contradict(name: str, main_value: Any, candidate_value: Any) -> None:
        contradictions.append(
            {
                "material": name,
                "main": main_value,
                "candidate": candidate_value,
            }
        )

    def lack(name: str, reason: str) -> None:
        missing.append({"material": name, "reason": reason})

    if main.elf_class == candidate.elf_class:
        match("elf_class")
    else:
        contradict("elf_class", main.elf_class, candidate.elf_class)

    if main.little_endian == candidate.little_endian:
        match("endianness")
    else:
        contradict(
            "endianness",
            "little" if main.little_endian else "big",
            "little" if candidate.little_endian else "big",
        )

    if main.machine == candidate.machine:
        match("machine")
    else:
        contradict("machine", main.machine, candidate.machine)

    if main.build_ids and candidate.build_ids:
        overlap = set(main.build_ids) & set(candidate.build_ids)
        if overlap:
            match("build_id", strong_match=True)
        else:
            contradict("build_id", list(main.build_ids), list(candidate.build_ids))
    elif main.build_ids:
        lack("build_id", "debug file has no GNU build-ID note")
    elif candidate.build_ids:
        lack("build_id", "main ELF has no GNU build-ID note")
    else:
        lack("build_id", "neither file has a GNU build-ID note")

    if main.dwo_ids and candidate.dwo_ids:
        if set(main.dwo_ids) & set(candidate.dwo_ids):
            match("dwo_id", strong_match=True)
        else:
            contradict(
                "dwo_id",
                [hex_int(v) for v in main.dwo_ids],
                [hex_int(v) for v in candidate.dwo_ids],
            )
    else:
        lack("dwo_id", "split-DWARF identity is not available on both sides")

    debuglink_matches_name = (
        main.debuglink_name is not None
        and candidate.basename == _base_name(main.debuglink_name)
    )
    if debuglink_matches_name:
        if main.debuglink_crc is not None and candidate.crc32 is not None:
            if main.debuglink_crc == candidate.crc32:
                match("gnu_debuglink_crc32", strong_match=True)
            else:
                contradict(
                    "gnu_debuglink_crc32",
                    hex_int(main.debuglink_crc),
                    hex_int(candidate.crc32),
                )
        else:
            lack(
                "gnu_debuglink_crc32",
                "the matching .gnu_debuglink checksum or candidate CRC is unavailable",
            )
    elif main.debuglink_name is not None:
        lack(
            "gnu_debuglink",
            f"candidate basename {candidate.basename!r} does not match "
            f".gnu_debuglink name {main.debuglink_name!r}",
        )
    else:
        lack("gnu_debuglink", "main ELF has no .gnu_debuglink section")

    if debuglink_matches_name:
        weak.append("same_basename_as_gnu_debuglink")
    if candidate.basename == main.basename:
        weak.append("same_basename_as_main")

    if contradictions:
        status = CONFLICT
    elif strong:
        status = VERIFIED
    else:
        status = UNVERIFIED

    return {
        "status": status,
        "matching": matching,
        "strong_matches": strong,
        "weak_matches": weak,
        "missing": missing,
        "contradictions": contradictions,
        "materials_available": {
            "build_id": bool(main.build_ids and candidate.build_ids),
            "gnu_debuglink_crc": bool(
                debuglink_matches_name
                and main.debuglink_crc is not None
                and candidate.crc32 is not None
            ),
            "dwo_id": bool(main.dwo_ids and candidate.dwo_ids),
        },
    }


@dataclass(slots=True)
class _Translation:
    link_address: int
    region: str | None


@dataclass(slots=True)
class _ResolvedMapping:
    mapping: LoadMapping
    regions: tuple[MappingRegion, ...]
    bounded: bool
    note: str | None = None

    @classmethod
    def resolve(
        cls, mapping: LoadMapping, load_segments: tuple[_LoadSegment, ...]
    ) -> _ResolvedMapping:
        if mapping.bias is None:
            return cls(mapping=mapping, regions=mapping.regions, bounded=True)
        if not mapping.restrict_to_load_segments:
            return cls(
                mapping=mapping,
                regions=(),
                bounded=False,
                note="bias translation is not restricted to PT_LOAD spans",
            )
        if not load_segments:
            return cls(
                mapping=mapping,
                regions=(),
                bounded=False,
                note="main ELF has no PT_LOAD spans; bias applies without bounds",
            )
        regions = tuple(
            MappingRegion(
                runtime_start=segment.vaddr + mapping.bias,
                runtime_end=segment.vaddr + mapping.bias + segment.memsz,
                elf_start=segment.vaddr,
                elf_size=segment.memsz,
                label=f"PT_LOAD[{segment.index}]",
            )
            for segment in load_segments
        )
        return cls(mapping=mapping, regions=regions, bounded=True)

    def translations(self, runtime_address: int) -> list[_Translation]:
        if self.mapping.bias is not None and not self.regions:
            return [_Translation(runtime_address - self.mapping.bias, None)]
        result: list[_Translation] = []
        seen: set[tuple[int, str | None]] = set()
        for index, region in enumerate(self.regions):
            if not (region.runtime_start <= runtime_address < region.runtime_end):
                continue
            delta = runtime_address - region.runtime_start
            if region.elf_size is not None and delta >= region.elf_size:
                continue
            label = region.label or f"region-{index + 1}"
            key = (region.elf_start + delta, label)
            if key not in seen:
                seen.add(key)
                result.append(_Translation(region.elf_start + delta, label))
        return result

    def report_dict(self) -> dict[str, Any]:
        result = self.mapping.definition()
        result["resolved_regions"] = [_region_dict(region) for region in self.regions]
        result["bounded"] = self.bounded
        if self.note is not None:
            result["note"] = self.note
        return result


@dataclass(frozen=True, slots=True)
class AttributionRequest:
    """A fully explicit attribution request.

    The request deliberately contains no lookup of debug files by build ID,
    debuglink, or filesystem convention.  Every file and every mapping that may
    influence an answer is listed here.
    """

    main_elf: str
    debug_files: tuple[DebugFile, ...]
    mappings: tuple[LoadMapping, ...]
    addresses: tuple[int, ...]
    include_main: bool = True


@dataclass(slots=True)
class AttributionReport:
    """The machine-readable result handed back to a crash platform."""

    main: dict[str, Any]
    debug_files: list[dict[str, Any]]
    mappings: list[dict[str, Any]]
    addresses: list[dict[str, Any]]
    conflicts: list[dict[str, Any]]
    ambiguities: list[dict[str, Any]]
    diagnostics: list[dict[str, Any]]
    summary: dict[str, Any]
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": "pyelftools-offline-address-attribution",
            "main": self.main,
            "debug_files": self.debug_files,
            "mappings": self.mappings,
            "addresses": self.addresses,
            "conflicts": self.conflicts,
            "ambiguities": self.ambiguities,
            "diagnostics": self.diagnostics,
            "summary": self.summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def write_json(
        self, path: str | os.PathLike[str], *, indent: int | None = 2
    ) -> None:
        with open(path, "w", encoding="utf-8") as output:
            json.dump(self.to_dict(), output, indent=indent, ensure_ascii=False)
            output.write("\n")


def _coerce_debug_file(value: DebugFile | str | os.PathLike[str]) -> DebugFile:
    if isinstance(value, DebugFile):
        return value
    try:
        path = os.fspath(value)
    except TypeError as exc:
        raise AttributionInputError(f"debug file is not a path: {value!r}") from exc
    if isinstance(path, bytes):
        path = os.fsdecode(path)
    return DebugFile(path)


def _coerce_mapping(value: LoadMapping | dict[str, Any]) -> LoadMapping:
    if isinstance(value, LoadMapping):
        return value
    if isinstance(value, dict):
        return LoadMapping.from_dict(value)
    raise AttributionInputError(f"mapping is not a LoadMapping or object: {value!r}")


def _coerce_address(value: int | str) -> int:
    return parse_int(value, what="address")


def _normalize_request(
    main_elf: str | os.PathLike[str] | AttributionRequest,
    debug_files: Sequence[DebugFile | str | os.PathLike[str]] | None,
    mappings: Sequence[LoadMapping | dict[str, Any]] | None,
    addresses: Sequence[int | str] | int | str | None,
    *,
    include_main: bool,
) -> AttributionRequest:
    if isinstance(main_elf, AttributionRequest):
        return main_elf

    try:
        main_path = os.fspath(main_elf)
    except TypeError as exc:
        raise AttributionInputError("main_elf must be a path") from exc
    if isinstance(main_path, bytes):
        main_path = os.fsdecode(main_path)
    if not main_path:
        raise AttributionInputError("main_elf must not be empty")

    if debug_files is None:
        debug_values: Sequence[DebugFile | str | os.PathLike[str]] = ()
    elif isinstance(debug_files, (DebugFile, str, bytes, os.PathLike)):
        debug_values = (debug_files,)
    else:
        debug_values = debug_files
    normalized_debug = tuple(_coerce_debug_file(v) for v in debug_values)

    if mappings is None:
        mapping_values: Sequence[LoadMapping | dict[str, Any]] = ()
    elif isinstance(mappings, (LoadMapping, dict)):
        mapping_values = (mappings,)
    else:
        mapping_values = mappings
    normalized_mappings = tuple(_coerce_mapping(v) for v in mapping_values)
    if not normalized_mappings:
        raise AttributionInputError("at least one explicit load mapping is required")

    if addresses is None:
        address_values: Sequence[int | str] = ()
    elif isinstance(addresses, (int, str)):
        address_values = (addresses,)
    else:
        address_values = addresses
    normalized_addresses = tuple(_coerce_address(v) for v in address_values)
    if not normalized_addresses:
        raise AttributionInputError("at least one address is required")

    return AttributionRequest(
        main_elf=main_path,
        debug_files=normalized_debug,
        mappings=normalized_mappings,
        addresses=normalized_addresses,
        include_main=include_main,
    )


def _main_identity(info: _ElfInfo) -> dict[str, Any]:
    return {
        "status": VERIFIED,
        "matching": [],
        "strong_matches": ["main_elf"],
        "weak_matches": [],
        "missing": [],
        "contradictions": [],
        "materials_available": {
            "main_elf": True,
            "build_id": info.build_id is not None,
            "gnu_debuglink_crc": info.debuglink_crc is not None,
            "dwo_id": bool(info.dwo_ids),
        },
    }


def _unreadable_identity(error: str) -> dict[str, Any]:
    return {
        "status": UNVERIFIED,
        "matching": [],
        "strong_matches": [],
        "weak_matches": [],
        "missing": [
            {
                "material": "artifact",
                "reason": f"debug file could not be parsed: {error}",
            }
        ],
        "contradictions": [],
        "materials_available": {
            "build_id": False,
            "gnu_debuglink_crc": False,
            "dwo_id": False,
        },
    }


def _conflict_id(artifact_id: str) -> str:
    safe = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in artifact_id
    )
    return f"identity-{safe}"


def _candidate_from_row(
    *,
    scan: _ArtifactScan,
    table: _LineTable,
    row: _LineRow,
    sequence_index: int,
    unterminated: bool,
    runtime_address: int,
    mapping: _ResolvedMapping,
    translation: _Translation,
) -> dict[str, Any]:
    trust = scan.status
    candidate: dict[str, Any] = {
        "file": row.file_name,
        "path": row.file_path,
        "line": row.line,
        "column": row.column,
        "discriminator": row.discriminator,
        "is_stmt": row.is_stmt,
        "trust": trust,
        "identity_status": trust,
        "accepted": trust == VERIFIED,
        "mapping": mapping.mapping.name,
        "link_address": hex_int(translation.link_address),
        "source": {
            "artifact_id": scan.info.id,
            "artifact_role": scan.info.role,
            "artifact_path": scan.info.path,
            "artifact_basename": scan.info.basename,
            "identity_status": trust,
            "identity_evidence": list(scan.identity.get("strong_matches", [])),
            "line_section": table.section,
            "line_program_offset": hex_int(table.program_offset),
            "cu_offset": hex_int(table.cu_offset)
            if table.cu_offset is not None
            else None,
            "unit_index": table.unit_index,
            "sequence_index": sequence_index,
            "file_index": row.file_index,
            "compilation_directory": table.compilation_directory,
            "mapping": mapping.mapping.name,
            "region": translation.region,
            "runtime_address": hex_int(runtime_address),
            "link_address": hex_int(translation.link_address),
            "sequence_complete": not unterminated,
            "standalone_line_unit": table.standalone,
        },
    }
    if unterminated:
        candidate["note"] = (
            "line sequence has no end_sequence row; coverage is open-ended"
        )
    if scan.status == CONFLICT:
        candidate["conflict_id"] = _conflict_id(scan.info.id)
    return candidate


def _candidate_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    source = candidate["source"]
    return (
        candidate["trust"],
        source["artifact_id"],
        source["line_program_offset"],
        source["sequence_index"],
        source["mapping"],
        source["link_address"],
        candidate["file"],
        candidate["line"],
        candidate["column"],
        candidate["discriminator"],
    )


def _coverage_entry(candidate: dict[str, Any], address: int) -> dict[str, Any]:
    return {
        "address": hex_int(address),
        "mapping": candidate["mapping"],
        "link_address": candidate["link_address"],
        "region": candidate["source"]["region"],
        "file": candidate["file"],
        "path": candidate["path"],
        "line": candidate["line"],
        "column": candidate["column"],
        "is_stmt": candidate["is_stmt"],
        "trust": candidate["trust"],
    }


def _coverage_key(entry: dict[str, Any]) -> tuple[Any, ...]:
    return (
        entry["address"],
        entry["mapping"],
        entry["link_address"],
        entry["file"],
        entry["line"],
        entry["column"],
        entry["is_stmt"],
    )


def _attribute_address(
    address: int,
    scans: Sequence[_ArtifactScan],
    mappings: Sequence[_ResolvedMapping],
    *,
    coverage_by_artifact: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    mapping_results: list[dict[str, Any]] = []
    candidate_keys: set[tuple[Any, ...]] = set()
    coverage_seen: set[tuple[Any, ...]] = set()

    for mapping in mappings:
        translations = mapping.translations(address)
        mapping_result: dict[str, Any] = {
            "name": mapping.mapping.name,
            "status": "mapped" if translations else "unmapped",
        }
        if translations:
            mapping_result["translations"] = [
                {
                    "link_address": hex_int(translation.link_address),
                    "region": translation.region,
                }
                for translation in translations
            ]
        else:
            mapping_result["reason"] = (
                "runtime address is outside the resolved PT_LOAD spans"
                if mapping.bounded
                else "runtime address is outside the supplied mapping regions"
            )
        mapping_results.append(mapping_result)

        for translation in translations:
            for scan in scans:
                for table in scan.line_tables:
                    for row, sequence_index, unterminated in table.candidates_at(
                        translation.link_address
                    ):
                        candidate = _candidate_from_row(
                            scan=scan,
                            table=table,
                            row=row,
                            sequence_index=sequence_index,
                            unterminated=unterminated,
                            runtime_address=address,
                            mapping=mapping,
                            translation=translation,
                        )
                        key = _candidate_key(candidate)
                        if key in candidate_keys:
                            continue
                        candidate_keys.add(key)
                        if scan.status == CONFLICT:
                            rejected.append(candidate)
                            # Keep the rejected answer next to the identity
                            # record, so an operator can see exactly which
                            # "plausible" line the wrong package produced.
                            coverage = coverage_by_artifact.setdefault(scan.info.id, [])
                            entry = _coverage_entry(candidate, address)
                            entry_key = _coverage_key(entry)
                            if entry_key not in coverage_seen:
                                coverage_seen.add(entry_key)
                                coverage.append(entry)
                        else:
                            candidates.append(candidate)
                            if scan.status == UNVERIFIED:
                                coverage = coverage_by_artifact.setdefault(
                                    scan.info.id, []
                                )
                                entry = _coverage_entry(candidate, address)
                                entry_key = _coverage_key(entry)
                                if entry_key not in coverage_seen:
                                    coverage_seen.add(entry_key)
                                    coverage.append(entry)

    candidates.sort(
        key=lambda c: (
            c["trust"] != VERIFIED,
            c["trust"] == CONFLICT,
            str(c["path"] or c["file"]),
            c["line"],
            c["column"],
            c["mapping"],
        )
    )
    rejected.sort(
        key=lambda c: (
            str(c["path"] or c["file"]),
            c["line"],
            c["mapping"],
        )
    )

    verified_answers = {
        (candidate["path"] or candidate["file"], candidate["line"])
        for candidate in candidates
        if candidate["trust"] == VERIFIED
    }
    if verified_answers:
        status = "ambiguous" if len(verified_answers) > 1 else "resolved"
    elif candidates:
        status = "provisional"
    else:
        status = "unresolved"

    mapped = any(item["status"] == "mapped" for item in mapping_results)
    if status == "resolved":
        reason = "verified line row found"
    elif status == "ambiguous":
        reason = "more than one verified file/line answer remains"
    elif status == "provisional":
        reason = (
            "candidates exist, but no shared strong identity material verified them"
        )
    elif rejected:
        reason = "only candidates from identity-conflicting debug files were found"
    elif not mapped:
        reason = "no supplied load mapping covers this address"
    else:
        reason = "the mapped address has no line-table row in the supplied debug data"

    conflict_ids = sorted(
        {
            candidate["conflict_id"]
            for candidate in rejected
            if "conflict_id" in candidate
        }
    )
    result: dict[str, Any] = {
        "address": address,
        "address_hex": hex_int(address),
        "status": status,
        "reason": reason,
        "candidates": candidates,
        "rejected_candidates": rejected,
        "mapping_results": mapping_results,
        "conflicts": conflict_ids,
    }

    ambiguities: list[dict[str, Any]] = []
    if status == "ambiguous":
        ambiguity = {
            "kind": "multiple_verified_attributions",
            "address": hex_int(address),
            "answers": [
                {"file": path, "line": line} for path, line in sorted(verified_answers)
            ],
            "candidates": [
                {
                    "file": candidate["file"],
                    "path": candidate["path"],
                    "line": candidate["line"],
                    "mapping": candidate["mapping"],
                    "link_address": candidate["link_address"],
                    "source": candidate["source"],
                }
                for candidate in candidates
                if candidate["trust"] == VERIFIED
            ],
        }
        ambiguities.append(ambiguity)
    return result, ambiguities


def _build_conflicts(
    scans: Sequence[_ArtifactScan],
    coverage_by_artifact: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    external = [scan for scan in scans if scan.info.role != "main"]
    by_id = {scan.info.id: scan.info for scan in external}
    by_basename: dict[str, list[str]] = {}
    for scan in external:
        by_basename.setdefault(scan.info.basename, []).append(scan.info.id)

    conflicts: list[dict[str, Any]] = []
    for scan in external:
        if scan.status == VERIFIED or scan.error is not None:
            continue
        if not scan.line_tables and not scan.info.has_debug_line:
            continue
        stats = scan.line_stats()
        coverage = coverage_by_artifact.get(scan.info.id, [])
        contradictions = scan.identity.get("contradictions", [])
        missing = scan.identity.get("missing", [])
        same_name = [
            artifact_id
            for artifact_id in by_basename.get(scan.info.basename, [])
            if artifact_id != scan.info.id
        ]
        same_name_artifacts = [
            {"id": artifact_id, "path": by_id[artifact_id].path}
            for artifact_id in same_name
        ]
        if scan.status == CONFLICT:
            materials = ", ".join(
                sorted({str(item.get("material")) for item in contradictions})
            )
            kind = "identity_conflict"
            severity = "error"
            message = (
                f"{scan.info.id} ({scan.info.basename}) exposes "
                f"{stats['rows']} line rows, but explicit identity "
                f"contradiction(s) ({materials or 'unknown'}) disconnect it from "
                f"the main ELF. Its plausible line answers were rejected."
            )
        else:
            materials = ", ".join(
                sorted({str(item.get("material")) for item in missing})
            )
            kind = "identity_unverified"
            severity = "warning"
            message = (
                f"{scan.info.id} ({scan.info.basename}) exposes "
                f"{stats['rows']} line rows, but no shared strong identity "
                f"material is available ({materials or 'none'}); its line "
                f"answers are provisional."
            )
        record = {
            "id": _conflict_id(scan.info.id),
            "kind": kind,
            "severity": severity,
            "message": message,
            "artifact_id": scan.info.id,
            "artifact_path": scan.info.path,
            "artifact_basename": scan.info.basename,
            "same_basename_as": same_name,
            "same_basename_artifacts": same_name_artifacts,
            "identity": scan.identity,
            "line_table": stats,
            "requested_address_coverage": coverage,
            "plausible_for_requested_addresses": bool(coverage),
            "operator_hint": (
                "Compare the reported build ID and .gnu_debuglink CRC against "
                "the main ELF. If the file is a split-DWARF companion, compare "
                "its dwo_id with the skeleton CU. Do not use this file's line "
                "rows as the primary answer until the identity connects."
            ),
        }
        conflicts.append(record)
    return conflicts


def attribute_addresses(
    main_elf: str | os.PathLike[str] | AttributionRequest,
    debug_files: Sequence[DebugFile | str | os.PathLike[str]] | None = None,
    mappings: Sequence[LoadMapping | dict[str, Any]] | None = None,
    addresses: Sequence[int | str] | int | str | None = None,
    *,
    include_main: bool = True,
) -> AttributionReport:
    """Attribute runtime addresses using only explicitly supplied inputs.

    Identity policy:

    * ``verified``: at least one strong material matches (GNU build ID, GNU
      debuglink CRC for the named file, or split-DWARF dwo_id) and there is no
      explicit contradiction.
    * ``conflict``: an available material disagrees (build ID, ELF class,
      endianness, machine, debuglink CRC, or dwo_id).  Such candidates are
      reported separately as ``rejected_candidates`` and in ``conflicts``.
    * ``unverified``: no contradiction was found, but no shared strong
      material could be checked.  Candidates are kept as provisional.

    Line tables are read from the main ELF when it has them and from every
    supplied debug file.  A file that only contains ``.debug_line`` (or
    ``.debug_line.dwo``) is parsed as a standalone line-unit sequence, so
    trimmed and split packages still work.  Every candidate records the
    mapping, ELF-side link address, line-program offset, CU offset, sequence,
    and debug-file path that produced it.
    """
    request = _normalize_request(
        main_elf, debug_files, mappings, addresses, include_main=include_main
    )
    diagnostics: list[dict[str, Any]] = []

    main_scan = _scan_artifact(
        request.main_elf, "main", role="main", diagnostics=diagnostics
    )
    if main_scan.error is not None:
        raise AttributionInputError(
            f"could not read main ELF {request.main_elf!r}: {main_scan.error}"
        )
    main_scan.identity = _main_identity(main_scan.info)

    scans: list[_ArtifactScan] = [main_scan] if request.include_main else []
    external_ids: set[str] = set()
    for index, debug_file in enumerate(request.debug_files):
        artifact_id = debug_file.id or f"debug-{index}"
        if artifact_id == "main":
            raise AttributionInputError("debug file id 'main' is reserved")
        if artifact_id in external_ids:
            raise AttributionInputError(f"duplicate debug file id: {artifact_id!r}")
        external_ids.add(artifact_id)
        path = os.path.abspath(debug_file.path)
        if path == main_scan.info.path:
            _add_diagnostic(
                diagnostics,
                "duplicate_main_debug_file",
                f"debug file {debug_file.path!r} is the main ELF; skipping it",
                artifact_id=artifact_id,
            )
            continue
        scan = _scan_artifact(
            path, artifact_id, role="external_debug", diagnostics=diagnostics
        )
        if scan.error is not None:
            scan.identity = _unreadable_identity(scan.error)
        else:
            scan.identity = _compare_identity(main_scan.info, scan.info)
        scans.append(scan)

    mapping_names = [mapping.name for mapping in request.mappings]
    if len(set(mapping_names)) != len(mapping_names):
        raise AttributionInputError(
            "mapping names must be unique so report provenance is unambiguous"
        )
    resolved_mappings = [
        _ResolvedMapping.resolve(mapping, main_scan.info.load_segments)
        for mapping in request.mappings
    ]
    for mapping in resolved_mappings:
        if mapping.mapping.bias is not None and not mapping.bounded:
            _add_diagnostic(
                diagnostics,
                "unbounded_bias_mapping",
                f"mapping {mapping.mapping.name!r} is not restricted to PT_LOAD "
                f"spans: {mapping.note}",
            )

    coverage_by_artifact: dict[str, list[dict[str, Any]]] = {}
    address_results: list[dict[str, Any]] = []
    ambiguities: list[dict[str, Any]] = []
    for address in request.addresses:
        result, address_ambiguities = _attribute_address(
            address, scans, resolved_mappings, coverage_by_artifact=coverage_by_artifact
        )
        address_results.append(result)
        ambiguities.extend(address_ambiguities)

    conflicts = _build_conflicts(scans, coverage_by_artifact)

    external = [scan for scan in scans if scan.info.role != "main"]
    by_basename: dict[str, list[str]] = {}
    for scan in external:
        by_basename.setdefault(scan.info.basename, []).append(scan.info.id)
    debug_reports: list[dict[str, Any]] = []
    for scan in external:
        report = scan.report_dict()
        report["same_basename_as"] = [
            artifact_id
            for artifact_id in by_basename.get(scan.info.basename, [])
            if artifact_id != scan.info.id
        ]
        debug_reports.append(report)

    main_report = main_scan.report_dict()
    summary = {
        "addresses": len(address_results),
        "resolved": sum(r["status"] == "resolved" for r in address_results),
        "ambiguous": sum(r["status"] == "ambiguous" for r in address_results),
        "provisional": sum(r["status"] == "provisional" for r in address_results),
        "unresolved": sum(r["status"] == "unresolved" for r in address_results),
        "verified_candidates": sum(
            candidate["trust"] == VERIFIED
            for result in address_results
            for candidate in result["candidates"]
        ),
        "provisional_candidates": sum(
            candidate["trust"] == UNVERIFIED
            for result in address_results
            for candidate in result["candidates"]
        ),
        "rejected_candidates": sum(
            len(result["rejected_candidates"]) for result in address_results
        ),
        "conflict_records": len(conflicts),
        "debug_files": len(external),
        "mappings": len(resolved_mappings),
    }

    # Make artifact-level parse/evidence diagnostics available at the top
    # level as well; the per-artifact copies stay next to their identity.
    for scan in scans:
        for item in scan.diagnostics:
            if item not in diagnostics:
                diagnostics.append(item)

    return AttributionReport(
        main=main_report,
        debug_files=debug_reports,
        mappings=[mapping.report_dict() for mapping in resolved_mappings],
        addresses=address_results,
        conflicts=conflicts,
        ambiguities=ambiguities,
        diagnostics=diagnostics,
        summary=summary,
    )


def attribute_addresses_dict(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Convenience wrapper returning the JSON-ready report object."""
    return attribute_addresses(*args, **kwargs).to_dict()


def request_from_config(
    config: dict[str, Any],
    *,
    base_dir: str | None = None,
) -> AttributionRequest:
    """Build a request from a JSON-compatible object.

    Relative paths are interpreted relative to ``base_dir`` (typically the
    directory containing a crash-platform config file), never relative to the
    process working directory.
    """
    if not isinstance(config, dict):
        raise AttributionInputError("request config must be a JSON object")

    def resolve_path(value: Any, what: str) -> str:
        if not isinstance(value, (str, os.PathLike)):
            raise AttributionInputError(f"{what} must be a path")
        path = os.fspath(value)
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if base_dir is not None and not os.path.isabs(path):
            path = os.path.join(base_dir, path)
        return os.path.abspath(path)

    main_value = config.get("main_elf", config.get("main", config.get("elf")))
    if main_value is None:
        raise AttributionInputError("request config needs main_elf")
    main_path = resolve_path(main_value, "main_elf")

    raw_debug = config.get("debug_files", config.get("debug", ()))
    if isinstance(raw_debug, (str, os.PathLike)):
        raw_debug = (raw_debug,)
    if not isinstance(raw_debug, Sequence):
        raise AttributionInputError("debug_files must be a list")
    debug_files: list[DebugFile] = []
    for index, item in enumerate(raw_debug):
        if isinstance(item, (str, os.PathLike)):
            debug_files.append(
                DebugFile(
                    resolve_path(item, f"debug_files[{index}]"),
                    id=f"debug-{index}",
                )
            )
        elif isinstance(item, dict):
            path_value = item.get("path", item.get("file"))
            if path_value is None:
                raise AttributionInputError(f"debug_files[{index}] needs path")
            debug_files.append(
                DebugFile(
                    resolve_path(path_value, f"debug_files[{index}].path"),
                    id=str(item["id"])
                    if item.get("id") is not None
                    else f"debug-{index}",
                    note=str(item["note"]) if item.get("note") is not None else None,
                )
            )
        else:
            raise AttributionInputError(f"debug_files[{index}] is not a path or object")

    raw_mappings = config.get(
        "mappings", config.get("load_mappings", config.get("mapping"))
    )
    if raw_mappings is None:
        raise AttributionInputError("request config needs mappings")
    if isinstance(raw_mappings, dict):
        raw_mappings = (raw_mappings,)
    if not isinstance(raw_mappings, Sequence):
        raise AttributionInputError("mappings must be a list")
    mappings = tuple(
        LoadMapping.from_dict(item, default_name=f"mapping-{index}")
        for index, item in enumerate(raw_mappings)
    )
    if not mappings:
        raise AttributionInputError("request config needs at least one mapping")

    raw_addresses = config.get("addresses", config.get("address"))
    if isinstance(raw_addresses, (int, str)):
        raw_addresses = (raw_addresses,)
    if not isinstance(raw_addresses, Sequence) or not raw_addresses:
        raise AttributionInputError("request config needs a non-empty addresses list")
    addresses = tuple(_coerce_address(value) for value in raw_addresses)

    include_main = bool(config.get("include_main", True))
    return AttributionRequest(
        main_elf=main_path,
        debug_files=tuple(debug_files),
        mappings=mappings,
        addresses=addresses,
        include_main=include_main,
    )
