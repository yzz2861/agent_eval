#-------------------------------------------------------------------------------
# elftools: elf/disclosure.py
#
# Read-only disclosure auditing for ELF symbol material.
#
# This module deliberately never modifies the files it inspects. It joins the
# data an outsourcing recipient can actually recover from an ELF (symbol names,
# section layout, DWARF file references, debug links) and checks that every
# recovered name/source location is covered by an explicit approval policy.
#
#-------------------------------------------------------------------------------
from __future__ import annotations

import hashlib
import os
import posixpath
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any, Iterable

from ..common.exceptions import DWARFError, ELFError
from ..common.utils import bytes2str
from .sections import Symbol, SymbolTableSection

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from ..dwarf.compileunit import CompileUnit
    from ..dwarf.lineprogram import LineProgram
    from .elffile import ELFFile
    from .sections import Section


SOURCE_SUFFIXES = (
    '.c', '.cc', '.cp', '.cpp', '.cxx', '.c++',
    '.h', '.hh', '.hpp', '.hxx', '.h++', '.inc',
    '.rs', '.go', '.swift', '.m', '.mm',
    '.s', '.S', '.asm',
)

_SOURCE_RE = re.compile(
    r'(?:^|[/\\])[^/\\\x00]+(?:' +
    '|'.join(re.escape(s) for s in SOURCE_SUFFIXES) +
    r')$')


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return bytes2str(value)
    return str(value)


def _norm_path(path: str) -> str:
    return posixpath.normpath(path.replace('\\', '/'))


def _path_variants(path: str) -> set[str]:
    """ Return normalized spellings used for approval matching. """
    norm = _norm_path(path)
    variants = {norm, posixpath.basename(norm)}
    if norm.startswith('./'):
        variants.add(norm[2:])
    return {v for v in variants if v}


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    variants = _path_variants(path)
    for pattern in patterns:
        pattern = _norm_path(pattern)
        if any(ch in pattern for ch in '*?['):
            if any(fnmatchcase(v, pattern) for v in variants):
                return True
        elif pattern in variants:
            return True
        elif any(v.endswith('/' + pattern) for v in variants):
            return True
    return False


def _is_source_path(value: str) -> bool:
    value = value.rstrip('/')
    return bool(_SOURCE_RE.search(value))


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _span(start: int, size: int) -> tuple[int, int]:
    return start, start + max(size, 1)


@dataclass(frozen=True)
class DisclosurePolicy:
    """ The material that is allowed to be disclosed.

    Symbol matching is exact unless a pattern contains ``*``, ``?`` or ``[``,
    in which case shell-style matching is used. Compilation-unit and source
    matching accepts either a full path, a path suffix, or a basename.
    """

    symbols: frozenset[str] = frozenset()
    compile_units: frozenset[str] = frozenset()
    sources: frozenset[str] = frozenset()
    allow_undefined_symbols: bool = False
    allow_raw_debug_paths: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DisclosurePolicy:
        def values(*keys: str) -> frozenset[str]:
            result: set[str] = set()
            for key in keys:
                raw = data.get(key, ())
                if raw is None:
                    continue
                if isinstance(raw, str):
                    result.add(raw)
                else:
                    result.update(str(v) for v in raw)
            return frozenset(result)

        return cls(
            symbols=values('symbols', 'allow_symbols', 'allowed_symbols'),
            compile_units=values(
                'compile_units', 'cus', 'allow_compile_units',
                'allowed_compile_units'),
            sources=values('sources', 'allow_sources', 'allowed_sources'),
            allow_undefined_symbols=bool(data.get(
                'allow_undefined_symbols', False)),
            allow_raw_debug_paths=bool(data.get(
                'allow_raw_debug_paths', False)),
        )

    def allows_symbol(self, name: str) -> bool:
        if not name:
            return True
        for pattern in self.symbols:
            if any(ch in pattern for ch in '*?['):
                if fnmatchcase(name, pattern):
                    return True
            elif name == pattern:
                return True
        return False

    def allows_compile_unit(self, name: str) -> bool:
        return _matches_any(name, self.compile_units)

    def allows_source(self, name: str) -> bool:
        return (_matches_any(name, self.sources) or
                _matches_any(name, self.compile_units))


@dataclass
class Finding:
    code: str
    message: str
    severity: str = 'error'
    subject: str | None = None
    via: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            'code': self.code,
            'severity': self.severity,
            'message': self.message,
            'subject': self.subject,
            'via': sorted(self.via),
            'context': self.context,
        }


@dataclass
class SymbolRecord:
    name: str
    tables: list[str]
    type: str
    binding: str
    visibility: str
    value: int
    size: int
    section: str | None
    section_index: int | None
    section_range: dict[str, int] | None
    file_range: dict[str, int] | None
    source_locations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'tables': sorted(self.tables),
            'type': self.type,
            'binding': self.binding,
            'visibility': self.visibility,
            'value': self.value,
            'size': self.size,
            'section': self.section,
            'section_index': self.section_index,
            'section_range': self.section_range,
            'file_range': self.file_range,
            'source_locations': self.source_locations,
        }


@dataclass
class CompileUnitRecord:
    offset: int
    version: int
    name: str
    comp_dir: str
    files: list[str]
    ranges: list[list[int]]
    approved: bool
    association: str
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'offset': self.offset,
            'version': self.version,
            'name': self.name,
            'comp_dir': self.comp_dir,
            'files': self.files,
            'ranges': self.ranges,
            'approved': self.approved,
            'association': self.association,
            'source': self.source,
        }


@dataclass
class DisclosureReport:
    object_path: str
    identity: dict[str, Any]
    sections: list[dict[str, Any]]
    symbols: list[SymbolRecord]
    compile_units: list[CompileUnitRecord]
    findings: list[Finding]
    debug_file: str | None = None
    excluded_symbol_count: int = 0
    excluded_compile_unit_count: int = 0
    unnamed_symbol_count: int = 0
    read_only: bool = True

    @property
    def approved(self) -> bool:
        return not any(f.severity == 'error' for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            'object': self.object_path,
            'debug_file': self.debug_file,
            'read_only': self.read_only,
            'approved': self.approved,
            'identity': self.identity,
            'sections': self.sections,
            'symbols': [s.to_dict() for s in self.symbols],
            'compile_units': [cu.to_dict() for cu in self.compile_units],
            'findings': [f.to_dict() for f in self.findings],
            'summary': {
                'section_count': len(self.sections),
                'approved_symbol_count': len(self.symbols),
                'associated_compile_unit_count': len(self.compile_units),
                'excluded_symbol_count': self.excluded_symbol_count,
                'excluded_compile_unit_count':
                    self.excluded_compile_unit_count,
                'unnamed_symbol_count': self.unnamed_symbol_count,
                'error_count': sum(
                    f.severity == 'error' for f in self.findings),
                'warning_count': sum(
                    f.severity == 'warning' for f in self.findings),
            },
        }


def _build_id(elffile: ELFFile) -> str | None:
    try:
        for section in elffile.iter_sections():
            if section['sh_type'] != 'SHT_NOTE':
                continue
            for note in section.iter_notes():
                if note['n_type'] == 'NT_GNU_BUILD_ID':
                    desc = note.get('n_desc')
                    if isinstance(desc, bytes):
                        return desc.hex()
                    if desc:
                        return str(desc)
    except (AttributeError, ELFError, KeyError, ValueError):
        return None
    return None


def _file_sha256(elffile: ELFFile) -> str | None:
    stream = elffile.stream
    try:
        position = stream.tell()
        stream.seek(0)
        digest = hashlib.sha256()
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        stream.seek(position)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def _identity(elffile: ELFFile) -> dict[str, Any]:
    return {
        'elf_class': elffile.elfclass,
        'little_endian': elffile.little_endian,
        'type': elffile['e_type'],
        'machine': elffile['e_machine'],
        'entry': elffile['e_entry'],
        'build_id': _build_id(elffile),
        'sha256': _file_sha256(elffile),
        'size': elffile.stream_len,
    }


def _section_record(index: int, section: Section) -> dict[str, Any]:
    start = section['sh_addr']
    size = section['sh_size']
    return {
        'index': index,
        'name': section.name,
        'type': section['sh_type'],
        'flags': section['sh_flags'],
        'address': start,
        'offset': section['sh_offset'],
        'size': size,
        'range': [start, start + size],
        'file_range': [section['sh_offset'],
                       section['sh_offset'] + size],
    }


def _iter_symbol_tables(elffile: ELFFile) -> Iterator[SymbolTableSection]:
    for section in elffile.iter_sections():
        if isinstance(section, SymbolTableSection):
            yield section


def _symbol_section(
        elffile: ELFFile,
        symbol: Symbol,
) -> Section | None:
    shndx = symbol['st_shndx']
    if isinstance(shndx, int) and 0 <= shndx < elffile.num_sections():
        return elffile.get_section(shndx)
    return None


def _object_ranges(elffile: ELFFile) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for segment in elffile.iter_segments(type='PT_LOAD'):
        if segment['p_memsz']:
            ranges.append((segment['p_vaddr'],
                           segment['p_vaddr'] + segment['p_memsz']))
    if ranges:
        return ranges
    for section in elffile.iter_sections():
        if not (section['sh_flags'] & 0x2) or not section['sh_size']:
            continue
        ranges.append((section['sh_addr'],
                       section['sh_addr'] + section['sh_size']))
    return ranges


def _file_range_for_symbol(
        section: Section | None,
        value: int,
        size: int,
) -> dict[str, int] | None:
    if section is None:
        return None
    start = section['sh_offset'] + value - section['sh_addr']
    end = start + max(size, 1)
    section_start = section['sh_offset']
    section_end = section_start + section['sh_size']
    if start < section_start or end > section_end:
        return None
    return {'start': start, 'end': end, 'size': max(size, 1)}


def _line_program_files(line_program: LineProgram) -> list[str]:
    header = line_program.header
    file_entries = header.get('file_entry', ())
    include_dirs = header.get('include_directory', ())
    version = header.get('version', 5)
    result: list[str] = []
    for entry in file_entries:
        name = _text(entry.get('name', b''))
        if not name:
            continue
        dir_index = entry.get('dir_index', 0) or 0
        directory = ''
        if include_dirs:
            lookup = dir_index if version >= 5 else dir_index - 1
            if 0 <= lookup < len(include_dirs):
                directory = _text(include_dirs[lookup])
        if directory and not posixpath.isabs(name):
            name = posixpath.join(directory, name)
        result.append(_norm_path(name))
    return result


def _file_from_index(line_program: LineProgram, index: int) -> str | None:
    header = line_program.header
    entries = header.get('file_entry', ())
    version = header.get('version', 5)
    lookup = index if version >= 5 else index - 1
    if lookup < 0 or lookup >= len(entries):
        return None
    entry = entries[lookup]
    name = _text(entry.get('name', b''))
    if not name:
        return None
    dir_index = entry.get('dir_index', 0) or 0
    include_dirs = header.get('include_directory', ())
    directory = ''
    if include_dirs:
        dir_lookup = dir_index if version >= 5 else dir_index - 1
        if 0 <= dir_lookup < len(include_dirs):
            directory = _text(include_dirs[dir_lookup])
    if directory and not posixpath.isabs(name):
        name = posixpath.join(directory, name)
    return _norm_path(name)


def _line_intervals(
        line_program: LineProgram,
) -> list[tuple[int, int, str | None, int, int]]:
    states = [
        entry.state for entry in line_program.get_entries()
        if entry.state is not None
    ]
    intervals: list[tuple[int, int, str | None, int, int]] = []
    for index, state in enumerate(states):
        if state.end_sequence:
            continue
        end = state.address
        if index + 1 < len(states):
            end = states[index + 1].address
        if end <= state.address:
            end = state.address + 1
        path = _file_from_index(line_program, state.file)
        intervals.append((
            state.address, end, path, state.line, state.column))
    return intervals


def _die_pc_ranges(cu: CompileUnit) -> list[tuple[int, int]]:
    top = cu.get_top_DIE()
    attributes = top.attributes
    low = attributes.get('DW_AT_low_pc')
    high = attributes.get('DW_AT_high_pc')
    if low is not None and high is not None:
        start = int(low.value)
        if str(high.form) == 'DW_FORM_addr':
            end = int(high.value)
        else:
            end = start + int(high.value)
        return [(start, end)] if end > start else []
    ranges = attributes.get('DW_AT_ranges')
    if ranges is None:
        return []
    try:
        range_lists = cu.dwarfinfo.range_lists()
        if range_lists is None:
            return []
        result: list[tuple[int, int]] = []
        for entry in range_lists.get_range_list_at_offset(
                int(ranges.value), cu):
            begin = getattr(entry, 'begin_offset', None)
            finish = getattr(entry, 'end_offset', None)
            if begin is not None and finish is not None and finish > begin:
                result.append((begin, finish))
        return result
    except (DWARFError, KeyError, TypeError, ValueError):
        return []


def _die_symbol_name(die: Any) -> str | None:
    for attribute in ('DW_AT_linkage_name', 'DW_AT_MIPS_linkage_name',
                      'DW_AT_name'):
        value = die.attributes.get(attribute)
        if value is not None and value.value:
            return _text(value.value)
    return None


def _debug_strings(elffile: ELFFile) -> Iterator[str]:
    for name in ('.debug_str', '.zdebug_str',
                 '.debug_line_str', '.zdebug_line_str'):
        section = elffile.get_section_by_name(name)
        if section is None:
            continue
        try:
            data = section.data()
        except (ELFError, ValueError):
            continue
        for raw in data.split(b'\x00'):
            if not raw:
                continue
            try:
                value = raw.decode('utf-8')
            except UnicodeDecodeError:
                value = raw.decode('latin-1')
            if _is_source_path(value):
                yield value


class _Auditor:
    def __init__(
        self,
        elffile: ELFFile,
        policy: DisclosurePolicy,
        *,
        object_path: str,
        debug_elffile: ELFFile | None,
        debug_file: str | None,
        object_ranges: Sequence[tuple[int, int]] | None,
        object_sources: Iterable[str] | None,
    ) -> None:
        self.elffile = elffile
        self.policy = policy
        self.object_path = object_path
        self.debug_elffile = debug_elffile
        self.debug_file = debug_file
        self.shared_debug = debug_elffile is not None
        self.object_ranges = (
            list(object_ranges) if object_ranges is not None
            else _object_ranges(elffile))

        self.sections: list[dict[str, Any]] = [
            _section_record(index, section)
            for index, section in enumerate(elffile.iter_sections())
        ]

        self.symbol_refs: dict[str, set[str]] = {}
        self.source_refs: dict[str, set[str]] = {}
        self.compile_units: list[CompileUnitRecord] = []
        self.symbols: dict[tuple[Any, ...], SymbolRecord] = {}
        self.findings: list[Finding] = []
        self._finding_keys: set[tuple[str, str | None]] = set()
        self.excluded_symbol_count = 0
        self.excluded_compile_unit_count = 0
        self.excluded_source_paths: set[str] = set()
        self.unnamed_symbol_count = 0
        self.unnamed_spans: list[tuple[int, int]] = []

        file_symbols = self._collect_file_symbols(elffile)
        if object_sources is not None:
            file_symbols.update(_norm_path(p) for p in object_sources)
        self.object_sources = file_symbols

        self.line_intervals: list[
            tuple[int, int, str | None, int, int]] = []
        self.die_decls: list[tuple[int, int, str, int, int]] = []

    def _add_finding(
        self,
        code: str,
        message: str,
        *,
        severity: str = 'error',
        subject: str | None = None,
        via: Iterable[str] = (),
        context: dict[str, Any] | None = None,
    ) -> None:
        key = (code, subject)
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(Finding(
            code=code,
            message=message,
            severity=severity,
            subject=subject,
            via=sorted(via),
            context=context or {},
        ))

    def _note_symbol(self, name: str, via: str) -> None:
        if not name:
            return
        self.symbol_refs.setdefault(name, set()).add(via)

    def _note_source(self, path: str | None, via: str) -> None:
        if not path:
            return
        self.source_refs.setdefault(_norm_path(path), set()).add(via)

    def _collect_file_symbols(self, elffile: ELFFile) -> set[str]:
        result: set[str] = set()
        for table in _iter_symbol_tables(elffile):
            for symbol in table.iter_symbols():
                if (symbol['st_info']['type'] == 'STT_FILE' and
                        symbol.name):
                    result.add(_norm_path(symbol.name))
        return result

    def _debug_symbol_belongs_to_object(
        self,
        symbol: Symbol,
        section: Section | None,
    ) -> tuple[bool, Section | None]:
        if section is None:
            return False, None
        target = self.elffile.get_section_by_name(section.name)
        if target is None:
            return False, None
        if target['sh_size'] == 0:
            return True, target
        value = int(symbol['st_value'])
        size = int(symbol['st_size'])
        if target['sh_addr'] == 0:
            fits = (0 <= value <= target['sh_size'] and
                    value + size <= target['sh_size'])
        else:
            fits = (target['sh_addr'] <= value <=
                    target['sh_addr'] + target['sh_size'])
        return fits, target

    def _add_symbol(
        self,
        symbol: Symbol,
        table_name: str,
        *,
        section: Section | None,
        section_index: int | None,
        from_debug_file: bool,
    ) -> None:
        name = symbol.name
        kind = symbol['st_info']['type']
        binding = symbol['st_info']['bind']
        visibility = symbol['st_other']['visibility']
        value = int(symbol['st_value'])
        size = int(symbol['st_size'])

        if not name:
            if kind in ('STT_FUNC', 'STT_OBJECT') and size:
                self.unnamed_symbol_count += 1
                self.unnamed_spans.append(_span(value, size))
            return

        if kind == 'STT_FILE':
            if (not from_debug_file or not self.object_sources or
                    _matches_any(name, self.object_sources)):
                self._note_source(name, 'stt_file_symbol')
            return

        if from_debug_file:
            belongs, target = self._debug_symbol_belongs_to_object(
                symbol, section)
            if not belongs:
                self.excluded_symbol_count += 1
                return
            section = target
            section_index = (
                self.elffile.get_section_index(target.name)
                if target is not None else None)

        if (symbol['st_shndx'] == 'SHN_UNDEF' and
                self.policy.allow_undefined_symbols and
                not self.policy.allows_symbol(name)):
            return

        self._note_symbol(name, table_name)

        if not self.policy.allows_symbol(name):
            return

        section_start = int(section['sh_addr']) if section is not None else None
        section_size = int(section['sh_size']) if section is not None else None
        section_range = (
            {'start': section_start,
             'end': section_start + section_size,
             'size': section_size}
            if section is not None else None)

        key = (
            name, value, size, kind, binding,
            section.name if section is not None else None,
        )
        record = self.symbols.get(key)
        if record is None:
            record = SymbolRecord(
                name=name,
                tables=[table_name],
                type=kind,
                binding=binding,
                visibility=visibility,
                value=value,
                size=size,
                section=section.name if section is not None else None,
                section_index=section_index,
                section_range=section_range,
                file_range=_file_range_for_symbol(section, value, size),
            )
            self.symbols[key] = record
        elif table_name not in record.tables:
            record.tables.append(table_name)

    def _collect_symbols(self) -> None:
        for table in _iter_symbol_tables(self.elffile):
            for symbol in table.iter_symbols():
                section = _symbol_section(self.elffile, symbol)
                self._add_symbol(
                    symbol, table.name, section=section,
                    section_index=(
                        self.elffile.get_section_index(section.name)
                        if section is not None else None),
                    from_debug_file=False)

        if self.debug_elffile is None:
            return
        for table in _iter_symbol_tables(self.debug_elffile):
            current_file: str | None = None
            for symbol in table.iter_symbols():
                kind = symbol['st_info']['type']
                if kind == 'STT_FILE':
                    current_file = (
                        _norm_path(symbol.name) if symbol.name else None)
                    self._add_symbol(
                        symbol, f'debug:{table.name}', section=None,
                        section_index=None, from_debug_file=True)
                    continue

                if (symbol['st_info']['bind'] == 'STT_LOCAL' and
                        current_file is not None and
                        self.object_sources and
                        not _matches_any(
                            current_file, self.object_sources)):
                    self.excluded_symbol_count += 1
                    continue

                section = _symbol_section(self.debug_elffile, symbol)
                self._add_symbol(
                    symbol, f'debug:{table.name}', section=section,
                    section_index=None, from_debug_file=True)

    def _cu_files(self, line_program: LineProgram | None) -> list[str]:
        if line_program is None:
            return []
        return list(dict.fromkeys(_line_program_files(line_program)))

    def _cu_ranges(
        self,
        cu: CompileUnit,
        line_program: LineProgram | None,
        files: list[str],
    ) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        if line_program is not None:
            for start, end, _path, _line, _column in _line_intervals(
                    line_program):
                ranges.append((start, end))
        if not ranges:
            ranges = _die_pc_ranges(cu)
        if not ranges:
            for path in files:
                if path in self.object_sources:
                    ranges = [(0, 1)]
                    break
        return ranges

    def _associate_cu(
        self,
        cu_name: str,
        files: list[str],
        ranges: list[tuple[int, int]],
    ) -> tuple[bool, str]:
        source_match = any(
            path in self.object_sources or
            _matches_any(path, self.object_sources)
            for path in [cu_name, *files])
        if source_match:
            return True, 'source'

        if self.object_sources and self.shared_debug:
            return False, 'source-mismatch'

        if self.object_ranges and ranges:
            if any(_overlaps(object_range, cu_range)
                   for object_range in self.object_ranges
                   for cu_range in ranges):
                return True, 'address-range'
            return False, 'range-mismatch'

        return True, 'single-object'

    def _record_die_sources(
        self,
        cu: CompileUnit,
        line_program: LineProgram | None,
        cu_path: str,
    ) -> None:
        if line_program is None:
            return
        for die in cu.iter_DIEs():
            if die.tag is None:
                continue
            if die.tag in ('DW_TAG_subprogram',
                           'DW_TAG_inlined_subroutine'):
                name = _die_symbol_name(die)
                if name:
                    self._note_symbol(name, 'dwarf_die')

            decl_file = die.attributes.get('DW_AT_decl_file')
            if decl_file is None:
                continue
            path = _file_from_index(line_program, int(decl_file.value))
            self._note_source(path, 'dwarf_decl_file')
            if path is None:
                continue
            if not self.policy.allows_source(path):
                self._add_finding(
                    'unapproved_decl_file',
                    f'DW_AT_decl_file reveals source {path!r}',
                    subject=path,
                    via=['dwarf_decl_file'],
                    context={'compile_unit': cu_path,
                             'die_tag': die.tag},
                )
            decl_line = die.attributes.get('DW_AT_decl_line')
            decl_column = die.attributes.get('DW_AT_decl_column')
            low = die.attributes.get('DW_AT_low_pc')
            high = die.attributes.get('DW_AT_high_pc')
            if low is not None and high is not None:
                start = int(low.value)
                if str(high.form) == 'DW_FORM_addr':
                    end = int(high.value)
                else:
                    end = start + int(high.value)
                if end > start:
                    self.die_decls.append((
                        start, end, path,
                        int(decl_line.value) if decl_line is not None else 0,
                        int(decl_column.value) if decl_column is not None else 0,
                    ))

    def _collect_dwarf(self) -> None:
        if (self.debug_elffile is not None and
                self.debug_elffile.has_dwarf_info(True)):
            source_elf = self.debug_elffile
        elif self.elffile.has_dwarf_info(True):
            source_elf = self.elffile
        elif self.elffile.has_dwarf_link():
            source_elf = self.elffile
        else:
            return

        try:
            dwarfinfo = source_elf.get_dwarf_info(follow_links=True)
        except (ELFError, DWARFError, OSError, ValueError) as error:
            self._add_finding(
                'debug_parse_error',
                f'Could not parse DWARF debug references: {error}',
                severity='error')
            return

        try:
            cus = list(dwarfinfo.iter_CUs())
        except (ELFError, DWARFError, ValueError) as error:
            self._add_finding(
                'debug_parse_error',
                f'Could not enumerate DWARF compile units: {error}',
                severity='error')
            return

        for cu in cus:
            try:
                top = cu.get_top_DIE()
                name_attr = top.attributes.get('DW_AT_name')
                comp_dir_attr = top.attributes.get('DW_AT_comp_dir')
                name = (_text(name_attr.value)
                        if name_attr is not None else '')
                comp_dir = (_text(comp_dir_attr.value)
                            if comp_dir_attr is not None else '')
                cu_path = (_norm_path(posixpath.join(comp_dir, name))
                           if comp_dir else _norm_path(name))
                line_program = dwarfinfo.line_program_for_CU(cu)
            except (ELFError, DWARFError, KeyError, TypeError, ValueError):
                self._add_finding(
                    'debug_parse_error',
                    f'Could not parse compile unit at {cu.cu_offset:#x}',
                    severity='error',
                    subject=f'{cu.cu_offset:#x}')
                continue

            files = self._cu_files(line_program)
            ranges = self._cu_ranges(cu, line_program, files)
            associated, association = self._associate_cu(
                cu_path, files, ranges)
            if not associated:
                self.excluded_compile_unit_count += 1
                self.excluded_source_paths.add(cu_path)
                self.excluded_source_paths.add(posixpath.basename(cu_path))
                for excluded_file in files:
                    self.excluded_source_paths.add(excluded_file)
                    self.excluded_source_paths.add(
                        posixpath.basename(excluded_file))
                continue

            self._note_source(cu_path, 'compile_unit')
            if cu_path and not self.policy.allows_compile_unit(cu_path):
                self._add_finding(
                    'unapproved_compile_unit',
                    f'Compile unit {cu_path!r} is outside the approved scope',
                    subject=cu_path,
                    via=['dwarf_compile_unit'],
                    context={'offset': cu.cu_offset,
                             'association': association},
                )

            for path in files:
                self._note_source(path, 'debug_line')

            if line_program is not None:
                for path in files:
                    if not self.policy.allows_source(path):
                        self._add_finding(
                            'unapproved_source_file',
                            f'.debug_line file table reveals source {path!r}',
                            subject=path,
                            via=['debug_line'],
                            context={'compile_unit': cu_path},
                        )
                self.line_intervals.extend(_line_intervals(line_program))

            self._record_die_sources(cu, line_program, cu_path)
            self.compile_units.append(CompileUnitRecord(
                offset=cu.cu_offset,
                version=int(cu['version']),
                name=name,
                comp_dir=comp_dir,
                files=files,
                ranges=[[start, end] for start, end in ranges],
                approved=self.policy.allows_compile_unit(cu_path),
                association=association,
                source=cu_path or None,
            ))

        if not self.policy.allow_raw_debug_paths:
            for path in _debug_strings(source_elf):
                if _norm_path(path) in self.excluded_source_paths:
                    continue
                self._note_source(path, 'raw_debug_string')
            if source_elf is not self.elffile:
                for path in _debug_strings(self.elffile):
                    if _norm_path(path) in self.excluded_source_paths:
                        continue
                    self._note_source(path, 'raw_debug_string')

    def _attach_sources_to_symbols(self) -> None:
        for record in self.symbols.values():
            span = _span(record.value, record.size)
            seen: set[tuple[str, int, int]] = set()
            for start, end, path, line, column in self.line_intervals:
                if path is None or not _overlaps(span, (start, end)):
                    continue
                key = (path, line, column)
                if key in seen:
                    continue
                seen.add(key)
                record.source_locations.append({
                    'path': path,
                    'line': line,
                    'column': column,
                    'via': 'debug_line',
                    'range': {'start': start, 'end': end},
                })
            for start, end, path, line, column in self.die_decls:
                if not _overlaps(span, (start, end)):
                    continue
                key = (path, line, column)
                if key in seen:
                    continue
                seen.add(key)
                record.source_locations.append({
                    'path': path,
                    'line': line,
                    'column': column,
                    'via': 'dwarf_decl',
                    'range': {'start': start, 'end': end},
                })

    def _finalize_findings(self) -> None:
        for name in sorted(self.symbol_refs):
            if self.policy.allows_symbol(name):
                continue
            self._add_finding(
                'unapproved_symbol',
                f'Symbol name {name!r} is outside the approved scope',
                subject=name,
                via=self.symbol_refs[name],
            )

        for path in sorted(self.source_refs):
            if self.policy.allows_source(path):
                continue
            self._add_finding(
                'unapproved_source',
                f'Source location {path!r} is reachable from debug metadata',
                subject=path,
                via=self.source_refs[path],
            )

        stripped_leak = any(
            path is not None and
            not self.policy.allows_source(path) and
            any(_overlaps(span, (start, end))
                for span in self.unnamed_spans)
            for start, end, path, _line, _column in self.line_intervals
        )
        if self.unnamed_symbol_count and stripped_leak:
            self._add_finding(
                'stripped_name_source_leak',
                'Stripped function/object names can still be correlated '
                'with an unapproved source file through debug references',
                severity='error',
                context={'unnamed_symbol_count':
                         self.unnamed_symbol_count},
            )

        self.findings.sort(key=lambda f: (
            0 if f.severity == 'error' else 1, f.code, f.subject or ''))

    def run(self) -> DisclosureReport:
        self._collect_symbols()
        self._collect_dwarf()
        self._attach_sources_to_symbols()
        self._finalize_findings()
        return DisclosureReport(
            object_path=self.object_path,
            identity=_identity(self.elffile),
            sections=self.sections,
            symbols=sorted(
                self.symbols.values(),
                key=lambda s: (s.name, s.section or '', s.value)),
            compile_units=sorted(
                self.compile_units, key=lambda cu: cu.offset),
            findings=self.findings,
            debug_file=self.debug_file,
            excluded_symbol_count=self.excluded_symbol_count,
            excluded_compile_unit_count=self.excluded_compile_unit_count,
            unnamed_symbol_count=self.unnamed_symbol_count,
        )


def audit_elf(
    elffile: ELFFile,
    policy: DisclosurePolicy,
    *,
    object_path: str = '<stream>',
    debug_elffile: ELFFile | None = None,
    debug_file: str | None = None,
    object_ranges: Sequence[tuple[int, int]] | None = None,
    object_sources: Iterable[str] | None = None,
) -> DisclosureReport:
    """ Audit an ELF stream without modifying it.

    ``debug_elffile`` is a separate symbol/debug ELF that may contain data for
    more than one object. ``object_ranges`` and ``object_sources`` (normally
    inferred from the object's own sections, STT_FILE symbols and debug links)
    isolate the subset that belongs to ``elffile`` before the approval policy
    is applied.
    """
    return _Auditor(
        elffile,
        policy,
        object_path=object_path,
        debug_elffile=debug_elffile,
        debug_file=debug_file,
        object_ranges=object_ranges,
        object_sources=object_sources,
    ).run()


def audit_path(
    path: str | os.PathLike[str],
    policy: DisclosurePolicy,
    *,
    debug_file: str | os.PathLike[str] | None = None,
    object_ranges: Sequence[tuple[int, int]] | None = None,
    object_sources: Iterable[str] | None = None,
) -> DisclosureReport:
    """ Audit an ELF file on disk. Both files are opened read-only. """
    from contextlib import ExitStack

    from .elffile import ELFFile

    object_path = os.fspath(path)
    with ExitStack() as stack:
        object_stream = stack.enter_context(open(object_path, 'rb'))
        object_elf = ELFFile(
            object_stream,
            ELFFile.make_relative_loader(object_path))

        if debug_file is not None:
            debug_path: str | None = os.fspath(debug_file)
        elif not object_elf.has_dwarf_info(True):
            debug_path = _discover_debug_link(object_path, object_elf)
        else:
            debug_path = None
        if debug_path is None:
            return audit_elf(
                object_elf,
                policy,
                object_path=object_path,
                debug_file=None,
                object_ranges=object_ranges,
                object_sources=object_sources,
            )

        debug_stream = stack.enter_context(open(debug_path, 'rb'))
        debug_elf = ELFFile(
            debug_stream,
            ELFFile.make_relative_loader(debug_path))
        return audit_elf(
            object_elf,
            policy,
            object_path=object_path,
            debug_elffile=debug_elf,
            debug_file=debug_path,
            object_ranges=object_ranges,
            object_sources=object_sources,
        )


def _discover_debug_link(
    object_path: str,
    elffile: ELFFile,
) -> str | None:
    """ Resolve a sibling ``.gnu_debuglink`` target without modifying it. """
    try:
        link = elffile.get_dwarf_link()
    except (ELFError, KeyError, ValueError):
        return None
    if link is None:
        return None
    name = os.path.basename(os.fsdecode(link.filename))
    if not name:
        return None
    object_dir = os.path.dirname(os.path.abspath(object_path))
    candidates = [
        os.path.join(object_dir, name),
        os.path.join(object_dir, '.debug', name),
    ]
    from ..dwarf.dwarf_util import _file_crc32

    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        try:
            with open(candidate, 'rb') as stream:
                matches = _file_crc32(stream) == link.checksum
        except OSError:
            continue
        if matches:
            return candidate
    return None
