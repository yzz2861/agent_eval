#------------------------------------------------------------------------------
# elftools: elf/gnuversions.py
#
# ELF sections
#
# Yann Rouillard (yann@pleiades.fr.eu.org)
# This code is in the public domain
#------------------------------------------------------------------------------
from __future__ import annotations

from collections import defaultdict
from functools import cached_property
from typing import TYPE_CHECKING, Any, TypedDict, cast

from ..common.exceptions import ELFError
from ..common.utils import struct_parse
from .dynamic import DynamicSection
from .hash import ELFHashTable
from .sections import Section, Symbol

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..construct.core import Struct
    from ..construct.lib.container import Container
    from .elffile import ELFFile
    from .sections import StringTableSection, SymbolTableSection


class SymbolVersion(TypedDict):
    index: str | int
    name: str | None
    filename: str | None
    hidden: bool


class _DiagnosticRequired(TypedDict):
    code: str
    message: str
    severity: str


class ELFDiagnostic(_DiagnosticRequired, total=False):
    """A structured, bounded description of a malformed or inconsistent ELF
    entry. Diagnostic values never contain whole sections or raw byte blobs.
    """
    section: str
    section_index: int | None
    field: str
    offset: int | None
    entry_offset: int | None
    symbol_table: str
    symbol_index: int | None
    symbol_name: str | None
    version_index: int | None
    name: str | None
    filename: str | None
    hash: int | None
    other_offset: int | None
    other_name: str | None
    other_index: int | None
    reason: str | None


class VersionRecord(TypedDict):
    """A normalized verdef/verneed entry used for provenance and checks."""
    kind: str
    section: str
    section_index: int | None
    offset: int
    index: int
    name: str
    filename: str | None
    hash: int
    flags: int
    auxiliary_offset: int
    chain_offset: int
    dependency_names: list[str]


class SymbolVersionInfo(TypedDict):
    """Detailed symbol version lookup result. Unlike SymbolVersion, this
    preserves the symbol name even when the version lookup is malformed.
    """
    symbol_table: str
    symbol_table_index: int | None
    symbol_index: int
    symbol: Symbol | None
    symbol_name: str | None
    versym_offset: int
    raw_index: str | int
    hidden: bool
    index: str | int
    version: SymbolVersion | None
    source: VersionRecord | None
    sources: list[VersionRecord]
    hash: int | None
    chain_offset: int | None
    dependency_names: list[str]
    diagnostics: list[ELFDiagnostic]


def _short_text(text: str | None, limit: int = 80) -> str | None:
    if text is None:
        return None
    return text if len(text) <= limit else text[:limit] + '...'


def make_diagnostic(
    code: str,
    message: str,
    severity: str = 'warning',
    **fields: Any,
) -> ELFDiagnostic:
    """Build a structured diagnostic without optional None-valued fields."""
    diagnostic: dict[str, Any] = {
        'code': code,
        'message': _short_text(message, 240),
        'severity': severity,
    }
    for key, value in fields.items():
        if value is not None:
            diagnostic[key] = _short_text(value, 80) if isinstance(value, str) else value
    return cast(ELFDiagnostic, diagnostic)


class Version:
    """ Version object - representing a version definition or dependency
        entry from a "Version Needed" or a "Version Dependency" table section.

        This kind of entry contains a pointer to an array of auxiliary entries
        that store the information about version names or dependencies.
        These entries are not stored in this object and should be accessed
        through the appropriate method of a section object which will return
        an iterator of VersionAuxiliary objects.

        Similarly to Section objects, allows dictionary-like access to
        verdef/verneed entry
    """
    def __init__(
        self,
        entry: Container,
        name: str | None = None,
        *,
        offset: int = 0,
        section: GNUVersionSection | None = None,
    ) -> None:
        self.entry = entry
        self.name = name
        self.offset = offset
        self.section = section

    def __getitem__(self, name: str) -> Any:
        """ Implement dict-like access to entry
        """
        return self.entry[name]


class VersionAuxiliary:
    """ Version Auxiliary object - representing an auxiliary entry of a version
        definition or dependency entry

        Similarly to Section objects, allows dictionary-like access to the
        verdaux/vernaux entry
    """
    def __init__(
        self,
        entry: Container,
        name: str,
        *,
        offset: int = 0,
        section: GNUVersionSection | None = None,
    ) -> None:
        self.entry = entry
        self.name = name
        self.offset = offset
        self.section = section

    def __getitem__(self, name: str) -> Any:
        """ Implement dict-like access to entries
        """
        return self.entry[name]


class GNUVersionSection(Section):
    """ Common ancestor class for ELF SUNW|GNU Version Needed/Dependency
        sections class which contains shareable code
    """

    def __init__(
        self,
        header: Container,
        name: str,
        elffile: ELFFile,
        stringtable: StringTableSection,
        field_prefix: str,
        version_struct: Struct,
        version_auxiliaries_struct: Struct,
    ) -> None:
        super().__init__(header, name, elffile)
        self.stringtable = stringtable
        self.field_prefix = field_prefix
        self.version_struct = version_struct
        self.version_auxiliaries_struct = version_auxiliaries_struct
        self._diagnostics: list[ELFDiagnostic] = []

    def num_versions(self) -> int:
        """ Number of version entries in the section
        """
        return self['sh_info']

    @property
    def kind(self) -> str:
        return 'verneed' if self.field_prefix == 'vn' else 'verdef'

    @cached_property
    def section_index(self) -> int | None:
        for index, section in enumerate(self.elffile.iter_sections()):
            if section == self:
                return index
        return None

    def _field_name(self, name: str, auxiliary: bool = False) -> str:
        """ Return the real field's name of version or a version auxiliary
            entry
        """
        middle = 'a_' if auxiliary else '_'
        return self.field_prefix + middle + name

    def _add_diagnostic(self, diagnostic: ELFDiagnostic) -> None:
        key = (
            diagnostic['code'],
            diagnostic.get('section'),
            diagnostic.get('offset'),
            diagnostic.get('entry_offset'),
            diagnostic.get('symbol_index'),
            diagnostic.get('version_index'),
            diagnostic.get('name'),
            diagnostic.get('field'),
        )
        known = {
            (
                item['code'],
                item.get('section'),
                item.get('offset'),
                item.get('entry_offset'),
                item.get('symbol_index'),
                item.get('version_index'),
                item.get('name'),
                item.get('field'),
            )
            for item in self._diagnostics
        }
        if key not in known:
            self._diagnostics.append(diagnostic)

    def _entry_range_valid(self, offset: int, size: int) -> bool:
        start = int(self['sh_offset'])
        end = start + int(self['sh_size'])
        return offset >= start and size >= 0 and offset <= end and size <= end - offset

    def _read_name(self, name_offset: int, entry_offset: int, field: str) -> str:
        """Read a version name with string-table bounds checks.

        Corrupt offsets are diagnosed and resolve to an empty name; the raw
        string table is never included in the diagnostic.
        """
        table_size = int(self.stringtable['sh_size'])
        if not isinstance(name_offset, int) or name_offset < 0 or name_offset >= table_size:
            self._add_diagnostic(make_diagnostic(
                'invalid-version-string-offset',
                f'{field} string offset {name_offset!r} is outside '
                f'{self.stringtable.name} (size {table_size})',
                section=self.name,
                section_index=self.section_index,
                field=field,
                offset=entry_offset,
                reason='version string offset outside string table'))
            return ''

        table_offset = int(self.stringtable['sh_offset'])
        max_length = min(table_size - name_offset, 1 << 20)
        self.stream.seek(table_offset + name_offset)
        data = self.stream.read(max_length)
        terminator = data.find(b'\x00')
        if terminator < 0:
            self._add_diagnostic(make_diagnostic(
                'unterminated-version-string',
                f'{field} string at offset {name_offset} is not NUL-terminated '
                f'inside {self.stringtable.name}',
                section=self.name,
                section_index=self.section_index,
                field=field,
                offset=entry_offset,
                reason='unterminated version string'))
            data = data[:80]
        else:
            data = data[:terminator]
        return data.decode('utf-8', errors='replace')

    def _iter_version_auxiliaries(
        self,
        entry_offset: int,
        count: int,
    ) -> Iterator[VersionAuxiliary]:
        """ Yield all auxiliary entries of a version entry
        """
        name_field = self._field_name('name', auxiliary=True)
        next_field = self._field_name('next', auxiliary=True)

        auxiliary_size = self.version_auxiliaries_struct.sizeof()
        for auxiliary_index in range(count):
            if not self._entry_range_valid(entry_offset, auxiliary_size):
                self._add_diagnostic(make_diagnostic(
                    'invalid-version-auxiliary',
                    f'version auxiliary entry {auxiliary_index} at offset '
                    f'{entry_offset:#x} is outside {self.name}',
                    section=self.name,
                    section_index=self.section_index,
                    field=next_field,
                    offset=entry_offset,
                    reason='auxiliary entry outside version section'))
                return
            entry = struct_parse(
                        self.version_auxiliaries_struct,
                        self.stream,
                        stream_pos=entry_offset)

            name = self._read_name(entry[name_field], entry_offset, name_field)
            version_aux = VersionAuxiliary(
                entry, name, offset=entry_offset, section=self)
            yield version_aux

            if auxiliary_index + 1 == count:
                return
            next_offset = int(entry[next_field])
            if next_offset == 0:
                self._add_diagnostic(make_diagnostic(
                    'truncated-version-auxiliary-chain',
                    f'auxiliary chain ends after {auxiliary_index + 1} entries '
                    f'but {count} were declared',
                    section=self.name,
                    section_index=self.section_index,
                    field=next_field,
                    offset=entry_offset,
                    reason='auxiliary chain shorter than declared count'))
                return
            if next_offset < auxiliary_size:
                self._add_diagnostic(make_diagnostic(
                    'invalid-version-auxiliary-chain',
                    f'{next_field}={next_offset} does not advance past the '
                    f'{auxiliary_size}-byte auxiliary entry',
                    section=self.name,
                    section_index=self.section_index,
                    field=next_field,
                    offset=entry_offset,
                    reason='auxiliary chain does not advance'))
                return
            entry_offset += next_offset

    def iter_versions(self) -> Iterator[tuple[Version, Iterator[VersionAuxiliary]]]:
        """ Yield all the version entries in the section
            Each time it returns the main version structure
            and an iterator to walk through its auxiliaries entries

            Bounds and chain links are validated. A corrupt entry is skipped
            with a diagnostic instead of being allowed to run off the section.
        """
        aux_field = self._field_name('aux')
        count_field = self._field_name('cnt')
        next_field = self._field_name('next')

        entry_offset = int(self['sh_offset'])
        version_size = self.version_struct.sizeof()
        version_count = self.num_versions()
        for version_index in range(version_count):
            if not self._entry_range_valid(entry_offset, version_size):
                self._add_diagnostic(make_diagnostic(
                    'invalid-version-entry',
                    f'version entry {version_index} at offset {entry_offset:#x} '
                    f'is outside {self.name}',
                    section=self.name,
                    section_index=self.section_index,
                    offset=entry_offset,
                    reason='version entry outside section'))
                return
            entry = struct_parse(
                self.version_struct,
                self.stream,
                stream_pos=entry_offset)

            count = int(entry[count_field])
            next_offset = int(entry[next_field])
            version = Version(entry, offset=entry_offset, section=self)

            if count <= 0:
                self._add_diagnostic(make_diagnostic(
                    'invalid-version-entry',
                    f'{count_field}={count} declares no auxiliary entries',
                    section=self.name,
                    section_index=self.section_index,
                    field=count_field,
                    offset=entry_offset,
                    reason='version entry has no auxiliary entries'))
            else:
                aux_entries_offset = entry_offset + int(entry[aux_field])
                auxiliary_size = self.version_auxiliaries_struct.sizeof()
                if not self._entry_range_valid(aux_entries_offset, auxiliary_size):
                    self._add_diagnostic(make_diagnostic(
                        'invalid-version-auxiliary',
                        f'auxiliary entries at offset {aux_entries_offset:#x} '
                        f'are outside {self.name}',
                        section=self.name,
                        section_index=self.section_index,
                        field=aux_field,
                        offset=entry_offset,
                        reason='auxiliary table outside section'))
                    version_auxiliaries_iter: Iterator[VersionAuxiliary] = iter(())
                else:
                    max_auxiliaries = (
                        int(self['sh_offset']) + int(self['sh_size'])
                        - aux_entries_offset
                    ) // auxiliary_size
                    if count > max_auxiliaries:
                        self._add_diagnostic(make_diagnostic(
                            'invalid-version-entry-count',
                            f'{count_field}={count} exceeds the {max_auxiliaries} '
                            f'auxiliary entries that fit in {self.name}',
                            section=self.name,
                            section_index=self.section_index,
                            field=count_field,
                            offset=entry_offset,
                            reason='auxiliary count larger than section'))
                        count = max_auxiliaries
                    version_auxiliaries_iter = self._iter_version_auxiliaries(
                        aux_entries_offset, count)

                yield version, version_auxiliaries_iter

            if next_offset == 0:
                if version_index + 1 < version_count:
                    self._add_diagnostic(make_diagnostic(
                        'truncated-version-chain',
                        f'{next_field}=0 after {version_index + 1} of '
                        f'{version_count} declared version entries',
                        section=self.name,
                        section_index=self.section_index,
                        field=next_field,
                        offset=entry_offset,
                        reason='version chain shorter than declared count'))
                return
            if next_offset < version_size:
                self._add_diagnostic(make_diagnostic(
                    'invalid-version-chain',
                    f'{next_field}={next_offset} does not advance past the '
                    f'{version_size}-byte version entry',
                    section=self.name,
                    section_index=self.section_index,
                    field=next_field,
                    offset=entry_offset,
                    reason='version chain does not advance'))
                return
            entry_offset += next_offset

    def _iter_version_records(self) -> Iterator[VersionRecord]:
        """Yield normalized entries, including their source offsets and hashes."""
        hash_field = 'vd_hash' if self.kind == 'verdef' else 'vna_hash'
        flags_field = 'vd_flags' if self.kind == 'verdef' else 'vna_flags'
        index_field = 'vd_ndx' if self.kind == 'verdef' else 'vna_other'
        chain_field = 'vd_next' if self.kind == 'verdef' else 'vna_next'

        for version, auxiliary_iter in self.iter_versions():
            auxiliary_entries = list(auxiliary_iter)
            if not auxiliary_entries:
                continue
            dependency_names = [auxiliary.name for auxiliary in auxiliary_entries]
            if self.kind == 'verdef':
                primary = auxiliary_entries[0]
                yield VersionRecord(
                    kind=self.kind,
                    section=self.name,
                    section_index=self.section_index,
                    offset=version.offset,
                    index=int(version[index_field]),
                    name=primary.name,
                    filename=None,
                    hash=int(version[hash_field]),
                    flags=int(version[flags_field]),
                    auxiliary_offset=primary.offset,
                    chain_offset=int(version[chain_field]),
                    dependency_names=dependency_names,
                )
            else:
                filename = version.name
                for auxiliary in auxiliary_entries:
                    yield VersionRecord(
                        kind=self.kind,
                        section=self.name,
                        section_index=self.section_index,
                        offset=version.offset,
                        index=int(auxiliary[index_field]),
                        name=auxiliary.name,
                        filename=filename,
                        hash=int(auxiliary[hash_field]),
                        flags=int(auxiliary[flags_field]),
                        auxiliary_offset=auxiliary.offset,
                        chain_offset=int(auxiliary[chain_field]),
                        dependency_names=dependency_names,
                    )

    @cached_property
    def version_records(self) -> list[VersionRecord]:
        return list(self._iter_version_records())

    @cached_property
    def version_records_by_index(self) -> dict[int, list[VersionRecord]]:
        records: dict[int, list[VersionRecord]] = defaultdict(list)
        for record in self.version_records:
            records[record['index']].append(record)
        return dict(records)

    def iter_version_records(self) -> Iterator[VersionRecord]:
        yield from self.version_records

    def _diagnose_records(self) -> None:
        by_index: dict[int, VersionRecord] = {}
        by_name: dict[tuple[str, str | None], VersionRecord] = {}
        for record in self.version_records:
            previous = by_index.get(record['index'])
            if previous is None:
                by_index[record['index']] = record
            else:
                self._add_diagnostic(make_diagnostic(
                    'duplicate-version-index',
                    f'version index {record["index"]} is used by both '
                    f'{_short_text(previous["name"])!r} and '
                    f'{_short_text(record["name"])!r} in {self.name}',
                    section=self.name,
                    section_index=self.section_index,
                    version_index=record['index'],
                    name=record['name'],
                    other_name=previous['name'],
                    offset=record['offset'],
                    other_offset=previous['offset'],
                    reason='duplicate version index'))

            if record['name']:
                name_key = (record['name'], record['filename'])
                previous_name = by_name.get(name_key)
                if previous_name is None:
                    by_name[name_key] = record
                else:
                    provider = (
                        f' from {_short_text(record["filename"])!r}'
                        if record['filename'] else '')
                    self._add_diagnostic(make_diagnostic(
                        'duplicate-version-name',
                        f'version name {_short_text(record["name"])!r} is used '
                        f'{provider} by indices {previous_name["index"]} and '
                        f'{record["index"]}',
                        section=self.name,
                        section_index=self.section_index,
                        version_index=record['index'],
                        name=record['name'],
                        other_index=previous_name['index'],
                        offset=record['offset'],
                        other_offset=previous_name['offset'],
                        reason='duplicate version name'))

            if record['name'] and record['hash'] != ELFHashTable.elf_hash(record['name']):
                self._add_diagnostic(make_diagnostic(
                    'version-hash-mismatch',
                    f'version hash {record["hash"]:#x} does not match ELF hash '
                    f'of {_short_text(record["name"])!r}',
                    section=self.name,
                    section_index=self.section_index,
                    version_index=record['index'],
                    name=record['name'],
                    hash=record['hash'],
                    offset=record['offset'],
                    reason='version hash does not match version name'))

    @property
    def diagnostics(self) -> list[ELFDiagnostic]:
        """All diagnostics collected while parsing this version table."""
        self.version_records
        self._diagnose_records()
        return list(self._diagnostics)

    def get_diagnostics(self) -> list[ELFDiagnostic]:
        return self.diagnostics


class GNUVerNeedSection(GNUVersionSection):
    """ ELF SUNW or GNU Version Needed table section.
        Has an associated StringTableSection that's passed in the constructor.
    """
    def __init__(
        self,
        header: Container,
        name: str,
        elffile: ELFFile,
        stringtable: StringTableSection,
    ) -> None:
        super().__init__(
                header, name, elffile, stringtable, 'vn',
                elffile.structs.Elf_Verneed, elffile.structs.Elf_Vernaux)

    def has_indexes(self) -> bool:
        """ Return True if at least one version definition entry has an index
            that is stored in the vna_other field.
            This information is used for symbol versioning
        """
        return self._has_indexes

    @cached_property
    def _has_indexes(self) -> bool:
        return any(
            vernaux['vna_other']
            for _, vernaux_iter in self.iter_versions()
            for vernaux in vernaux_iter
        )

    def iter_versions(self) -> Iterator[tuple[Version, Iterator[VersionAuxiliary]]]:
        for verneed, vernaux in super().iter_versions():
            verneed.name = self._read_name(
                verneed['vn_file'], verneed.offset, 'vn_file')
            yield verneed, vernaux

    def get_version(self, index: int) -> tuple[Version, VersionAuxiliary] | None:
        """ Get the version information located at index #n in the table
            Return boths the verneed structure and the vernaux structure
            that contains the name of the version
        """
        for verneed, vernaux_iter in self.iter_versions():
            for vernaux in vernaux_iter:
                if vernaux['vna_other'] == index:
                    return verneed, vernaux

        return None


class GNUVerDefSection(GNUVersionSection):
    """ ELF SUNW or GNU Version Definition table section.
        Has an associated StringTableSection that's passed in the constructor.
    """
    def __init__(
        self,
        header: Container,
        name: str,
        elffile: ELFFile,
        stringtable: StringTableSection,
    ) -> None:
        super().__init__(
                header, name, elffile, stringtable, 'vd',
                elffile.structs.Elf_Verdef, elffile.structs.Elf_Verdaux)

    def get_version(self, index: int) -> tuple[Version, Iterator[VersionAuxiliary]] | None:
        """ Get the version information located at index #n in the table
            Return boths the verdef structure and an iterator to retrieve
            both the version names and dependencies in the form of
            verdaux entries
        """
        for verdef, verdaux_iter in self.iter_versions():
            if verdef['vd_ndx'] == index:
                return verdef, verdaux_iter

        return None


class GNUVerSymSection(Section):
    """ ELF SUNW or GNU Versym table section.
        Has an associated SymbolTableSection that's passed in the constructor.
    """
    def __init__(
            self,
            header: Container,
            name: str,
            elffile: ELFFile,
            symboltable: SymbolTableSection,
    ) -> None:
        super().__init__(header, name, elffile)
        self.symboltable = symboltable
        self._diagnostics: list[ELFDiagnostic] = []

    def num_symbols(self) -> int:
        """ Number of symbols in the table
        """
        entry_size = int(self['sh_entsize'])
        return int(self['sh_size']) // entry_size if entry_size > 0 else 0

    def get_symbol(self, n: int) -> Symbol:
        """ Get the symbol at index #n from the table (Symbol object)
            It begins at 1 and not 0 since the first entry is used to
            store the current version of the syminfo table
        """
        # Grab the symbol's entry from the stream
        entry_offset = self['sh_offset'] + n * self['sh_entsize']
        entry = struct_parse(
            self.structs.Elf_Versym,
            self.stream,
            stream_pos=entry_offset)
        # Find the symbol name in the associated symbol table
        name = (
            self.symboltable.get_symbol(n).name
            if 0 <= n < self.symboltable.num_symbols() else ''
        )
        return Symbol(entry, name)

    @cached_property
    def is_gnu(self) -> bool:
        """ Whether this file uses GNU rather than Solaris versioning.
            GNU versioning is identified by the DT_VERSYM dynamic tag.
        """
        return any(
            tag['d_tag'] == 'DT_VERSYM'
            for section in self.elffile.iter_sections()
            if isinstance(section, DynamicSection)
            for tag in section.iter_tags())

    @cached_property
    def _version_sections(self) -> list[GNUVerDefSection | GNUVerNeedSection]:
        # Version definitions and requirements refer to the same string table
        # as the symbol table linked by this versym section.
        return [
            section for section in self.elffile.iter_sections()
            if isinstance(section, (GNUVerDefSection, GNUVerNeedSection))
            and section['sh_link'] == self.symboltable['sh_link']]

    @cached_property
    def section_index(self) -> int | None:
        for index, section in enumerate(self.elffile.iter_sections()):
            if section == self:
                return index
        return None

    def _add_diagnostic(
        self,
        diagnostic: ELFDiagnostic,
        local: list[ELFDiagnostic] | None = None,
    ) -> None:
        key = (
            diagnostic['code'],
            diagnostic.get('section'),
            diagnostic.get('offset'),
            diagnostic.get('symbol_index'),
            diagnostic.get('version_index'),
            diagnostic.get('name'),
        )
        known = {
            (
                item['code'],
                item.get('section'),
                item.get('offset'),
                item.get('symbol_index'),
                item.get('version_index'),
                item.get('name'),
            )
            for item in self._diagnostics
        }
        if key not in known:
            self._diagnostics.append(diagnostic)
        if local is not None and diagnostic not in local:
            local.append(diagnostic)

    def _parse_versym(
        self,
        n: int,
        local: list[ELFDiagnostic],
    ) -> tuple[int, str | int, bool, str | int]:
        entry_offset = int(self['sh_offset']) + n * int(self['sh_entsize'])
        entry = struct_parse(
            self.structs.Elf_Versym,
            self.stream,
            stream_pos=entry_offset)
        raw_index: str | int = entry['ndx']
        hidden = False
        index: str | int = raw_index
        if isinstance(raw_index, int) and self.is_gnu:
            # GNU uses the high bit as a flag; the remaining bits are the
            # index shared with the version definition/requirement tables.
            hidden = bool(raw_index & 0x8000)
            index = raw_index & 0x7fff
            if index == 0:
                index = 'VER_NDX_LOCAL'
            elif index == 1:
                index = 'VER_NDX_GLOBAL'

        if not 0 <= n < self.symboltable.num_symbols():
            self._add_diagnostic(make_diagnostic(
                'versym-symbol-out-of-range',
                f'versym entry {n} has no corresponding symbol in '
                f'{self.symboltable.name}',
                severity='error',
                section=self.name,
                section_index=self.section_index,
                symbol_table=self.symboltable.name,
                symbol_index=n,
                version_index=index if isinstance(index, int) else None,
                offset=entry_offset,
                reason='versym symbol index outside symbol table'), local)
        return entry_offset, raw_index, hidden, index

    def _resolve_version_records(
        self,
        index: str | int,
        symbol_index: int,
        entry_offset: int,
        local: list[ELFDiagnostic],
    ) -> list[VersionRecord]:
        if not isinstance(index, int):
            return []

        candidates: list[VersionRecord] = []
        for section in self._version_sections:
            candidates.extend(section.version_records_by_index.get(index, ()))

        if not candidates:
            self._add_diagnostic(make_diagnostic(
                'versym-index-out-of-range',
                f'symbol {symbol_index} refers to version index {index}, '
                f'which has no verdef or verneed entry',
                severity='error',
                section=self.name,
                section_index=self.section_index,
                symbol_table=self.symboltable.name,
                symbol_index=symbol_index,
                version_index=index,
                offset=entry_offset,
                reason='version index has no definition or requirement'), local)
            return []

        kinds = {record['kind'] for record in candidates}
        names = {record['name'] for record in candidates if record['name']}
        if len(kinds) > 1:
            previous, current = candidates[0], candidates[1]
            self._add_diagnostic(make_diagnostic(
                'verdef-verneed-index-conflict',
                f'version index {index} names both definition '
                f'{_short_text(previous["name"])!r} and requirement '
                f'{_short_text(current["name"])!r}',
                section=self.name,
                section_index=self.section_index,
                symbol_index=symbol_index,
                version_index=index,
                name=current['name'],
                other_name=previous['name'],
                filename=current['filename'],
                offset=entry_offset,
                other_offset=previous['offset'],
                reason='same index present in verdef and verneed'), local)
            if len(names) > 1:
                self._add_diagnostic(make_diagnostic(
                    'verdef-verneed-name-conflict',
                    f'version index {index} resolves to different names: '
                    f'{_short_text(previous["name"])!r} and '
                    f'{_short_text(current["name"])!r}',
                    section=self.name,
                    section_index=self.section_index,
                    symbol_index=symbol_index,
                    version_index=index,
                    name=current['name'],
                    other_name=previous['name'],
                    offset=entry_offset,
                    other_offset=previous['offset'],
                    reason='verdef and verneed disagree on version name'), local)
        elif len(candidates) > 1:
            self._add_diagnostic(make_diagnostic(
                'duplicate-version-index',
                f'version index {index} appears {len(candidates)} times in '
                f'{self._version_sections[0].name} candidates',
                section=self.name,
                section_index=self.section_index,
                symbol_index=symbol_index,
                version_index=index,
                name=candidates[0]['name'],
                offset=entry_offset,
                other_offset=candidates[1]['offset'],
                reason='duplicate version index'), local)
        return candidates

    def _version_from_record(self, record: VersionRecord, hidden: bool) -> SymbolVersion:
        return {
            'index': record['index'],
            'name': record['name'],
            'filename': record['filename'],
            'hidden': hidden,
        }

    def _check_hidden_bit(
        self,
        *,
        n: int,
        entry_offset: int,
        hidden: bool,
        index: str | int,
        version: SymbolVersion | None,
        source: VersionRecord | None,
        symbol: Symbol | None,
        local: list[ELFDiagnostic],
    ) -> None:
        if not hidden:
            return
        common = {
            'section': self.name,
            'section_index': self.section_index,
            'symbol_table': self.symboltable.name,
            'symbol_index': n,
            'version_index': index if isinstance(index, int) else None,
            'offset': entry_offset,
        }
        if index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            self._add_diagnostic(make_diagnostic(
                'versym-hidden-without-version',
                f'symbol {n} sets the hidden version bit but uses {index}',
                reason='hidden bit without a named version', **common), local)
            return
        if symbol is None or not symbol.name:
            self._add_diagnostic(make_diagnostic(
                'versym-hidden-empty-name',
                f'symbol {n} sets the hidden version bit but has no visible name',
                reason='hidden bit on an empty symbol name', **common), local)
        if symbol is not None and symbol['st_shndx'] == 'SHN_UNDEF':
            self._add_diagnostic(make_diagnostic(
                'versym-hidden-undefined-symbol',
                f'undefined symbol {n} {symbol.name!r} sets the hidden version bit',
                reason='hidden bit on an undefined symbol',
                symbol_name=symbol.name, **common), local)
        if source is not None and source['kind'] == 'verneed':
            self._add_diagnostic(make_diagnostic(
                'versym-hidden-requirement',
                f'symbol {n} hides a required version from '
                f'{_short_text(source["filename"])!r}',
                reason='hidden bit on a version requirement',
                filename=source['filename'], **common), local)
        if version is not None and not version['name']:
            self._add_diagnostic(make_diagnostic(
                'versym-hidden-empty-version-name',
                f'symbol {n} sets the hidden version bit but index {index} '
                f'has no visible version name',
                reason='hidden bit without a version name', **common), local)

    def get_symbol_version_info(self, n: int) -> SymbolVersionInfo | None:
        """Detailed version lookup for symbol #n.

        Unlike get_symbol_version(), this preserves the original symbol name
        and returns source offsets, hashes and diagnostics even when the
        version entry is malformed. Return None only when n is outside the
        versym table.
        """
        if not 0 <= n < self.num_symbols():
            return None

        local: list[ELFDiagnostic] = []
        entry_offset, raw_index, hidden, index = self._parse_versym(n, local)
        symbol = (
            self.symboltable.get_symbol(n)
            if 0 <= n < self.symboltable.num_symbols() else None
        )

        version: SymbolVersion | None = None
        source: VersionRecord | None = None
        sources: list[VersionRecord] = []
        if index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            version = {
                'index': index, 'name': None, 'filename': None, 'hidden': hidden}
        else:
            sources = self._resolve_version_records(
                index, n, entry_offset, local)
            if sources:
                source = sources[0]
                version = self._version_from_record(source, hidden)

        self._check_hidden_bit(
            n=n, entry_offset=entry_offset, hidden=hidden, index=index,
            version=version, source=source, symbol=symbol, local=local)
        return {
            'symbol_table': self.symboltable.name,
            'symbol_table_index': self['sh_link'],
            'symbol_index': n,
            'symbol': symbol,
            'symbol_name': symbol.name if symbol is not None else None,
            'versym_offset': entry_offset,
            'raw_index': raw_index,
            'hidden': hidden,
            'index': index,
            'version': version,
            'source': source,
            'sources': sources,
            'hash': source['hash'] if source is not None else None,
            'chain_offset': source['chain_offset'] if source is not None else None,
            'dependency_names': (
                source['dependency_names'] if source is not None else []),
            'diagnostics': local,
        }

    def get_symbol_version(self, n: int) -> SymbolVersion | None:
        """ Resolve the version of symbol #n in this section's symboltable.

            Return a dict with index, name, filename, and hidden fields, or
            None if n is outside the table. Local and unversioned global
            symbols have indices 'VER_NDX_LOCAL' and 'VER_NDX_GLOBAL' and no
            name or filename. For named versions, filename identifies the
            dependency supplying the version, or is None for a definition
            in this file. hidden is the GNU version-hidden bit, not ELF symbol
            visibility; it is False for Solaris versioning.

            Raise ELFError if a version index has no matching definition or
            requirement. Resolving versions requires section headers.
        """
        info = self.get_symbol_version_info(n)
        if info is None:
            return None

        if info['version'] is None:
            raise ELFError(
                f'No version definition or requirement for index {info["index"]}')
        return info['version']

    def _diagnose_cross_versions(self) -> None:
        by_index: dict[int, list[VersionRecord]] = defaultdict(list)
        by_provider_name: dict[
            tuple[str, str | None], list[VersionRecord]] = defaultdict(list)
        definitions: dict[str, list[VersionRecord]] = defaultdict(list)
        requirements: dict[str, list[VersionRecord]] = defaultdict(list)
        for section in self._version_sections:
            for diagnostic in section.diagnostics:
                self._add_diagnostic(diagnostic)
            for record in section.iter_version_records():
                by_index[record['index']].append(record)
                if record['name']:
                    by_provider_name[
                        (record['name'], record['filename'])].append(record)
                    if record['kind'] == 'verdef':
                        definitions[record['name']].append(record)
                    else:
                        requirements[record['name']].append(record)

        for index, records in by_index.items():
            kinds = {record['kind'] for record in records}
            if len(kinds) > 1:
                definition = next(
                    record for record in records if record['kind'] == 'verdef')
                requirement = next(
                    record for record in records if record['kind'] == 'verneed')
                self._add_diagnostic(make_diagnostic(
                    'verdef-verneed-index-conflict',
                    f'version index {index} appears as both definition '
                    f'{_short_text(definition["name"])!r} and requirement '
                    f'{_short_text(requirement["name"])!r}',
                    section=self.name,
                    section_index=self.section_index,
                    version_index=index,
                    name=requirement['name'],
                    other_name=definition['name'],
                    filename=requirement['filename'],
                    offset=requirement['offset'],
                    other_offset=definition['offset'],
                    reason='same index present in verdef and verneed'))
            elif (len(records) > 1
                  and len({record['section'] for record in records}) > 1):
                self._add_diagnostic(make_diagnostic(
                    'duplicate-version-index',
                    f'version index {index} appears {len(records)} times across '
                    'version tables sharing this symbol table',
                    section=self.name,
                    section_index=self.section_index,
                    version_index=index,
                    name=records[0]['name'],
                    offset=records[0]['offset'],
                    other_offset=records[1]['offset'],
                    reason='duplicate version index'))

        for name in definitions.keys() & requirements.keys():
            definition = definitions[name][0]
            requirement = requirements[name][0]
            self._add_diagnostic(make_diagnostic(
                'verdef-verneed-name-conflict',
                f'version name {_short_text(name)!r} is both defined and '
                'required by this object',
                section=self.name,
                section_index=self.section_index,
                name=name,
                version_index=requirement['index'],
                other_index=definition['index'],
                filename=requirement['filename'],
                offset=requirement['offset'],
                other_offset=definition['offset'],
                reason='version name in both verdef and verneed'))

        for key, records in by_provider_name.items():
            if (len(records) > 1
                    and len({record['section'] for record in records}) > 1):
                name, filename = key
                self._add_diagnostic(make_diagnostic(
                    'duplicate-version-name',
                    f'version name {_short_text(name)!r} appears '
                    f'{len(records)} times across version tables for '
                    f'{_short_text(filename)!r}',
                    section=self.name,
                    section_index=self.section_index,
                    name=name,
                    filename=filename,
                    version_index=records[0]['index'],
                    other_index=records[1]['index'],
                    offset=records[0]['offset'],
                    other_offset=records[1]['offset'],
                    reason='duplicate version name across tables'))

    @property
    def diagnostics(self) -> list[ELFDiagnostic]:
        """Consistency and corruption diagnostics for all linked symbols.

        This is computed lazily when requested and has no effect on the
        results returned by get_symbol_version().
        """
        if int(self['sh_entsize']) <= 0:
            self._add_diagnostic(make_diagnostic(
                'invalid-versym-entry-size',
                f'{self.name} has sh_entsize={self["sh_entsize"]}',
                severity='error',
                section=self.name,
                section_index=self.section_index,
                offset=int(self['sh_offset']),
                field='sh_entsize',
                reason='versym entries cannot be parsed'))
            return list(self._diagnostics)

        for n in range(self.num_symbols()):
            self.get_symbol_version_info(n)
        self._diagnose_cross_versions()
        return list(self._diagnostics)

    def get_symbol_diagnostics(self, n: int) -> list[ELFDiagnostic]:
        """Return diagnostics for only symbol #n, without scanning the table."""
        info = self.get_symbol_version_info(n)
        return list(info['diagnostics']) if info is not None else []

    def get_diagnostics(self) -> list[ELFDiagnostic]:
        return self.diagnostics

    def iter_symbols(self) -> Iterator[Symbol]:
        """ Yield all the symbols in the table
        """
        for i in range(self.num_symbols()):
            yield self.get_symbol(i)
