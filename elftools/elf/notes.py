#-------------------------------------------------------------------------------
# elftools: elf/notes.py
#
# ELF notes
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from ..common.exceptions import ELFParseError, NoteDuplicateError, NoteParseError
from ..common.utils import bytes2str, roundup, stream_read, struct_parse
from ..construct.lib.container import Container
from .enums import ENUM_ANDROID_NOTE_N_TYPE, ENUM_CORE_NOTE_N_TYPE, ENUM_NOTE_N_TYPE

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .elffile import ELFFile
    from .sections import Section
    from .segments import Segment


# Note type numbers have meaning only within their owner's namespace.
_NOTE_TYPE_NAMES = {
    owner: {value: name for name, value in enum.items() if name != '_default_'}
    for owner, enum in (
        ('GNU', ENUM_NOTE_N_TYPE),
        ('Android', ENUM_ANDROID_NOTE_N_TYPE),
    )
}
_CORE_NOTE_TYPE_NAMES = {
    value: name for name, value in ENUM_CORE_NOTE_N_TYPE.items() if name != '_default_'
}

_DUPLICATE_POLICIES = frozenset(('all', 'mark', 'conflict', 'reject', 'error'))
_ERROR_POLICIES = frozenset(('raise', 'record', 'stop'))


def _make_source(
    source: Section | Segment | None,
    source_type: str | None,
    source_name: str | None,
    vaddr: int | None,
    offset: int,
    size: int,
) -> Container:
    """ Return a self-contained description of the section or segment that
        owns a note range.
    """
    header = getattr(source, 'header', None)
    if source is not None and source_type is None and header is not None:
        if 'sh_offset' in header:
            source_type = 'section'
        elif 'p_offset' in header:
            source_type = 'segment'
    if source_name is None:
        source_name = getattr(source, 'name', None)
    if vaddr is None and header is not None:
        if 'sh_addr' in header:
            vaddr = header['sh_addr']
        elif 'p_vaddr' in header:
            vaddr = header['p_vaddr']

    return Container(
        type=source_type,
        kind=source_type,
        name=source_name,
        offset=offset,
        file_offset=offset,
        size=size,
        vaddr=vaddr,
    )


def _add_source_fields(
    note: Container,
    source: Container,
    note_offset: int,
) -> None:
    """ Attach note-relative and virtual addresses to a parsed note.
    """
    relative_offset = note_offset - source['file_offset']
    note['n_source'] = source.copy()
    note['n_source_type'] = source['type']
    note['n_source_name'] = source['name']
    note['n_source_file_offset'] = source['file_offset']
    note['n_source_offset'] = relative_offset
    note['n_source_relative_offset'] = relative_offset
    note['n_source_size'] = source['size']
    note['n_source_vaddr'] = source['vaddr']
    note['n_section_offset'] = relative_offset if source['type'] == 'section' else None
    note['n_section_relative_offset'] = (
        relative_offset if source['type'] == 'section' else None)
    note['n_section_file_offset'] = (
        source['file_offset'] if source['type'] == 'section' else None)
    note['n_segment_offset'] = relative_offset if source['type'] == 'segment' else None
    note['n_segment_relative_offset'] = (
        relative_offset if source['type'] == 'segment' else None)
    note['n_segment_file_offset'] = (
        source['file_offset'] if source['type'] == 'segment' else None)
    note['n_section_name'] = source['name'] if source['type'] == 'section' else None
    note['n_file_offset'] = note_offset
    note['n_note_offset'] = note_offset
    note['n_raw_offset'] = note_offset
    note['n_end_offset'] = note['n_raw_offset'] + note['n_raw_size']
    note['n_raw_end'] = note['n_end_offset']
    note['n_vaddr'] = (
        source['vaddr'] + relative_offset
        if source['vaddr'] is not None else None
    )


def _note_error(
    offset: int,
    category: str,
    message: str,
    note_offset: int,
    source: Container,
) -> NoteParseError:
    return NoteParseError(
        offset,
        category,
        message,
        note_offset=note_offset,
        source_type=source['type'],
        source_offset=note_offset - source['file_offset'],
    )


def _read_range(
    elffile: ELFFile,
    start: int,
    length: int,
    source_end: int,
    category: str,
    note_offset: int,
    source: Container,
) -> bytes:
    if start < source['file_offset'] or length < 0 or start > source_end:
        raise _note_error(
            start,
            category,
            f'range [{start:#x}, {start + length:#x}) starts outside note source',
            note_offset,
            source,
        )
    if length > source_end - start:
        raise _note_error(
            start,
            category,
            f'range [{start:#x}, {start + length:#x}) exceeds '
            f'note source end {source_end:#x}',
            note_offset,
            source,
        )
    try:
        data = stream_read(elffile.stream, start, length)
    except ELFParseError as e:
        raise _note_error(
            start,
            'source_out_of_bounds',
            str(e),
            note_offset,
            source,
        ) from e
    if len(data) != length:
        raise _note_error(
            start,
            category,
            f'expected {length} bytes, found {len(data)}',
            note_offset,
            source,
        )
    return data


def _decode_description(
    note: Container,
    desc_data: bytes,
    elffile: ELFFile,
    source: Container,
) -> None:
    """ Decode a known descriptor without ever reading past its raw bytes.
    """
    n_type = note['n_type']
    desc_offset = note['n_desc_offset']
    try:
        if n_type == 'NT_GNU_ABI_TAG':
            note['n_desc'] = struct_parse(elffile.structs.Elf_abi,
                                          BytesIO(desc_data))
        elif n_type == 'NT_GNU_BUILD_ID':
            note['n_desc'] = bytes(desc_data).hex()
            note['n_build_id'] = note['n_desc']
        elif n_type == 'NT_GNU_GOLD_VERSION':
            note['n_desc'] = bytes2str(desc_data)
        elif n_type == 'NT_PRPSINFO':
            note['n_desc'] = struct_parse(elffile.structs.Elf_Prpsinfo,
                                          BytesIO(desc_data))
        elif n_type == 'NT_FILE':
            note['n_desc'] = struct_parse(elffile.structs.Elf_Nt_File,
                                          BytesIO(desc_data))
        elif n_type == 'NT_GNU_PROPERTY_TYPE_0':
            off = 0
            desc_stream = BytesIO(desc_data)
            props: list[Container] = []
            alignment = 2 if elffile.elfclass == 32 else 3
            while off < len(desc_data):
                if len(desc_data) - off < 8:
                    raise ValueError('truncated GNU property header')
                p: Container = struct_parse(
                    elffile.structs.Elf_Prop, desc_stream, off)
                data_start = off + 8
                if p.pr_datasz > len(desc_data) - data_start:
                    raise ValueError(
                        f'GNU property data size {p.pr_datasz} exceeds '
                        f'descriptor remainder {len(desc_data) - data_start}')
                next_off = data_start + roundup(p.pr_datasz, alignment)
                if next_off > len(desc_data):
                    raise ValueError(
                        'GNU property padding exceeds descriptor')
                off = next_off
                props.append(p)
            note['n_desc'] = props
        else:
            note['n_desc'] = desc_data
    except ELFParseError as e:
        raise _note_error(
            desc_offset,
            'invalid_descriptor',
            f'cannot decode {n_type!r}: {e}',
            note['n_offset'],
            source,
        ) from e
    except (IndexError, OverflowError, ValueError) as e:
        raise _note_error(
            desc_offset,
            'invalid_descriptor',
            f'cannot decode {n_type!r}: {e}',
            note['n_offset'],
            source,
        ) from e


def _parse_note_at(
    elffile: ELFFile,
    source_start: int,
    source_end: int,
    offset: int,
    source: Container,
) -> Container:
    nhdr_size = elffile.structs.Elf_Nhdr.sizeof()
    if offset < source_start or offset + nhdr_size > source_end:
        raise _note_error(
            offset,
            'truncated_header',
            f'{nhdr_size}-byte note header does not fit in source '
            f'[{source_start:#x}, {source_end:#x})',
            offset,
            source,
        )
    if offset % 4 or (offset - source_start) % 4:
        raise _note_error(
            offset,
            'bad_alignment',
            'note header is not aligned to a 4-byte boundary',
            offset,
            source,
        )

    header_data = _read_range(
        elffile, offset, nhdr_size, source_end,
        'truncated_header', offset, source)
    try:
        header = struct_parse(
            elffile.structs.Elf_Nhdr, BytesIO(header_data))
    except ELFParseError as e:
        raise _note_error(
            offset, 'truncated_header', str(e), offset, source) from e

    namesz = int(header['n_namesz'])
    descsz = int(header['n_descsz'])
    raw_type = int(header['n_type'])

    name_offset = offset + nhdr_size
    if namesz > source_end - name_offset:
        raise _note_error(
            name_offset,
            'name_out_of_bounds',
            f'n_namesz={namesz} exceeds source remainder '
            f'{source_end - name_offset}',
            offset,
            source,
        )
    disk_namesz = roundup(namesz, 2)
    if disk_namesz > source_end - name_offset:
        raise _note_error(
            name_offset,
            'bad_alignment',
            f'name alignment padding for n_namesz={namesz} needs '
            f'{disk_namesz} bytes but only '
            f'{source_end - name_offset}',
            offset,
            source,
        )

    desc_offset = name_offset + disk_namesz
    if descsz > source_end - desc_offset:
        raise _note_error(
            desc_offset,
            'desc_out_of_bounds',
            f'n_descsz={descsz} exceeds source remainder '
            f'{source_end - desc_offset}',
            offset,
            source,
        )
    disk_descsz = roundup(descsz, 2)
    if disk_descsz > source_end - desc_offset:
        raise _note_error(
            desc_offset,
            'bad_alignment',
            f'descriptor alignment padding for n_descsz={descsz} needs '
            f'{disk_descsz} bytes but only '
            f'{source_end - desc_offset}',
            offset,
            source,
        )
    note_end = desc_offset + disk_descsz

    name_storage = _read_range(
        elffile, name_offset, disk_namesz, source_end,
        'name_out_of_bounds', offset, source)
    name_data = name_storage[:namesz]
    name_padding = name_storage[namesz:]
    if namesz:
        terminator = name_data.find(b'\x00')
        if terminator < 0:
            raise _note_error(
                name_offset,
                'missing_name_terminator',
                f'n_namesz={namesz} note name does not contain a NUL byte',
                offset,
                source,
            )
        name: str | None = bytes2str(name_data[:terminator])
    else:
        name = None
    desc_storage = _read_range(
        elffile, desc_offset, disk_descsz, source_end,
        'desc_out_of_bounds', offset, source)
    desc_data = desc_storage[:descsz]
    desc_padding = desc_storage[descsz:]

    note: Container = Container(
        n_namesz=namesz,
        n_descsz=descsz,
        n_type=raw_type,
        n_type_raw=raw_type,
        n_name_raw=name_data,
        n_owner_raw=name_data,
        n_name_bytes=name_data,
        n_name_storage=name_storage,
        n_name_padding=name_padding,
        n_name=name,
        n_owner=name,
        n_owner_name=name,
        n_descdata=desc_data,
        n_desc_bytes=desc_data,
        n_desc_raw=desc_data,
        n_desc_storage=desc_storage,
        n_desc_padding=desc_padding,
        n_header_data=header_data,
        n_header_offset=offset,
        n_header_size=nhdr_size,
        n_name_offset=name_offset,
        n_name_size=namesz,
        n_name_region_size=disk_namesz,
        n_name_padding_offset=name_offset + namesz,
        n_name_padding_size=disk_namesz - namesz,
        n_name_padding_nonzero=any(name_padding),
        n_desc_offset=desc_offset,
        n_desc_size=descsz,
        n_desc_region_size=disk_descsz,
        n_desc_padding_offset=desc_offset + descsz,
        n_desc_padding_size=disk_descsz - descsz,
        n_desc_padding_nonzero=any(desc_padding),
        n_offset=offset,
        n_size=note_end - offset,
        n_raw_size=note_end - offset,
        n_status='ok',
        n_is_corrupt=False,
    )

    note_types = _NOTE_TYPE_NAMES.get(name, {})
    if name == 'CORE' and elffile['e_type'] == 'ET_CORE':
        note_types = _CORE_NOTE_TYPE_NAMES
    resolved_type = note_types.get(raw_type, raw_type)
    note['n_type'] = resolved_type
    note['n_type_name'] = resolved_type
    note['n_type_known'] = isinstance(resolved_type, str)

    _add_source_fields(note, source, offset)
    _decode_description(note, desc_data, elffile, source)
    return note


def _corrupt_note(
    error: NoteParseError,
    source: Container,
) -> Container:
    failure_offset = error.offset
    note_offset = error.note_offset if error.note_offset is not None else failure_offset
    source_relative_offset = note_offset - source['file_offset']
    error_info = Container(
        offset=failure_offset,
        file_offset=failure_offset,
        source_offset=failure_offset - source['file_offset'],
        source_relative_offset=source_relative_offset,
        source_type=source['type'],
        source_name=source['name'],
        source_file_offset=source['file_offset'],
        source=source.copy(),
        note_offset=note_offset,
        category=error.category,
        reason=error.category,
        message=error.message,
    )
    note: Container = Container(
        n_error=error_info,
        n_failure=error_info,
        n_error_offset=failure_offset,
        n_error_category=error.category,
        n_failure_offset=failure_offset,
        n_failure_category=error.category,
        n_is_corrupt=True,
        n_status='corrupt',
        n_offset=note_offset,
        n_size=0,
        n_raw_offset=failure_offset,
        n_raw_size=0,
    )
    note['n_source'] = source.copy()
    note['n_source_type'] = source['type']
    note['n_source_name'] = source['name']
    note['n_source_file_offset'] = source['file_offset']
    note['n_source_offset'] = source_relative_offset
    note['n_source_relative_offset'] = source_relative_offset
    note['n_source_size'] = source['size']
    note['n_source_vaddr'] = source['vaddr']
    note['n_section_offset'] = source_relative_offset if source['type'] == 'section' else None
    note['n_section_relative_offset'] = (
        source_relative_offset if source['type'] == 'section' else None)
    note['n_section_file_offset'] = (
        source['file_offset'] if source['type'] == 'section' else None)
    note['n_segment_offset'] = source_relative_offset if source['type'] == 'segment' else None
    note['n_segment_relative_offset'] = (
        source_relative_offset if source['type'] == 'segment' else None)
    note['n_segment_file_offset'] = (
        source['file_offset'] if source['type'] == 'segment' else None)
    note['n_section_name'] = source['name'] if source['type'] == 'section' else None
    note['n_file_offset'] = note_offset
    note['n_note_offset'] = note_offset
    note['n_end_offset'] = failure_offset
    note['n_raw_end'] = failure_offset
    note['n_vaddr'] = (
        source['vaddr'] + source_relative_offset
        if source['vaddr'] is not None else None
    )
    return note


def _annotate_duplicates(
    notes: list[Container],
    duplicate_policy: str,
    source: Container,
) -> None:
    groups: dict[tuple[bytes, int], list[Container]] = {}
    for note in notes:
        if note['n_is_corrupt']:
            continue
        key = (note['n_name_raw'], note['n_type_raw'])
        groups.setdefault(key, []).append(note)

    for (owner, note_type), group in groups.items():
        count = len(group)
        offsets = [note['n_offset'] for note in group]
        if count > 1 and duplicate_policy in ('reject', 'error'):
            duplicate = group[1]
            owner_text = bytes2str(owner.split(b'\x00', 1)[0]) or '<no owner>'
            raise NoteDuplicateError(
                duplicate['n_offset'],
                message=(
                    f'duplicate note owner/type {owner_text!r}/'
                    f'{note_type:#x} at offsets '
                    f'{", ".join(hex(offset) for offset in offsets)}'
                ),
                note_offset=duplicate['n_offset'],
                source_type=source['type'],
                source_offset=duplicate['n_offset'] - source['file_offset'],
            )
        for index, note in enumerate(group):
            note['n_duplicate'] = index > 0
            note['n_duplicate_index'] = index
            note['n_duplicate_count'] = count
            note['n_duplicate_group'] = count > 1
            note['n_duplicate_offsets'] = list(offsets)
            note['n_duplicate_of'] = offsets[0] if index > 0 else None
            note['n_conflict'] = count > 1


def iter_notes(
    elffile: ELFFile,
    offset: int,
    size: int,
    *,
    source: Section | Segment | None = None,
    source_type: str | None = None,
    source_name: str | None = None,
    vaddr: int | None = None,
    duplicate_policy: str = 'all',
    on_error: str = 'raise',
) -> Iterator[Container]:
    """ Yield notes fully contained within ``[offset, offset + size)``.

        Every note is validated before any of its bytes are decoded:

        * the 12-byte header must fit and start on a 4-byte boundary,
        * the NUL-terminated name and 4-byte padding must fit,
        * the descriptor and its padding must fit,
        * the next note is only considered within the same source range.

        Parsed notes retain the historical ``n_name``, ``n_type``,
        ``n_descdata``, ``n_desc``, ``n_offset`` and ``n_size`` fields.
        ``n_type`` remains symbolic for known owner/type pairs and numeric for
        unknown owners and types; ``n_type_raw`` always keeps the numeric value
        and ``n_name_raw``/``n_desc_raw`` keep the raw bytes.

        Source fields include ``n_source_offset`` (relative to the section or
        segment), ``n_file_offset`` (absolute), ``n_vaddr`` (when the source
        has a virtual address), and explicit raw ranges such as
        ``n_header_offset``, ``n_name_offset`` and ``n_desc_offset``.

        ``duplicate_policy`` controls repeated ``(owner, n_type)`` pairs:
        ``'all'``/``'mark'``/``'conflict'`` return every occurrence with
        ``n_duplicate``, ``n_duplicate_count`` and ``n_conflict`` annotations;
        ``'reject'``/``'error'`` raise :class:`NoteDuplicateError`. Duplicates
        are never silently collapsed to the first note.

        ``on_error`` controls malformed notes: ``'raise'`` raises
        :class:`NoteParseError` (the default), ``'record'`` yields one
        ``n_is_corrupt`` record carrying ``n_error['offset']`` and
        ``n_error['category']`` and then stops, and ``'stop'`` stops silently
        for backwards compatibility.
    """
    if duplicate_policy not in _DUPLICATE_POLICIES:
        raise ValueError(
            f'unknown duplicate_policy {duplicate_policy!r}; expected one of '
            f'{sorted(_DUPLICATE_POLICIES)}')
    if on_error not in _ERROR_POLICIES:
        raise ValueError(
            f'unknown on_error policy {on_error!r}; expected one of '
            f'{sorted(_ERROR_POLICIES)}')
    if size < 0:
        raise _note_error(
            offset,
            'source_out_of_bounds',
            f'negative note source size {size}',
            offset,
            _make_source(source, source_type, source_name, vaddr, offset, size),
        )

    source_info = _make_source(
        source, source_type, source_name, vaddr, offset, size)
    source_start = offset
    source_end = offset + size
    nhdr_size = elffile.structs.Elf_Nhdr.sizeof()
    notes: list[Container] = []

    while offset < source_end:
        if offset + nhdr_size > source_end:
            remaining = source_end - offset
            try:
                tail = _read_range(
                    elffile, offset, remaining, source_end,
                    'truncated_header', offset, source_info)
            except NoteParseError as e:
                if on_error == 'raise':
                    raise
                if on_error == 'record':
                    notes.append(_corrupt_note(e, source_info))
                break
            if any(tail):
                error = _note_error(
                    offset,
                    'truncated_header',
                    f'{remaining} non-zero trailing bytes cannot form a note '
                    f'header',
                    offset,
                    source_info,
                )
                if on_error == 'raise':
                    raise error
                if on_error == 'record':
                    notes.append(_corrupt_note(error, source_info))
            break

        try:
            note = _parse_note_at(
                elffile, source_start, source_end, offset, source_info)
        except NoteParseError as e:
            if on_error == 'raise':
                raise
            if on_error == 'record':
                notes.append(_corrupt_note(e, source_info))
            break

        notes.append(note)
        next_offset = note['n_end_offset']
        if next_offset <= offset:
            raise _note_error(
                offset,
                'invalid_note_size',
                'note parser made no progress',
                offset,
                source_info,
            )
        offset = next_offset

    _annotate_duplicates(notes, duplicate_policy, source_info)
    yield from notes
