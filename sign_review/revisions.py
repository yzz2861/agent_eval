"""Byte-level PDF revision scanning and ByteRange-to-revision mapping.

A PDF grows through incremental updates: each revision appends new/updated
objects, a cross-reference section and a fresh startxref/%%EOF trailer.  A
signature only protects the byte ranges listed in /ByteRange, so the revision
whose trailer falls inside those ranges is the signed state; every later
revision is a post-signature change that needs explicit permission.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from io import BytesIO

from pypdf import PdfReader
from pypdf.errors import PdfReadError

_OBJ_HEADER_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj")
_XREF_TABLE_HEADER_RE = re.compile(rb"(\d+)\s+(\d+)\s*(?:f|n)?\s*\r?\n")
_XREF_ENTRY_RE = re.compile(rb"(\d{10})\s+(\d{5})\s+([fn])\s*(?:\r?\n|\r|$)")
_BYTERANGE_RE = re.compile(rb"/ByteRange\s*\[\s*([0-9\s]+)\]")


@dataclass
class RevisionInfo:
    """One parseable incremental update inside the file."""

    index: int
    start_offset: int
    end_offset: int
    startxref: int
    touched_objects: set[int] = field(default_factory=set)

    @property
    def size(self) -> int:
        return self.end_offset - self.start_offset


@dataclass
class TruncatedFragment:
    """Trailing bytes that do not form a complete, parseable revision."""

    start_offset: int
    end_offset: int
    reason: str


@dataclass
class RevisionScan:
    """Complete revisions plus any dangling, unparseable tail."""

    revisions: list[RevisionInfo]
    truncated_fragments: list[TruncatedFragment]
    byte_ranges: list[list[int]]

    def revision_for_offset(self, offset: int | None) -> int | None:
        """Index of the revision whose byte span contains ``offset``."""
        if offset is None:
            return None
        for revision in self.revisions:
            if revision.start_offset <= offset < revision.end_offset:
                return revision.index
        return None


def _find_revision_markers(data: bytes) -> list[tuple[int, int, int]]:
    """Locate (start, end, startxref) of every complete revision."""
    markers: list[tuple[int, int]] = []
    cursor = 0
    while True:
        marker = data.find(b'%%EOF', cursor)
        if marker < 0:
            break
        cursor = marker + 5
        preceding = data.rfind(b'startxref', 0, marker)
        if preceding < 0 or (markers and preceding < markers[-1][0]):
            continue
        markers.append((preceding, min(cursor, len(data))))
    revisions: list[tuple[int, int, int]] = []
    start = 0
    for marker_start, end in markers:
        match = re.search(rb'startxref\s+(\d+)\s*(?:\r?\n|\r)', data[marker_start:end])
        if match is None:
            continue
        revisions.append((start, end, int(match.group(1))))
        start = end
    return revisions


def _read_xref_stream_ids(reader: PdfReader) -> set[int]:
    ids: set[int] = set()
    xref = getattr(reader, '_xref', None)
    if not xref:
        return ids
    for entry_map in xref.values():
        for object_id in entry_map:
            if object_id != 0:
                ids.add(object_id)
    return ids


def _parse_table_xref(segment: bytes, xref_offset: int) -> set[int]:
    """Fallback parser for classical (non-stream) xref subsections."""
    ids: set[int] = set()
    if xref_offset >= len(segment):
        return ids
    header = _XREF_TABLE_HEADER_RE.match(segment, xref_offset)
    while header:
        first_id = int(header.group(1))
        count = int(header.group(2))
        position = header.end()
        parsed = 0
        while parsed < count:
            entry = _XREF_ENTRY_RE.match(segment, position)
            if entry is None:
                break
            if entry.group(3) == b'n':
                ids.add(first_id + parsed)
            position = entry.end()
            parsed += 1
        header = _XREF_TABLE_HEADER_RE.match(segment, position)
    return ids


def _touched_objects(segment: bytes, startxref: int, reader: PdfReader) -> set[int]:
    """Collect object numbers (de)allocated by one incremental update."""
    try:
        ids = _read_xref_stream_ids(reader)
    except Exception:
        ids = set()
    if not ids:
        ids = _parse_table_xref(segment, startxref)
    if not ids:
        ids = {int(match.group(1)) for match in _OBJ_HEADER_RE.finditer(segment)
               if int(match.group(2)) == 0}
    return ids


def extract_byte_ranges(data: bytes) -> list[list[int]]:
    """Read every /ByteRange without any cryptographic verification."""
    ranges: list[list[int]] = []
    for match in _BYTERANGE_RE.finditer(data):
        numbers = [int(part) for part in match.group(1).split()]
        if len(numbers) != 4:
            continue
        offset, head_length, gap_offset, tail_length = numbers
        if min(numbers) < 0 or offset + head_length > gap_offset:
            continue
        ranges.append(numbers)
    return ranges


def scan_revisions(data: bytes) -> RevisionScan:
    """Split data into complete revisions and any truncated tail."""
    markers = _find_revision_markers(data)
    if not markers:
        raise PdfReadError('No %%EOF marker found: not a parseable PDF')
    revisions: list[RevisionInfo] = []
    for index, (start, end, startxref) in enumerate(markers):
        try:
            reader = PdfReader(BytesIO(data[:end]), strict=False)
        except PdfReadError:
            break
        relative_xref = startxref - start if startxref >= start else startxref
        touched = _touched_objects(data[start:end], relative_xref, reader)
        revisions.append(RevisionInfo(
            index=index, start_offset=start, end_offset=end,
            startxref=startxref, touched_objects=touched))
    if not revisions:
        raise PdfReadError('No revision could be parsed from the PDF bytes')
    fragments: list[TruncatedFragment] = []
    consumed = revisions[-1].end_offset
    tail = data[consumed:]
    if tail.strip():
        reason = 'trailing bytes after last %%EOF'
        if b'obj' in tail or b'xref' in tail or b'startxref' in tail:
            reason = 'unfinished incremental update (missing %%EOF/startxref)'
        fragments.append(TruncatedFragment(consumed, len(data), reason))
    return RevisionScan(revisions, fragments, extract_byte_ranges(data))
