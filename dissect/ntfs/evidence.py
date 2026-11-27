from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    FILE_NAME_DOS,
    FILE_RECORD_SEGMENT_IN_USE,
    c_ntfs,
)
from dissect.ntfs.exceptions import BrokenIndexError, Error
from dissect.ntfs.util import segment_reference

if TYPE_CHECKING:
    from dissect.ntfs.c_ntfs import _MFT_SEGMENT_REFERENCE
    from dissect.ntfs.mft import Mft, MftRecord


class PathEvidenceStatus(Enum):
    """Describe how strongly a path clue is supported."""

    CORROBORATED = auto()
    FILE_NAME_ONLY = auto()
    INDEX_ONLY = auto()

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class PathEvidence:
    """A path clue and the evidence source that currently supports it."""

    path: str
    name: str
    is_dos: bool
    status: PathEvidenceStatus
    parent_reference: int
    parent_sequence: int
    parent_sequence_valid: bool


@dataclass(frozen=True, slots=True)
class StaleIndexEvidence:
    """A directory index entry whose target reference is no longer current."""

    path: str
    name: str
    is_dos: bool
    parent_reference: int
    parent_sequence: int
    parent_sequence_valid: bool
    target_reference: int
    target_sequence: int


@dataclass(frozen=True, slots=True)
class FileReferenceEvidence:
    """Current path and name evidence for one MFT file reference."""

    reference: int
    sequence: int
    record_allocated: bool
    content_present: bool
    current_paths: tuple[PathEvidence, ...]
    dos_aliases: tuple[PathEvidence, ...]
    filename_only: tuple[PathEvidence, ...]
    index_only: tuple[PathEvidence, ...]
    stale_indexes: tuple[StaleIndexEvidence, ...]

    @property
    def name_valid(self) -> bool:
        """Return whether at least one non-DOS path name is currently provable."""
        return bool(self.current_paths)


def file_reference_evidence(mft: Mft, reference: int | _MFT_SEGMENT_REFERENCE) -> FileReferenceEvidence:
    """Return current path evidence for an MFT segment reference.

    Directory index entries and ``$FILE_NAME`` attributes are compared separately. A path is only returned as a
    current path when both sources identify the same parent, name, DOS state and current sequence number. Mismatches
    remain available as one-sided clues so a removed name is not confused with the still-present MFT content object.
    """
    if isinstance(reference, c_ntfs._MFT_SEGMENT_REFERENCE):
        target_sequence = reference.SequenceNumber
        reference = segment_reference(reference)
    elif isinstance(reference, int):
        target_sequence = None
    else:
        raise TypeError(f"Invalid MFT reference: {reference!r}")

    record = mft.get(reference)
    sequence = record.header.SequenceNumber
    if target_sequence is not None and target_sequence != sequence:
        raise ValueError(f"Stale MFT reference: {reference}#{target_sequence}, current sequence is {sequence}")

    filename_entries = _filename_entries(mft, record)
    index_entries, stale_indexes = _index_entries(mft, reference, sequence)

    filename_keys = {_evidence_key(entry) for entry in filename_entries}
    index_keys = {_evidence_key(entry) for entry in index_entries}

    current_paths: list[PathEvidence] = []
    dos_aliases: list[PathEvidence] = []
    filename_only: list[PathEvidence] = []
    index_only: list[PathEvidence] = []

    for entry in filename_entries:
        evidence = _path_evidence(
            entry,
            PathEvidenceStatus.CORROBORATED
            if _evidence_key(entry) in index_keys
            else PathEvidenceStatus.FILE_NAME_ONLY,
        )
        if evidence.status == PathEvidenceStatus.CORROBORATED:
            if not evidence.is_dos:
                current_paths.append(evidence)
        elif not evidence.is_dos:
            filename_only.append(evidence)
        if evidence.is_dos:
            dos_aliases.append(evidence)

    for entry in index_entries:
        if _evidence_key(entry) in filename_keys:
            continue

        evidence = _path_evidence(entry, PathEvidenceStatus.INDEX_ONLY)
        if not evidence.is_dos:
            index_only.append(evidence)
        if evidence.is_dos:
            dos_aliases.append(evidence)

    return FileReferenceEvidence(
        reference=reference,
        sequence=sequence,
        record_allocated=bool(record.header.Flags & FILE_RECORD_SEGMENT_IN_USE),
        content_present=True,
        current_paths=tuple(_deduplicate(current_paths)),
        dos_aliases=tuple(_deduplicate(dos_aliases)),
        filename_only=tuple(_deduplicate(filename_only)),
        index_only=tuple(_deduplicate(index_only)),
        stale_indexes=tuple(_deduplicate(stale_indexes)),
    )


def _filename_entries(mft: Mft, record: MftRecord) -> list[PathEvidence]:
    entries = []
    for filename in record.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME]:
        parent = filename.attr.ParentDirectory
        parent_record, is_parent_sequence_valid = _resolve_parent(mft, parent)
        entries.append(
            PathEvidence(
                path=_filename_path(mft, filename.file_name, parent, parent_record),
                name=filename.file_name,
                is_dos=filename.flags == FILE_NAME_DOS,
                status=PathEvidenceStatus.FILE_NAME_ONLY,
                parent_reference=segment_reference(parent),
                parent_sequence=parent.SequenceNumber,
                parent_sequence_valid=is_parent_sequence_valid,
            )
        )
    return entries


def _index_entries(
    mft: Mft,
    target_reference: int,
    target_sequence: int,
) -> tuple[list[PathEvidence], list[StaleIndexEvidence]]:
    entries: list[PathEvidence] = []
    stale: list[StaleIndexEvidence] = []

    for directory in mft.segments():
        if not directory.is_dir():
            continue

        try:
            index = directory.index("$I30")
        except (Error, EOFError):
            continue

        try:
            index_entries = list(index.entries())
        except (Error, EOFError):
            continue

        for entry in index_entries:
            try:
                file_reference = entry.header.FileReference
                reference = segment_reference(file_reference)
                filename = entry.attribute
                if filename is None:
                    continue
            except (Error, EOFError):
                continue

            common = {
                "path": _join_path(_directory_path(directory), filename.file_name),
                "name": filename.file_name,
                "is_dos": filename.flags == FILE_NAME_DOS,
                "parent_reference": directory.segment,
                "parent_sequence": directory.header.SequenceNumber,
                "parent_sequence_valid": True,
            }
            if reference == target_reference and file_reference.SequenceNumber == target_sequence:
                entries.append(PathEvidence(**common, status=PathEvidenceStatus.INDEX_ONLY))
            elif reference == target_reference:
                stale.append(
                    StaleIndexEvidence(
                        **common,
                        target_reference=reference,
                        target_sequence=file_reference.SequenceNumber,
                    )
                )

    return entries, stale


def _directory_path(record: MftRecord) -> str:
    paths = record.full_paths(ignore_dos=True)
    if paths:
        return paths[0]

    return record.filename or f"<unknown_segment_0x{record.segment:x}>"


def _filename_path(
    mft: Mft,
    name: str,
    parent: _MFT_SEGMENT_REFERENCE,
    parent_record: MftRecord | None,
) -> str:
    if parent_record is None:
        parent_path = f"<broken_reference_0x{segment_reference(parent):x}#{parent.SequenceNumber}>"
        return _join_path(parent_path, name)

    from dissect.ntfs.util import get_full_path

    return get_full_path(mft, name, parent)


def _resolve_parent(mft: Mft, parent: _MFT_SEGMENT_REFERENCE) -> tuple[MftRecord | None, bool]:
    try:
        record = mft.get(segment_reference(parent))
    except (Error, EOFError):
        return None, False
    return record, record.header.SequenceNumber == parent.SequenceNumber


def _join_path(parent_path: str, name: str) -> str:
    return f"{parent_path}\\{name}" if parent_path else name


def _evidence_key(entry: PathEvidence) -> tuple[object, ...]:
    return (
        entry.parent_reference,
        entry.parent_sequence,
        entry.name,
        entry.is_dos,
        entry.parent_sequence_valid,
    )


def _path_evidence(entry: PathEvidence, status: PathEvidenceStatus) -> PathEvidence:
    return PathEvidence(
        path=entry.path,
        name=entry.name,
        is_dos=entry.is_dos,
        status=status,
        parent_reference=entry.parent_reference,
        parent_sequence=entry.parent_sequence,
        parent_sequence_valid=entry.parent_sequence_valid,
    )


def _deduplicate(
    items: Iterable[PathEvidence | StaleIndexEvidence],
) -> list[PathEvidence | StaleIndexEvidence]:
    result = []
    seen = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
