from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    FILE_NAME_DOS,
    FILE_NAME_NTFS,
    FILE_RECORD_SEGMENT_IN_USE,
    c_ntfs,
)
from dissect.ntfs.evidence import PathEvidenceStatus, file_reference_evidence
from dissect.ntfs.exceptions import Error
from dissect.ntfs.mft import Mft


class FakeAttributes(dict):
    def __getitem__(self, key: int) -> list:
        return self.get(key, [])

    def __getattr__(self, name: str) -> object:
        if name == "FILE_NAME":
            names = self.get(ATTRIBUTE_TYPE_CODE.FILE_NAME, [])
            return SimpleNamespace(attr=names[0].attr) if names else SimpleNamespace()
        raise AttributeError(name)


class FakeMft:
    def __init__(self, records: dict[int, object]):
        self.records = records

    def get(self, reference: int | object) -> object:
        if hasattr(reference, "SegmentNumberLowPart"):
            reference = reference.SegmentNumberLowPart
        try:
            return self.records[reference]
        except KeyError as error:
            raise Error(str(error)) from error

    def segments(self) -> object:
        return iter(self.records.values())


def filename(
    name: str,
    parent_segment: int,
    parent_sequence: int,
    flags: int = FILE_NAME_NTFS,
) -> SimpleNamespace:
    return SimpleNamespace(
        file_name=name,
        flags=flags,
        attr=SimpleNamespace(
            ParentDirectory=SimpleNamespace(
                SegmentNumberLowPart=parent_segment,
                SegmentNumberHighPart=0,
                SequenceNumber=parent_sequence,
            )
        ),
    )


def record(
    segment: int,
    sequence: int,
    names: list[SimpleNamespace],
    is_directory: bool = False,
    full_paths: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        segment=segment,
        header=SimpleNamespace(SequenceNumber=sequence, Flags=FILE_RECORD_SEGMENT_IN_USE),
        attributes=FakeAttributes({ATTRIBUTE_TYPE_CODE.FILE_NAME: names}),
        ntfs=SimpleNamespace(mft=None),
        is_dir=Mock(return_value=is_directory),
        index=Mock(),
        full_paths=Mock(side_effect=lambda ignore_dos=False: full_paths or []),
        filename=names[0].file_name if names else None,
    )


def index_entry(
    name: str,
    reference: int,
    sequence: int,
    is_dos: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        header=SimpleNamespace(
            FileReference=SimpleNamespace(
                SegmentNumberLowPart=reference,
                SegmentNumberHighPart=0,
                SequenceNumber=sequence,
            )
        ),
        attribute=SimpleNamespace(file_name=name, flags=FILE_NAME_DOS if is_dos else FILE_NAME_NTFS),
    )


def directory_with_entries(
    record: SimpleNamespace,
    entries: list[SimpleNamespace],
) -> SimpleNamespace:
    record.index = Mock(return_value=SimpleNamespace(entries=Mock(return_value=iter(entries))))
    return record


def test_file_reference_evidence_corroborates_hard_links_and_keeps_stale_index() -> None:
    root = record(5, 1, [], is_directory=True)
    case_dir = record(8, 1, [filename("case", 5, 1)], is_directory=True, full_paths=["case"])
    links = record(6, 2, [filename("links", 8, 1)], is_directory=True, full_paths=["case\\links"])
    deleted_dir = record(7, 3, [filename("deleted", 8, 1)], is_directory=True, full_paths=["case\\deleted"])
    target = record(
        42,
        2,
        [
            filename("survivor.txt", 6, 2),
            filename("SURVIV~1.TXT", 6, 2, FILE_NAME_DOS),
        ],
    )
    target.ntfs.mft = None
    directory_with_entries(root, [])
    directory_with_entries(case_dir, [])

    directory_with_entries(
        links,
        [
            index_entry("survivor.txt", 42, 2),
            index_entry("SURVIV~1.TXT", 42, 2, is_dos=True),
        ],
    )
    directory_with_entries(deleted_dir, [index_entry("deleted-name.txt", 42, 1)])
    mft = FakeMft({5: root, 6: links, 7: deleted_dir, 8: case_dir, 42: target})
    root.filename = None
    case_dir.ntfs.mft = mft
    root.ntfs.mft = mft
    links.ntfs.mft = mft
    deleted_dir.ntfs.mft = mft
    target.ntfs.mft = mft

    evidence = file_reference_evidence(mft, 42)

    assert evidence.reference == 42
    assert evidence.sequence == 2
    assert evidence.record_allocated is True
    assert evidence.content_present is True
    assert evidence.name_valid is True
    assert [entry.path for entry in evidence.current_paths] == [
        "case\\links\\survivor.txt",
    ]
    assert [entry.status for entry in evidence.current_paths] == [
        PathEvidenceStatus.CORROBORATED,
    ]
    assert [entry.path for entry in evidence.dos_aliases] == ["case\\links\\SURVIV~1.TXT"]
    assert evidence.filename_only == ()
    assert evidence.index_only == ()
    assert evidence.stale_indexes[0].path == "case\\deleted\\deleted-name.txt"
    assert evidence.stale_indexes[0].target_sequence == 1
    assert evidence.stale_indexes[0].parent_sequence_valid is True


def test_file_reference_evidence_keeps_parent_and_sequence_mismatches_as_one_sided_clues() -> None:
    root = record(5, 1, [], is_directory=True)
    root.filename = None
    valid_parent = record(10, 4, [filename("valid", 5, 1)], is_directory=True, full_paths=["valid"])
    stale_parent = record(
        11,
        4,
        [filename("stale-parent", 5, 1)],
        is_directory=True,
        full_paths=["stale-parent"],
    )
    target = record(42, 2, [filename("valid-name.txt", 10, 4)])
    directory_with_entries(valid_parent, [index_entry("valid-name.txt", 42, 2)])
    directory_with_entries(
        stale_parent,
        [index_entry("valid-name.txt", 42, 2), index_entry("index-only.txt", 42, 2)],
    )
    mft = FakeMft({5: root, 10: valid_parent, 11: stale_parent, 42: target})
    directory_with_entries(root, [])
    root.ntfs.mft = mft
    valid_parent.ntfs.mft = mft
    stale_parent.ntfs.mft = mft
    target.ntfs.mft = mft
    target.attributes[ATTRIBUTE_TYPE_CODE.FILE_NAME].append(filename("orphan-name.txt", 99, 7))

    evidence = file_reference_evidence(mft, 42)

    assert [entry.path for entry in evidence.current_paths] == ["valid\\valid-name.txt"]
    assert [entry.path for entry in evidence.filename_only] == [
        "<broken_reference_0x63#7>\\orphan-name.txt",
    ]
    assert evidence.filename_only[0].parent_sequence_valid is False
    assert [entry.path for entry in evidence.index_only] == [
        "stale-parent\\valid-name.txt",
        "stale-parent\\index-only.txt",
    ]
    assert all(entry.parent_sequence_valid is True for entry in evidence.index_only)


def test_file_reference_evidence_marks_stale_parent_sequence_as_filename_only() -> None:
    reused_parent = record(
        10,
        5,
        [filename("reused", 5, 1)],
        is_directory=True,
        full_paths=["reused"],
    )
    root = record(5, 1, [], is_directory=True)
    root.filename = None
    target = record(42, 2, [filename("old-name.txt", 10, 4)])
    mft = FakeMft({5: root, 10: reused_parent, 42: target})
    directory_with_entries(root, [])
    directory_with_entries(reused_parent, [])
    for current_record in mft.records.values():
        current_record.ntfs.mft = mft

    evidence = file_reference_evidence(mft, 42)

    assert evidence.current_paths == ()
    assert evidence.name_valid is False
    assert evidence.index_only == ()
    assert [entry.path for entry in evidence.filename_only] == [
        "<broken_reference_0xa#4>\\old-name.txt",
    ]
    assert evidence.filename_only[0].parent_sequence_valid is False


def test_file_reference_evidence_rejects_stale_cstruct_reference() -> None:
    target = record(42, 2, [])
    mft = FakeMft({42: target})
    target.ntfs.mft = mft

    stale_reference = c_ntfs._MFT_SEGMENT_REFERENCE(
        SegmentNumberLowPart=42,
        SegmentNumberHighPart=0,
        SequenceNumber=1,
    )
    with pytest.raises(ValueError, match="Stale MFT reference"):
        file_reference_evidence(mft, stale_reference)


def test_mft_file_reference_evidence_entry_point() -> None:
    parent = record(10, 4, [filename("valid", 5, 1)], is_directory=True, full_paths=["valid"])
    root = record(5, 1, [], is_directory=True)
    root.filename = None
    target = record(42, 2, [filename("valid-name.txt", 10, 4)])
    directory_with_entries(parent, [index_entry("valid-name.txt", 42, 2)])
    directory_with_entries(root, [])
    mft = Mft.__new__(Mft)
    mft.records = {5: root, 10: parent, 42: target}
    mft.get = lambda reference: mft.records[reference]
    mft.segments = lambda: iter(mft.records.values())
    for current_record in mft.records.values():
        current_record.ntfs = SimpleNamespace(mft=mft)

    evidence = mft.evidence(42)
    assert mft.file_reference_evidence(42).reference == evidence.reference
    assert evidence.reference == 42
    assert evidence.current_paths[0].path == "valid\\valid-name.txt"
