import os
import shutil
import struct

import Evtx.Evtx as evtx
import evtx_scripts.evtx_relocate as evtx_relocate

from Evtx.Relocation import relocate, Classification


def system_path():
    """
    fetch the file system path of the system.evtx test file.

    Returns:
      str: the file system path of the test file.
    """
    cd = os.path.dirname(__file__)
    return os.path.join(cd, "data", "system.evtx")


def first_record_offsets(path, count):
    """
    fetch the (record number, file offset) pairs of the first records.

    Args:
      path (str): the file system path of the EVTX file.
      count (int): the number of records to enumerate.

    Returns:
      list[tuple[int, int]]: (record number, file offset) pairs.
    """
    found = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            found.append((record.record_num(), record.offset()))
            if len(found) == count:
                break
    return found


def patch_record_num(path, offset, record_num):
    """
    overwrite the record number of the record at the given file offset.
    the record number is a qword at offset 0x8 within the record header.
    """
    with open(path, "r+b") as f:
        f.seek(offset + 0x8)
        f.write(struct.pack("<Q", record_num))


def patch_next_record_number(path, next_record_number):
    """
    overwrite the next record number in the file header (offset 0x18),
    simulating an independently written archive header.
    """
    with open(path, "r+b") as f:
        f.seek(0x18)
        f.write(struct.pack("<Q", next_record_number))


def entry_by_record_num(report, record_num):
    for entry in report.entries:
        if entry.source.record_num == record_num:
            return entry
    raise AssertionError("no entry for record {}".format(record_num))


def test_identical_archives_relocate_precisely():
    """
    relocating an archive against itself must recover every address precisely.
    """
    report = relocate(system_path(), system_path())
    assert report.markers_match is True
    assert len(report.entries) > 0
    assert report.is_precise() is True
    for entry in report.entries:
        assert entry.classification == Classification.PRECISE
        assert len(entry.candidates) == 1
        assert entry.candidates[0].file_offset == entry.source.file_offset


def test_duplicate_record_numbers_yield_candidates(tmp_path):
    """
    given a target archive containing two records with the same record
    number, the relocation must report both addresses as candidates and
    must not silently pick one (e.g. by display text).
    """
    target = str(tmp_path / "target.evtx")
    shutil.copyfile(system_path(), target)

    (num_a, offset_a), (num_b, offset_b) = first_record_offsets(system_path(), 2)
    assert num_a != num_b

    # create a second record numbered like the first one.
    patch_record_num(target, offset_b, num_a)

    report = relocate(system_path(), target)
    assert report.markers_match is True

    # the duplicated record number: two candidate addresses, no automatic pick.
    entry = entry_by_record_num(report, num_a)
    assert entry.classification == Classification.CANDIDATE
    assert len(entry.candidates) == 2
    candidate_offsets = sorted(candidate.file_offset for candidate in entry.candidates)
    assert candidate_offsets == sorted([offset_a, offset_b])

    # the displaced record number no longer exists in the target.
    entry = entry_by_record_num(report, num_b)
    assert entry.classification == Classification.UNRESOLVED
    assert entry.candidates == []

    # untouched records still relocate precisely.
    (num_c, offset_c) = first_record_offsets(system_path(), 3)[2]
    entry = entry_by_record_num(report, num_c)
    assert entry.classification == Classification.PRECISE
    assert entry.candidates[0].file_offset == offset_c


def test_independent_archive_header_demotes_to_candidates(tmp_path):
    """
    when the target archive carries an independently written header, the
    version markers no longer agree and no address can be recovered
    precisely, even if the record identifiers still match.
    """
    target = str(tmp_path / "target.evtx")
    shutil.copyfile(system_path(), target)

    with evtx.Evtx(system_path()) as log:
        next_record_number = log.get_file_header().next_record_number()
    patch_next_record_number(target, next_record_number + 1)

    report = relocate(system_path(), target)
    assert report.markers_match is False
    assert report.is_precise() is False
    assert len(report.entries) > 0
    for entry in report.entries:
        assert entry.classification == Classification.CANDIDATE
        assert len(entry.candidates) == 1
        assert entry.candidates[0].file_offset == entry.source.file_offset


def test_relocate_script_reports_duplicate_candidates(tmp_path, capsys):
    """
    the command line comparison must list both addresses of the two
    records that share a record number, and exit non-zero.
    """
    target = str(tmp_path / "target.evtx")
    shutil.copyfile(system_path(), target)

    (num_a, offset_a), (_, offset_b) = first_record_offsets(system_path(), 2)
    patch_record_num(target, offset_b, num_a)

    result = evtx_relocate.main([system_path(), target])
    assert result == 1

    out = capsys.readouterr().out
    assert "CANDIDATE" in out
    assert "UNRESOLVED" in out
    assert "candidate: {:#x}".format(offset_a) in out
    assert "candidate: {:#x}".format(offset_b) in out

    # an unmodified pair of archives relocates cleanly.
    result = evtx_relocate.main([system_path(), system_path()])
    assert result == 0
