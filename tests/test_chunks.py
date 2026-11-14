import struct

import pytest

import Evtx.Evtx as evtx
from Evtx.Integrity import (
    CHUNK_HEADER_CHECKSUM_SCOPE,
    CheckType,
    IntegrityStatus,
    RecoverableIntegrityException,
    StructuralIntegrityException,
)

from integrity_helpers import (
    CHUNK_DATA_CHECKSUM_OFFSET,
    CHUNK_HEADER_CHECKSUM_OFFSET,
    CHUNK_NEXT_RECORD_OFFSET,
    TEMPLATE_TABLE_OFFSET,
    chunk_offset,
    get_check,
    load_evtx_bytes,
    statuses,
    write_tmp_evtx,
)

EMPTY_MAGIC = "\x00" * 0x8


def test_chunks(system):
    """
    regression test parsing some known fields in the file chunks.

    Args:
      system (bytes): the system.evtx test file contents. pytest fixture.
    """
    fh = evtx.FileHeader(system, 0x0)

    # collected empirically
    expecteds = [
        {"start_file": 1, "end_file": 153, "start_log": 12049, "end_log": 12201},
        {"start_file": 154, "end_file": 336, "start_log": 12202, "end_log": 12384},
        {"start_file": 337, "end_file": 526, "start_log": 12385, "end_log": 12574},
        {"start_file": 527, "end_file": 708, "start_log": 12575, "end_log": 12756},
        {"start_file": 709, "end_file": 882, "start_log": 12757, "end_log": 12930},
        {"start_file": 883, "end_file": 1059, "start_log": 12931, "end_log": 13107},
        {"start_file": 1060, "end_file": 1241, "start_log": 13108, "end_log": 13289},
        {"start_file": 1242, "end_file": 1424, "start_log": 13290, "end_log": 13472},
        {"start_file": 1425, "end_file": 1601, "start_log": 13473, "end_log": 13649},
    ]

    for i, chunk in enumerate(fh.chunks()):
        # collected empirically
        if i < 9:
            assert chunk.check_magic() is True
            assert chunk.magic() == "ElfChnk\x00"
            assert chunk.calculate_header_checksum() == chunk.header_checksum()
            assert chunk.calculate_data_checksum() == chunk.data_checksum()

            expected = expecteds[i]
            assert chunk.file_first_record_number() == expected["start_file"]
            assert chunk.file_last_record_number() == expected["end_file"]
            assert chunk.log_first_record_number() == expected["start_log"]
            assert chunk.log_last_record_number() == expected["end_log"]

        else:
            assert chunk.check_magic() is False
            assert chunk.magic() == EMPTY_MAGIC


def test_chunk_integrity_clean_control(security):
    """
    every check of a legitimate EVTX must pass and expose the fixed
    algorithm, expected/actual values and byte scope.
    """
    fh = evtx.FileHeader(security, 0x0)
    for chunk in fh.chunks():
        if not chunk.check_magic():
            continue
        report = chunk.integrity()
        assert report.ok()
        names = {check.check for check in report.checks}
        assert CheckType.CHUNK_HEADER_CHECKSUM in names
        assert CheckType.CHUNK_DATA_CHECKSUM in names
        assert CheckType.TEMPLATE_REFERENCE in names

        header = get_check(report, CheckType.CHUNK_HEADER_CHECKSUM)
        assert header.algorithm == "CRC32/ISO-HDLC"
        assert header.scope == CHUNK_HEADER_CHECKSUM_SCOPE
        assert header.expected == header.actual
        assert header.expected == chunk.header_checksum()

        data = get_check(report, CheckType.CHUNK_DATA_CHECKSUM)
        assert data.scope == ((0x200, chunk.next_record_offset()),)
        assert data.expected == data.actual == chunk.data_checksum()
        assert chunk.verify() is True


def test_zeroed_chunk_header_checksum_is_recoverable(data_path, tmp_path):
    """
    a zeroed chunk header checksum still parses, but must be reported as a
    recoverable integrity failure localized to the affected chunk.
    """
    data = load_evtx_bytes(data_path, "security.evtx")
    target = chunk_offset(0)
    struct.pack_into("<I", data, target + CHUNK_HEADER_CHECKSUM_OFFSET, 0)
    path = write_tmp_evtx(tmp_path, data, "zeroed_chunk_checksum.evtx")

    with evtx.Evtx(path) as log:
        chunk = next(log.get_file_header().chunks())
        report = chunk.integrity()
        assert report.status() == IntegrityStatus.RECOVERABLE
        header = get_check(report, CheckType.CHUNK_HEADER_CHECKSUM)
        assert header.status == IntegrityStatus.RECOVERABLE
        assert header.expected == 0
        assert header.actual == chunk.calculate_header_checksum()
        assert header.actual != 0

        # recovery mode keeps emitting records, each carrying the failure
        record = next(chunk.records())
        record_report = record.integrity()
        assert record_report.status() == IntegrityStatus.RECOVERABLE
        assert statuses(record_report)[CheckType.CHUNK_HEADER_CHECKSUM.value] == "recoverable"


def test_zeroed_chunk_header_checksum_strict_mode(data_path, tmp_path):
    with evtx.Evtx(
        write_tmp_evtx(
            tmp_path,
            _zero_header_checksum(data_path),
            "strict_zero.evtx",
        ),
        recover=False,
    ) as log:
        try:
            next(log.get_file_header().chunks()).check_header_integrity()
        except RecoverableIntegrityException as exc:
            assert exc.result.check == CheckType.CHUNK_HEADER_CHECKSUM
        else:
            raise AssertionError("strict mode must raise on a bad checksum")


def _zero_header_checksum(data_path):
    data = load_evtx_bytes(data_path, "security.evtx")
    struct.pack_into("<I", data, chunk_offset(0) + CHUNK_HEADER_CHECKSUM_OFFSET, 0)
    return data


def test_chunk_size_corruption_is_structural(data_path, tmp_path):
    """
    an impossible next_record_offset is structural damage, not a mere
    checksum mismatch; it is detected even if the stored checksum is forged.
    """
    data = load_evtx_bytes(data_path, "security.evtx")
    target = chunk_offset(0)
    struct.pack_into("<I", data, target + CHUNK_NEXT_RECORD_OFFSET, 0x99999)
    path = write_tmp_evtx(tmp_path, data, "bad_chunk_size.evtx")

    with evtx.Evtx(path) as log:
        chunk = next(log.get_file_header().chunks())
        report = chunk.integrity()
        assert report.status() == IntegrityStatus.STRUCTURAL
        header = get_check(report, CheckType.CHUNK_HEADER_CHECKSUM)
        assert header.status == IntegrityStatus.STRUCTURAL
        assert "next_record_offset" in header.detail

    with pytest.raises(StructuralIntegrityException):
        with evtx.Evtx(path, recover=False) as log:
            next(log.get_file_header().chunks()).check_header_integrity()


def test_chunk_magic_corruption_is_structural(data_path, tmp_path):
    data = load_evtx_bytes(data_path, "security.evtx")
    target = chunk_offset(0)
    data[target] ^= 0xFF
    path = write_tmp_evtx(tmp_path, data, "bad_magic.evtx")

    with evtx.Evtx(path) as log:
        chunk = next(log.get_file_header().chunks())
        assert chunk.check_magic() is False
        report = chunk.integrity()
        assert report.status() == IntegrityStatus.STRUCTURAL


def test_forged_chunk_data_checksum_is_detected(data_path, tmp_path):
    """
    a forged data checksum cannot hide a flipped record byte: the stored and
    recomputed fixed-scope CRC32 values are both returned and must disagree.
    """
    data = load_evtx_bytes(data_path, "security.evtx")
    target = chunk_offset(0)
    data[target + 0x200 + 0x40] ^= 0xFF
    struct.pack_into("<I", data, target + CHUNK_DATA_CHECKSUM_OFFSET, 0xDEADBEEF)
    path = write_tmp_evtx(tmp_path, data, "forged_data_checksum.evtx")

    with evtx.Evtx(path) as log:
        chunk = next(log.get_file_header().chunks())
        data_check = get_check(chunk.integrity(), CheckType.CHUNK_DATA_CHECKSUM)
        assert data_check.status == IntegrityStatus.RECOVERABLE
        assert data_check.expected == 0xDEADBEEF
        assert data_check.actual == chunk.calculate_data_checksum()
        assert data_check.actual != 0xDEADBEEF

        record = next(chunk.records())
        assert record.integrity_status() == IntegrityStatus.RECOVERABLE


def test_template_pointer_tampering_is_structural(data_path, tmp_path):
    """
    an overwritten chunk template pointer slot fails the template reference
    layer and taints the records rendered from that chunk.
    """
    data = load_evtx_bytes(data_path, "security.evtx")
    target = chunk_offset(0)
    slot = None
    for index in range(32):
        value = struct.unpack_from("<I", data, target + TEMPLATE_TABLE_OFFSET + (index * 4))[0]
        if value:
            slot = index
            break
    assert slot is not None
    struct.pack_into("<I", data, target + TEMPLATE_TABLE_OFFSET + (slot * 4), 0x4000)
    path = write_tmp_evtx(tmp_path, data, "bad_template_pointer.evtx")

    with evtx.Evtx(path) as log:
        chunk = next(log.get_file_header().chunks())
        template_check = chunk.check_template_references()
        assert template_check.status == IntegrityStatus.STRUCTURAL
        assert "slot {}".format(slot) in template_check.detail
        record = next(chunk.records())
        assert record.integrity_status() == IntegrityStatus.STRUCTURAL


def test_empty_chunk_slot_is_not_corruption(data_path, tmp_path):
    """
    a fully zeroed chunk header is unallocated space and must remain OK,
    while a partially zeroed header is structural damage.
    """
    data = load_evtx_bytes(data_path, "security.evtx")
    last_index = 25
    target = chunk_offset(last_index)
    for offset in range(0x200):
        data[target + offset] = 0
    path = write_tmp_evtx(tmp_path, data, "empty_chunk.evtx")

    with evtx.Evtx(path) as log:
        chunks = list(log.get_file_header().chunks())
        empty_chunk = chunks[last_index]
        assert empty_chunk.is_empty()
        assert empty_chunk.integrity().ok()
        assert list(empty_chunk.records()) == []

    # partial zeroing (magic only) is structural, not empty
    data = load_evtx_bytes(data_path, "security.evtx")
    data[target : target + 8] = b"\x00" * 8
    path = write_tmp_evtx(tmp_path, data, "partial_zero.evtx")
    with evtx.Evtx(path) as log:
        chunk = list(log.get_file_header().chunks())[last_index]
        assert not chunk.is_empty()
        assert chunk.integrity().status() == IntegrityStatus.STRUCTURAL


def test_chunks2(security):
    """
    regression test parsing some known fields in the file chunks.

    Args:
      security (bytes): the security.evtx test file contents. pytest fixture.
    """
    fh = evtx.FileHeader(security, 0x0)

    # collected empirically
    expecteds = [
        {"start_file": 1, "end_file": 91, "start_log": 1, "end_log": 91},
        {"start_file": 92, "end_file": 177, "start_log": 92, "end_log": 177},
        {"start_file": 178, "end_file": 260, "start_log": 178, "end_log": 260},
        {"start_file": 261, "end_file": 349, "start_log": 261, "end_log": 349},
        {"start_file": 350, "end_file": 441, "start_log": 350, "end_log": 441},
        {"start_file": 442, "end_file": 530, "start_log": 442, "end_log": 530},
        {"start_file": 531, "end_file": 622, "start_log": 531, "end_log": 622},
        {"start_file": 623, "end_file": 711, "start_log": 623, "end_log": 711},
        {"start_file": 712, "end_file": 802, "start_log": 712, "end_log": 802},
        {"start_file": 803, "end_file": 888, "start_log": 803, "end_log": 888},
        {"start_file": 889, "end_file": 976, "start_log": 889, "end_log": 976},
        {"start_file": 977, "end_file": 1063, "start_log": 977, "end_log": 1063},
        {"start_file": 1064, "end_file": 1148, "start_log": 1064, "end_log": 1148},
        {"start_file": 1149, "end_file": 1239, "start_log": 1149, "end_log": 1239},
        {"start_file": 1240, "end_file": 1327, "start_log": 1240, "end_log": 1327},
        {"start_file": 1328, "end_file": 1414, "start_log": 1328, "end_log": 1414},
        {"start_file": 1415, "end_file": 1501, "start_log": 1415, "end_log": 1501},
        {"start_file": 1502, "end_file": 1587, "start_log": 1502, "end_log": 1587},
        {"start_file": 1588, "end_file": 1682, "start_log": 1588, "end_log": 1682},
        {"start_file": 1683, "end_file": 1766, "start_log": 1683, "end_log": 1766},
        {"start_file": 1767, "end_file": 1847, "start_log": 1767, "end_log": 1847},
        {"start_file": 1848, "end_file": 1942, "start_log": 1848, "end_log": 1942},
        {"start_file": 1943, "end_file": 2027, "start_log": 1943, "end_log": 2027},
        {"start_file": 2028, "end_file": 2109, "start_log": 2028, "end_log": 2109},
        {"start_file": 2110, "end_file": 2201, "start_log": 2110, "end_log": 2201},
        {"start_file": 2202, "end_file": 2261, "start_log": 2202, "end_log": 2261},
    ]

    for i, chunk in enumerate(fh.chunks()):
        # collected empirically
        if i < 26:
            assert chunk.check_magic() is True
            assert chunk.magic() == "ElfChnk\x00"
            assert chunk.calculate_header_checksum() == chunk.header_checksum()
            assert chunk.calculate_data_checksum() == chunk.data_checksum()

            expected = expecteds[i]
            assert chunk.file_first_record_number() == expected["start_file"]
            assert chunk.file_last_record_number() == expected["end_file"]
            assert chunk.log_first_record_number() == expected["start_log"]
            assert chunk.log_last_record_number() == expected["end_log"]

        else:
            assert chunk.check_magic() is False
            assert chunk.magic() == EMPTY_MAGIC
