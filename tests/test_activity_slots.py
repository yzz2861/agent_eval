import binascii
import struct

import Evtx.Evtx as evtx
from Evtx.activity import ACTIVE, INDETERMINATE, RESIDUAL, inspect_buffer


HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000


def make_record(record_number, size=64):
    record = bytearray(size)
    struct.pack_into("<I", record, 0x00, 0x00002A2A)
    struct.pack_into("<I", record, 0x04, size)
    struct.pack_into("<Q", record, 0x08, record_number)
    struct.pack_into("<Q", record, 0x10, 133000000000000000 + record_number)
    struct.pack_into("<I", record, size - 4, size)
    return bytes(record)


def write_header(buf, slot_count, oldest, current, next_record_number):
    buf[0:8] = b"ElfFile\x00"
    struct.pack_into("<Q", buf, 0x08, oldest)
    struct.pack_into("<Q", buf, 0x10, current)
    struct.pack_into("<Q", buf, 0x18, next_record_number)
    struct.pack_into("<I", buf, 0x20, 0x80)
    struct.pack_into("<H", buf, 0x24, 1)
    struct.pack_into("<H", buf, 0x26, 3)
    struct.pack_into("<H", buf, 0x28, HEADER_SIZE)
    struct.pack_into("<H", buf, 0x2A, slot_count)
    struct.pack_into("<I", buf, 0x78, 0)
    checksum = binascii.crc32(bytes(buf[0:0x78])) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 0x7C, checksum)


def write_chunk(buf, slot_number, record_numbers, slack_records=(), corrupt_data=False):
    offset = HEADER_SIZE + slot_number * CHUNK_SIZE
    buf[offset : offset + 8] = b"ElfChnk\x00"
    struct.pack_into("<Q", buf, offset + 0x08, 1)
    struct.pack_into("<Q", buf, offset + 0x10, len(record_numbers))
    first_number = record_numbers[0] if record_numbers else 0
    last_number = record_numbers[-1] if record_numbers else 0
    struct.pack_into("<Q", buf, offset + 0x18, first_number)
    struct.pack_into("<Q", buf, offset + 0x20, last_number)
    struct.pack_into("<I", buf, offset + 0x28, 0x80)

    cursor = 0x200
    first_offsets = []
    for number in record_numbers:
        first_offsets.append(cursor)
        record = make_record(number)
        buf[offset + cursor : offset + cursor + len(record)] = record
        cursor += len(record)

    last_record_offset = first_offsets[-1] if first_offsets else 0x200
    struct.pack_into("<I", buf, offset + 0x2C, last_record_offset)
    struct.pack_into("<I", buf, offset + 0x30, cursor)

    for relative_offset, number in slack_records:
        record = make_record(number)
        buf[offset + relative_offset : offset + relative_offset + len(record)] = record

    data_checksum = binascii.crc32(bytes(buf[offset + 0x200 : offset + cursor])) & 0xFFFFFFFF
    struct.pack_into("<I", buf, offset + 0x34, data_checksum)

    chunk = evtx.ChunkHeader(buf, offset)
    header_checksum = chunk.calculate_header_checksum()
    struct.pack_into("<I", buf, offset + 0x7C, header_checksum)

    if corrupt_data:
        buf[offset + 0x228] ^= 0x01

    return offset


def build_buffer(slot_count):
    return bytearray(HEADER_SIZE + slot_count * CHUNK_SIZE)


def test_normal_full_log_preserves_active_and_default_order():
    buf = build_buffer(3)
    write_chunk(buf, 0, [1, 2])
    write_chunk(buf, 1, [3, 4])
    write_chunk(buf, 2, [5, 6])
    write_header(buf, 3, oldest=0, current=2, next_record_number=7)

    fh = evtx.FileHeader(buf, 0)
    report = fh.activity_report()

    assert report.header.trusted is True
    assert report.active_physical_order == [0, 1, 2]
    assert report.active_logical_order == [0, 1, 2]
    assert [slot.physical_slot for slot in report.active_slot_reports()] == [0, 1, 2]
    assert [record.record_num() for record in report.active_records()] == [1, 2, 3, 4, 5, 6]
    assert report.conflicts == []

    assert len(list(fh.chunks())) == 3
    default_numbers = [
        record.record_num()
        for chunk in fh.chunks()
        for record in chunk.records()
    ]
    assert default_numbers == [1, 2, 3, 4, 5, 6]
    assert "Active current scope" in report.format_text()


def test_wrapped_log_uses_physical_order_and_keeps_slack_residue_out():
    buf = build_buffer(4)
    write_chunk(buf, 1, [101, 102])
    write_chunk(buf, 2, [103, 104])
    write_chunk(buf, 3, [105, 106])
    write_chunk(
        buf,
        0,
        [107, 108],
        slack_records=((0xF000, 9001), (0xF040, 9002)),
    )
    write_header(buf, 4, oldest=1, current=4, next_record_number=109)

    fh = evtx.FileHeader(buf, 0)
    report = fh.activity_report()
    slot0 = report.slot_by_number(0)

    assert report.header.trusted is True
    assert report.active_logical_order == [1, 2, 3, 4]
    assert report.active_physical_order == [1, 2, 3, 0]
    assert [slot.physical_slot for slot in report.active_slot_reports()] == [1, 2, 3, 0]
    assert [record.record_num() for record in report.active_records()] == list(range(101, 109))

    assert slot0.classification == ACTIVE
    assert [record.record_number for record in slot0.active_records] == [107, 108]
    slack = slot0.residual_records
    assert [record.record_number for record in slack] == [9001, 9002]
    assert [record.origin for record in slack] == ["slack_carve", "slack_carve"]
    assert [record.offset for record in slack] == [
        HEADER_SIZE + 0 * CHUNK_SIZE + 0xF000,
        HEADER_SIZE + 0 * CHUNK_SIZE + 0xF040,
    ]
    assert list(report.active_records())[-1].record_num() == 108

    default_numbers = [
        record.record_num()
        for chunk in fh.chunks()
        for record in chunk.records()
    ]
    assert default_numbers == [107, 108, 101, 102, 103, 104, 105, 106]

    text = report.format_text()
    assert "slack_carve" in text
    assert "not joined to timeline" in text


def test_parseable_slot_outside_declared_active_range_is_residual():
    buf = build_buffer(2)
    write_chunk(buf, 0, [1, 2])
    write_chunk(buf, 1, [3, 4])
    write_header(buf, 2, oldest=1, current=1, next_record_number=5)

    report = inspect_buffer(buf)
    old_slot = report.slot_by_number(0)
    current_slot = report.slot_by_number(1)

    assert old_slot.magic_ok is True
    assert current_slot.magic_ok is True
    assert len(list(evtx.ChunkHeader(buf, HEADER_SIZE).records())) == 2
    assert len(list(evtx.ChunkHeader(buf, HEADER_SIZE + CHUNK_SIZE).records())) == 2

    assert report.active_physical_order == [1]
    assert current_slot.classification == ACTIVE
    assert old_slot.classification == RESIDUAL
    assert "outside the header-declared active order" in old_slot.reasons[0]
    assert [slot.physical_slot for slot in report.active_slot_reports()] == [1]

    text = report.format_text()
    assert "inactive_generation_readable" in text


def test_declared_missing_slot_is_reported_and_not_replaced():
    full = build_buffer(3)
    write_chunk(full, 0, [1, 2])
    write_chunk(full, 1, [3, 4])
    write_chunk(full, 2, [5, 6])
    write_header(full, 3, oldest=0, current=2, next_record_number=7)
    buf = bytes(full[: HEADER_SIZE + 2 * CHUNK_SIZE])

    fh = evtx.FileHeader(buf, 0)
    report = fh.activity_report()
    missing = report.slot_by_number(2)

    assert report.header.physical_slot_count == 2
    assert report.active_physical_order == [0, 1, 2]
    assert missing.exists is False
    assert missing.classification == INDETERMINATE
    assert missing.status == "missing_declared_active_slot"
    assert missing.offset == HEADER_SIZE + 2 * CHUNK_SIZE
    assert any(c.code == "declared_chunk_count_has_missing_physical_slots" for c in report.conflicts)
    assert any(c.code == "declared_active_slot_missing" for c in missing.conflicts)
    assert [slot.physical_slot for slot in report.active_slot_reports()] == [0, 1]
    assert len(list(fh.chunks())) == 2


def test_chunk_checksum_failure_keeps_parseable_slot_out_of_countable_active_log():
    buf = build_buffer(2)
    write_chunk(buf, 0, [1, 2])
    bad_offset = write_chunk(buf, 1, [3, 4], corrupt_data=True)
    write_header(buf, 2, oldest=0, current=1, next_record_number=5)

    fh = evtx.FileHeader(buf, 0)
    bad_chunk = evtx.ChunkHeader(buf, bad_offset)
    assert len(list(bad_chunk.records())) == 2

    report = fh.activity_report()
    good_slot = report.slot_by_number(0)
    bad_slot = report.slot_by_number(1)
    checksum_conflict = next(c for c in bad_slot.conflicts if c.code == "chunk_data_checksum_mismatch")

    assert good_slot.classification == ACTIVE
    assert bad_slot.classification == INDETERMINATE
    assert bad_slot.countable is False
    assert checksum_conflict.offset == bad_offset + 0x34
    assert checksum_conflict.stored != checksum_conflict.calculated
    assert [slot.physical_slot for slot in report.active_slot_reports()] == [0]
    assert [record.record_num() for record in report.active_records()] == [1, 2]
    assert "CRC32" in report.format_text()


def test_header_checksum_failure_preserves_values_but_withholds_activity():
    buf = build_buffer(2)
    write_chunk(buf, 0, [1, 2])
    write_chunk(buf, 1, [3, 4])
    write_header(buf, 2, oldest=0, current=1, next_record_number=5)
    struct.pack_into("<I", buf, 0x7C, 0xDEADBEEF)

    report = inspect_buffer(buf)
    conflict = next(c for c in report.header.conflicts if c.code == "file_header_checksum_mismatch")

    assert report.header.trusted is False
    assert report.active_physical_order == []
    assert report.claimed_physical_order == [0, 1]
    assert conflict.offset == 0x7C
    assert conflict.stored == 0xDEADBEEF
    assert conflict.calculated != 0xDEADBEEF
    assert all(slot.classification == INDETERMINATE for slot in report.slots)
    assert list(report.active_chunks()) == []


def test_short_tail_complete_record_is_readable_but_indeterminate():
    buf = bytearray(HEADER_SIZE + CHUNK_SIZE + 0x300)
    write_chunk(buf, 0, [1, 2])
    tail_offset = HEADER_SIZE + CHUNK_SIZE
    record = make_record(777)
    record_offset = tail_offset + 0x200
    buf[record_offset : record_offset + len(record)] = record
    write_header(buf, 2, oldest=0, current=1, next_record_number=3)

    report = inspect_buffer(buf)
    tail = report.slot_by_number(1)

    assert report.header.physical_slot_count == 1
    assert report.header.partial_tail_length == 0x300
    assert tail.full_slot is False
    assert tail.classification == INDETERMINATE
    assert tail.conflicts[0].code == "partial_physical_slot"
    assert len(tail.records) == 1
    assert tail.records[0].record_number == 777
    assert tail.records[0].structurally_complete is True
    assert tail.records[0].classification == INDETERMINATE
    assert [slot.physical_slot for slot in report.active_slot_reports()] == [0]


def test_real_system_log_report_runs(system):
    report = inspect_buffer(system)

    assert report.header.magic_ok if hasattr(report.header, "magic_ok") else True
    assert report.active_physical_order == list(range(9))
    assert report.slot_by_number(0).classification == ACTIVE
    assert any(c.code == "header_next_record_conflict" for c in report.conflicts)
