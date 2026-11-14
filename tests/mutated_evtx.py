"""
In-memory mutation helpers for forensic layout tests.

Each helper starts from a small, valid EVTX byte string (issue_38.evtx: one
chunk whose single record begins at chunk offset 0x200) and returns a new
byte string with one well defined structural defect.  Assertions reason about
integer offsets and issue codes only; raw record bytes are never printed.
"""

import struct

import Evtx.Evtx as evtx

CHUNK_BASE = 0x1000
NRO_OFFSET = 0x30
RECORD_AREA_START = 0x200


def _record_size(buf):
    return struct.unpack_from("<I", buf, CHUNK_BASE + RECORD_AREA_START + 4)[0]


def _plant_record(buf, offset, size, record_num):
    struct.pack_into("<IIQ", buf, CHUNK_BASE + offset, evtx.RECORD_MAGIC, size, record_num)
    struct.pack_into("<I", buf, CHUNK_BASE + offset + size - 4, size)


def make_overlapping(source):
    """
    Hide a second, self-consistent record inside the body of the first record.
      The hidden offset falls within the first record's interval, so the
      reconstructed table has overlapping, non-mutually-exclusive ranges.
    """
    buf = bytearray(source)
    original_size = _record_size(buf)
    # Do not change the legitimate record's own size (it stays self-consistent);
    # only embed an extra self-consistent header inside its body.
    hidden_offset = RECORD_AREA_START + 0x100
    hidden_size = 0x100
    buf[CHUNK_BASE + hidden_offset : CHUNK_BASE + hidden_offset + hidden_size] = b"\x00" * hidden_size
    _plant_record(buf, hidden_offset, hidden_size, 999)
    struct.pack_into("<I", buf, CHUNK_BASE + NRO_OFFSET, RECORD_AREA_START + original_size)
    return bytes(buf)


def make_out_of_order(source):
    """
    Create two records whose second start offset sorts before the first
      record's end, producing an unsorted offset table entry in addition to
      the overlapping interval.
    """
    buf = bytearray(source)
    first_size = 0x300
    first_end = RECORD_AREA_START + first_size
    second_offset = RECORD_AREA_START + 0x100
    second_size = 0x80
    struct.pack_into("<IIQ", buf, CHUNK_BASE + RECORD_AREA_START, evtx.RECORD_MAGIC, first_size, 1)
    struct.pack_into("<I", buf, CHUNK_BASE + first_end - 4, first_size)
    buf[CHUNK_BASE + second_offset : CHUNK_BASE + second_offset + second_size] = b"\x00" * second_size
    _plant_record(buf, second_offset, second_size, 2)
    struct.pack_into("<I", buf, CHUNK_BASE + NRO_OFFSET, first_end)
    return bytes(buf)


def make_slack_pseudo_record(source):
    """
    Plant a complete, self-consistent record in unallocated slack, beyond the
      legitimate record area.  Neither analysis mode may iterate it; the slack
      audit helper must expose its chunk-relative offset.
    """
    buf = bytearray(source)
    area_end = RECORD_AREA_START + _record_size(buf)
    planted_offset = area_end + 0x80
    _plant_record(buf, planted_offset, 0x100, 4242)
    return bytes(buf)


def make_truncated_chunk(source):
    """
    Truncate the file inside the only record so the chunk header and record
      start are present but the record body runs past end of file.
    """
    buf = bytearray(source)
    size = _record_size(buf)
    return bytes(buf[: CHUNK_BASE + RECORD_AREA_START + size // 2])


def make_zero_length_record(source):
    """
    Overwrite the first record's size with zero.
    """
    buf = bytearray(source)
    struct.pack_into("<I", buf, CHUNK_BASE + RECORD_AREA_START + 4, 0)
    return bytes(buf)


def make_duplicate_offset(source):
    """
    Force a zero stride: the next table entry resolves to the current start
      offset, which is both a zero-length record and a duplicated offset.  The
      validator emits both classifications deterministically.
    """
    buf = bytearray(source)
    struct.pack_into("<I", buf, CHUNK_BASE + RECORD_AREA_START + 4, 0)
    return bytes(buf)


def make_cross_chunk_reference(source):
    """
    Inflate the first record length so its interval extends past the 0x10000
      chunk boundary, which no in-chunk record is allowed to cross.
    """
    buf = bytearray(source)
    oversized = evtx.CHUNK_SIZE - RECORD_AREA_START + 0x100
    struct.pack_into("<I", buf, CHUNK_BASE + RECORD_AREA_START + 4, oversized)
    struct.pack_into("<I", buf, CHUNK_BASE + NRO_OFFSET, evtx.CHUNK_SIZE)
    return bytes(buf)


def make_corrupt_chunk(source):
    """
    Corrupt the chunk magic so the header fails its structural sanity check.
    """
    buf = bytearray(source)
    buf[CHUNK_BASE : CHUNK_BASE + 8] = b"\x00" * 8
    return bytes(buf)


def make_bad_record_magic(source):
    """
    Overwrite the first record magic with an invalid value.
    """
    buf = bytearray(source)
    struct.pack_into("<I", buf, CHUNK_BASE + RECORD_AREA_START, 0xDEADBEEF)
    return bytes(buf)


def make_record_number_regression(source):
    """
    Build two adjacent, self-consistent records whose second record number is
      smaller than the first.  The physical layout stays valid, so this must be
      reported as a non-fatal semantic anomaly rather than trusted blindly.
    """
    buf = bytearray(source)
    first_size = 0x200
    first_end = RECORD_AREA_START + first_size
    second_size = 0x180
    second_end = first_end + second_size
    struct.pack_into("<IIQ", buf, CHUNK_BASE + RECORD_AREA_START, evtx.RECORD_MAGIC, first_size, 100)
    struct.pack_into("<I", buf, CHUNK_BASE + first_end - 4, first_size)
    buf[CHUNK_BASE + first_end : CHUNK_BASE + second_end] = b"\x00" * second_size
    struct.pack_into("<IIQ", buf, CHUNK_BASE + first_end, evtx.RECORD_MAGIC, second_size, 50)
    struct.pack_into("<I", buf, CHUNK_BASE + second_end - 4, second_size)
    struct.pack_into("<I", buf, CHUNK_BASE + NRO_OFFSET, second_end)
    return bytes(buf)


def make_timestamp_regression(source):
    """
    Build two adjacent, self-consistent records and give the second record a
      zero filetime, which is earlier than the first record's timestamp.  The
      physical layout stays valid while the timestamp ordering is broken.
    """
    buf = bytearray(source)
    first_size = 0x200
    first_end = RECORD_AREA_START + first_size
    second_size = 0x180
    second_end = first_end + second_size
    struct.pack_into("<IIQ", buf, CHUNK_BASE + RECORD_AREA_START, evtx.RECORD_MAGIC, first_size, 1)
    struct.pack_into("<I", buf, CHUNK_BASE + first_end - 4, first_size)
    buf[CHUNK_BASE + first_end : CHUNK_BASE + second_end] = b"\x00" * second_size
    struct.pack_into("<IIQ", buf, CHUNK_BASE + first_end, evtx.RECORD_MAGIC, second_size, 2)
    struct.pack_into("<I", buf, CHUNK_BASE + second_end - 4, second_size)
    struct.pack_into("<Q", buf, CHUNK_BASE + first_end + 0x10, 0)
    struct.pack_into("<I", buf, CHUNK_BASE + NRO_OFFSET, second_end)
    return bytes(buf)
