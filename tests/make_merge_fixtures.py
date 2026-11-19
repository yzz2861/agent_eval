"""
Build three synthetic EVTX collections from security.evtx for merge tests.

The fixtures model the exact scenario from the engagement:
  A_full.evtx        full export, chunks 0..25, record numbers 1..2261;
  B_overlap.evtx     earlier export window (chunks 0..13), overlapping A;
  C_cleared.evtx     a volume that crossed a log clear: chunks 0..13 keep the
                     pre-clear records, while chunks 14..25 are post-clear
                     records whose numbers restart at 1 (so record numbers now
                     collide with pre-clear records) and whose timestamps move
                     forward; its final chunk is deliberately corrupted.

The generator is byte-level and deterministic, and recomputes the EVTX chunk
and file checksums so every intact chunk still verifies with python-evtx.
"""
from __future__ import annotations

import binascii
import os
import struct

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
CLEAR_BOUNDARY_CHUNK = 14
FORWARD_TIME_SHIFT_SECONDS = 30 * 24 * 60 * 60
CHUNK_MAGIC = b'ElfChnk\x00'


def _crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def _rewrite_chunk_checksums(buf, chunk_offset):
    # python-evtx: header checksum covers [0x0,0x78) + [0x80,0x200);
    # data checksum covers [0x200, next_record_offset).
    # the hashed window [0,0x78) stops at byte 0x77, so the checksum
    # slot at 0x7C is not part of its own input; no zeroing is required.
    # write the data checksum first: it lives at 0x34, inside the
    # header-checksum window [0,0x78), so the header CRC must be computed last.
    next_record_offset = struct.unpack_from("<I", buf, chunk_offset + 0x30)[0]
    data = bytes(buf[chunk_offset + 0x200 : chunk_offset + next_record_offset])
    struct.pack_into("<I", buf, chunk_offset + 0x34, _crc32(data))
    header_data = bytes(buf[chunk_offset : chunk_offset + 0x78])
    header_data += bytes(buf[chunk_offset + 0x80 : chunk_offset + 0x200])
    struct.pack_into("<I", buf, chunk_offset + 0x7C, _crc32(header_data))


def _rewrite_file_checksum(buf):
    struct.pack_into("<I", buf, 0x128, _crc32(bytes(buf[0:0x78])))


def _renumber_chunk(buf, chunk_offset, new_first_number, shift_time):
    """
    Rewrite every active record in a chunk to use a contiguous numbering
    starting at new_first_number, optionally shifting the FILETIME forward,
    then update the chunk header number fields. Returns the next free number.
    """
    next_record_offset = struct.unpack_from("<I", buf, chunk_offset + 0x30)[0]
    cursor = chunk_offset + 0x200
    data_end = chunk_offset + next_record_offset
    number = new_first_number
    first = number
    while cursor < data_end:
        magic, size = struct.unpack_from("<II", buf, cursor)
        if magic != 0x2A2A or size <= 0:
            # inactive/slack region inside this chunk; nothing more to renumber
            break
        struct.pack_into("<Q", buf, cursor + 0x8, number)
        if shift_time:
            filetime = struct.unpack_from("<Q", buf, cursor + 0x10)[0]
            shifted = filetime + FORWARD_TIME_SHIFT_SECONDS * 10_000_000
            struct.pack_into("<Q", buf, cursor + 0x10, shifted)
        cursor += size
        number += 1
    last = number - 1
    struct.pack_into("<Q", buf, chunk_offset + 0x8, first)
    struct.pack_into("<Q", buf, chunk_offset + 0x10, last)
    struct.pack_into("<Q", buf, chunk_offset + 0x18, first)
    struct.pack_into("<Q", buf, chunk_offset + 0x20, last)
    _rewrite_chunk_checksums(buf, chunk_offset)
    return number


def _truncate_to_chunks(src_buf, chunk_count):
    size = FILE_HEADER_SIZE + chunk_count * CHUNK_SIZE
    buf = bytearray(src_buf[:size])
    struct.pack_into("<H", buf, 0x2C, chunk_count)
    # keep the original next_record_number: truncation only removes chunks,
    # it does not reset the per-log record counter.
    _rewrite_file_checksum(buf)
    return buf


def _corrupt_final_chunk(buf, active_chunk_count):
    chunk_index = active_chunk_count - 1
    while chunk_index >= 0:
        candidate = FILE_HEADER_SIZE + chunk_index * CHUNK_SIZE
        if bytes(buf[candidate:candidate+8]) == b'ElfChnk\x00':
            break
        chunk_index -= 1
    first_record = candidate + 0x200
    struct.pack_into('<I', buf, first_record + 0x4, CHUNK_SIZE + 1)


def build_fixtures(src_path, out_dir):
    with open(src_path, "rb") as handle:
        original = bytearray(handle.read())
    # the header chunk_count includes inactive slots; derive the number of
    # chunk blocks actually present in the file from its size.
    active_chunks = (len(original) - FILE_HEADER_SIZE) // CHUNK_SIZE
    os.makedirs(out_dir, exist_ok=True)

    path_a = os.path.join(out_dir, "A_full.evtx")
    with open(path_a, "wb") as handle:
        handle.write(original)

    path_b = os.path.join(out_dir, "B_overlap.evtx")
    buf_b = _truncate_to_chunks(original, CLEAR_BOUNDARY_CHUNK)
    with open(path_b, "wb") as handle:
        handle.write(buf_b)

    buf_c = bytearray(original)
    next_number = 1
    for chunk_index in range(CLEAR_BOUNDARY_CHUNK, active_chunks):
        chunk_offset = FILE_HEADER_SIZE + chunk_index * CHUNK_SIZE
        if bytes(buf_c[chunk_offset : chunk_offset + 8]) != b"ElfChnk\x00":
            # inactive chunk slots carry no records and must not be rewritten
            continue
        next_number = _renumber_chunk(buf_c, chunk_offset, next_number, shift_time=True)
    post_clear_records = next_number - 1
    struct.pack_into("<Q", buf_c, 0x18, post_clear_records + 1)
    _rewrite_file_checksum(buf_c)
    active_chunk_count = sum(1 for idx in range(active_chunks) if bytes(buf_c[FILE_HEADER_SIZE + idx * CHUNK_SIZE:FILE_HEADER_SIZE + idx * CHUNK_SIZE + 8]) == CHUNK_MAGIC)
    _corrupt_final_chunk(buf_c, active_chunk_count)
    path_c = os.path.join(out_dir, "C_cleared.evtx")
    with open(path_c, "wb") as handle:
        handle.write(buf_c)

    return {
        "A_full": path_a,
        "B_overlap": path_b,
        "C_cleared": path_c,
        "active_chunks": active_chunks,
        "clear_boundary_chunk": CLEAR_BOUNDARY_CHUNK,
        "post_clear_records": post_clear_records,
    }
