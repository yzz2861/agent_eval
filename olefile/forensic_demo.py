"""Synthetic audit scenario for provenance-preserving property views."""

from __future__ import print_function

import struct
import uuid

from .propertyview import parse_property_set


FMTID_LEGACY_REVIEW = "12345678-1234-1234-1234-123456789ABC"
FMTID_UNKNOWN_GAPS = "87654321-4321-4321-4321-CBA987654321"


def _guid_bytes(guid):
    return uuid.UUID(guid).bytes_le


def lpstr_property(text, codec="cp936", raw_bytes=None):
    raw = raw_bytes if raw_bytes is not None else text.encode(codec) + b"\x00"
    return struct.pack("<II", 30, len(raw)) + raw


def lpwstr_property(text):
    count = len(text) + 1
    raw = text.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<II", 31, count) + raw


def ui4_property(value):
    return struct.pack("<II", 19, value)


def _align4(offset):
    return (offset + 3) & ~3


def build_section(dictionary, properties, codepage=936):
    dict_blob = struct.pack("<I", len(dictionary))
    for property_id, raw_name in dictionary:
        dict_blob += struct.pack("<II", property_id, len(raw_name)) + raw_name

    entries = []
    if codepage is not None:
        entries.append((1, None))
    entries.append((0, None))
    entries.extend((property_id, None) for property_id, _ in properties)
    # Physical order is intentionally PID 0 then PID 1 in the identifier table.
    entries = [(0, None)] + ([(1, None)] if codepage is not None else [])
    entries.extend((property_id, None) for property_id, _ in properties)

    cursor = 8 + 8 * len(entries)
    dictionary_offset = cursor
    cursor += len(dict_blob)
    cursor = _align4(cursor)

    codepage_offset = None
    codepage_blob = b""
    if codepage is not None:
        codepage_offset = cursor
        codepage_blob = struct.pack("<IhH", 2, codepage, 0)
        cursor += len(codepage_blob)
        cursor = _align4(cursor)

    property_offsets = {}
    placed = []
    for property_id, blob in properties:
        cursor = _align4(cursor)
        property_offsets[property_id] = cursor
        placed.append((cursor, blob))
        cursor += len(blob)

    size = _align4(cursor)
    section = bytearray(size)
    struct.pack_into("<II", section, 0, size, len(entries))
    struct.pack_into("<II", section, 8, 0, dictionary_offset)
    entry_index = 1
    if codepage is not None:
        struct.pack_into("<II", section, 8 + 8 * entry_index, 1, codepage_offset)
        entry_index += 1
    for property_id, _ in properties:
        offset = 8 + 8 * entry_index
        struct.pack_into("<II", section, offset, property_id,
                         property_offsets[property_id])
        entry_index += 1

    section[dictionary_offset:dictionary_offset + len(dict_blob)] = dict_blob
    if codepage is not None:
        section[codepage_offset:codepage_offset + len(codepage_blob)] = codepage_blob
    for offset, blob in placed:
        section[offset:offset + len(blob)] = blob
    return bytes(section)


def build_property_set(sections):
    count = len(sections)
    cursor = 28 + 20 * count
    descriptors = []
    blobs = []
    for fmtid, section in sections:
        cursor = _align4(cursor)
        descriptors.append((fmtid, cursor))
        blobs.append((cursor, section))
        cursor += len(section)
    size = _align4(cursor)
    stream = bytearray(size)
    stream[0:2] = b"\xfe\xff"
    struct.pack_into("<H", stream, 2, 1)
    struct.pack_into("<I", stream, 24, count)
    for index, (fmtid, offset) in enumerate(descriptors):
        start = 28 + index * 20
        stream[start:start + 16] = _guid_bytes(fmtid)
        struct.pack_into("<I", stream, start + 16, offset)
    for offset, section in blobs:
        stream[offset:offset + len(section)] = section
    return bytes(stream)


def build_synthetic_review_stream():
    reviewer = "核验人".encode("cp936") + b"\x00"
    checker = "复核人".encode("cp936") + b"\x00"
    old_alias = "核验员（旧别名）".encode("cp936") + b"\x00"
    unknown_name = "编码证据缺失项".encode("gbk") + b"\x00"

    current_section = build_section(
        dictionary=[(2, reviewer), (3, checker)],
        properties=[
            (2, lpwstr_property("周核验")),
            (3, lpstr_property("吴复核")),
        ],
        codepage=936,
    )
    legacy_section = build_section(
        dictionary=[(18, reviewer), (18, old_alias)],
        properties=[(18, lpstr_property("郑旧档"))],
        codepage=936,
    )
    gap_section = build_section(
        dictionary=[(9, unknown_name)],
        properties=[
            (9, lpstr_property(None, raw_bytes=unknown_name)),
            (0x4E21, ui4_property(2026026)),
        ],
        codepage=None,
    )
    return build_property_set([
        ("D5CDD505-2E9C-101B-9397-08002B2CF9AE", current_section),
        (FMTID_LEGACY_REVIEW, legacy_section),
        (FMTID_UNKNOWN_GAPS, gap_section),
    ])


def build_synthetic_review_view():
    data = build_synthetic_review_stream()
    return parse_property_set(
        data, stream_path=("\\x05DocumentSummaryInformation",),
        convert_time=False)


def main():
    print(build_synthetic_review_view().audit_report())


if __name__ == "__main__":
    main()
