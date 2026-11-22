"""
Acceptance tests for the read-only forensics entry point.

A tiny two-section fixture is built from scratch (one unknown block per
section). The same fixture is re-used with a payload byte flipped and with
a tail truncated, asserting the report flags changed content and incomplete
material respectively.
"""

import hashlib
import io
import struct

from pcapng import scan_unknown_blocks
from pcapng.forensics import ForensicsReport, ForensicsScanner


SHB_MAGIC = 0x0A0D0D0A
BOM = 0x1A2B3C4D
UNKNOWN_TYPE = 0x00004000


def _section_header(endianness):
    body = (
        struct.pack(endianness + "I", BOM)
        + struct.pack(endianness + "HH", 1, 0)
        + struct.pack(endianness + "q", -1)
    )
    length = 12 + len(body)
    return (
        struct.pack(endianness + "II", SHB_MAGIC, length)
        + body
        + struct.pack(endianness + "I", length)
    )


def _unknown_block(endianness, block_type, payload):
    padding = bytes(4 - (len(payload) % 4)) if len(payload) % 4 else b""
    padded = payload + padding
    length = 12 + len(padded)
    return (
        struct.pack(endianness + "II", block_type, length)
        + padded
        + struct.pack(endianness + "I", length)
    )


def _two_section_fixture():
    # Section 0 is big-endian and section 1 is little-endian, proving a
    # later section never inherits the previous section byte order.
    section_zero = _section_header(">") + _unknown_block(
        ">", UNKNOWN_TYPE, b"evidence-aa"
    )
    section_one = _section_header("<") + _unknown_block(
        "<", UNKNOWN_TYPE, b"evidence-bb"
    )
    return section_zero + section_one


def test_clean_two_section_fixture_is_complete():
    report = scan_unknown_blocks(io.BytesIO(_two_section_fixture()))

    assert isinstance(report, ForensicsReport)
    assert report.section_count == 2
    assert report.complete is True
    assert len(report.unknown_blocks) == 2

    first, second = report.unknown_blocks
    assert first.section == 0
    assert second.section == 1
    assert first.block_type == UNKNOWN_TYPE
    assert second.block_type == UNKNOWN_TYPE
    assert first.data == b"evidence-aa\x00"  # padding is part of the archived bytes
    assert second.data == b"evidence-bb\x00"
    assert first.incomplete is False
    assert second.incomplete is False
    assert first.issues == ()
    declared_payload = first.declared_length - 12
    assert first.declared_payload_length == declared_payload
    assert first.readable_end - first.readable_start == declared_payload
    assert first.readable_payload_length == declared_payload
    assert first.digest_algorithm == "sha256"
    assert first.digest == hashlib.sha256(first.data).hexdigest()


def test_changing_a_payload_changes_the_digest():
    original = _two_section_fixture()
    baseline = scan_unknown_blocks(io.BytesIO(original))

    tampered = bytearray(original)
    target = baseline.unknown_blocks[0].readable_start
    tampered[target] = tampered[target] ^ 0xFF

    changed = scan_unknown_blocks(io.BytesIO(bytes(tampered)))
    assert changed.complete is True
    assert changed.unknown_blocks[0].digest != baseline.unknown_blocks[0].digest
    assert changed.unknown_blocks[0].digest == hashlib.sha256(
        bytes(tampered)[target:baseline.unknown_blocks[0].readable_end]
    ).hexdigest()
    assert changed.unknown_blocks[1].digest == baseline.unknown_blocks[1].digest


def test_truncated_material_is_reported_incomplete():
    original = _two_section_fixture()
    baseline = scan_unknown_blocks(io.BytesIO(original))

    cut = original[:-6]
    report = scan_unknown_blocks(io.BytesIO(cut))

    assert report.complete is False
    last = report.unknown_blocks[-1]
    assert last.incomplete is True
    assert last.section == 1
    assert last.readable_payload_length < last.declared_payload_length
    assert any("stream ended" in issue for issue in last.issues)
    first = report.unknown_blocks[0]
    assert first.incomplete is False
    assert first.digest == baseline.unknown_blocks[0].digest


def test_sections_do_not_inherit_endianness():
    report = ForensicsScanner(io.BytesIO(_two_section_fixture())).scan()
    assert [item.section for item in report.unknown_blocks] == [0, 1]
    assert report.unknown_blocks[1].block_type == UNKNOWN_TYPE


def test_known_blocks_are_not_evidenced():
    idb = _unknown_block(">", 0x00000001, struct.pack(">HHI", 1, 0, 65535))
    report = scan_unknown_blocks(io.BytesIO(_section_header(">") + idb))
    assert report.unknown_blocks == []
    assert report.complete is True


def test_empty_stream_produces_no_evidence():
    report = scan_unknown_blocks(io.BytesIO(b""))
    assert report.section_count == 0
    assert report.unknown_blocks == []
    assert report.complete is True


def test_orphan_bytes_before_first_section_are_kept():
    report = scan_unknown_blocks(io.BytesIO(b"\x01\x02\x03"))
    assert report.section_count == 0
    assert report.complete is False
    evidence = report.unknown_blocks[0]
    assert evidence.section == -1
    assert evidence.block_type is None
    assert evidence.incomplete is True
    assert evidence.data == b"\x01\x02\x03"


def test_mismatched_trailing_length_is_incomplete():
    payload = b"abc"
    padded = payload + b"\x00"
    declared = 12 + len(padded)
    bad_block = (
        struct.pack(">II", UNKNOWN_TYPE, declared)
        + padded
        + struct.pack(">I", declared + 8)
    )
    stream = io.BytesIO(_section_header(">") + bad_block)
    report = scan_unknown_blocks(stream)
    assert report.complete is False
    evidence = report.unknown_blocks[0]
    assert evidence.incomplete is True
    assert any("mismatching block lengths" in issue for issue in evidence.issues)


def test_custom_hash_algorithm_is_supported():
    stream = io.BytesIO(_two_section_fixture())
    report = scan_unknown_blocks(stream, hash_algorithm="sha1")
    evidence = report.unknown_blocks[0]
    assert evidence.digest_algorithm == "sha1"
    assert evidence.digest == hashlib.sha1(evidence.data).hexdigest()