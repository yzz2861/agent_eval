"""Two version-less firmware header layouts used by the discriminator tests.

The layouts share an identical 4-byte prefix (magic/type and one byte that is
valid in both) and diverge from offset 2 onwards, which is exactly the
situation in which "first definition that parses" back-ends mis-translate
fields.
"""

from __future__ import annotations

import struct

from dissect.cstruct.discriminator import (
    FieldSpec,
    PayloadChecksum,
    RecordLengthEquals,
    SchemaSpec,
    equal_to,
    masked_equals,
    one_of,
)

MAGIC = 0xA5
HEADER_SIZE = 16
HEADER_PACK = "<4B2H2I"
PAYLOAD = b"firmware-body"


def layout_a() -> SchemaSpec:
    """First candidate: explicit total size plus a version enum."""
    fields = (
        FieldSpec("magic", 0, 1, constraint=equal_to(MAGIC)),
        FieldSpec("record_type", 1, 1, constraint=one_of(1, 2, 3)),
        FieldSpec("version", 2, 1, constraint=one_of(1, 2)),
        FieldSpec("flags", 3, 1, constraint=masked_equals(0b11110000, 0)),
        FieldSpec("payload_len", 4, 2),
        FieldSpec("total_size", 6, 2),
        FieldSpec("seq", 8, 4),
        FieldSpec("checksum", 12, 4),
    )
    invariants = (
        RecordLengthEquals(size_field="total_size", name="record_length"),
        PayloadChecksum(
            checksum_field="checksum",
            start=HEADER_SIZE,
            end="payload_len",
            end_base=HEADER_SIZE,
            name="payload_checksum",
        ),
    )
    return SchemaSpec(name="layout_a", fields=fields, invariants=invariants)


def layout_b() -> SchemaSpec:
    """Second candidate: reserved word at offset 6 and a wider hardware rev."""
    fields = (
        FieldSpec("magic", 0, 1, constraint=equal_to(MAGIC)),
        FieldSpec("record_type", 1, 1, constraint=one_of(1, 2, 3)),
        FieldSpec("hw_rev", 2, 1, constraint=one_of(1, 2, 3)),
        FieldSpec("feature_flags", 3, 1, constraint=masked_equals(0b11000000, 0)),
        FieldSpec("payload_len", 4, 2),
        FieldSpec("reserved", 6, 2, constraint=equal_to(0)),
        FieldSpec("seq", 8, 4),
        FieldSpec("checksum", 12, 4),
    )
    invariants = (
        PayloadChecksum(
            checksum_field="checksum",
            start=HEADER_SIZE,
            end="payload_len",
            end_base=HEADER_SIZE,
            name="payload_checksum",
        ),
    )
    return SchemaSpec(name="layout_b", fields=fields, invariants=invariants)


def ambiguous_record() -> bytes:
    """A zero-payload record satisfying every invariant of both layouts."""
    return struct.pack(HEADER_PACK, MAGIC, 2, 1, 0, 0, 0, 0, 0)


def layout_a_record(payload: bytes = PAYLOAD) -> bytes:
    """A record that only layout A can semantically accept."""
    total = HEADER_SIZE + len(payload)
    header = struct.pack(
        HEADER_PACK,
        MAGIC,
        1,
        1,
        0x0F,
        len(payload),
        total,
        7,
        sum(payload) & 0xFFFF,
    )
    return header + payload


def layout_b_record(payload: bytes = PAYLOAD) -> bytes:
    """A record that only layout B can semantically accept."""
    header = struct.pack(
        HEADER_PACK,
        MAGIC,
        1,
        3,
        0x20,
        len(payload),
        0,
        9,
        sum(payload) & 0xFFFF,
    )
    return header + payload
