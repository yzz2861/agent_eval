# ruff: noqa: INP001
"""Forensic example: reading a firmware dump split over logical segments.

Run with ``python examples/firmware_dump.py``.

Two independent exhibits contain the same numeric payload address, but the
bytes behind that address differ. One exhibit also lacks the final page of a
trailer signature. The example shows that a saved pointer stays bound to the
exhibit it was parsed from, and that a missing page leaves the unconfirmed
field visible instead of silently consuming some other segment.
"""

from __future__ import annotations

import struct

from dissect.cstruct import cstruct
from dissect.cstruct.exception import AccessDenied, MissingPage, SegmentConflict
from dissect.cstruct.mapped import MappedStream, Segment, Unresolved

CDEF = """
struct payload_desc {
    uint32 id;
    uint32 offset;
    uint32 length;
    uint32 crc;
};

struct fw_header {
    char   magic[4];
    uint16 version;
    uint16 flags;
    uint32 entry;
    payload_desc *payload;
    char   *name;
};

struct fw_trailer {
    uint32 build;
    char   signature[8];
};
"""


def make_header(*, version: int, entry: int, payload: int, name: int) -> bytes:
    data = bytearray(0x20)
    data[0:4] = b"FWH1"
    struct.pack_into("<HHII", data, 4, version, 1, entry, payload)
    struct.pack_into("<I", data, 0x10, name)
    return bytes(data)


def make_desc(*, ident: int, offset: int, length: int, crc: int) -> bytes:
    return struct.pack("<IIII", ident, offset, length, crc)


def exhibit_a() -> MappedStream:
    """Three small ranges, plus an explicitly unreadable fuse window."""
    return MappedStream(
        [
            # Adjacent in logical address space, but captured from different regions.
            Segment(0x1000, make_header(version=3, entry=0x10420, payload=0x1040, name=0x1020), label="boot-rom"),
            Segment(0x1020, b"fw-name\x00" + b"\x00" * 0x18, label="calibration"),
            Segment(0x1040, make_desc(ident=0xDEAD, offset=0x20000, length=0x1800, crc=0x11112222), label="payload"),
            Segment(0x1070, b"\x00" * 8 + struct.pack("<I", 20261120) + b"SGN1ALPH", label="trailer"),
            Segment.forbidden(0x10A0, 0x10, label="key-fuse"),
        ]
    )


def exhibit_b() -> MappedStream:
    """Same addresses as exhibit A, but different bytes and no signature page."""
    return MappedStream(
        [
            Segment(0x1000, make_header(version=4, entry=0x10428, payload=0x1040, name=0x1080), label="boot-rom"),
            Segment(0x1020, b"fw-name\x00" + b"\x00" * 0x18, label="calibration"),
            Segment(0x1040, make_desc(ident=0xBEEF, offset=0x24000, length=0x1C00, crc=0x33334444), label="payload"),
            Segment(0x1070, b"\x00" * 8 + struct.pack("<I", 20261121) + b"SGN1", label="trailer"),
            Segment.forbidden(0x10A0, 0x10, label="key-fuse"),
        ]
    )


def main() -> None:
    cs = cstruct(pointer="uint32")
    cs.load(CDEF)

    a = exhibit_a()
    b = exhibit_b()

    print("cross-segment read:", a.read_at(0x101E, 4).hex(), "from", a.sources_at(0x101E, 4))

    print(f"same address in exhibit A: id={a.parse(cs.payload_desc, 0x1040).id:#x}")
    print(f"same address in exhibit B: id={b.parse(cs.payload_desc, 0x1040).id:#x}")

    header_a = a.parse(cs.fw_header, 0x1000)
    saved_pointer = header_a.payload
    header_b = b.parse(cs.fw_header, 0x1000)
    print(f"saved pointer after parsing exhibit B: {saved_pointer.dereference().id:#x}")
    print(f"pointer from exhibit B: {header_b.payload.dereference().id:#x}")

    for label, operation in (
        ("missing page", lambda: b.parse(cs.fw_header, 0x2000)),
        ("forbidden fuse", lambda: a.read_at(0x10A0, 4)),
        (
            "conflicting overlap",
            lambda: MappedStream([Segment(0x2000, b"AAAA"), Segment(0x2002, b"BBBB")]),
        ),
    ):
        try:
            operation()
        except (MissingPage, AccessDenied, SegmentConflict) as error:  # noqa: PERF203
            print(label + ":", type(error).__name__, str(error))

    partial = b.parse_partial(cs.fw_trailer, 0x1078)
    print("partial trailer build:", partial.build)
    print("partial trailer signature:", partial.signature, "of type", type(partial.signature).__name__)
    assert isinstance(partial.signature, Unresolved)
    assert partial.__unconfirmed__["signature"] is partial.signature

    full = a.parse_partial(cs.fw_trailer, 0x1078)
    print("complete trailer signature:", full.signature)


if __name__ == "__main__":
    main()
