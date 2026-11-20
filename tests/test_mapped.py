from __future__ import annotations

import io
import struct

import pytest

from dissect.cstruct import cstruct
from dissect.cstruct.exception import AccessDenied, MappingError, MissingPage, SegmentConflict
from dissect.cstruct.mapped import UNCONFIRMED, MappedStream, Segment, Unresolved
from tests.util import verify_compiled

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


def _header(*, version: int, flags: int, entry: int, payload: int, name: int) -> bytes:
    data = bytearray(0x20)
    data[0:4] = b"FWH1"
    struct.pack_into("<HHII", data, 4, version, flags, entry, payload)
    struct.pack_into("<I", data, 0x10, name)
    return bytes(data)


def _desc(*, ident: int, offset: int, length: int, crc: int) -> bytes:
    return struct.pack("<IIII", ident, offset, length, crc)


@pytest.fixture
def cs32() -> cstruct:
    return cstruct(pointer="uint32")


def _load(cs: cstruct, compiled: bool) -> None:
    cs.load(CDEF, compiled=compiled)


def _exhibit_a() -> MappedStream:
    # The first two logical ranges are adjacent but sourced from different regions.
    boot = Segment(0x1000, _header(version=3, flags=1, entry=0x10420, payload=0x1040, name=0x1020), label="boot-rom")
    calib = Segment(0x1020, b"hello\x00" + b"\x00" * 0x1A, label="calibration")
    payload = Segment(0x1040, _desc(ident=0xDEAD, offset=0x20000, length=0x1800, crc=0x11112222), label="payload")
    trailer = Segment(0x1070, b"\x00" * 8 + struct.pack("<I", 20261120) + b"SGN1ALPH", label="trailer")
    return MappedStream([boot, calib, payload, trailer, Segment.forbidden(0x10A0, 0x10, label="key-fuse")])


def _exhibit_b() -> MappedStream:
    boot = Segment(0x1000, _header(version=4, flags=5, entry=0x10428, payload=0x1040, name=0x1080), label="boot-rom")
    calib = Segment(0x1020, b"hello\x00" + b"\x00" * 0x1A, label="calibration")
    payload = Segment(0x1040, _desc(ident=0xBEEF, offset=0x24000, length=0x1C00, crc=0x33334444), label="payload")
    trailer = Segment(0x1070, b"\x00" * 8 + struct.pack("<I", 20261121) + b"SGN1", label="trailer")
    return MappedStream([boot, calib, payload, trailer, Segment.forbidden(0x10A0, 0x10, label="key-fuse")])


def test_cross_segment_read_and_sources() -> None:
    view = MappedStream(
        [
            Segment(0x1000, b"ABCD", label="flash-a"),
            Segment(0x1004, b"EFGH", label="flash-b"),
        ]
    )

    assert view.read_at(0x1002, 4) == b"CDEF"
    assert view.sources_at(0x1002, 4) == ("flash-a", "flash-b")

    with pytest.raises(MissingPage):
        view.read_at(0x1004, 5)


def test_overlap_conflict_and_identical_overlap() -> None:
    with pytest.raises(SegmentConflict):
        MappedStream([Segment(0x1000, b"abcd"), Segment(0x1002, b"XXef")])

    with pytest.raises(SegmentConflict):
        MappedStream([Segment(0x1000, b"abcd"), Segment(0x1002, b"cd", readable=False)])

    view = MappedStream([Segment(0x1000, b"abcd"), Segment(0x1002, b"cdef")])
    assert view.read_at(0x1000, 6) == b"abcdef"


def test_missing_and_forbidden_are_distinct() -> None:
    view = MappedStream([Segment(0x1000, b"abcd"), Segment.forbidden(0x1004, 4)])

    with pytest.raises(AccessDenied):
        view.read_at(0x1004, 1)
    with pytest.raises(MissingPage):
        view.read_at(0x1008, 1)

    assert issubclass(MissingPage, MappingError)
    assert issubclass(AccessDenied, MappingError)
    assert not issubclass(MissingPage, AccessDenied)
    assert not issubclass(AccessDenied, MissingPage)


def test_compiled_and_interpreted_use_same_mapping_constraints(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)
    assert verify_compiled(cs32.fw_header, compiled)

    view = _exhibit_a()
    header = view.parse(cs32.fw_header, 0x1000)
    assert header.magic == b"FWH1"
    assert header.version == 3
    assert header.payload.dereference().id == 0xDEAD
    assert header.name.dereference() == b"hello"

    with pytest.raises(MissingPage):
        view.parse(cs32.fw_header, 0x2000)

    with pytest.raises(AccessDenied):
        view.read_at(0x10A0, 4)


def test_pointer_reads_the_mapping_from_when_it_was_parsed(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)

    view_a = _exhibit_a()
    view_b = _exhibit_b()
    header_a = view_a.parse(cs32.fw_header, 0x1000)
    pointer_a = header_a.payload

    header_b = view_b.parse(cs32.fw_header, 0x1000)
    assert int(pointer_a) == int(header_b.payload) == 0x1040
    assert pointer_a.dereference().id == 0xDEAD
    assert header_b.payload.dereference().id == 0xBEEF

    # A remapped view is a new immutable snapshot. The old pointer is unaffected.
    view_c = view_a.remap(
        [
            Segment(0x1000, _header(version=5, flags=0, entry=0x10420, payload=0x1040, name=0x1020), label="boot-rom"),
            Segment(0x1040, _desc(ident=0xCAFE, offset=0, length=0, crc=0), label="payload"),
        ]
    )
    assert view_c.parse(cs32.fw_header, 0x1000).payload.dereference().id == 0xCAFE
    assert pointer_a.dereference().id == 0xDEAD


def test_same_numeric_address_in_two_exhibits(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)

    desc_a = _exhibit_a().parse(cs32.payload_desc, 0x1040)
    desc_b = _exhibit_b().parse(cs32.payload_desc, 0x1040)

    assert desc_a.id == 0xDEAD
    assert desc_b.id == 0xBEEF
    assert desc_a != desc_b


def test_partial_read_retains_unconfirmed_fields(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)

    view_a = _exhibit_a()
    view_a.seek(0x400)
    trailer_a = view_a.parse_partial(cs32.fw_trailer, 0x1078)
    assert view_a.tell() == 0x400
    assert trailer_a.build == 20261120
    assert trailer_a.signature == b"SGN1ALPH"
    assert not hasattr(trailer_a, "__unconfirmed__")

    view_b = _exhibit_b()
    view_b.seek(0x400)
    trailer_b = view_b.parse_partial(cs32.fw_trailer, 0x1078)
    assert view_b.tell() == 0x400
    assert trailer_b.build == 20261121
    assert isinstance(trailer_b.signature, Unresolved)
    assert trailer_b.signature.confirmed is False
    assert trailer_b.__unconfirmed__["signature"] is trailer_b.signature
    assert isinstance(trailer_b.__unconfirmed__["signature"].error, MissingPage)


def test_partial_read_continues_after_hole(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)
    cs32.load("struct span { uint32 a; uint32 b; uint32 c; };", compiled=compiled)

    view = MappedStream([Segment(0x1000, struct.pack("<I", 1)), Segment(0x1008, struct.pack("<I", 3))])
    result = view.parse_partial(cs32.span, 0x1000)

    assert result.a == 1
    assert isinstance(result.b, Unresolved)
    assert result.c == 3
    assert result.__unconfirmed_names__ == ("b",)


def test_stream_position_is_restored_on_success_and_failure(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)
    view = _exhibit_b()
    view.seek(0x900)

    assert view.parse(cs32.fw_header, 0x1000).version == 4
    assert view.tell() == 0x900

    with pytest.raises(MissingPage):
        view.parse(cs32.fw_header, 0x2000)
    assert view.tell() == 0x900

    assert view.read_at(0x1000, 2) == b"FW"
    assert view.tell() == 0x900


def test_read_only_view() -> None:
    view = MappedStream([Segment(0x1000, b"\x00" * 4)])
    assert view.readable()
    assert not view.writable()
    assert view.seekable()

    with pytest.raises(io.UnsupportedOperation):
        view.write(b"x")
    with pytest.raises(io.UnsupportedOperation):
        view.truncate()


def test_cstruct_entry_points(cs32: cstruct, compiled: bool) -> None:
    _load(cs32, compiled)

    view = cs32.mapped(_exhibit_a())
    assert cs32.parse_at(0x1000, "fw_header", view).magic == b"FWH1"
    assert cs32.parse_at("fw_header", 0x1000, view).version == 3
    assert cs32.parse_at(view, 0x1000, "fw_header").version == 3
    assert cs32.read_at(0x1000, 4, view) == b"FWH1"
    assert cs32.read_at(view, 0x1000, 4) == b"FWH1"


def test_char_pointer_can_cross_adjacent_segments() -> None:
    cs = cstruct(pointer="uint32")
    cs.load("struct text { char *value; };", compiled=True)
    view = MappedStream(
        [
            Segment(0x1000, struct.pack("<I", 0x1008)),
            Segment(0x1008, b"hello"),
            Segment(0x100D, b" world\x00"),
        ]
    )

    assert view.parse(cs.text, 0x1000).value.dereference() == b"hello world"
    assert UNCONFIRMED.confirmed is False
