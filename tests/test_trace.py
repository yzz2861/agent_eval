from __future__ import annotations

import io
from typing import TYPE_CHECKING, Any, BinaryIO

import pytest

from dissect.cstruct import cstruct
from dissect.cstruct.trace import (
    ByteSpan,
    NodeKind,
    OverlapKind,
    current_tracer,
    trace_read,
)
from dissect.cstruct.types import BaseType

if TYPE_CHECKING:
    from dissect.cstruct.trace import SourceGraph


def _spans(graph: SourceGraph, path: str) -> list[tuple[int, int, int | None, int | None]]:
    node = graph.find(path)
    assert node is not None, path
    return [(span.start, span.end, span.bit_start, span.bit_end) for span in node.evidence()]


def _bit_span(graph: SourceGraph, path: str) -> ByteSpan:
    node = graph.find(path)
    assert node is not None, path
    bits = [span for span in node.spans if span.bit_start is not None]
    assert bits, path
    return bits[0]


def test_basic_field_spans_interpreted() -> None:
    cs = cstruct()
    cs.load("struct Header { uint16 magic; uint32 size; };", compiled=False)
    data = (0x4453).to_bytes(2, "little") + (0x20).to_bytes(4, "little")
    with trace_read("Header") as traced:
        obj = cs.Header(io.BytesIO(data))
    graph = traced.graph
    assert obj.magic == 0x4453
    assert _spans(graph, "$.magic") == [(0, 2, None, None)]
    assert _spans(graph, "$.size") == [(2, 6, None, None)]
    assert graph.reconstruct(io.BytesIO(data)) == {"$.magic": data[0:2], "$.size": data[2:6]}


def test_compiled_and_interpreted_produce_equivalent_graphs() -> None:
    cdef = "struct Header { uint16 magic; uint32 size; uint8 flag; };"
    data = b"SD" + (0x20).to_bytes(4, "little") + bytes([7])
    graphs = {}
    for compiled_flag in (True, False):
        cs = cstruct()
        cs.load(cdef, compiled=compiled_flag)
        # Exercise the lazy compiler before tracing as well
        cs.Header(io.BytesIO(data))
        with trace_read("Header") as traced:
            cs.Header(io.BytesIO(data))
        graphs[compiled_flag] = traced.graph.to_dict()
    assert graphs[True] == graphs[False]


@pytest.mark.parametrize("endian", ["<", ">"])
def test_bitfield_spans_including_straddling(endian: str) -> None:
    cs = cstruct(endian="little" if endian == "<" else "big")
    cs.load(
        "struct Bits { uint8 a : 3; uint8 b : 5; uint16 c : 12; uint16 d : 4; };",
        compiled=False,
    )
    data = bytes([0b11010010, 0xAB, 0xCD]) if endian == "<" else bytes([0xCD, 0xAB, 0b11010010])
    with trace_read("Bits") as traced:
        cs.Bits(io.BytesIO(data))
    graph = traced.graph
    a = graph.find("$.a")
    b = graph.find("$.b")
    c_span = _bit_span(graph, "$.c")
    d_span = _bit_span(graph, "$.d")
    c = graph.find("$.c")
    d = graph.find("$.d")
    assert a.bit_width == 3
    assert b.bit_width == 5
    assert c.bit_width == 12
    assert d.bit_width == 4
    # a and b share the first byte but occupy disjoint bits
    a_bits = _bit_span(graph, "$.a")
    b_bits = _bit_span(graph, "$.b")
    assert a_bits.bit_end <= b_bits.bit_start or endian == ">"
    # c straddles two bytes (1..3) and is recorded with an exact bit range
    assert (c_span.start, c_span.end) == (1, 3)
    assert c_span.bit_end - c_span.bit_start == 12
    assert d_span.bit_end - d_span.bit_start == 4


def test_nested_structure_spans() -> None:
    cs = cstruct()
    cs.load(
        "struct Inner { uint32 x; }; struct Outer { uint8 head; Inner inner; uint8 tail; };",
        compiled=False,
    )
    data = b"H" + (0x01020304).to_bytes(4, "little") + b"T"
    with trace_read("Outer") as traced:
        cs.Outer(io.BytesIO(data))
    graph = traced.graph
    assert _spans(graph, "$.head") == [(0, 1, None, None)]
    assert _spans(graph, "$.inner.x") == [(1, 5, None, None)]
    assert _spans(graph, "$.tail") == [(5, 6, None, None)]


def test_static_array_element_spans() -> None:
    cs = cstruct()
    cs.load("struct Arr { uint8 fixed[3]; uint16 words[2]; };", compiled=False)
    data = b"abc" + (0x1111).to_bytes(2, "little") + (0x2222).to_bytes(2, "little")
    with trace_read("Arr") as traced:
        cs.Arr(io.BytesIO(data))
    graph = traced.graph
    elements = [node for node in graph.root.walk() if node.kind is NodeKind.ELEMENT]
    # three uint8 elements and two uint16 elements
    uint8_elems = [node for node in elements if node.type_name == "uint8"]
    uint16_elems = [node for node in elements if node.type_name == "uint16"]
    assert [(n.evidence()[0].start, n.evidence()[0].end) for n in uint8_elems] == [(0, 1), (1, 2), (2, 3)]
    assert [(n.evidence()[0].start, n.evidence()[0].end) for n in uint16_elems] == [(3, 5), (5, 7)]


def test_dynamic_array_depends_on_length_field() -> None:
    cs = cstruct()
    cs.load("struct Dyn { uint32 count; uint16 items[count]; };", compiled=False)
    data = (2).to_bytes(4, "little") + (0x1111).to_bytes(2, "little") + (0x2222).to_bytes(2, "little")
    with trace_read("Dyn") as traced:
        obj = cs.Dyn(io.BytesIO(data))
    graph = traced.graph
    assert len(obj.items) == 2
    field_node = graph.find("$.items")
    array_node = next(node for node in field_node.children if node.kind is NodeKind.ARRAY)
    assert "$.count" in field_node.depends_on
    assert "$.count" in array_node.depends_on
    # the deciding count itself is fully proven
    assert graph.find("$.count").evidence() == [ByteSpan(0, 4)]


def test_pointer_dereference_and_alias_is_shared_evidence() -> None:
    cs = cstruct()
    cs.load(
        "struct Item { uint32 a; uint32 b; }; struct Ref { Item* p1; Item* p2; };",
        compiled=False,
    )
    item = (0xAAAA).to_bytes(4, "little") + (0xBBBB).to_bytes(4, "little")
    data = (8).to_bytes(8, "little") + (8).to_bytes(8, "little") + item
    with trace_read("Ref") as traced:
        obj = cs.Ref(io.BytesIO(data))
    obj.p1.dereference()
    obj.p2.dereference()
    graph = traced.graph
    p1 = graph.find("$.p1")
    p2 = graph.find("$.p2")
    # dereference nodes live under their pointer
    assert len(p1.dereferences) == 1
    assert p1.dereferences[0].target_address == 8
    assert len(p2.dereferences) == 1
    assert p2.dereferences[0].target_address == 8
    deref_a = graph.find("$.p1.dereference.a")
    assert deref_a.evidence() == [ByteSpan(8, 12)]
    # both aliases read the same bytes on purpose: shared evidence, not an accidental overwrite
    aliased = [event for event in graph.events if event.span == ByteSpan(8, 12)]
    assert len(aliased) == 2
    # every repeated read of the aliased bytes is intentional shared evidence, never an accidental overwrite
    assert all(event.overlap is not OverlapKind.OVERWRITE for event in aliased)
    assert any(event.overlap is OverlapKind.SHARED_EVIDENCE for event in aliased)


def test_union_members_are_shared_evidence() -> None:
    cs = cstruct()
    cs.load("union U { uint32 whole; uint16 parts[2]; }; struct Holder { U u; uint8 tail; };", compiled=False)
    data = (0x11223344).to_bytes(4, "little") + b"Z"
    with trace_read("Holder") as traced:
        cs.Holder(io.BytesIO(data))
    graph = traced.graph
    whole = graph.find("$.u.U.whole")
    first_elem = next(node for node in graph.root.walk() if node.kind is NodeKind.ELEMENT)
    assert whole.evidence() == [ByteSpan(0, 4)]
    assert first_elem.evidence()[0].start == 0
    union_events = [event for event in graph.events if event.span.overlaps(ByteSpan(0, 4))]
    assert all(event.overlap is not OverlapKind.OVERWRITE for event in union_events)
    assert any(event.overlap is OverlapKind.SHARED_EVIDENCE for event in union_events)
    assert _spans(graph, "$.tail") == [(4, 5, None, None)]


def test_partial_failure_marks_event_and_excludes_from_proven() -> None:
    cs = cstruct()
    cs.load("struct H { uint32 a; uint32 b; };", compiled=False)
    data = bytes([1, 2, 3])  # truncated, only 3 of 8 bytes
    with trace_read("H") as traced, pytest.raises(EOFError):
        cs.H(io.BytesIO(data))
    graph = traced.graph
    partial_events = [event for event in graph.events if event.partial]
    assert len(partial_events) == 1
    assert partial_events[0].span == ByteSpan(0, 3)
    node = graph.find("$.a")
    assert node.partial is True
    # the partial field cannot be reconstructed as proven evidence
    assert "$.a" not in graph.reconstruct(io.BytesIO(data))
    assert node.path not in [proven.path for proven in graph.proven_fields()]


class _Mystery(int, BaseType):
    __traceable__ = False

    @classmethod
    def __default__(cls) -> int:
        return cls(0)

    @classmethod
    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: str, **kwargs: Any) -> int:
        raw = stream.read(4)
        return cls(int.from_bytes(raw, "little") ^ 0xFF)


def test_non_traceable_custom_type_is_explicitly_unresolved() -> None:
    cs = cstruct()
    cs.add_custom_type("Mystery", _Mystery, size=4)
    cs.load("struct Box { uint16 head; Mystery m; };", compiled=False)
    data = bytes([1, 0]) + bytes([0x10, 0x20, 0x30, 0x40])
    with trace_read("Box") as traced:
        cs.Box(io.BytesIO(data))
    graph = traced.graph
    mystery = graph.find("$.m")
    assert mystery.unresolved is not None
    assert "__traceable__" in mystery.unresolved
    # no fabricated range enters the proven reconstruction
    assert mystery.path not in graph.reconstruct(io.BytesIO(data))
    assert [node.path for node in graph.unresolved_nodes()] == ["$.m"]
    # the ordinary field next to it is still proven
    assert graph.reconstruct(io.BytesIO(data)) == {"$.head": bytes([1, 0])}


def test_tracking_is_opt_in_and_default_path_is_unwrapped() -> None:
    cs = cstruct()
    cs.load("struct S { uint32 a; };")
    stream = io.BytesIO((7).to_bytes(4, "little"))
    obj = cs.S(stream)
    assert obj.a == 7
    # without an active tracer the raw stream is not wrapped
    assert current_tracer(stream) is None
    assert not hasattr(stream, "_tracer")


def test_reconstruct_rebuilds_only_proven_leaves() -> None:
    cs = cstruct()
    cs.load("struct P { uint8 a; uint16 b; uint8 c; };", compiled=False)
    data = bytes([1]) + (0x0203).to_bytes(2, "little") + bytes([4])
    with trace_read("P") as traced:
        cs.P(io.BytesIO(data))
    rebuilt = traced.graph.reconstruct(io.BytesIO(data))
    assert rebuilt == {"$.a": bytes([1]), "$.b": bytes([3, 2]), "$.c": bytes([4])}


def test_eof_array_records_every_element() -> None:
    cs = cstruct()
    cs.load("struct E { uint8 data[EOF]; };", compiled=False)
    data = bytes([1, 2, 3, 4])
    with trace_read("E") as traced:
        obj = cs.E(io.BytesIO(data))
    assert list(obj.data) == [1, 2, 3, 4]
    elements = [node for node in traced.graph.root.walk() if node.kind is NodeKind.ELEMENT]
    assert [(node.evidence()[0].start, node.evidence()[0].end) for node in elements] == [(0, 1), (1, 2), (2, 3), (3, 4)]


def test_complex_graph_equivalent_across_backends() -> None:
    cdef = (
        "struct Inner { uint16 v; };",
        "struct Complex { uint8 a : 3; uint8 b : 5; uint32 count; Inner items[2]; uint8 tail[2]; };",
    )
    data = (
        bytes([0b11010010])
        + (2).to_bytes(4, "little")
        + (0x1111).to_bytes(2, "little")
        + (0x2222).to_bytes(2, "little")
        + b"XY"
    )
    graphs = {}
    for compiled_flag in (True, False):
        cs = cstruct()
        cs.load(" ".join(cdef), compiled=compiled_flag)
        cs.Complex(io.BytesIO(data))  # trigger lazy compilation first
        with trace_read("Complex") as traced:
            cs.Complex(io.BytesIO(data))
        graphs[compiled_flag] = traced.graph.to_dict()
    assert graphs[True] == graphs[False]


def test_pointer_arithmetic_keeps_tracking_without_recursion() -> None:
    cs = cstruct()
    cs.load("struct R { uint32* p; };", compiled=False)
    data = (8).to_bytes(8, "little") + (0x1111).to_bytes(4, "little") + (0x2222).to_bytes(4, "little")
    with trace_read("R") as traced:
        obj = cs.R(io.BytesIO(data))
    # arithmetic produces a new pointer that still dereferences through the tracked stream
    shifted = obj.p + 1
    shifted.dereference()  # must not recurse through Pointer.__getattr__
    pointer_node = traced.graph.find("$.p")
    assert pointer_node is not None
    assert any(deref.target_address == 9 for deref in pointer_node.dereferences)
