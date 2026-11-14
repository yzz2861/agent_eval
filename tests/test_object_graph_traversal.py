"""
Tests for the unified object graph traversal guard shared by the page tree,
outline, AcroForm, resource dictionary and object stream traversals.

All fixtures are built in memory so that the tests run fully offline.
"""

import io

import pytest

from pypdf import PdfReader, PdfWriter, apply_configuration
from pypdf.errors import CyclicObjectGraphError, LimitReachedError, PdfReadError
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    RectangleObject,
    TextStringObject,
)


def _write(writer: PdfWriter) -> bytes:
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _cyclic_page_tree_pdf(*, self_loop: bool) -> bytes:
    """Build a PDF whose page tree contains a self loop or a two-node cycle."""
    writer = PdfWriter()
    root_pages = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Pages"),
            NameObject("/Count"): NumberObject(1),
        })
    )
    real_page = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Page"),
            NameObject("/MediaBox"): RectangleObject([0, 0, 100, 100]),
        })
    )
    node_a = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Pages"),
            NameObject("/Count"): NumberObject(1),
        })
    )
    node_b = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Pages"),
            NameObject("/Count"): NumberObject(1),
        })
    )
    if self_loop:
        node_a.get_object()[NameObject("/Kids")] = ArrayObject([node_a])
    else:
        node_a.get_object()[NameObject("/Kids")] = ArrayObject([node_b])
        node_b.get_object()[NameObject("/Kids")] = ArrayObject([node_a])
    root_pages.get_object()[NameObject("/Kids")] = ArrayObject([real_page, node_a])
    writer._root_object[NameObject("/Pages")] = root_pages
    return _write(writer)


def test_page_tree_self_loop_raises_explainable_error():
    reader = PdfReader(io.BytesIO(_cyclic_page_tree_pdf(self_loop=True)))
    # No half-initialized page list before the traversal runs.
    assert reader.flattened_pages is None
    with pytest.raises(PdfReadError, match=r"^Detected cyclic page references\.$"):
        len(reader.pages)
    # A failed traversal must not leave a partial page list behind.
    assert reader.flattened_pages is None


def test_page_tree_two_node_cycle_raises():
    reader = PdfReader(io.BytesIO(_cyclic_page_tree_pdf(self_loop=False)))
    with pytest.raises(PdfReadError, match=r"^Detected cyclic page references\.$"):
        len(reader.pages)
    assert reader.flattened_pages is None


def test_shared_font_resource_is_not_mistaken_for_a_cycle():
    """The same font object referenced by several pages is legal sharing."""
    writer = PdfWriter()
    page1 = writer.add_blank_page(width=100, height=100)
    page2 = writer.add_blank_page(width=100, height=100)
    font = writer._add_object(
        DictionaryObject({
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        })
    )
    for page in (page1, page2):
        resources = writer._add_object(
            DictionaryObject({
                NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})
            })
        )
        page[NameObject("/Resources")] = resources

    reader = PdfReader(io.BytesIO(_write(writer)))
    assert len(reader.pages) == 2
    first = reader.pages[0]["/Resources"]["/Font"]["/F1"]
    second = reader.pages[1]["/Resources"]["/Font"]["/F1"]
    # Both references resolve to the same object generation.
    assert first.indirect_reference == second.indirect_reference


def _cyclic_acroform_pdf() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    field_a = writer._add_object(
        DictionaryObject({
            NameObject("/T"): TextStringObject("a"),
            NameObject("/FT"): NameObject("/Tx"),
        })
    )
    field_b = writer._add_object(
        DictionaryObject({
            NameObject("/T"): TextStringObject("b"),
            NameObject("/FT"): NameObject("/Tx"),
        })
    )
    field_a.get_object()[NameObject("/Kids")] = ArrayObject([field_b])
    field_b.get_object()[NameObject("/Kids")] = ArrayObject([field_a])
    acroform = writer._add_object(
        DictionaryObject({NameObject("/Fields"): ArrayObject([field_a])})
    )
    writer._root_object[NameObject("/AcroForm")] = acroform
    return _write(writer)


def test_acroform_cycle_raises_with_object_number_not_contents():
    reader = PdfReader(io.BytesIO(_cyclic_acroform_pdf()))
    with pytest.raises(CyclicObjectGraphError) as exc_info:
        reader.get_fields()
    message = str(exc_info.value)
    # Explainable: area, object number/generation and depth are present ...
    assert "AcroForm" in message
    assert "object 5 0" in message
    # ... but the field dictionary contents must not be dumped into the error.
    assert "/FT" not in message
    assert "/Kids" not in message


def _outline_pdf(*, depth: int, cycle: bool = False) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    outlines = writer._add_object(DictionaryObject())
    writer._root_object[NameObject("/Outlines")] = outlines
    items = []
    for index in range(depth):
        item = writer._add_object(
            DictionaryObject({
                NameObject("/Title"): TextStringObject(f"title{index}"),
                NameObject("/Parent"): outlines,
            })
        )
        items.append(item)
    for index, item in enumerate(items):
        obj = item.get_object()
        if index == 0:
            outlines.get_object()[NameObject("/First")] = item
        if index == len(items) - 1:
            outlines.get_object()[NameObject("/Last")] = item
        else:
            obj[NameObject("/Next")] = items[index + 1]
            items[index + 1].get_object()[NameObject("/Prev")] = item
        if index < len(items) - 1:
            obj[NameObject("/First")] = items[index + 1]
            obj[NameObject("/Last")] = items[index + 1]
    if cycle and items:
        items[-1].get_object()[NameObject("/First")] = items[0]
        items[-1].get_object()[NameObject("/Last")] = items[0]
    return _write(writer)


def test_deep_outline_raises_limit_error():
    reader = PdfReader(io.BytesIO(_outline_pdf(depth=150)))
    with pytest.raises(LimitReachedError, match=r"Maximum outline depth reached: 101 > 100\."):
        reader.outline


def test_outline_cycle_raises_with_object_number_not_contents():
    reader = PdfReader(io.BytesIO(_outline_pdf(depth=5, cycle=True)))
    with pytest.raises(CyclicObjectGraphError) as exc_info:
        reader.outline
    message = str(exc_info.value)
    assert "outline" in message
    assert "object 6 0" in message
    # The outline item dictionary must not be rendered into the message.
    assert "/Title" not in message


def _nested_page_tree_pdf(depth: int) -> bytes:
    writer = PdfWriter()
    node = writer.add_blank_page(width=10, height=10)
    for _ in range(depth):
        node = writer._add_object(
            DictionaryObject({
                NameObject("/Type"): NameObject("/Pages"),
                NameObject("/Kids"): ArrayObject([node]),
                NameObject("/Count"): NumberObject(1),
            })
        )
    writer._root_object[NameObject("/Pages")] = node
    return _write(writer)


def test_reader_instance_depth_budget_is_configurable():
    data = _nested_page_tree_pdf(5)

    # Default reader accepts the document.
    assert len(PdfReader(io.BytesIO(data)).pages) == 1

    # A reader with a tighter shared budget rejects it via the shared backstop.
    tight_reader = PdfReader(io.BytesIO(data), object_graph_maximum_depth=2)
    with pytest.raises(LimitReachedError, match=r"Maximum page tree traversal depth reached"):
        len(tight_reader.pages)
    assert tight_reader.object_graph_maximum_depth == 2


def test_incremental_update_still_reads():
    """A genuine incremental update (two revisions) must keep parsing."""
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    base = _write(writer)

    incremental_writer = PdfWriter(io.BytesIO(base), incremental=True)
    incremental_writer.add_metadata({"/Title": "updated"})
    out = io.BytesIO()
    incremental_writer.write(out)
    updated = out.getvalue()

    assert updated.count(b"%%EOF") == 2
    reader = PdfReader(io.BytesIO(updated))
    assert len(reader.pages) == 1
    assert reader.metadata.title == "updated"


def test_deep_but_acyclic_page_tree_reads_with_larger_budget():
    depth = 120
    data = _nested_page_tree_pdf(depth)
    reader = PdfReader(io.BytesIO(data), object_graph_maximum_depth=depth + 5)
    with apply_configuration(page_tree_maximum_depth=depth + 5):
        assert len(reader.pages) == 1


def _write_objstm_cycle_pdf() -> bytes:
    """
    Two object streams whose hosted objects force a cyclic resolution.

    The page tree nodes themselves are hosted by object streams that reference
    each other: the page is hosted by stream 5 and its /Parent points at an
    object hosted by stream 4, while another object in stream 4 points back at
    an object in stream 5. Flattening the page tree resolves the nested streams
    and hits the cycle.
    """
    buf = io.BytesIO()

    def write_obj(objnum: int, data: bytes) -> int:
        offset = buf.tell()
        buf.write(f"{objnum} 0 obj\n".encode())
        buf.write(data)
        buf.write(b"\nendobj\n")
        return offset

    def write_objstm(objnum: int, contents: list[tuple[int, bytes]]) -> int:
        header_parts, data_parts, current = [], [], 0
        for oid, content in contents:
            header_parts.append(f"{oid} {current}")
            data_parts.append(content)
            current += len(content) + 1
        header = " ".join(header_parts) + " "
        stream = header.encode() + b" ".join(data_parts)
        offset = buf.tell()
        buf.write(f"{objnum} 0 obj\n".encode())
        buf.write(
            f"<< /Type /ObjStm /N {len(contents)} /First {len(header)} "
            f"/Length {len(stream)} >>\n".encode()
        )
        buf.write(b"stream\n")
        buf.write(stream)
        buf.write(b"\nendstream\nendobj\n")
        return offset

    buf.write(b"%PDF-1.5\n")
    offsets = {}
    offsets[1] = write_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    # /Pages (2) and object 6 are hosted in object stream 4.
    offsets[4] = write_objstm(
        4,
        [
            (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (6, b"<< /V 7 0 R >>"),
        ],
    )
    # The page (3) and object 7 are hosted in object stream 5. Object 7 points
    # back at object 6, closing the loop across the two object streams.
    offsets[5] = write_objstm(
        5,
        [
            (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>"),
            (7, b"<< /V 6 0 R >>"),
        ],
    )

    xref_offset = buf.tell()
    raw_entries = [
        (0, 0, 65535),
        (1, offsets[1], 0),
        (1, offsets[4], 0),
        (1, offsets[5], 0),
        (2, 4, 0),  # obj 2 is inside object stream 4, index 0
        (2, 5, 0),  # obj 3 is inside object stream 5, index 0
        (2, 4, 1),  # obj 6 is inside object stream 4, index 1
        (2, 5, 1),  # obj 7 is inside object stream 5, index 1
        (1, xref_offset, 0),
    ]
    stream_data = bytearray()
    for type_id, first, second in raw_entries:
        stream_data.append(type_id)
        stream_data.extend(first.to_bytes(4, "big"))
        stream_data.extend(second.to_bytes(2, "big"))
    buf.write(
        f"8 0 obj\n<< /Type /XRef /Size 9 /W [1 4 2] /Index [0 9] "
        f"/Root 1 0 R /Length {len(stream_data)} >>".encode()
    )
    buf.write(b"\nstream\n")
    buf.write(bytes(stream_data))
    buf.write(b"\nendstream\nendobj\n")
    buf.write(f"startxref\n{xref_offset}\n%%EOF\n".encode())
    return buf.getvalue()


def test_object_stream_cycle_reports_numbers_not_stream_contents():
    reader = PdfReader(io.BytesIO(_write_objstm_cycle_pdf()))
    # Resolving object 6 parses object stream 4, which resolves object 7 in
    # stream 5, which resolves object 6 again -> a cyclic object-stream reference.
    with pytest.raises(
        PdfReadError, match=r"Circular object-stream reference detected"
    ) as exc_info:
        reader.get_object(6)["/V"].get_object()
    message = str(exc_info.value)
    # Only object numbers are exposed, never the stream payload.
    assert "/V" not in message
    assert "object-stream" in message
    # The repeating object stream number identifies the cycle.
    assert "4 -> 4" in message


def test_object_stream_resolution_uses_reader_depth_budget():
    tight_reader = PdfReader(
        io.BytesIO(_write_objstm_cycle_pdf()),
        object_graph_maximum_depth=0,
    )
    with pytest.raises(LimitReachedError, match=r"Maximum object stream resolution depth reached"):
        tight_reader.get_object(6)
