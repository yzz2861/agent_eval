from io import BytesIO

import pytest

from pypdf import (
    PdfReader,
    PdfWriter,
    PreviewDeliveryError,
    PreviewIssueCode,
    build_page_preview,
    check_page_delivery,
)
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NullObject,
    TextStringObject,
)


def _font(writer, base_font):
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject(base_font),
        }
    )
    return writer._add_object(font)


def _content(writer, text):
    stream = DecodedStreamObject()
    stream.set_data(("BT (" + text + ") Tj ET").encode())
    return writer._add_object(stream)


def _build_two_page_document():
    writer = PdfWriter()
    page_one = writer.add_blank_page(width=200, height=200)
    page_two = writer.add_blank_page(width=200, height=200)

    shared_font = _font(writer, "/Helvetica")
    page_one_font = _font(writer, "/Courier")
    page_two_font = _font(writer, "/Times-Roman")

    inherited_resources = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/Shared"): shared_font})}
    )
    writer._root_object["/Pages"][NameObject("/Resources")] = writer._add_object(
        inherited_resources
    )

    page_one[NameObject("/Resources")] = writer._add_object(
        DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): page_one_font})})
    )
    page_two[NameObject("/Resources")] = writer._add_object(
        DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F2"): page_two_font})})
    )

    page_one[NameObject("/Contents")] = _content(writer, "page one")
    page_two[NameObject("/Contents")] = _content(writer, "page two")

    external_spec = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Filespec"),
            NameObject("/F"): TextStringObject("outside/confidential.txt"),
        }
    )
    external_ref = writer._add_object(external_spec)
    page_two[NameObject("/AF")] = ArrayObject([external_ref])

    buffer = BytesIO()
    writer.write(buffer)
    return PdfReader(BytesIO(buffer.getvalue()))


def _font_names(reader, report):
    names = set()
    for idnum, _generation in report.deliverable_objects:
        obj = reader.get_object(idnum)
        if isinstance(obj, DictionaryObject) and obj.get("/Type") == "/Font":
            names.add(str(obj["/BaseFont"]))
    return names


def test_check_only_keeps_dependencies_of_approved_page():
    reader = _build_two_page_document()
    report = check_page_delivery(reader, page_number=0)

    assert report.is_deliverable
    font_names = _font_names(reader, report)
    assert font_names == {"/Helvetica", "/Courier"}
    assert "/Times-Roman" not in font_names

    page_two_id = reader.pages[1].indirect_reference.idnum
    assert all(idnum != page_two_id for idnum, _ in report.deliverable_objects)


def test_shared_resource_is_cloned_once_into_preview():
    reader = _build_two_page_document()
    writer, report = build_page_preview(reader, page_number=0)

    assert len(writer.pages) == 1
    delivered_ids = [
        obj.indirect_reference.idnum
        for obj in writer._objects
        if obj is not None and obj.indirect_reference is not None
    ]
    assert len(delivered_ids) == len(set(delivered_ids))

    fonts = writer.pages[0]["/Resources"]["/Font"]
    assert set(fonts.keys()) == {"/Shared", "/F1"}
    assert report.is_deliverable


def test_preview_contains_no_unapproved_page_objects():
    reader = _build_two_page_document()
    writer, _ = build_page_preview(reader, page_number=0)

    buffer = BytesIO()
    writer.write(buffer)
    exported = PdfReader(BytesIO(buffer.getvalue()))
    assert len(exported.pages) == 1

    exported_fonts = _font_names(exported, check_page_delivery(exported, 0))
    assert exported_fonts == {"/Helvetica", "/Courier"}


def test_external_material_blocks_delivery_and_is_never_read():
    reader = _build_two_page_document()
    report = check_page_delivery(reader, page_number=1)

    assert report.requires_manual_review
    assert any(
        issue.code is PreviewIssueCode.EXTERNAL_FILE_SPECIFICATION
        and "confidential.txt" in issue.detail
        for issue in report.issues
    )

    with pytest.raises(PreviewDeliveryError) as exc_info:
        build_page_preview(reader, page_number=1)
    error_report = exc_info.value.report
    assert error_report.requires_manual_review
    assert [issue.code for issue in error_report.issues] == [
        issue.code for issue in report.issues
    ]


def _reader_with_external_stream():
    writer = PdfWriter()
    page = writer.add_blank_page(width=120, height=120)
    stream = DecodedStreamObject()
    stream.set_data(b"placeholder")
    stream[NameObject("/F")] = TextStringObject("outside/data.bin")
    image_ref = writer._add_object(stream)
    resources = writer._add_object(
        DictionaryObject(
            {NameObject("/XObject"): DictionaryObject({NameObject("/Im"): image_ref})}
        )
    )
    page[NameObject("/Resources")] = resources
    buffer = BytesIO()
    writer.write(buffer)
    return PdfReader(BytesIO(buffer.getvalue()))


def test_external_stream_is_flagged_and_blocks_delivery():
    reader = _reader_with_external_stream()
    report = check_page_delivery(reader, 0)

    assert report.requires_manual_review
    codes = {issue.code for issue in report.issues}
    assert PreviewIssueCode.EXTERNAL_STREAM in codes
    assert PreviewIssueCode.EXTERNAL_FILE_SPECIFICATION in codes
    assert any("data.bin" in issue.detail for issue in report.issues)

    with pytest.raises(PreviewDeliveryError):
        build_page_preview(reader, 0)


def _reader_with_remote_action():
    writer = PdfWriter()
    page = writer.add_blank_page(width=120, height=120)
    action = DictionaryObject(
        {
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://example.invalid/secret"),
        }
    )
    annotation = DictionaryObject(
        {
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/A"): writer._add_object(action),
        }
    )
    page[NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
    buffer = BytesIO()
    writer.write(buffer)
    return PdfReader(BytesIO(buffer.getvalue()))


def test_remote_action_is_flagged_and_never_followed():
    reader = _reader_with_remote_action()
    report = check_page_delivery(reader, 0)

    assert report.requires_manual_review
    assert any(
        issue.code is PreviewIssueCode.REMOTE_ACTION and "/URI" in issue.detail
        for issue in report.issues
    )
    with pytest.raises(PreviewDeliveryError):
        build_page_preview(reader, 0)


def _reader_with_dangling_reference():
    # Object 99 0 R is referenced by the page resources but never defined
    # in the xref table, so it cannot be resolved from inside the document.
    pdf = bytes([10]).join([
        b"%PDF-1.4",
        b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj",
        b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj",
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
        b"/Resources << /Font << /Ghost 99 0 R >> >> >>endobj",
        b"xref", b"0 4",
        b"0000000000 65535 f ",
        b"0000000009 00000 n ",
        b"0000000058 00000 n ",
        b"0000000111 00000 n ",
        b"trailer<< /Size 4 /Root 1 0 R >>",
        b"startxref", b"220", b"%%EOF",
    ])
    return PdfReader(BytesIO(pdf))


def test_unresolvable_reference_is_manual_review():
    reader = _reader_with_dangling_reference()
    report = check_page_delivery(reader, 0)
    assert any(
        issue.code is PreviewIssueCode.UNRESOLVABLE_REFERENCE
        and issue.object_ref is None
        for issue in report.issues
    )
    with pytest.raises(PreviewDeliveryError):
        build_page_preview(reader, 0)


def test_writer_preview_page_classmethod_matches_helper():
    reader = _build_two_page_document()
    writer, report = PdfWriter.preview_page(reader, 0)
    helper_writer, helper_report = build_page_preview(reader, 0)

    assert len(writer.pages) == 1
    assert report.deliverable_objects == helper_report.deliverable_objects
    assert helper_writer.pages[0]["/Resources"]["/Font"].keys() == writer.pages[0][
        "/Resources"
    ]["/Font"].keys()


def test_check_never_reads_external_files(monkeypatch):
    reader = _reader_with_external_stream()

    def fail_open(*args, **kwargs):
        raise AssertionError("external material must not be opened")

    monkeypatch.setattr("builtins.open", fail_open)
    report = check_page_delivery(reader, 0)
    assert report.requires_manual_review
