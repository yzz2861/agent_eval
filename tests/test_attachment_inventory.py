"""Tests for the read-only attachment inventory API."""
from io import BytesIO

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    AttachmentFlag,
    AttachmentSource,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)


def _build_reader() -> PdfReader:
    """Build a small document exercising all inventory features."""
    writer = PdfWriter()
    page = writer.add_blank_page(72, 72)

    # One embedded file, referenced from several locations.
    writer.add_attachment("summary.txt", b"shared-content")
    names = (
        writer.root_object["/Names"]
        .get_object()["/EmbeddedFiles"]
        .get_object()["/Names"]
    )
    filespec_reference = names[names.index("summary.txt") + 1]

    # A second name for the very same file specification.
    names.append(TextStringObject("说明.txt"))
    names.append(filespec_reference)

    # The same file specification referenced at page level ...
    page[NameObject("/AF")] = ArrayObject([filespec_reference])

    # ... and from a FileAttachment annotation.
    annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/FileAttachment"),
            NameObject("/FS"): filespec_reference,
        }
    )
    page[NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])

    # The same name twice, but with different content.
    writer.add_attachment("dup.txt", b"first-content")
    writer.add_attachment("dup.txt", b"second-content")

    # An external file specification (no /EF entry).
    external = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Filespec"),
            NameObject("/F"): TextStringObject("external.txt"),
        }
    )
    names.append(TextStringObject("external.txt"))
    names.append(writer._add_object(external))

    # A broken reference: the name tree value is not a dictionary.
    names.append(TextStringObject("broken.txt"))
    names.append(NumberObject(42))

    # A broken reference: /EF without any embedded file stream.
    broken_ef = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Filespec"),
            NameObject("/F"): TextStringObject("bad-ef.txt"),
            NameObject("/EF"): DictionaryObject(),
        }
    )
    names.append(TextStringObject("bad-ef.txt"))
    names.append(writer._add_object(broken_ef))

    buffer = BytesIO()
    writer.write(buffer)
    buffer.seek(0)
    return PdfReader(buffer)


def test_two_names_resolve_to_the_same_stream():
    reader = _build_reader()
    inventory = reader.attachment_inventory

    by_summary = inventory.find_by_name("summary.txt")
    by_chinese = inventory.find_by_name("说明.txt")
    assert len(by_summary) == 1
    assert len(by_chinese) == 1

    # Both names lead to the same record and thus the same stream.
    record = by_summary[0]
    assert by_chinese[0] is record
    assert record.stream is not None
    assert record.names == ("summary.txt", "说明.txt")
    assert record.flags == frozenset()

    # All reference locations are preserved for the shared stream.
    sources = [reference.source for reference in record.references]
    assert sources.count(AttachmentSource.DOCUMENT_NAME_TREE) == 2
    assert AttachmentSource.PAGE_ASSOCIATED_FILE in sources
    assert AttachmentSource.ANNOTATION in sources
    page_level = [
        reference
        for reference in record.references
        if reference.source
        in (AttachmentSource.PAGE_ASSOCIATED_FILE, AttachmentSource.ANNOTATION)
    ]
    assert all(reference.page_index == 0 for reference in page_level)

    # The stream can be followed back to the record.
    assert inventory.find_by_stream(record.stream) is record


def test_same_name_with_different_content_is_flagged():
    reader = _build_reader()
    inventory = reader.attachment_inventory

    records = inventory.find_by_name("dup.txt")
    assert len(records) == 2
    assert records[0].stream is not None
    assert records[1].stream is not None
    # Same name, but genuinely different streams.
    assert records[0].stream != records[1].stream
    assert all(record.has_name_conflict for record in records)
    assert all(
        AttachmentFlag.NAME_CONFLICT in record.flags for record in records
    )


def test_external_filespec_is_flagged():
    reader = _build_reader()
    inventory = reader.attachment_inventory

    records = inventory.find_by_name("external.txt")
    assert len(records) == 1
    record = records[0]
    assert record.stream is None
    assert record.is_external
    assert not record.is_broken


def test_broken_references_are_flagged():
    reader = _build_reader()
    inventory = reader.attachment_inventory

    broken = inventory.find_by_name("broken.txt")
    assert len(broken) == 1
    assert broken[0].is_broken
    assert broken[0].stream is None

    bad_ef = inventory.find_by_name("bad-ef.txt")
    assert len(bad_ef) == 1
    assert bad_ef[0].is_broken
    assert bad_ef[0].stream is None


def test_inventory_is_read_only_information():
    reader = _build_reader()
    inventory = reader.attachment_inventory

    # The inventory exposes identities and locations, never content.
    record = inventory.find_by_name("summary.txt")[0]
    assert not hasattr(record, "content")
    assert str(record.stream).endswith(" R")

    # Filespec identities of the references are accessible.
    assert len(record.filespecs) == 1


def test_empty_document_has_empty_inventory():
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    buffer = BytesIO()
    writer.write(buffer)
    buffer.seek(0)
    reader = PdfReader(buffer)

    inventory = reader.attachment_inventory
    assert len(inventory) == 0
    assert list(inventory) == []
    assert inventory.find_by_name("anything") == []
