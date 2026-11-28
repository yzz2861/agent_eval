"""Retention checks for a synthetic redaction export.

The source PDFs are generated in memory. Their page content is left
uncompressed so the tests can inspect the serialized bytes instead of relying
only on the reader's view of the latest revision.
"""

from dataclasses import dataclass
from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
)

SOURCE_PAGE_TEXT = "SYNTHETIC OLD PAGE MATERIAL 7C1F"
SOURCE_TITLE = "SYNTHETIC OLD TITLE 9A3D"
SOURCE_SUBJECT = "SYNTHETIC OLD SUBJECT 2E8B"
SOURCE_MARKERS = (SOURCE_PAGE_TEXT, SOURCE_TITLE, SOURCE_SUBJECT)

PLACEHOLDER_TEXT = "[SYNTHETIC REDACTED PLACEHOLDER 4B2A]"
EXPORT_TITLE = "SYNTHETIC REDACTED EXPORT 6D70"
EXPORT_SUBJECT = "SYNTHETIC REDACTION DECLARATION 5F21"


@dataclass(frozen=True)
class ExportInspection:
    pdf_bytes: bytes
    text: str
    title: str | None
    subject: str | None

    @property
    def retained_source_markers(self) -> tuple[str, ...]:
        return tuple(marker for marker in SOURCE_MARKERS if marker.encode("ascii") in self.pdf_bytes)


def _content_stream(text: str) -> DecodedStreamObject:
    stream = DecodedStreamObject()
    stream.set_data(f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii"))
    return stream


def _synthetic_source_pdf() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {
                    NameObject("/F1"): writer._add_object(font),
                }
            ),
        }
    )
    page[NameObject("/Contents")] = writer._add_object(_content_stream(SOURCE_PAGE_TEXT))
    writer.add_metadata(
        {
            "/Title": SOURCE_TITLE,
            "/Subject": SOURCE_SUBJECT,
            "/Producer": "synthetic source revision",
        }
    )

    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def _redacted_export(incremental: bool) -> bytes:
    source = BytesIO(_synthetic_source_pdf())
    writer = PdfWriter(source, incremental=True) if incremental else PdfWriter(clone_from=PdfReader(source))

    writer.remove_text()
    writer.pages[0].replace_contents(_content_stream(PLACEHOLDER_TEXT))
    writer.add_metadata(
        {
            "/Title": EXPORT_TITLE,
            "/Subject": EXPORT_SUBJECT,
            "/Producer": "pypdf synthetic redaction fixture",
        }
    )

    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def _inspect(pdf_bytes: bytes) -> ExportInspection:
    reader = PdfReader(BytesIO(pdf_bytes))
    metadata = reader.metadata
    return ExportInspection(
        pdf_bytes=pdf_bytes,
        text=reader.pages[0].extract_text(),
        title=metadata.title if metadata is not None else None,
        subject=metadata.subject if metadata is not None else None,
    )


@pytest.mark.parametrize(
    "incremental",
    [
        pytest.param(False, id="rewrite"),
        pytest.param(True, id="incremental"),
    ],
)
def test_redaction_export__latest_revision_shows_placeholder_and_declaration(
    incremental,
):
    inspection = _inspect(_redacted_export(incremental))

    assert PLACEHOLDER_TEXT in inspection.text
    assert SOURCE_PAGE_TEXT not in inspection.text
    assert inspection.title == EXPORT_TITLE
    assert inspection.subject == EXPORT_SUBJECT


def test_redaction_export__full_rewrite_drops_source_revision():
    inspection = _inspect(_redacted_export(incremental=False))

    assert inspection.retained_source_markers == ()
    assert b"/Prev" not in inspection.pdf_bytes


def test_redaction_export__incremental_retains_source_revision():
    inspection = _inspect(_redacted_export(incremental=True))

    assert inspection.retained_source_markers == SOURCE_MARKERS
    assert b"/Prev" in inspection.pdf_bytes


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Incremental save appends to the original file, so the pre-redaction "
        "page text and metadata remain in the serialized output. Redacted "
        "exports must use a full rewrite."
    ),
)
def test_redaction_export__incremental_meets_retention_contract():
    inspection = _inspect(_redacted_export(incremental=True))

    assert inspection.retained_source_markers == ()
