"""Tests for the offline annotation disclosure reconciliation."""

import io
import json

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf._disclosure import (
    DisclosureScope,
    SkipReason,
    collect_annotation_statements,
    reconcile_statements,
)
from pypdf.annotations import FreeText, Text
from pypdf.generic import ArrayObject, NameObject


def _write_to_reader(writer: PdfWriter) -> PdfReader:
    stream = io.BytesIO()
    writer.write(stream)
    stream.seek(0)
    return PdfReader(stream)


def _build_excerpt_reader() -> PdfReader:
    """Hand-generate blank pages with plain annotations and page labels."""
    writer = PdfWriter()
    for _ in range(3):
        writer.add_blank_page(width=200, height=200)
    writer.set_page_label(0, 0, style="/r")
    writer.set_page_label(1, 2, style="/D", prefix="A-", start=1)
    writer.add_annotation(
        page_number=0,
        annotation=Text(text="internal note one", rect=(10, 10, 50, 50)),
    )
    writer.add_annotation(
        page_number=1,
        annotation=FreeText(text="confidential body", rect=(20, 20, 60, 60)),
    )
    return _write_to_reader(writer)


def test_statements_from_both_excerpts_refer_back_to_source():
    reader = _build_excerpt_reader()

    internal = collect_annotation_statements(reader, DisclosureScope.INTERNAL)
    external = collect_annotation_statements(reader, DisclosureScope.EXTERNAL)
    result = reconcile_statements(internal, external)

    assert result.is_consistent
    assert len(result.bindings) == 2
    assert not internal.skipped
    assert not external.skipped

    # The actual annotation object listed on the first page.
    annot_ref = reader.pages[0]["/Annots"][0]
    binding = next(b for b in result.bindings if b.internal.category == "/Text")

    # Both statements trace back to the same source object.
    assert binding.source.idnum == annot_ref.idnum
    assert binding.source.generation == annot_ref.generation
    assert binding.internal.source == binding.source
    assert binding.external.source == binding.source

    # The internal excerpt may review the position, the external may not.
    assert binding.internal.rect == (10.0, 10.0, 50.0, 50.0)
    assert binding.external.rect is None

    # Page labels and relative page numbers are bound to the statements.
    assert binding.internal.page_label == "i"
    assert binding.external.page_label == "i"
    assert binding.internal.relative_page == 1
    assert binding.external.relative_page == 1

    other = next(b for b in result.bindings if b.internal.category == "/FreeText")
    assert other.internal.page_label == "A-1"
    assert other.external.relative_page == 2


def test_public_artifact_contains_no_annotation_text():
    reader = _build_excerpt_reader()

    external = collect_annotation_statements(reader, DisclosureScope.EXTERNAL)
    artifact = external.public_artifact()
    payload = json.dumps(artifact)

    assert "internal note one" not in payload
    assert "confidential body" not in payload
    assert [entry["category"] for entry in artifact] == ["/Text", "/FreeText"]
    assert [entry["relative_page"] for entry in artifact] == [1, 2]
    assert [entry["page_label"] for entry in artifact] == ["i", "A-1"]
    assert all("rect" not in entry for entry in artifact)
    assert all(set(entry["source"]) == {"idnum", "generation"} for entry in artifact)

    # The internal artifact is allowed to carry positions.
    internal = collect_annotation_statements(reader, DisclosureScope.INTERNAL)
    internal_artifact = internal.public_artifact()
    assert internal_artifact[0]["rect"] == [10.0, 10.0, 50.0, 50.0]


def test_shared_annotation_object_instances_are_skipped():
    writer = PdfWriter()
    for _ in range(2):
        writer.add_blank_page(width=200, height=200)
    inserted = writer.add_annotation(
        page_number=0,
        annotation=Text(text="shared secret", rect=(0, 0, 10, 10)),
    )
    # Attach the same annotation object to the second page as well.
    writer.pages[1][NameObject("/Annots")] = ArrayObject(
        [inserted.indirect_reference]
    )
    reader = _write_to_reader(writer)

    report = collect_annotation_statements(reader, DisclosureScope.INTERNAL)

    assert report.statements == []
    assert len(report.skipped) == 2
    assert {item.reason for item in report.skipped} == {SkipReason.SHARED_OBJECT}
    assert {item.relative_page for item in report.skipped} == {1, 2}
    assert report.skipped[0].source is not None
    assert report.skipped[0].source == report.skipped[1].source
    assert report.skipped[0].source.idnum == inserted.indirect_reference.idnum


def test_unexplainable_page_relation_is_skipped():
    writer = PdfWriter()
    for _ in range(2):
        writer.add_blank_page(width=200, height=200)
    inserted = writer.add_annotation(
        page_number=1,
        annotation=Text(text="misplaced note", rect=(0, 0, 10, 10)),
    )
    # The annotation is listed on page 2 but claims to belong to page 1.
    inserted[NameObject("/P")] = writer.pages[0].indirect_reference
    reader = _write_to_reader(writer)

    report = collect_annotation_statements(reader, DisclosureScope.EXTERNAL)

    assert report.statements == []
    assert len(report.skipped) == 1
    skipped = report.skipped[0]
    assert skipped.reason is SkipReason.UNEXPLAINABLE_PAGE_RELATION
    assert skipped.relative_page == 2
    assert skipped.source is not None
    assert skipped.source.idnum == inserted.indirect_reference.idnum


def test_reconcile_requires_matching_scopes():
    reader = _build_excerpt_reader()
    internal = collect_annotation_statements(reader, DisclosureScope.INTERNAL)
    external = collect_annotation_statements(reader, DisclosureScope.EXTERNAL)

    with pytest.raises(ValueError, match="INTERNAL"):
        reconcile_statements(external, external)
    with pytest.raises(ValueError, match="EXTERNAL"):
        reconcile_statements(internal, internal)


def test_reconcile_reports_unmatched_statements():
    reader = _build_excerpt_reader()
    internal = collect_annotation_statements(reader, DisclosureScope.INTERNAL)
    external = collect_annotation_statements(reader, DisclosureScope.EXTERNAL)

    # Drop one statement from the external excerpt.
    external.statements.pop()
    result = reconcile_statements(internal, external)

    assert not result.is_consistent
    assert len(result.bindings) == 1
    assert len(result.unmatched_internal) == 1
    assert not result.unmatched_external
    assert result.unmatched_internal[0].category == "/FreeText"
