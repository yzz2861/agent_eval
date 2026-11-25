"""Tests for read-only navigation forensics."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    NullObject,
    RectangleObject,
    TextStringObject,
)
from pypdf.navigation import audit_navigation


def _add_link(writer: PdfWriter, page_index: int, destination: object) -> None:
    link = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): RectangleObject([0, 0, 100, 20]),
        }
    )
    if isinstance(destination, str):
        link[NameObject("/Dest")] = TextStringObject(destination)
    else:
        link[NameObject("/Dest")] = destination
    reference = writer._add_object(link)
    page = writer.pages[page_index]
    annotations = page.get(NameObject("/Annots"))
    if not isinstance(annotations, ArrayObject):
        annotations = ArrayObject()
        page[NameObject("/Annots")] = annotations
    annotations.append(reference)


def _three_page_reader(*, removed_name: str | None = None) -> PdfReader:
    writer = PdfWriter()
    for _ in range(3):
        writer.add_blank_page(width=300, height=400)

    writer.add_named_destination("step-1", 1)
    writer.add_named_destination("step-2", 2)
    _add_link(writer, 0, "step-1")
    _add_link(writer, 1, "step-2")
    writer.add_outline_item("Direct to final page", 2)

    if removed_name is not None:
        names = writer.get_named_dest_root()
        for index in range(0, len(names), 2):
            if names[index] == removed_name:
                del names[index : index + 2]
                break
        else:  # pragma: no cover - test setup guard
            raise AssertionError(f"destination {removed_name!r} not registered")

    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    return PdfReader(stream)


def test_three_page_two_hop_navigation_is_reconciled() -> None:
    report = audit_navigation(_three_page_reader())

    assert report.page_count == 3
    assert [item.name for item in report.named_destinations] == ["step-1", "step-2"]
    assert len(report.direct_references) == 1
    assert report.direct_references[0].origin.outline_title == "Direct to final page"

    trace = report.trace(page=0)
    assert len(trace) == 1
    path = trace.path
    assert path is not None
    assert path.hop_count == 2
    assert path.complete is True
    assert path.broken_hop is None
    assert path.target_pages == [1, 2]
    assert path.hops[0].provenance.location == "pages[0]/Annots[0]"
    assert path.hops[1].provenance.page_index == 1


@pytest.mark.parametrize(
    ("removed_name", "expected_hop"),
    [("step-1", 1), ("step-2", 2)],
)
def test_missing_registration_reports_exact_broken_hop(removed_name: str, expected_hop: int) -> None:
    reader = _three_page_reader(removed_name=removed_name)
    report = audit_navigation(reader)

    path = report.trace(page=0).path
    assert path is not None
    assert path.broken is True
    assert path.complete is False
    assert path.broken_hop == expected_hop
    assert path.hops[expected_hop - 1].status == "missing_registration"
    assert removed_name in path.missing_names

    missing = [item for item in report.missing_targets if item.name == removed_name]
    assert len(missing) == 1
    assert missing[0].origin.location.startswith("pages[")
    assert missing[0].registrations == []


def test_direct_duplicate_and_missing_target_provenance_are_separate() -> None:
    writer = PdfWriter()
    for _ in range(3):
        writer.add_blank_page(width=300, height=400)
    writer.add_named_destination("dup", 0)
    writer.add_named_destination("ghost-target", 2)

    duplicate_array = ArrayObject([writer.pages[0].indirect_reference, NameObject("/Fit")])
    duplicate_reference = writer._add_object(duplicate_array)
    names = writer.get_named_dest_root()
    names.extend([TextStringObject("dup"), duplicate_reference])

    _add_link(writer, 0, ArrayObject([writer.pages[1].indirect_reference, NameObject("/Fit")]))
    _add_link(writer, 1, "missing-name")
    _add_link(
        writer,
        2,
        ArrayObject([NullObject(), NameObject("/Fit")]),
    )

    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    reader = PdfReader(stream)
    report = audit_navigation(reader)

    direct_pages = {item.origin.page_index: item for item in report.direct_references}
    assert direct_pages[0].target_page == 1
    assert direct_pages[2].status == "missing_target"
    assert direct_pages[2].target_page is None
    assert direct_pages[0].origin.object_reference is not None

    assert "dup" in report.duplicate_names
    duplicate_group = report.duplicate_names["dup"]
    assert duplicate_group.count == 2
    assert len(duplicate_group.sources) == 2
    assert all(source.location.startswith("catalog/") for source in duplicate_group.sources)

    missing_named = [item for item in report.missing_targets if item.name == "missing-name"]
    assert len(missing_named) == 1
    assert missing_named[0].origin.page_index == 1
    assert missing_named[0].origin.location == "pages[1]/Annots[0]"

    missing_direct = [item for item in report.missing_targets if item.kind == "direct"]
    assert len(missing_direct) == 1
    assert missing_direct[0].origin.page_index == 2


def test_external_link_is_recorded_but_not_opened() -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=400)
    writer.add_uri(
        0,
        "https://example.invalid/case-file",
        RectangleObject([0, 0, 100, 20]),
    )

    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    report = audit_navigation(PdfReader(stream))

    assert len(report.external_references) == 1
    external = report.external_references[0]
    assert external.external is True
    assert "example.invalid" in (external.external_target or "")
    path = report.trace(page=0).path
    assert path is not None
    assert path.external is True
    assert path.complete is False
    assert path.broken is False


def test_report_supports_mapping_style_access() -> None:
    report = audit_navigation(_three_page_reader())

    assert report["page_count"] == 3
    assert report["broken_hop"] is None
    assert len(report["direct_references"]) == 1
    assert len(report["navigation_paths"]) == len(report.paths)
    plain = report.to_dict()
    assert plain["page_count"] == 3
    assert "reader" not in plain
