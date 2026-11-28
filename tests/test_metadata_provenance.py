"""Tests for the metadata provenance attribution interface."""

from datetime import datetime
from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf._metadata_provenance import (
    MetadataLayer,
    MetadataProvenance,
    MissingMetadataLayerError,
)
from pypdf.xmp import XmpInformation

INFO_METADATA = {
    "/Title": "Annual Report",
    "/Author": "Ada Lovelace",
    "/Subject": "Archival copy",
    "/Keywords": "archive, report",
    "/Creator": "pypdf-test-suite",
    "/Producer": "pypdf",
    "/CreationDate": "D:20240102030405",
    "/ModDate": "D:20240203040506",
}

INFO_MOD_DATE = datetime(2024, 2, 3, 4, 5, 6)
XMP_METADATA_DATE = datetime(2024, 3, 4, 5, 6, 7)

EXPECTED_VALUES = {
    "title": "Annual Report",
    "author": "Ada Lovelace",
    "subject": "Archival copy",
    "keywords": "archive, report",
    "creator": "pypdf-test-suite",
    "producer": "pypdf",
    "creation_date": datetime(2024, 1, 2, 3, 4, 5),
    "modification_date": INFO_MOD_DATE,
}


def make_xmp(**overrides):
    """XMP metadata holding the same values as INFO_METADATA."""
    xmp = XmpInformation.create()
    xmp.dc_title = {"x-default": "Annual Report"}
    xmp.dc_creator = ["Ada Lovelace"]
    xmp.dc_description = {"x-default": "Archival copy"}
    xmp.pdf_keywords = "archive, report"
    xmp.xmp_creator_tool = "pypdf-test-suite"
    xmp.pdf_producer = "pypdf"
    xmp.xmp_create_date = datetime(2024, 1, 2, 3, 4, 5)
    xmp.xmp_modify_date = INFO_MOD_DATE
    xmp.xmp_metadata_date = XMP_METADATA_DATE
    for attribute, value in overrides.items():
        setattr(xmp, attribute, value)
    return xmp


def make_pdf(*, info=INFO_METADATA, xmp=None):
    """Generate a small PDF locally with the given metadata layers."""
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if info is not None:
        writer.add_metadata(info)
    if xmp is not None:
        writer.xmp_metadata = xmp
    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    return stream


def provenance_of(stream):
    return MetadataProvenance.from_reader(PdfReader(stream))


def test_info_layer_only_attributes_each_field_to_info():
    provenance = provenance_of(make_pdf())
    for name, expected in EXPECTED_VALUES.items():
        field = provenance.fields[name]
        assert field.layers == {MetadataLayer.INFO}
        assert field.confirmed_by() == {MetadataLayer.INFO}
        assert field.agrees is None
        assert field.value_for(MetadataLayer.INFO) == expected


def test_missing_xmp_layer_is_never_backfilled_from_info():
    provenance = provenance_of(make_pdf())
    for name in EXPECTED_VALUES:
        with pytest.raises(MissingMetadataLayerError):
            provenance.value_for(name, MetadataLayer.XMP)
    with pytest.raises(MissingMetadataLayerError):
        provenance.value_for("nonexistent_field", MetadataLayer.INFO)


def test_missing_info_layer_is_never_backfilled_from_xmp():
    stream = make_pdf(info=None, xmp=make_xmp())
    provenance = provenance_of(stream)
    assert provenance.value_for("title", MetadataLayer.XMP) == "Annual Report"
    with pytest.raises(MissingMetadataLayerError):
        provenance.value_for("title", MetadataLayer.INFO)


def test_identical_layers_still_traceable_to_their_own_confirmation():
    provenance = provenance_of(make_pdf(xmp=make_xmp()))
    for name, expected in EXPECTED_VALUES.items():
        field = provenance.fields[name]
        assert field.agrees is True
        assert field.confirmed_by() == {MetadataLayer.INFO, MetadataLayer.XMP}
        assert field.value_for(MetadataLayer.INFO) == expected
        assert field.value_for(MetadataLayer.XMP) == expected
        info_record = field.records[MetadataLayer.INFO]
        xmp_record = field.records[MetadataLayer.XMP]
        assert info_record.layer is MetadataLayer.INFO
        assert xmp_record.layer is MetadataLayer.XMP
        # Each record carries its own layer's update time, so the two
        # confirmations stay distinguishable even with equal values.
        assert info_record.updated_at == INFO_MOD_DATE
        assert xmp_record.updated_at == XMP_METADATA_DATE


def test_layer_update_times_are_checked_per_layer():
    info_only = provenance_of(make_pdf())
    assert info_only.layer_updated_at[MetadataLayer.INFO] == INFO_MOD_DATE
    assert info_only.layer_updated_at[MetadataLayer.XMP] is None
    both = provenance_of(make_pdf(xmp=make_xmp()))
    assert both.layer_updated_at[MetadataLayer.INFO] == INFO_MOD_DATE
    assert both.layer_updated_at[MetadataLayer.XMP] == XMP_METADATA_DATE


def test_disagreement_between_layers_is_reported():
    xmp = make_xmp()
    xmp.dc_title = {"x-default": "Draft Report"}
    provenance = provenance_of(make_pdf(xmp=xmp))
    assert provenance.fields["title"].agrees is False
    assert provenance.disagreements() == ["title"]
    assert provenance.value_for("title", MetadataLayer.INFO) == "Annual Report"
    assert provenance.value_for("title", MetadataLayer.XMP) == "Draft Report"


def test_info_date_outside_allowed_format_is_flagged_on_info_only():
    info = dict(INFO_METADATA, **{"/CreationDate": "not-a-date"})
    provenance = provenance_of(make_pdf(info=info, xmp=make_xmp()))
    field = provenance.fields["creation_date"]
    info_record = field.records[MetadataLayer.INFO]
    assert not info_record.valid
    assert "not a valid PDF date" in info_record.issues[0]
    # The XMP layer's own confirmation is unaffected.
    assert field.records[MetadataLayer.XMP].valid
    assert field.confirmed_by() == {MetadataLayer.XMP}


def test_info_key_outside_allowed_range_is_flagged():
    info = dict(INFO_METADATA, **{"/CustomArchiveKey": "x"})
    provenance = provenance_of(make_pdf(info=info))
    issues = provenance.layer_issues[MetadataLayer.INFO]
    assert any("/CustomArchiveKey" in issue for issue in issues)


def test_explicit_copy_between_layers_leaves_an_audit_trail():
    provenance = provenance_of(make_pdf())
    copied_at = datetime(2024, 5, 6, 7, 8, 9)
    record = provenance.copy_value(
        "title", MetadataLayer.INFO, MetadataLayer.XMP, copied_at=copied_at
    )
    assert record.source is MetadataLayer.INFO
    assert record.target is MetadataLayer.XMP
    assert record.value == "Annual Report"
    assert record.copied_at == copied_at
    assert provenance.copies == [record]
    xmp_record = provenance.fields["title"].records[MetadataLayer.XMP]
    assert xmp_record.copied_from is MetadataLayer.INFO
    assert provenance.fields["title"].agrees is True


def test_copy_from_a_missing_layer_is_rejected():
    provenance = provenance_of(make_pdf())
    with pytest.raises(MissingMetadataLayerError):
        provenance.copy_value("title", MetadataLayer.XMP, MetadataLayer.INFO)
    assert provenance.copies == []


def test_report_lists_each_layer_separately():
    provenance = provenance_of(make_pdf(xmp=make_xmp()))
    report = provenance.report()
    assert "title: info: 'Annual Report' | xmp: 'Annual Report'" in report
    info_only = provenance_of(make_pdf()).report()
    assert "title: info: 'Annual Report' | xmp: -" in info_only

