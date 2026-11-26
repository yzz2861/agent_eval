from pathlib import Path

import pytest

from bleach.provenance import (
    AmbiguousFragmentError,
    clean_with_provenance,
)


FIXTURE = Path(__file__).parent / "fixtures" / "ordinary_manual.html"
MANUAL_HTML = FIXTURE.read_text(encoding="utf-8")
MANUAL_TAGS = {"article", "h1", "h2", "section", "p"}
MANUAL_ATTRIBUTES = {"*": ["id", "class", "data-manual"]}


def _audit(**kwargs):
    options = {
        "tags": MANUAL_TAGS,
        "attributes": MANUAL_ATTRIBUTES,
        "approved_ids": {"manual-receipt-check"},
        "placeholder": "[REDACTED]",
    }
    options.update(kwargs)
    return clean_with_provenance(MANUAL_HTML, **options)


def test_manual_fixture_has_two_positionally_distinct_identical_paragraphs():
    report = _audit()

    duplicates = report.duplicate_paragraphs
    assert len(duplicates) == 1
    group = duplicates[0]
    assert list(group.fragment_ids) == [
        "manual-storage-check",
        "manual-receipt-check",
    ]
    assert group.positions[0] != group.positions[1]
    assert (
        report.trace("manual-storage-check").content_hash
        == report.trace("manual-receipt-check").content_hash
    )


def test_public_record_traces_exactly_to_approved_paragraph():
    report = _audit()

    assert len(report.public_records) == 1
    public_record = report.public_records[0]
    assert public_record.fragment_id == "manual-receipt-check"

    source = report.trace(public_record)
    assert source.fragment_id == "manual-receipt-check"
    assert 'id="manual-receipt-check"' in source.original_html
    assert "storage-chapter" in MANUAL_HTML
    assert source.index != report.trace("manual-storage-check").index

    legal_trace = report.trace_approved()
    assert legal_trace.fragment_id == "manual-receipt-check"
    assert report.public_record_for("manual-receipt-check").trace() is source


def test_content_alone_is_ambiguous_but_identity_is_exact():
    report = _audit(approved_ids={"manual-storage-check"})

    matches = report.trace_content(
        "Verify the serial plate before placing the unit in long-term storage."
    )
    assert {record.fragment_id for record in matches} == {
        "manual-storage-check",
        "manual-receipt-check",
    }
    with pytest.raises(AmbiguousFragmentError):
        report.find(
            report.trace_content(matches[0].normalized_text)[0].content_hash[:12]
        )

    approved = report.trace_approved()
    assert approved.fragment_id == "manual-storage-check"
    assert 'id="manual-storage-check"' in approved.original_html


def test_emptied_placeholder_and_duplicate_records_are_independent():
    fragments = [
        {
            "fragment_id": "approved-paragraph",
            "html": "<p>Public guidance.</p>",
            "approved": True,
            "source_ref": "manual:p/1",
        },
        {
            "fragment_id": "empty-redaction",
            "html": "<p>Confidential supplier names.</p>",
            "approved": False,
            "placeholder": False,
            "source_ref": "interview:14",
        },
        {
            "fragment_id": "placeholder-redaction",
            "html": "<p>Confidential methodology.</p>",
            "approved": False,
            "placeholder": "[METHOD WITHHELD]",
            "source_ref": "interview:18",
        },
        {
            "fragment_id": "same-guidance-elsewhere",
            "html": "<p>Public guidance.</p>",
            "approved": True,
            "source_ref": "manual:p/88",
        },
    ]

    report = clean_with_provenance(
        fragments,
        tags={"p"},
        attributes={"p": ["id"]},
        placeholder="[REDACTED]",
    )

    assert [record.fragment_id for record in report.emptied] == ["empty-redaction"]
    assert [record.fragment_id for record in report.placeholders] == [
        "placeholder-redaction"
    ]
    assert report.placeholders[0].placeholder_marker == "[METHOD WITHHELD]"
    assert len(report.duplicate_paragraphs) == 1
    assert report.duplicate_ids == [["approved-paragraph", "same-guidance-elsewhere"]]
    assert {record.fragment_id for record in report.public_records} == {
        "approved-paragraph",
        "same-guidance-elsewhere",
    }


def test_attribute_sources_are_associated_with_fragment():
    html = (
        '<p id="approved" href="https://example.com/manual" '
        'data-public-source="legal-approval-7">Read the manual.</p>'
    )
    report = clean_with_provenance(
        html,
        tags={"p", "a"},
        attributes={"p": ["id", "href", "data-public-source"]},
        approved_ids={"approved"},
    )

    record = report.trace("approved")
    by_name = {item.name: item for item in record.attribute_sources}
    assert by_name["id"].source == "legal-approval-7"
    assert by_name["id"].attribute_source == "legal-approval-7"
    assert by_name["id"].source_attribute == "data-public-source"
    assert by_name["id"].policy == "caller-attributes"
    assert "data-public-source" in by_name
    href = next(item for item in record.attribute_sources if item.name == "href")
    assert href.original_value == "https://example.com/manual"
    assert href.fragment_id == "approved"


def test_plain_bleach_clean_contract_is_unchanged():
    from bleach import clean

    assert clean("<script>x</script>") == "&lt;script&gt;x&lt;/script&gt;"
