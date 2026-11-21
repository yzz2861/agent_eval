"""Test the pypdf.annotations evidence index."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.annotations import AnnotationEvidenceIndex, Text
from pypdf.generic import NameObject


def make_dossier():
    """
    Build a 4-page document:

    - page 0: annotation A ("shared note") and B ("duplicate text")
    - page 1: a copy of A's reference plus independent C ("duplicate text")
    - page 2: reply R to annotation D
    - page 3: annotation D ("original note"), outside the dossier
    """
    writer = PdfWriter()
    for _ in range(4):
        writer.add_blank_page(width=200, height=200)

    annot_a = writer.add_annotation(0, Text(rect=(10, 10, 20, 20), text="shared note"))
    writer.add_annotation(0, Text(rect=(30, 30, 40, 40), text="duplicate text"))
    annot_c = writer.add_annotation(1, Text(rect=(50, 50, 60, 60), text="duplicate text"))
    annot_d = writer.add_annotation(3, Text(rect=(10, 10, 20, 20), text="original note"))
    writer.add_annotation(
        2,
        Text(
            rect=(70, 70, 80, 80),
            text="reply to original",
            in_reply_to=annot_d.indirect_reference,
        ),
    )
    # Copy annotation A to page 1 by reusing its indirect reference.
    page1 = writer.pages[1]
    page1[NameObject("/Annots")].append(annot_a.indirect_reference)

    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    return PdfReader(stream), annot_c


def test_index_records_entities_replies_and_page_references():
    reader, _ = make_dossier()
    index = AnnotationEvidenceIndex(reader, pages=[0, 1, 2])

    assert index.covered_pages == (0, 1, 2)
    # A, B, C, R -- D is not covered.
    assert len(index.entities) == 4
    assert len(index.replies) == 1

    page1 = index.page(1)
    assert len(page1.references) == 2
    assert {ref.position for ref in page1.references} == {0, 1}
    assert all(ref.indirect for ref in page1.references)
    assert all(ref.idnum is not None for ref in page1.references)
    assert {entity.contents for entity in page1.entities} == {
        "duplicate text",
        "shared note",
    }

    with pytest.raises(IndexError):
        index.page(3)
    with pytest.raises(IndexError):
        AnnotationEvidenceIndex(reader, pages=[7])


def test_copied_annotation_keeps_identity_beyond_text():
    reader, annot_c = make_dossier()
    index = AnnotationEvidenceIndex(reader, pages=[0, 1, 2])
    report = index.report()

    # The copy of A on page 1 is the same entity, not a same-text duplicate.
    assert len(report.copied_to_other_pages) == 1
    copied = report.copied_to_other_pages[0]
    assert copied.contents == "shared note"
    assert copied.pages == (0, 1)
    assert copied.key == ("indirect", copied.idnum, copied.generation)

    # B and C share text but are distinct objects: independent duplicates.
    assert len(report.same_text_independent) == 1
    group = report.same_text_independent[0]
    assert {entity.contents for entity in group} == {"duplicate text"}
    assert len({entity.key for entity in group}) == 2
    c_keys = [entity.key for entity in group if entity.pages == (1,)]
    assert c_keys == [("indirect", annot_c.indirect_reference.idnum, 0)]


def test_reply_to_uncovered_page_keeps_missing_evidence_note():
    reader, _ = make_dossier()
    index = AnnotationEvidenceIndex(reader, pages=[0, 1, 2])
    report = index.report()

    assert len(index.replies) == 1
    reply = index.replies[0]
    assert reply.source_pages == (2,)
    assert reply.reply_type == "R"
    assert reply.target_key is None
    assert reply.target_reference is not None

    assert len(report.missing_evidence) == 1
    note = report.missing_evidence[0]
    assert note.target_pages == (3,)
    assert "page(s) [3]" in note.reason
    assert "not covered" in note.reason

    text = report.to_text()
    assert "Copied to another page" in text
    assert "Independent same-text annotations" in text
    assert "page(s) [3]" in text


def test_full_coverage_resolves_reply():
    reader, _ = make_dossier()
    index = AnnotationEvidenceIndex(reader)

    assert index.covered_pages == (0, 1, 2, 3)
    assert len(index.entities) == 5
    reply = index.replies[0]
    assert reply.target_key == reply.target_reference
    assert reply.missing is None
    assert index.report().missing_evidence == ()
    # The original D is found on page 3.
    assert index.entity(reply.target_key).pages == (3,)


def test_index_is_read_only():
    reader, _ = make_dossier()
    before = [len(page.get("/Annots", [])) for page in reader.pages]
    AnnotationEvidenceIndex(reader, pages=[0, 1, 2]).report().to_text()
    after = [len(page.get("/Annots", [])) for page in reader.pages]
    assert before == after
