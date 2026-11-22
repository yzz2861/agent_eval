"""Tests for the optional export guardrails."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest

from pypdf import (
    DocumentIdentity,
    ExportAuditEvent,
    ExportAuthorization,
    ExportBlockReason,
    ExportGuard,
    ExportGuardError,
    PdfReader,
    PdfWriter,
)
from pypdf.generic import DecodedStreamObject, NameObject


def _make_pdf(text, name=None, page_count=3) -> BytesIO:
    writer = PdfWriter()
    for index in range(page_count):
        page = writer.add_blank_page(width=200, height=200)
        contents = DecodedStreamObject()
        contents.set_data(f"BT ({text} page {index}) Tj ET".encode())
        page[NameObject("/Contents")] = writer._add_object(contents)
    writer.encrypt(user_password="secret")
    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    if name is not None:
        stream.name = name
    return stream


def _reader(text, name=None) -> PdfReader:
    return PdfReader(_make_pdf(text, name=name), password="secret")


def test_two_encrypted_in_memory_documents_keep_identity_and_provenance():
    doc_a = _reader("alpha", name="alpha.pdf")
    doc_b = _reader("beta", name="beta.pdf")
    auth_a = ExportAuthorization.issue(
        doc_a,
        "legal_transmittal",
        [0, 2],
        document_name="alpha.pdf",
        subject="auditor",
    )
    auth_b = ExportAuthorization.issue(
        doc_b,
        "legal_transmittal",
        [1],
        document_name="beta.pdf",
        subject="viewer",
    )
    guard = ExportGuard([auth_a, auth_b])
    writer = PdfWriter(export_guard=guard)

    writer.append(doc_a, pages=[0], purpose="legal_transmittal")
    writer.append(doc_b, pages=[1], purpose="legal_transmittal")

    assert len(writer.pages) == 2
    provenance = writer.export_provenance
    assert [record.document_name for record in provenance] == [
        "alpha.pdf",
        "beta.pdf",
    ]
    assert [record.source_page_index for record in provenance] == [0, 1]
    assert [record.output_page_index for record in provenance] == [0, 1]
    assert [record.authorization_id for record in provenance] == [
        auth_a.authorization_id,
        auth_b.authorization_id,
    ]
    assert [record.document_id for record in provenance] == [
        DocumentIdentity.from_pdf(doc_a).fingerprint,
        DocumentIdentity.from_pdf(doc_b).fingerprint,
    ]

    partial_records = [
        record
        for record in guard.audit_log
        if record.event is ExportAuditEvent.PARTIAL_SELECTION
    ]
    assert len(partial_records) == 2
    assert partial_records[0].details["unselected_document_pages"] == [1, 2]


def test_cross_used_authorization_names_the_source_page_without_basis():
    doc_a = _reader("alpha", name="contract.pdf")
    doc_b = _reader("beta", name="contract.pdf")
    auth_a = ExportAuthorization.issue(
        doc_a, "legal_transmittal", [0, 1], document_name="contract.pdf"
    )
    auth_b = ExportAuthorization.issue(
        doc_b, "legal_transmittal", [0, 1], document_name="contract.pdf"
    )
    guard = ExportGuard([auth_a, auth_b])
    writer = PdfWriter()

    with pytest.raises(ExportGuardError) as exc_info:
        writer.append(
            doc_b,
            pages=[0, 1],
            purpose="legal_transmittal",
            authorization=auth_a,
            export_guard=guard,
        )

    error = exc_info.value
    assert error.reason is ExportBlockReason.DOCUMENT_MISMATCH
    assert error.page_index == 0
    assert error.page_number == 1
    assert error.unauthorized_page_numbers == (1, 2)
    assert "source page 1 (index 0) has no matching authorization" in str(error)
    assert "names match but the document content does not" in str(error)
    assert len(writer.pages) == 0

    blocked = guard.audit_log[-1]
    assert blocked.event is ExportAuditEvent.EXPORT_BLOCKED
    assert blocked.reason is ExportBlockReason.DOCUMENT_MISMATCH
    assert blocked.details["authorization_document"]["name"] == "contract.pdf"
    assert blocked.details["source_document"]["name"] == "contract.pdf"
    assert blocked.details["same_name_different_content"] is True



def test_same_name_different_content_are_different_documents():
    doc_a = _reader("alpha", name="contract.pdf")
    doc_b = _reader("beta", name="contract.pdf")
    auth_a = ExportAuthorization.issue(
        doc_a, "legal_transmittal", [0], document_name="contract.pdf"
    )
    auth_b = ExportAuthorization.issue(
        doc_b, "legal_transmittal", [0], document_name="contract.pdf"
    )
    guard = ExportGuard([auth_a, auth_b])

    assert DocumentIdentity.from_pdf(doc_a) != DocumentIdentity.from_pdf(doc_b)
    assert [
        item.authorization_id for item in guard.authorizations_for(doc_a)
    ] == [auth_a.authorization_id]
    assert [
        item.authorization_id for item in guard.authorizations_for(doc_b)
    ] == [auth_b.authorization_id]


def test_expired_and_revoked_authorizations_are_blocked_and_audited():
    doc = _reader("alpha", name="alpha.pdf")
    expired = ExportAuthorization.issue(doc, "out", [0], expires_in=1)
    guard = ExportGuard([expired])

    with pytest.raises(ExportGuardError) as exc_info:
        guard.check(
            doc,
            "out",
            [0],
            authorization=expired,
            now=datetime.now(timezone.utc) + timedelta(seconds=5),
        )
    assert exc_info.value.reason is ExportBlockReason.AUTHORIZATION_EXPIRED
    assert guard.audit_log[-1].reason is ExportBlockReason.AUTHORIZATION_EXPIRED

    revoked = ExportAuthorization.issue(doc, "out", [0])
    guard.register(revoked)
    guard.revoke(revoked.authorization_id)
    with pytest.raises(ExportGuardError) as exc_info:
        guard.check(doc, "out", [0], authorization=revoked)
    assert exc_info.value.reason is ExportBlockReason.AUTHORIZATION_REVOKED
    assert guard.audit_log[-1].reason is ExportBlockReason.AUTHORIZATION_REVOKED


def test_page_outside_authorized_range_identifies_the_page():
    doc = _reader("alpha", name="alpha.pdf")
    auth = ExportAuthorization.issue(doc, "out", [0])
    writer = PdfWriter()

    with pytest.raises(ExportGuardError) as exc_info:
        writer.append(
            doc,
            pages=[0, 2],
            purpose="out",
            authorization=auth,
            export_guard=ExportGuard([auth]),
        )

    error = exc_info.value
    assert error.reason is ExportBlockReason.PAGE_NOT_AUTHORIZED
    assert error.page_index == 2
    assert error.page_number == 3
    assert error.unauthorized_page_numbers == (3,)
    assert "unauthorized pages: 3 (index 2)" in str(error)
    assert len(writer.pages) == 0


def test_partial_page_selection_leaves_an_audit_record():
    doc = _reader("alpha", name="alpha.pdf")
    auth = ExportAuthorization.issue(doc, "out", [0, 1, 2])
    guard = ExportGuard([auth])

    decision = guard.check(doc, "out", [0])

    assert decision.partial is True
    assert decision.requested_pages == (0,)
    assert decision.unselected_document_pages == (1, 2)
    assert decision.unexported_authorized_pages == (1, 2)
    partial = [
        record
        for record in guard.audit_log
        if record.event is ExportAuditEvent.PARTIAL_SELECTION
    ]
    assert len(partial) == 1
    assert partial[0].details["unselected_document_pages"] == [1, 2]
    assert partial[0].details["unexported_authorized_pages"] == [1, 2]


def test_merge_uses_the_authorization_matching_each_actual_source():
    doc_a = _reader("alpha", name="alpha.pdf")
    doc_b = _reader("beta", name="beta.pdf")
    auth_a = ExportAuthorization.issue(
        doc_a, "out", [0, 2], document_name="alpha.pdf"
    )
    auth_b = ExportAuthorization.issue(doc_b, "out", [1], document_name="beta.pdf")
    guard = ExportGuard([auth_a, auth_b])
    writer = PdfWriter(export_guard=guard)

    writer.merge(0, doc_b, pages=[1], purpose="out")
    writer.merge(1, doc_a, pages=[2, 0], purpose="out")

    assert [record.document_name for record in writer.export_provenance] == [
        "beta.pdf",
        "alpha.pdf",
        "alpha.pdf",
    ]
    assert [record.source_page_index for record in writer.export_provenance] == [
        1,
        2,
        0,
    ]
    assert [record.authorization_id for record in writer.export_provenance] == [
        auth_b.authorization_id,
        auth_a.authorization_id,
        auth_a.authorization_id,
    ]


def test_clone_document_from_reader_records_all_source_pages():
    doc = _reader("alpha", name="alpha.pdf")
    auth = ExportAuthorization.issue(doc, "out", None, document_name="alpha.pdf")
    guard = ExportGuard([auth])
    writer = PdfWriter(export_guard=guard)

    writer.clone_document_from_reader(doc, purpose="out")

    assert [record.output_page_index for record in writer.export_provenance] == [
        0,
        1,
        2,
    ]
    assert [record.source_page_index for record in writer.export_provenance] == [
        0,
        1,
        2,
    ]
    assert all(
        record.authorization_id == auth.authorization_id
        for record in writer.export_provenance
    )


def test_undecrypted_reader_is_rejected_before_identity_is_trusted():
    stream = _make_pdf("alpha", name="alpha.pdf")
    reader = PdfReader(stream)
    guard = ExportGuard()

    with pytest.raises(ExportGuardError) as exc_info:
        guard.check(reader, "out", [0])

    assert exc_info.value.reason is ExportBlockReason.NOT_DECRYPTED
    assert guard.audit_log[-1].reason is ExportBlockReason.NOT_DECRYPTED


def test_missing_purpose_is_rejected():
    doc = _reader("alpha")
    auth = ExportAuthorization.issue(doc, "out", [0])
    guard = ExportGuard([auth])

    with pytest.raises(ExportGuardError) as exc_info:
        guard.check(doc, None, [0])

    assert exc_info.value.reason is ExportBlockReason.MISSING_PURPOSE


def test_append_pages_from_reader_is_guarded_and_recorded():
    doc = _reader("alpha", name="alpha.pdf")
    auth = ExportAuthorization.issue(doc, "out", None, document_name="alpha.pdf")
    writer = PdfWriter(export_guard=ExportGuard([auth]))

    writer.append_pages_from_reader(doc, purpose="out")

    assert len(writer.export_provenance) == 3
    assert [record.source_page_index for record in writer.export_provenance] == [
        0,
        1,
        2,
    ]


def test_clone_from_constructor_is_guarded():
    doc = _reader("alpha", name="alpha.pdf")
    auth = ExportAuthorization.issue(doc, "out", None, document_name="alpha.pdf")
    writer = PdfWriter(clone_from=doc, export_guard=ExportGuard([auth]), purpose="out")

    assert len(writer.export_provenance) == 3
    assert all(
        record.authorization_id == auth.authorization_id
        for record in writer.export_provenance
    )
