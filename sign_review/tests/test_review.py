"""End-to-end and unit tests for sign_review.

Fixtures are built in-memory with pypdf incremental updates, so the tests do
not depend on any checked-in PDF or network access.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfReader

from sign_review import (
    ChangeType,
    ReviewDecision,
    ReviewPolicy,
    StructuralStubVerifier,
    record_to_dict,
    review_pdf_bytes,
    scan_revisions,
)
from sign_review.demo.fixtures import (
    add_page_revision,
    build_all,
    build_clear_form,
    build_manual_form,
    fill_fields_revision,
)
from sign_review.verifiers import ByteRangeDigestVerifier

pytestmark = pytest.mark.filterwarnings("ignore::pypdf.errors.PdfReadWarning")


@pytest.fixture()
def fixture_dir(tmp_path: Path) -> Path:
    return build_all(tmp_path / 'fixtures')


def _read(path: Path) -> bytes:
    return path.read_bytes()


class TestRevisionScanning:
    def test_clear_form_has_three_revisions(self, fixture_dir: Path) -> None:
        scan = scan_revisions(_read(fixture_dir['clear']))
        assert len(scan.revisions) == 3
        assert scan.truncated_fragments == []

    def test_manual_form_has_seven_revisions(self, fixture_dir: Path) -> None:
        scan = scan_revisions(_read(fixture_dir['manual']))
        assert len(scan.revisions) == 7

    def test_byterange_maps_to_signature_revision(self, fixture_dir: Path) -> None:
        data = _read(fixture_dir['clear'])
        scan = scan_revisions(data)
        assert len(scan.byte_ranges) == 1
        offset, head, gap, tail = scan.byte_ranges[0]
        anchor = gap + 1
        assert scan.revision_for_offset(anchor) == 1
        assert scan.revision_for_offset(gap + tail) == 2

    def test_truncated_tail_is_flagged(self, fixture_dir: Path) -> None:
        scan = scan_revisions(_read(fixture_dir['truncated']))
        assert len(scan.truncated_fragments) == 1
        fragment = scan.truncated_fragments[0]
        assert fragment.start_offset < fragment.end_offset

    def test_every_revision_prefix_is_parseable(self, fixture_dir: Path) -> None:
        data = _read(fixture_dir['manual'])
        scan = scan_revisions(data)
        for revision in scan.revisions:
            reader = PdfReader(BytesIO(data[: revision.end_offset]))
            assert len(reader.pages) >= 2


POLICY = ReviewPolicy(
    allowed_field_fills=frozenset({'officer_name', 'case_id', 'review_note'}),
)


class TestReviewDecisions:
    def test_clear_form_continues_when_fills_are_allowed(self, fixture_dir: Path) -> None:
        record = review_pdf_bytes(
            _read(fixture_dir['clear']), POLICY, StructuralStubVerifier(),
            source='clear_form.pdf')
        assert record.decision == ReviewDecision.CONTINUE
        assert record.signed_revision_index == 1
        assert all(sig.valid for sig in record.signatures)
        assert {f.severity for f in record.findings} <= {'allowed'}
        assert any(
            f.change_type == ChangeType.FIELD_VALUE and f.severity == 'allowed'
            for f in record.findings)

    def test_manual_form_is_routed_to_manual(self, fixture_dir: Path) -> None:
        record = review_pdf_bytes(
            _read(fixture_dir['manual']), POLICY, StructuralStubVerifier(),
            source='manual_form.pdf')
        assert record.decision == ReviewDecision.MANUAL
        assert record.routing_reason
        assert record.deciding_findings
        first = record.deciding_findings[0]
        assert first['severity'] == 'unauthorized'
        assert first['from_revision'] > record.signed_revision_index

    def test_truncated_form_always_goes_manual(self, fixture_dir: Path) -> None:
        permissive = ReviewPolicy(
            allowed_field_fills=frozenset({'officer_name', 'case_id', 'review_note'}),
            allow_page_changes=True, allow_shared_resource_changes=True,
            allow_inherited_attr_changes=True)
        record = review_pdf_bytes(
            _read(fixture_dir['truncated']), permissive, StructuralStubVerifier())
        assert record.decision == ReviewDecision.MANUAL
        assert record.truncated is True
        assert any(f.change_type == ChangeType.TRUNCATED_REVISION
                   for f in record.findings)


class TestPolicyEnforcement:
    def test_unlisted_field_fill_is_unauthorized(self, tmp_path: Path) -> None:
        path = build_clear_form(tmp_path / 'c.pdf')
        fill_fields_revision(path, {'review_note': 'secret note'})
        strict = ReviewPolicy(allowed_field_fills=frozenset({'officer_name'}))
        record = review_pdf_bytes(
            _read(path), strict, StructuralStubVerifier())
        assert record.decision == ReviewDecision.MANUAL
        note = next(f for f in record.findings if f.target == 'field:review_note')
        assert note.severity == 'unauthorized'
        assert 'review_note' in (note.policy_basis or '')

    def test_page_change_allowed_only_when_permitted(self, tmp_path: Path) -> None:
        path = build_clear_form(tmp_path / 'p.pdf')
        add_page_revision(path)
        blocked = review_pdf_bytes(
            _read(path), ReviewPolicy(), StructuralStubVerifier())
        assert blocked.decision == ReviewDecision.MANUAL
        permitted = review_pdf_bytes(
            _read(path), ReviewPolicy(
                allowed_field_fills=frozenset({'officer_name', 'case_id', 'review_note'}),
                allow_page_changes=True),
            StructuralStubVerifier())
        assert permitted.decision == ReviewDecision.CONTINUE

    def test_appearance_change_needs_explicit_permission(self, tmp_path: Path) -> None:
        path = build_manual_form(tmp_path / 'a.pdf')
        denied = ReviewPolicy()
        record = review_pdf_bytes(_read(path), denied, StructuralStubVerifier())
        appearance = next(
            f for f in record.findings
            if f.change_type == ChangeType.FIELD_APPEARANCE)
        assert appearance.severity == 'unauthorized'

    def test_record_is_json_serializable(self, fixture_dir: Path) -> None:
        import json
        record = review_pdf_bytes(
            _read(fixture_dir['manual']), POLICY, StructuralStubVerifier())
        payload = record_to_dict(record)
        encoded = json.dumps(payload, ensure_ascii=False)
        assert json.loads(encoded)['decision'] == ReviewDecision.MANUAL


class TestVerifierInjection:
    def test_caller_verifier_controls_validity(self, fixture_dir: Path) -> None:
        from sign_review.models import SignatureInfo, VerificationResult

        class AlwaysReject:
            name = 'test-reject'

            def verify(self, data: bytes, signature: SignatureInfo) -> VerificationResult:
                return VerificationResult(False, self.name, {'reason': 'test rejection'})

        record = review_pdf_bytes(
            _read(fixture_dir['clear']), POLICY, AlwaysReject())
        assert record.decision == ReviewDecision.MANUAL
        assert record.signatures[0].valid is False
        assert record.signatures[0].verifier == 'test-reject'

    def test_digest_verifier_hashes_covered_bytes(self, fixture_dir: Path) -> None:
        record = review_pdf_bytes(
            _read(fixture_dir['clear']), POLICY, ByteRangeDigestVerifier())
        signature = record.signatures[0]
        assert signature.valid is True
        assert signature.detail and 'digest' in signature.detail

    def test_stub_verifier_rejects_malformed_range(self) -> None:
        from sign_review.models import SignatureInfo, VerificationResult
        verifier = StructuralStubVerifier()
        sig = SignatureInfo('x', None, None, [0, 10], None, None)
        result = verifier.verify(b'data', sig)
        assert isinstance(result, VerificationResult)
        assert result.valid is False


class TestSharedAndInheritedImpact:
    def test_shared_resource_lists_every_impacted_page(self, fixture_dir: Path) -> None:
        record = review_pdf_bytes(
            _read(fixture_dir['manual']), POLICY, StructuralStubVerifier())
        resource = next(
            f for f in record.findings
            if f.change_type == ChangeType.SHARED_RESOURCE)
        impacted = resource.detail['impacted_pages']
        page_indices = {entry['page_index'] for entry in impacted}
        assert page_indices == {0, 1}
        assert all(entry['names'] for entry in impacted)
        assert '影响页面 1, 2' in resource.explanation

    def test_inherited_attribute_names_defining_node(self, fixture_dir: Path) -> None:
        record = review_pdf_bytes(
            _read(fixture_dir['manual']), POLICY, StructuralStubVerifier())
        inherited = [f for f in record.findings
                     if f.change_type == ChangeType.INHERITED_ATTR]
        assert inherited
        for finding in inherited:
            assert finding.detail['defined_on'] is not None
            assert finding.detail['attribute'] == '/Rotate'

    def test_each_finding_carries_revision_pair(self, fixture_dir: Path) -> None:
        record = review_pdf_bytes(
            _read(fixture_dir['manual']), POLICY, StructuralStubVerifier())
        for finding in record.findings:
            if finding.change_type == ChangeType.TRUNCATED_REVISION:
                continue
            assert finding.from_revision is not None
            assert finding.to_revision == finding.from_revision + 1
            assert finding.to_revision > record.signed_revision_index
