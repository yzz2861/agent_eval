"""Review tests for signing-time authority across key rotation and approval."""

import unittest
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

from securesystemslib.signer import CryptoSigner, Signature
from tests.key_rotation_review import (
    ApprovalRecord,
    Evidence,
    FixedClock,
    KeyAuthorization,
    ReasonCode,
    Responsibility,
    Reviewer,
    ReviewPolicy,
    Stage,
    TimestampAttestation,
    Verdict,
    Window,
    artifact_digest,
    date_window,
    make_approval_record,
    make_timestamp_attestation,
    with_approval,
    with_ingestion,
    with_timestamp,
)

QUERY_WHILE_APPROVAL_OPEN = datetime(2025, 12, 24, 12, 0, tzinfo=UTC)
QUERY_AFTER_KEY_ROTATION = datetime(2026, 1, 5, 12, 0, tzinfo=UTC)
QUERY_AFTER_APPROVAL_CLOSE = datetime(2026, 1, 20, 12, 0, tzinfo=UTC)


class RotationFixture:
    """One old-key signature whose public key remains readable forever."""

    def __init__(self) -> None:
        self.old_signer = CryptoSigner.generate_ed25519("retired-artifact-key")
        self.timestamp_signer = CryptoSigner.generate_ed25519("timestamp-authority")
        self.approver_signer = CryptoSigner.generate_ed25519("launch-approver")

        self.payload = b'{"product":"widget","build":"2025.12.20"}'
        self.signed_at = datetime(2025, 12, 20, 10, 0, tzinfo=UTC)
        self.approved_at = datetime(2025, 12, 22, 9, 0, tzinfo=UTC)
        self.ingested_at = datetime(2025, 12, 23, 9, 0, tzinfo=UTC)

        self.key_window = date_window(date(2025, 6, 1), date(2026, 1, 1))
        self.approval_window = date_window(date(2025, 12, 1), date(2026, 1, 15))

        self.artifact_keyid = self.old_signer.public_key.keyid
        self.signature = self.old_signer.sign(self.payload)
        self.timestamp = make_timestamp_attestation(
            self.timestamp_signer,
            artifact_digest(self.payload),
            self.artifact_keyid,
            self.signed_at,
        )
        self.approval = make_approval_record(
            self.approver_signer,
            "APR-2025-1222",
            artifact_digest(self.payload),
            self.approved_at,
        )

        self.policy = ReviewPolicy(
            keys={
                self.artifact_keyid: KeyAuthorization(
                    self.old_signer.public_key, self.key_window
                )
            },
            approval_window=self.approval_window,
            reverification_window=self.approval_window,
            timestamp_key=self.timestamp_signer.public_key,
            approval_key=self.approver_signer.public_key,
        )
        self.evidence = Evidence(
            artifact_id="widget-2025.12.20",
            payload=self.payload,
            signature=self.signature,
            timestamp=self.timestamp,
            approval=self.approval,
            ingested_at=self.ingested_at,
        )
        self.clock = FixedClock(QUERY_WHILE_APPROVAL_OPEN)
        self.reviewer = Reviewer(self.policy, self.clock)


class TestKeyRotationReview(unittest.TestCase):
    """Each lifecycle stage is checked against its own temporal authority."""

    def setUp(self) -> None:
        self.fixture = RotationFixture()

    def test_fixture_old_key_is_signed_and_still_readable(self) -> None:
        """The retired key still verifies after its window, but proves no time."""

        fixture = self.fixture
        authorization = fixture.policy.keys[fixture.artifact_keyid]
        self.assertEqual(authorization.key, fixture.old_signer.public_key)

        later = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
        self.assertFalse(fixture.key_window.covers(later))
        fixture.clock.move_to(later)

        authorization.key.verify_signature(fixture.signature, fixture.payload)
        self.assertEqual(fixture.clock(), later)

    def test_all_four_stages_are_valid_while_approval_is_open(self) -> None:
        report = self.fixture.reviewer.review(self.fixture.evidence)

        expected_stages = (
            Stage.SIGNING,
            Stage.APPROVAL,
            Stage.INGESTION,
            Stage.REVERIFICATION,
        )
        for stage in expected_stages:
            result = report.for_stage(stage)
            self.assertEqual(result.verdict, Verdict.VALID)
            self.assertEqual(result.responsibility, Responsibility.NONE)
            self.assertEqual(result.reason, ReasonCode.OK)

        self.assertEqual(report.verdict, Verdict.VALID)
        self.assertEqual(report.responsibility, Responsibility.NONE)

    def test_two_date_queries_return_different_responsibility(self) -> None:
        """Same fixture, same signature: approval coverage changes the verdict."""

        fixture = self.fixture
        open_report = fixture.reviewer.review(fixture.evidence)

        closed_reviewer = Reviewer(
            fixture.policy, FixedClock(QUERY_AFTER_APPROVAL_CLOSE)
        )
        closed_report = closed_reviewer.review(fixture.evidence)

        fixture.policy.keys[fixture.artifact_keyid].key.verify_signature(
            fixture.signature, fixture.payload
        )

        self.assertEqual(open_report.evaluated_at, QUERY_WHILE_APPROVAL_OPEN)
        self.assertEqual(closed_report.evaluated_at, QUERY_AFTER_APPROVAL_CLOSE)
        self.assertEqual(open_report.verdict, Verdict.VALID)
        self.assertEqual(open_report.responsibility, Responsibility.NONE)

        self.assertEqual(closed_report.verdict, Verdict.INVALID)
        self.assertEqual(closed_report.responsibility, Responsibility.ON_CALL_VERIFIER)
        self.assertEqual(
            closed_report.for_stage(Stage.REVERIFICATION).reason,
            ReasonCode.REVERIFICATION_OUTSIDE_APPROVAL_WINDOW,
        )

        self.assertNotEqual(open_report.responsibility, closed_report.responsibility)
        self.assertNotEqual(open_report.verdict, closed_report.verdict)

        for stage in (Stage.SIGNING, Stage.APPROVAL, Stage.INGESTION):
            result = closed_report.for_stage(stage)
            self.assertEqual(result.verdict, Verdict.VALID)
            self.assertEqual(result.responsibility, Responsibility.NONE)

        self.assertNotEqual(open_report.responsibility, Responsibility.UNDETERMINED)
        self.assertNotEqual(closed_report.responsibility, Responsibility.UNDETERMINED)

    def test_unknown_signing_time_does_not_become_a_blame_verdict(self) -> None:
        fixture = self.fixture
        evidence = with_timestamp(fixture.evidence, None)
        query_dates = (
            QUERY_WHILE_APPROVAL_OPEN,
            QUERY_AFTER_KEY_ROTATION,
            QUERY_AFTER_APPROVAL_CLOSE,
        )
        for instant in query_dates:
            reviewer = Reviewer(fixture.policy, FixedClock(instant))
            report = reviewer.review(evidence)
            self.assertEqual(report.verdict, Verdict.INDETERMINATE)
            self.assertEqual(report.responsibility, Responsibility.UNDETERMINED)
            self.assertEqual(
                report.for_stage(Stage.SIGNING).reason,
                ReasonCode.SIGNING_TIME_UNKNOWN,
            )

    def test_reverification_after_key_rotation_uses_signing_time(self) -> None:
        """A retired key is fine if its authority covered the signing moment."""

        fixture = self.fixture
        fixture.clock.move_to(QUERY_AFTER_KEY_ROTATION)

        self.assertFalse(fixture.key_window.covers(fixture.clock()))
        self.assertTrue(fixture.approval_window.covers(fixture.clock()))

        report = fixture.reviewer.review(fixture.evidence)
        self.assertEqual(report.verdict, Verdict.VALID)
        self.assertEqual(report.responsibility, Responsibility.NONE)
        self.assertEqual(report.for_stage(Stage.REVERIFICATION).reason, ReasonCode.OK)

    def test_signing_time_unknown_is_explicit_indeterminate_state(self) -> None:
        """No trusted signing time is neither a pass nor an accusation."""

        fixture = self.fixture
        evidence = with_timestamp(fixture.evidence, None)
        report = fixture.reviewer.review(evidence)

        signing = report.for_stage(Stage.SIGNING)
        self.assertEqual(signing.verdict, Verdict.INDETERMINATE)
        self.assertEqual(signing.responsibility, Responsibility.UNDETERMINED)
        self.assertEqual(signing.reason, ReasonCode.SIGNING_TIME_UNKNOWN)

        reverification = report.for_stage(Stage.REVERIFICATION)
        self.assertEqual(reverification.verdict, Verdict.INDETERMINATE)
        self.assertEqual(reverification.responsibility, Responsibility.UNDETERMINED)
        self.assertEqual(
            reverification.reason,
            ReasonCode.REVERIFICATION_WITHOUT_SIGNING_TIME,
        )

        self.assertEqual(report.verdict, Verdict.INDETERMINATE)
        self.assertEqual(report.responsibility, Responsibility.UNDETERMINED)
        self.assertNotEqual(report.verdict, Verdict.VALID)

        fixture.policy.keys[fixture.artifact_keyid].key.verify_signature(
            fixture.signature, fixture.payload
        )
        self.assertTrue(fixture.key_window.covers(fixture.clock()))

    def test_tampered_timestamp_is_untrusted_not_a_pass(self) -> None:
        fixture = self.fixture
        tampered = TimestampAttestation(
            datetime(2026, 1, 10, 10, 0, tzinfo=UTC),
            fixture.timestamp.signature,
        )
        evidence = with_timestamp(fixture.evidence, tampered)

        report = fixture.reviewer.review(evidence)
        signing = report.for_stage(Stage.SIGNING)
        self.assertEqual(signing.verdict, Verdict.INDETERMINATE)
        self.assertEqual(signing.responsibility, Responsibility.UNDETERMINED)
        self.assertEqual(signing.reason, ReasonCode.SIGNING_TIME_UNTRUSTED)
        self.assertEqual(report.verdict, Verdict.INDETERMINATE)

    def test_signing_after_key_rotation_is_signer_liability(self) -> None:
        fixture = self.fixture
        late_signing = make_timestamp_attestation(
            fixture.timestamp_signer,
            fixture.evidence.sha256,
            fixture.artifact_keyid,
            datetime(2026, 1, 10, 10, 0, tzinfo=UTC),
        )
        evidence = with_timestamp(fixture.evidence, late_signing)

        fixture.clock.move_to(datetime(2026, 1, 12, 12, 0, tzinfo=UTC))
        signing = fixture.reviewer.check_signing(evidence)

        self.assertEqual(signing.verdict, Verdict.INVALID)
        self.assertEqual(signing.responsibility, Responsibility.SIGNER)
        self.assertEqual(signing.reason, ReasonCode.KEY_NOT_AUTHORIZED_AT_SIGNING)

    def test_approval_window_is_separate_from_key_rotation(self) -> None:
        fixture = self.fixture
        self.assertNotEqual(fixture.key_window.end, fixture.approval_window.end)

        after_rotation = make_approval_record(
            fixture.approver_signer,
            "APR-2026-0105",
            fixture.evidence.sha256,
            datetime(2026, 1, 5, 9, 0, tzinfo=UTC),
        )
        evidence = with_approval(fixture.evidence, after_rotation)
        result = fixture.reviewer.check_approval(evidence)
        self.assertEqual(result.verdict, Verdict.VALID)

        outside_window = make_approval_record(
            fixture.approver_signer,
            "APR-2026-0116",
            fixture.evidence.sha256,
            datetime(2026, 1, 16, 9, 0, tzinfo=UTC),
        )
        evidence = with_approval(fixture.evidence, outside_window)
        result = fixture.reviewer.check_approval(evidence)

        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.APPROVER)
        self.assertEqual(result.reason, ReasonCode.APPROVAL_OUTSIDE_WINDOW)

        evidence = with_approval(fixture.evidence, None)
        result = fixture.reviewer.check_approval(evidence)
        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.APPROVER)
        self.assertEqual(result.reason, ReasonCode.APPROVAL_MISSING)

    def test_approval_must_bind_the_exact_artifact(self) -> None:
        fixture = self.fixture
        approval = ApprovalRecord(
            fixture.approval.approval_id,
            "f" * 64,
            fixture.approval.approved_at,
            fixture.approval.signature,
        )
        evidence = with_approval(fixture.evidence, approval)
        result = fixture.reviewer.check_approval(evidence)

        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.APPROVER)
        self.assertEqual(result.reason, ReasonCode.APPROVAL_DIGEST_MISMATCH)

    def test_ingestion_before_approval_or_outside_window_is_operator_liability(
        self,
    ) -> None:
        fixture = self.fixture

        evidence = with_ingestion(
            fixture.evidence, datetime(2025, 12, 21, 9, 0, tzinfo=UTC)
        )
        result = fixture.reviewer.check_ingestion(evidence)
        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.INGEST_OWNER)
        self.assertEqual(result.reason, ReasonCode.INGESTION_BEFORE_APPROVAL)

        evidence = with_ingestion(
            fixture.evidence, datetime(2026, 1, 16, 9, 0, tzinfo=UTC)
        )
        result = fixture.reviewer.check_ingestion(evidence)
        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.INGEST_OWNER)
        self.assertEqual(result.reason, ReasonCode.INGESTION_OUTSIDE_APPROVAL_WINDOW)

        evidence = with_ingestion(fixture.evidence, None)
        result = fixture.reviewer.check_ingestion(evidence)
        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.INGEST_OWNER)
        self.assertEqual(result.reason, ReasonCode.INGESTION_MISSING)

    def test_invalid_artifact_signature_is_signer_liability(self) -> None:
        fixture = self.fixture
        bad_signature = Signature(fixture.artifact_keyid, "00" * 64)
        evidence = replace(fixture.evidence, signature=bad_signature)
        result = fixture.reviewer.check_signing(evidence)

        self.assertEqual(result.verdict, Verdict.INVALID)
        self.assertEqual(result.responsibility, Responsibility.SIGNER)
        self.assertEqual(result.reason, ReasonCode.SIGNATURE_INVALID)

    def test_windows_are_half_open_at_rotation_and_approval_boundaries(self) -> None:
        fixture = self.fixture

        rotation_boundary = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
        approval_boundary = datetime(2026, 1, 15, 0, 0, tzinfo=UTC)

        self.assertFalse(fixture.key_window.covers(rotation_boundary))
        self.assertTrue(
            fixture.key_window.covers(rotation_boundary - timedelta(seconds=1))
        )
        self.assertFalse(fixture.approval_window.covers(approval_boundary))

        evidence = with_ingestion(fixture.evidence, approval_boundary)
        result = fixture.reviewer.check_ingestion(evidence)
        self.assertEqual(result.reason, ReasonCode.INGESTION_OUTSIDE_APPROVAL_WINDOW)


class TestWindow(unittest.TestCase):
    """The interval type itself is explicit about date boundaries."""

    def test_half_open_window(self) -> None:
        window = date_window(date(2025, 12, 1), date(2026, 1, 15))
        self.assertEqual(
            window,
            Window(
                datetime(2025, 12, 1, tzinfo=UTC),
                datetime(2026, 1, 15, tzinfo=UTC),
            ),
        )
        self.assertTrue(window.covers(datetime(2025, 12, 1, tzinfo=UTC)))
        self.assertFalse(window.covers(datetime(2026, 1, 15, tzinfo=UTC)))

    def test_naive_timestamps_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Window(datetime(2025, 1, 1), datetime(2025, 2, 1))


if __name__ == "__main__":
    unittest.main()
