"""Tests for migrating historical DSSE review records."""

import copy
import json
import unittest
from pathlib import Path

from securesystemslib.dsse import (
    Envelope,
    EnvironmentCapabilities,
    MigrationDecision,
    MigrationReport,
    ReviewRecord,
    SigningAlgorithm,
    VerificationFailure,
    assess_migration,
)
from securesystemslib.signer import Key

DATA_DIR = Path(__file__).parent / "data" / "dsse_migration"


def load_fixture(name: str) -> dict:
    with open(DATA_DIR / f"{name}.json", encoding="utf-8") as fixture:
        return json.load(fixture)


class TestEnvelopeMigration(unittest.TestCase):
    """Test migration assessment for DSSE review records."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = {
            name: load_fixture(name)
            for name in ("reverifiable", "reuse_approved", "no_trust")
        }

    def test_three_fixed_envelopes(self):
        """The three fixed envelopes take the three distinct paths."""
        expected = {
            "reverifiable": MigrationDecision.REVERIFIED,
            "reuse_approved": MigrationDecision.REUSE_APPROVED_EVIDENCE,
            "no_trust": MigrationDecision.RECHECK,
        }

        assessments = []
        for name, decision in expected.items():
            fixture = copy.deepcopy(self.fixtures[name])
            report = assess_migration(fixture["record"], fixture["capabilities"])
            assessment = report.assessments[0]
            assessments.append(assessment)
            self.assertEqual(assessment.decision, decision, name)

        reverified, reused, recheck = assessments

        # 1. Re-verification: key material and algorithm are both available.
        self.assertTrue(reverified.usable)
        self.assertEqual(
            reverified.verified_keyids,
            frozenset(self.fixtures["reverifiable"]["record"]["evidenceKeyids"]),
        )
        self.assertIsNone(reverified.failure)

        # 2. Approved evidence: no key material in the new environment, but
        # the review source is explicitly trusted for legacy reuse.
        self.assertTrue(reused.usable)
        self.assertEqual(
            reused.reused_keyids,
            frozenset(self.fixtures["reuse_approved"]["record"]["evidenceKeyids"]),
        )
        self.assertEqual(reused.failure, VerificationFailure.MISSING_PUBLIC_KEY)
        self.assertEqual(reused.prior_failure, VerificationFailure.MISSING_PUBLIC_KEY)

        # 3. No trusted conditions: no key material, no trusted source and
        # legacy reuse disabled.
        self.assertFalse(recheck.usable)
        self.assertEqual(recheck.failure, VerificationFailure.MISSING_PUBLIC_KEY)
        self.assertEqual(
            recheck.reuse_blocked_by,
            VerificationFailure.LEGACY_EVIDENCE_DISABLED,
        )

        report = MigrationReport(assessments)
        self.assertEqual(
            [item.record_id for item in report.reusable],
            ["reverifiable-ed25519", "reuse-approved-ecdsa"],
        )
        self.assertEqual([item.record_id for item in report.recheck], ["no-trust-rsa"])

    def test_envelope_digest_matches_fixture(self):
        """The fixed envelopes bind to the recorded digests."""
        for fixture in self.fixtures.values():
            record = ReviewRecord.from_dict(copy.deepcopy(fixture["record"]))
            self.assertEqual(record.envelope.digest(), record.envelope_digest)

    def test_digest_mismatch_forces_recheck(self):
        """A modified envelope cannot reuse approved historical evidence."""
        fixture = copy.deepcopy(self.fixtures["reuse_approved"])
        fixture["record"]["envelopeDigest"] = "00" * 32

        assessment = assess_migration(
            fixture["record"], fixture["capabilities"]
        ).assessments[0]

        self.assertEqual(assessment.decision, MigrationDecision.RECHECK)
        self.assertEqual(assessment.failure, VerificationFailure.ENVELOPE_MISMATCH)

    def test_invalid_signature_blocks_legacy_reuse(self):
        """A verifiable but invalid signature is never rescued by evidence."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        record_dict = fixture["record"]
        signature = record_dict["envelope"]["signatures"][0]
        signature["sig"] = signature["sig"][:-4] + "AAAA"
        record_dict["envelopeDigest"] = Envelope.from_dict(
            copy.deepcopy(record_dict["envelope"])
        ).digest()

        assessment = assess_migration(record_dict, fixture["capabilities"]).assessments[
            0
        ]

        self.assertEqual(assessment.decision, MigrationDecision.RECHECK)
        self.assertEqual(assessment.failure, VerificationFailure.INVALID_SIGNATURE)

    def test_algorithm_parameter_mismatch_is_classified(self):
        """Recorded signing parameters are checked against capabilities."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        fixture["capabilities"]["supportedAlgorithms"][0]["parameters"] = {
            "hash": "sha512"
        }

        assessment = assess_migration(
            fixture["record"], fixture["capabilities"]
        ).assessments[0]

        self.assertIn(
            VerificationFailure.ALGORITHM_PARAMETER_MISMATCH,
            assessment.failures,
        )
        self.assertEqual(assessment.decision, MigrationDecision.REUSE_APPROVED_EVIDENCE)

    def test_untrusted_source_blocks_reuse(self):
        """Legacy evidence from an untrusted source requires a review."""
        fixture = copy.deepcopy(self.fixtures["reuse_approved"])
        fixture["capabilities"]["trustedReviewSources"] = []

        assessment = assess_migration(
            fixture["record"], fixture["capabilities"]
        ).assessments[0]

        self.assertEqual(assessment.decision, MigrationDecision.RECHECK)
        self.assertEqual(
            assessment.reuse_blocked_by,
            VerificationFailure.UNTRUSTED_REVIEW_SOURCE,
        )

    def test_threshold_shortfall_forces_recheck(self):
        """Re-verification must satisfy the declared threshold."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        fixture["capabilities"]["threshold"] = 2

        assessment = assess_migration(
            fixture["record"], fixture["capabilities"]
        ).assessments[0]

        self.assertEqual(assessment.decision, MigrationDecision.RECHECK)
        self.assertEqual(assessment.failure, VerificationFailure.INSUFFICIENT_EVIDENCE)

    def test_non_approval_conclusion_forces_recheck(self):
        """Only approval conclusions can be carried over."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        fixture["record"]["conclusion"] = "rejected"

        assessment = assess_migration(
            fixture["record"], fixture["capabilities"]
        ).assessments[0]

        self.assertEqual(assessment.decision, MigrationDecision.RECHECK)
        self.assertEqual(assessment.failure, VerificationFailure.UNSUPPORTED_CONCLUSION)

    def test_malformed_record_is_classified(self):
        """Malformed historical records are classified, not raised."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        report = assess_migration(
            {"recordId": "broken", "envelope": {"payload": "not-base64"}},
            fixture["capabilities"],
        )

        assessment = report.assessments[0]
        self.assertEqual(assessment.decision, MigrationDecision.RECHECK)
        self.assertEqual(assessment.failure, VerificationFailure.MALFORMED_ENVELOPE)

    def test_serialization_round_trip(self):
        """Records, capabilities and reports serialize losslessly."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        record = ReviewRecord.from_dict(copy.deepcopy(fixture["record"]))
        capabilities = EnvironmentCapabilities.from_dict(
            copy.deepcopy(fixture["capabilities"])
        )

        self.assertEqual(record.to_dict(), fixture["record"])
        self.assertEqual(capabilities.to_dict(), fixture["capabilities"])

        assessment = assess_migration(
            ReviewRecord.from_dict(record.to_dict()),
            EnvironmentCapabilities.from_dict(capabilities.to_dict()),
        ).assessments[0]
        self.assertEqual(assessment.decision, MigrationDecision.REVERIFIED)

    def test_input_record_is_not_mutated(self):
        """Assessing a mapping record must not destroy it."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        record_before = copy.deepcopy(fixture["record"])

        assess_migration(fixture["record"], fixture["capabilities"])

        self.assertEqual(fixture["record"], record_before)

    def test_typed_api(self):
        """The migration interface also accepts typed objects."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        record_data = fixture["record"]
        keyid = record_data["evidenceKeyids"][0]
        algorithm = record_data["signingAlgorithms"][keyid]

        key_data = copy.deepcopy(fixture["capabilities"]["publicKeys"][0])
        keyid_from_key = key_data.pop("keyid")
        key = Key.from_dict(keyid_from_key, key_data)

        capabilities = EnvironmentCapabilities(
            [
                SigningAlgorithm(
                    algorithm["keytype"],
                    algorithm["scheme"],
                    algorithm["parameters"],
                )
            ],
            public_keys=[key],
            trusted_review_sources=["legacy-review-v1"],
            allow_legacy_evidence=True,
        )
        record = ReviewRecord(
            record_data["recordId"],
            Envelope.from_dict(copy.deepcopy(record_data["envelope"])),
            record_data["conclusion"],
            review_source=record_data["reviewSource"],
            evidence_keyids=record_data["evidenceKeyids"],
            signing_algorithms={
                keyid: SigningAlgorithm(
                    algorithm["keytype"],
                    algorithm["scheme"],
                    algorithm["parameters"],
                )
            },
            envelope_digest=record_data["envelopeDigest"],
        )

        assessment = assess_migration(record, capabilities).assessments[0]
        self.assertEqual(assessment.decision, MigrationDecision.REVERIFIED)

    def test_batch_records_report_subsets(self):
        """A record batch is partitioned into reusable and recheck sets."""
        fixture = copy.deepcopy(self.fixtures["reverifiable"])
        capabilities = copy.deepcopy(fixture["capabilities"])

        reuse_record = copy.deepcopy(self.fixtures["reuse_approved"]["record"])
        untrusted_record = copy.deepcopy(self.fixtures["no_trust"]["record"])
        untrusted_record["reviewSource"] = "unknown-review-source"

        report = assess_migration(
            [fixture["record"], reuse_record, untrusted_record],
            capabilities,
        )

        self.assertEqual(
            [item.record_id for item in report.reusable],
            ["reverifiable-ed25519", "reuse-approved-ecdsa"],
        )
        self.assertEqual(
            [item.record_id for item in report.recheck],
            ["no-trust-rsa"],
        )
        self.assertEqual(
            report.by_id()["no-trust-rsa"].reuse_blocked_by,
            VerificationFailure.UNTRUSTED_REVIEW_SOURCE,
        )

    def test_report_to_dict(self):
        """Report serialization exposes classifications and subsets."""
        fixture = copy.deepcopy(self.fixtures["no_trust"])
        report = assess_migration(fixture["record"], fixture["capabilities"])
        data = report.to_dict()

        self.assertEqual(data["reusable"], [])
        self.assertEqual(data["recheck"], ["no-trust-rsa"])
        self.assertEqual(
            data["records"][0]["failure"],
            VerificationFailure.MISSING_PUBLIC_KEY.value,
        )
        self.assertEqual(
            data["records"][0]["reuseBlockedBy"],
            VerificationFailure.LEGACY_EVIDENCE_DISABLED.value,
        )


if __name__ == "__main__":
    unittest.main()
