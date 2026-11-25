"""Tests for the DSSE-based release gate (``securesystemslib.gate``)."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from securesystemslib.dsse import Envelope
from securesystemslib.gate import (
    GATE_ORDER,
    GATE_POLICY_SCHEMA_VERSION,
    IN_TOTO_PAYLOAD_TYPE,
    GateInputError,
    GateStatus,
    ReleaseGate,
    ReleasePolicy,
)
from securesystemslib.gate_exceptions import PolicyError
from securesystemslib.signer import CryptoSigner

BUILD_PREDICATE = "https://example.com/predicate/build"
APPROVAL_PREDICATE = "https://example.com/predicate/approval"
DEPENDENCY_PREDICATE = "https://example.com/predicate/dependency"


def make_statement(name: str, digest: str, predicate_type: str) -> dict:
    """Builds a minimal in-toto v1 statement."""

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
        "predicate": {},
    }


class GateFixture:
    """Generates signers, envelopes and a matching policy for one release."""

    ARTIFACT = "release/app-1.0.0.tar.gz"
    DIGEST = "a" * 64
    OTHER_DIGEST = "b" * 64

    def __init__(self) -> None:
        self.builder_a = CryptoSigner.generate_ed25519("builder-a-key-1")
        self.builder_a_second = CryptoSigner.generate_ed25519("builder-a-key-2")
        self.builder_b = CryptoSigner.generate_ed25519("builder-b-key-1")
        self.approver = CryptoSigner.generate_ed25519("approver-key-1")
        self.dependency = CryptoSigner.generate_ed25519("dependency-key-1")
        self.outsider = CryptoSigner.generate_ed25519("outsider-key-1")

        self.signers = [
            self.builder_a,
            self.builder_a_second,
            self.builder_b,
            self.approver,
            self.dependency,
            self.outsider,
        ]

        self.policy = self._make_policy()
        self.gate = ReleaseGate(self.policy)

    def _key_dict(self, signer: CryptoSigner) -> dict:
        return signer.public_key.to_dict()

    def _make_policy(self) -> ReleasePolicy:
        keyring = {
            signer.public_key.keyid: self._key_dict(signer) for signer in self.signers
        }
        data = {
            "schema_version": GATE_POLICY_SCHEMA_VERSION,
            "policy_id": "release-gate-demo",
            "policy_version": "2026.11.0",
            "expected_payload_types": [IN_TOTO_PAYLOAD_TYPE],
            "expected_subjects": [
                {"name": self.ARTIFACT, "digest": {"sha256": self.DIGEST}}
            ],
            "keyring": keyring,
            "roles": [
                {
                    "predicate_type": BUILD_PREDICATE,
                    "allowed_keyids": [
                        "builder-a-key-1",
                        "builder-a-key-2",
                        "builder-b-key-1",
                    ],
                    "threshold": 2,
                },
                {
                    "predicate_type": APPROVAL_PREDICATE,
                    "allowed_keyids": ["approver-key-1"],
                    "threshold": 1,
                    "separation_from": [BUILD_PREDICATE],
                },
                {
                    "predicate_type": DEPENDENCY_PREDICATE,
                    "allowed_keyids": ["dependency-key-1"],
                    "threshold": 1,
                },
            ],
            "principals": {
                "builder-a": ["builder-a-key-1", "builder-a-key-2"],
                "builder-b": ["builder-b-key-1"],
                "approver": ["approver-key-1"],
                "dependency-scanner": ["dependency-key-1"],
                "outsider": ["outsider-key-1"],
            },
        }
        return ReleasePolicy.from_dict(data)

    def envelope(
        self,
        signer: CryptoSigner,
        predicate_type: str,
        digest: str | None = None,
        payload_type: str = IN_TOTO_PAYLOAD_TYPE,
        name: str | None = None,
    ) -> dict:
        statement = make_statement(
            name or self.ARTIFACT, digest or self.DIGEST, predicate_type
        )
        payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        envelope = Envelope(payload, payload_type, {})
        envelope.sign(signer)
        return envelope.to_dict()

    def happy_path(self) -> list[dict]:
        return [
            self.envelope(self.builder_a, BUILD_PREDICATE),
            self.envelope(self.builder_b, BUILD_PREDICATE),
            self.envelope(self.approver, APPROVAL_PREDICATE),
            self.envelope(self.dependency, DEPENDENCY_PREDICATE),
        ]


class TestReleaseGate(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = GateFixture()
        self.gate = self.fixture.gate

    def _statuses(self, result) -> dict:
        return {
            gate: any(
                finding.gate == gate and finding.status == GateStatus.FAIL
                for finding in result.findings
            )
            for gate in GATE_ORDER
        }

    def test_happy_path_allows_release(self) -> None:
        result = self.gate.evaluate(self.fixture.happy_path())
        self.assertTrue(result.allowed, result.to_dict())
        self.assertEqual(result.blocking_gates, ())
        self.assertEqual({finding.gate for finding in result.findings}, set(GATE_ORDER))
        self.assertEqual(len(result.evidence), 4)

    def test_envelope_order_does_not_change_decision(self) -> None:
        envelopes = self.fixture.happy_path()
        baseline = self.gate.evaluate(envelopes)
        reordered = self.gate.evaluate(list(reversed(envelopes)))
        self.assertEqual(baseline.allowed, reordered.allowed)
        self.assertEqual(
            sorted(item.payload_digest + item.keyid for item in baseline.evidence),
            sorted(item.payload_digest + item.keyid for item in reordered.evidence),
        )

    def test_duplicate_reports_are_deduplicated(self) -> None:
        build = self.fixture.envelope(self.fixture.builder_a, BUILD_PREDICATE)
        envelopes = [
            build,
            copy.deepcopy(build),
            self.fixture.envelope(self.fixture.builder_b, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.approver, APPROVAL_PREDICATE),
            self.fixture.envelope(self.fixture.dependency, DEPENDENCY_PREDICATE),
        ]
        result = self.gate.evaluate(envelopes)
        self.assertTrue(result.allowed, result.to_dict())
        build_evidence = [
            item for item in result.evidence if item.predicate_type == BUILD_PREDICATE
        ]
        self.assertEqual(len(build_evidence), 2)
        self.assertTrue(
            any(
                finding.status == GateStatus.WARN
                and "Duplicate report" in finding.message
                for finding in result.findings
            )
        )

    def test_multiple_registered_keys_collapse_to_one_principal(self) -> None:
        envelopes = [
            self.fixture.envelope(self.fixture.builder_a, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.builder_a_second, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.approver, APPROVAL_PREDICATE),
            self.fixture.envelope(self.fixture.dependency, DEPENDENCY_PREDICATE),
        ]
        result = self.gate.evaluate(envelopes)
        self.assertFalse(result.allowed)
        self.assertEqual(result.blocking_gates, ("role",))
        threshold_finding = next(
            finding
            for finding in result.findings
            if finding.gate == "role"
            and finding.status == GateStatus.FAIL
            and "requires" in finding.message
        )
        self.assertIn("found 1", threshold_finding.message)

    def test_swapped_artifact_is_rejected_even_if_signatures_verify(self) -> None:
        envelopes = self.fixture.happy_path()
        for envelope in self.gate.evaluate(envelopes).findings:
            self.assertNotEqual(envelope.status, GateStatus.FAIL)
        swapped = []
        for envelope_dict in envelopes:
            tampered = copy.deepcopy(envelope_dict)
            statement = json.loads(Envelope.from_dict(tampered).payload.decode("utf-8"))
            statement["subject"][0]["digest"]["sha256"] = self.fixture.OTHER_DIGEST
            swapped.append(self._resign(statement, envelope_dict))
        result = self.gate.evaluate(swapped)
        self.assertFalse(result.allowed)
        self.assertEqual(result.blocking_gates, ("role",))
        self.assertEqual(result.evidence, ())

    def _resign(self, statement: dict, original: dict) -> dict:
        original_envelope = Envelope.from_dict(copy.deepcopy(original))
        signer = self._signer_for(original_envelope)
        payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        envelope = Envelope(payload, original_envelope.payload_type, {})
        envelope.sign(signer)
        return envelope.to_dict()

    def _signer_for(self, envelope: Envelope) -> CryptoSigner:
        keyid = next(iter(envelope.signatures))
        return next(
            signer
            for signer in self.fixture.signers
            if signer.public_key.keyid == keyid
        )

    def test_approval_independence_violation_blocks_role_gate(self) -> None:
        policy_dict = self.fixture.policy.to_dict()
        for role in policy_dict["roles"]:
            if role["predicate_type"] == APPROVAL_PREDICATE:
                role["allowed_keyids"] = [
                    "approver-key-1",
                    "builder-a-key-1",
                ]
        gate = ReleaseGate(ReleasePolicy.from_dict(policy_dict))
        envelopes = [
            self.fixture.envelope(self.fixture.builder_a, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.builder_b, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.builder_a, APPROVAL_PREDICATE),
            self.fixture.envelope(self.fixture.dependency, DEPENDENCY_PREDICATE),
        ]
        result = gate.evaluate(envelopes)
        self.assertFalse(result.allowed)
        self.assertEqual(result.blocking_gates, ("role",))
        self.assertTrue(
            any(
                finding.status == GateStatus.FAIL
                and "Approval independence" in finding.message
                for finding in result.findings
            )
        )

    def test_signer_type_not_allowed_blocks_role_gate(self) -> None:
        envelopes = [
            self.fixture.envelope(self.fixture.outsider, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.builder_b, BUILD_PREDICATE),
            self.fixture.envelope(self.fixture.approver, APPROVAL_PREDICATE),
            self.fixture.envelope(self.fixture.dependency, DEPENDENCY_PREDICATE),
        ]
        result = self.gate.evaluate(envelopes)
        self.assertFalse(result.allowed)
        self.assertEqual(result.blocking_gates, ("role",))
        self.assertTrue(
            any(
                "not allowed to issue" in finding.message for finding in result.findings
            )
        )

    def test_unknown_key_signature_is_warning_and_envelope_fails_signature(
        self,
    ) -> None:
        rogue = CryptoSigner.generate_ed25519("rogue-key")
        envelopes = self.fixture.happy_path()
        envelopes.append(self.fixture.envelope(rogue, BUILD_PREDICATE))
        result = self.gate.evaluate(envelopes)
        self.assertFalse(result.allowed)
        self.assertIn("signature", result.blocking_gates)
        self.assertTrue(
            any(
                finding.gate == "signature"
                and finding.status == GateStatus.WARN
                and "not registered" in finding.message
                for finding in result.findings
            )
        )

    def test_valid_but_inapplicable_attestation_only_warns(self) -> None:
        envelopes = self.fixture.happy_path()
        envelopes.append(
            self.fixture.envelope(
                self.fixture.approver,
                APPROVAL_PREDICATE,
                digest=self.fixture.OTHER_DIGEST,
            )
        )
        result = self.gate.evaluate(envelopes)
        self.assertTrue(result.allowed, result.to_dict())
        self.assertTrue(
            any(
                finding.gate == "subject"
                and finding.status == GateStatus.WARN
                and "does not apply" in finding.message
                for finding in result.findings
            )
        )

    def test_unexpected_payload_type_only_warns(self) -> None:
        envelopes = self.fixture.happy_path()
        envelopes.append(
            self.fixture.envelope(
                self.fixture.approver,
                APPROVAL_PREDICATE,
                payload_type="https://example.com/OtherEnvelope/v1",
            )
        )
        result = self.gate.evaluate(envelopes)
        self.assertTrue(result.allowed, result.to_dict())
        self.assertTrue(
            any(
                finding.gate == "payload_type" and finding.status == GateStatus.WARN
                for finding in result.findings
            )
        )

    def test_malformed_envelope_blocks_envelope_gate(self) -> None:
        envelopes = self.fixture.happy_path()
        malformed = copy.deepcopy(envelopes[0])
        malformed["payload"] = "not-base64!!!"
        envelopes.append(malformed)
        result = self.gate.evaluate(envelopes)
        self.assertFalse(result.allowed)
        self.assertEqual(result.blocking_gates[0], "envelope")

    def test_no_envelopes_raises_gate_input_error(self) -> None:
        with self.assertRaises(GateInputError):
            self.gate.evaluate([])

    def test_corrupted_signature_fails_signature_gate(self) -> None:
        envelopes = self.fixture.happy_path()
        corrupted = copy.deepcopy(envelopes[0])
        signature = corrupted["signatures"][0]
        raw = bytearray(__import__("base64").b64decode(signature["sig"]))
        raw[0] ^= 0xFF
        signature["sig"] = __import__("base64").b64encode(bytes(raw)).decode()
        envelopes[0] = corrupted
        result = self.gate.evaluate(envelopes)
        self.assertIn("signature", result.blocking_gates)

    def test_policy_round_trip_preserves_version(self) -> None:
        policy_dict = self.fixture.policy.to_dict()
        rebuilt = ReleasePolicy.from_dict(policy_dict)
        self.assertEqual(rebuilt.policy_id, self.fixture.policy.policy_id)
        self.assertEqual(rebuilt.policy_version, self.fixture.policy.policy_version)
        gate = ReleaseGate(rebuilt)
        self.assertTrue(gate.evaluate(self.fixture.happy_path()).allowed)

    def test_unsupported_schema_version_rejected(self) -> None:
        policy_dict = self.fixture.policy.to_dict()
        policy_dict["schema_version"] = 999
        with self.assertRaises(PolicyError):
            ReleasePolicy.from_dict(policy_dict)

    def test_policy_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(self.fixture.policy.to_dict()))
            gate = ReleaseGate.from_policy_file(path)
            result = gate.evaluate(self.fixture.happy_path())
            self.assertTrue(result.allowed)
            self.assertEqual(result.policy_version, "2026.11.0")

    def test_separation_unknown_role_rejected_at_load(self) -> None:
        policy_dict = self.fixture.policy.to_dict()
        policy_dict["roles"][1]["separation_from"] = ["https://example.com/nope"]
        with self.assertRaises(PolicyError):
            ReleasePolicy.from_dict(policy_dict)

    def test_key_registered_to_two_principals_rejected(self) -> None:
        policy_dict = self.fixture.policy.to_dict()
        policy_dict["principals"]["builder-b"] = [
            "builder-b-key-1",
            "builder-a-key-1",
        ]
        with self.assertRaises(PolicyError):
            ReleasePolicy.from_dict(policy_dict)


if __name__ == "__main__":
    unittest.main()
