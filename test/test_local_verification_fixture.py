#!/usr/bin/env python

import hashlib
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from lxml import etree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from signxml import (
    CanonicalizationMethod,
    InvalidInput,
    InvalidSignature,
    SignatureConfiguration,
    SignatureMethod,
    XMLSigner,
    XMLVerifier,
    namespaces,
)

_HMAC_KEY = b"signxml-local-test-secret"
_RELAXED_HMAC_POLICY = SignatureConfiguration(
    require_x509=False,
    signature_methods=frozenset({SignatureMethod.HMAC_SHA256}),
)


def _approval_xml():
    return (
        b'<approval xmlns="urn:signxml:approval" xmlns:audit="urn:signxml:audit" Id="approval-1">'
        b'<audit:record case="A001">created</audit:record>'
        b'<audit:record case="A002">approved</audit:record>'
        b"<decision>accepted</decision>"
        b"</approval>"
    )


def _namespace_reorganized_xml():
    return (
        b'<approval xmlns="urn:signxml:approval" Id="approval-1">'
        b'<audit:record xmlns:audit="urn:signxml:audit" case="A001">created</audit:record>'
        b'<audit:record xmlns:audit="urn:signxml:audit" case="A002">approved</audit:record>'
        b"<decision>accepted</decision>"
        b"</approval>"
    )


def _write_evidence(path: Path, name: str, data: bytes) -> None:
    evidence_path = path / name
    evidence_path.write_bytes(data)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _LocalVerificationFixture:
    def __init__(self, directory: str, c14n_method: CanonicalizationMethod):
        self.directory = Path(directory)
        self.c14n_method = c14n_method
        self.exclusive = c14n_method == CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0
        self.signer = XMLSigner(
            signature_algorithm=SignatureMethod.HMAC_SHA256,
            c14n_algorithm=c14n_method,
        )
        self.original_root = etree.fromstring(_approval_xml())
        self.signed_original = self.signer.sign(
            self.original_root,
            key=_HMAC_KEY,
            exclude_c14n_transform_element=False,
        )
        self.rearranged_root = etree.fromstring(_namespace_reorganized_xml())
        signature = self.signed_original.find("ds:Signature", namespaces=namespaces)
        self.rearranged_root.append(deepcopy(signature))

    @property
    def proof_scope(self):
        reference = self.signed_original.find(".//ds:Reference", namespaces=namespaces)
        transform_nodes = reference.findall("ds:Transforms/ds:Transform", namespaces=namespaces)
        signed_info = self.signed_original.find("ds:Signature/ds:SignedInfo", namespaces=namespaces)
        return {
            "reference_uri": reference.get("URI"),
            "declared_transforms": [node.get("Algorithm") for node in transform_nodes],
            "signed_info_c14n": self.c14n_method.value,
            "hmac_key_fingerprint": _sha256_hex(_HMAC_KEY),
            "signed_info_digest": _sha256_hex(self._c14n(signed_info)),
        }

    def payload_without_signature(self, root):
        payload = etree.fromstring(etree.tostring(root))
        signature = payload.find("ds:Signature", namespaces=namespaces)
        payload.remove(signature)
        return payload

    def _c14n(self, node) -> bytes:
        return etree.tostring(node, method="c14n", exclusive=self.exclusive)

    def canonicalized_pair(self):
        original_payload = self.payload_without_signature(self.signed_original)
        rearranged_payload = self.payload_without_signature(self.rearranged_root)
        return self._c14n(original_payload), self._c14n(rearranged_payload)

    def write_evidence(self, case_name: str, verify_results: list[dict[str, str]]) -> Path:
        case_directory = self.directory / case_name
        case_directory.mkdir()
        original_c14n, rearranged_c14n = self.canonicalized_pair()
        _write_evidence(case_directory, "original.xml", etree.tostring(self.signed_original))
        _write_evidence(case_directory, "namespace-reorganized.xml", etree.tostring(self.rearranged_root))
        _write_evidence(case_directory, "original-reference-scope.c14n", original_c14n)
        _write_evidence(case_directory, "rearranged-reference-scope.c14n", rearranged_c14n)
        manifest = {
            "canonicalization_method": self.c14n_method.value,
            "exclusive_c14n": self.exclusive,
            "proof_scope": self.proof_scope,
            "reference_scope_equal": original_c14n == rearranged_c14n,
            "original_reference_sha256": _sha256_hex(original_c14n),
            "rearranged_reference_sha256": _sha256_hex(rearranged_c14n),
            "verification_results": verify_results,
        }
        (case_directory / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        return case_directory


def _verify_case(label: str, root, policy: SignatureConfiguration) -> dict[str, str]:
    try:
        result = XMLVerifier().verify(
            deepcopy(root),
            hmac_key=_HMAC_KEY,
            expect_config=policy,
        )
    except InvalidSignature as exc:
        outcome = "signature-invalid"
        detail = str(exc)
    except InvalidInput as exc:
        outcome = "local-policy-denied"
        detail = str(exc)
    else:
        outcome = "equivalent-and-verifiable"
        detail = result.signed_data.decode("utf-8")
    return {"document": label, "outcome": outcome, "detail": detail}


class TestLocalVerificationFixture(unittest.TestCase):
    def setUp(self):
        self.temp_context = tempfile.TemporaryDirectory()
        self.evidence_root = self.temp_context.name

    def tearDown(self):
        self.temp_context.cleanup()

    def test_inclusive_c14n_namespace_reorganization_changes_reference_scope(self):
        fixture = _LocalVerificationFixture(
            self.evidence_root,
            CanonicalizationMethod.CANONICAL_XML_1_1,
        )
        original_c14n, rearranged_c14n = fixture.canonicalized_pair()
        results = [
            _verify_case("original", fixture.signed_original, _RELAXED_HMAC_POLICY),
            _verify_case("namespace-reorganized", fixture.rearranged_root, _RELAXED_HMAC_POLICY),
        ]
        evidence_directory = fixture.write_evidence("inclusive-invalid", results)

        self.assertNotEqual(original_c14n, rearranged_c14n)
        self.assertEqual(results[0]["outcome"], "equivalent-and-verifiable")
        self.assertEqual(results[1]["outcome"], "signature-invalid")
        self.assertTrue((evidence_directory / "original-reference-scope.c14n").is_file())
        self.assertTrue((evidence_directory / "rearranged-reference-scope.c14n").is_file())

    def test_exclusive_c14n_namespace_reorganization_is_equivalent(self):
        fixture = _LocalVerificationFixture(
            self.evidence_root,
            CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        original_c14n, rearranged_c14n = fixture.canonicalized_pair()
        results = [
            _verify_case("original", fixture.signed_original, _RELAXED_HMAC_POLICY),
            _verify_case("namespace-reorganized", fixture.rearranged_root, _RELAXED_HMAC_POLICY),
        ]
        evidence_directory = fixture.write_evidence("exclusive-equivalent", results)

        self.assertEqual(original_c14n, rearranged_c14n)
        self.assertEqual([result["outcome"] for result in results], ["equivalent-and-verifiable"] * 2)
        self.assertTrue((evidence_directory / "manifest.json").is_file())

    def test_default_x509_policy_denies_otherwise_valid_hmac_signature(self):
        fixture = _LocalVerificationFixture(
            self.evidence_root,
            CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        results = [
            _verify_case("relaxed-hmac-policy", fixture.signed_original, _RELAXED_HMAC_POLICY),
            _verify_case("default-x509-policy", fixture.signed_original, SignatureConfiguration()),
        ]
        evidence_directory = fixture.write_evidence("policy-denied", results)

        self.assertEqual(results[0]["outcome"], "equivalent-and-verifiable")
        self.assertEqual(results[1]["outcome"], "local-policy-denied")
        self.assertIn("X.509", results[1]["detail"])
        manifest = json.loads((evidence_directory / "manifest.json").read_text())
        self.assertEqual(manifest["proof_scope"]["declared_transforms"][0], namespaces.ds + "enveloped-signature")
        self.assertEqual(
            manifest["proof_scope"]["declared_transforms"][1],
            CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0.value,
        )


if __name__ == "__main__":
    unittest.main()
