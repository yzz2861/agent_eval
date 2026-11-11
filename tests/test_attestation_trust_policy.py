from unittest import TestCase

from webauthn import verify_registration_response
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import AttestationFormat
from webauthn.registration.trust_policy import (
    AttestationRejectionReason,
    AttestationTrustPolicy,
    AttestationTrustPolicyError,
    FormatAttestationPolicy,
)

from .helpers.attestation_policy import (
    build_none_credential,
    build_packed_credential,
    der,
    generate_intermediate,
    generate_leaf,
    generate_root,
    pem,
)

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"
CHALLENGE = b"trust-policy-test-challenge-0123456789"
ALLOWED_AAGUID = b"\x01" * 16
DENIED_AAGUID = b"\x02" * 16


class TestAttestationTrustPolicy(TestCase):
    def setUp(self) -> None:
        # root -> intermediate -> leaf, all valid and correctly asserted
        self.root_key, self.root_cert = generate_root()
        self.intermediate_key, self.intermediate_cert = generate_intermediate(
            issuer_key=self.root_key,
            issuer_cert=self.root_cert,
        )
        self.leaf_key, self.leaf_cert = generate_leaf(
            issuer_key=self.intermediate_key,
            issuer_cert=self.intermediate_cert,
        )

        # An unrelated root used to prove roots cannot be shared across formats/chains
        self.other_root_key, self.other_root_cert = generate_root(cn="Unrelated Root CA")

    def _packed_credential(self, *, aaguid: bytes = ALLOWED_AAGUID, x5c=None):
        if x5c is None:
            x5c = [der(self.leaf_cert), der(self.intermediate_cert)]
        return build_packed_credential(
            challenge=CHALLENGE,
            aaguid=aaguid,
            x5c=x5c,
            signing_key=self.leaf_key,
        )

    def _verify(self, credential, policy: AttestationTrustPolicy):
        return verify_registration_response(
            credential=credential,
            expected_challenge=CHALLENGE,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            attestation_trust_policy=policy,
        )

    def _packed_policy(self, **overrides) -> AttestationTrustPolicy:
        settings = {
            "pem_root_certs_bytes": [pem(self.root_cert)],
        }
        settings.update(overrides)
        return AttestationTrustPolicy(
            format_policies={AttestationFormat.PACKED: FormatAttestationPolicy(**settings)}
        )

    def test_packed_full_chain_is_verified(self) -> None:
        policy = self._packed_policy()
        result = self._verify(self._packed_credential(), policy)

        self.assertEqual(result.fmt, AttestationFormat.PACKED)
        self.assertEqual(result.aaguid, "01010101-0101-0101-0101-010101010101")

    def test_packed_chain_completes_with_policy_intermediate(self) -> None:
        # Authenticator only sends its leaf; the missing intermediate lives on the policy
        policy = self._packed_policy(pem_intermediate_certs_bytes=[pem(self.intermediate_cert)])
        credential = self._packed_credential(x5c=[der(self.leaf_cert)])

        result = self._verify(credential, policy)
        self.assertEqual(result.fmt, AttestationFormat.PACKED)

    def test_missing_intermediate_is_rejected_before_result(self) -> None:
        policy = self._packed_policy()
        credential = self._packed_credential(x5c=[der(self.leaf_cert)])

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.CERTIFICATE_CHAIN_INCOMPLETE,
        )
        self.assertNotIn("BEGIN CERTIFICATE", str(raised.exception))

    def test_wrong_root_is_rejected_as_missing_trust_root(self) -> None:
        policy = self._packed_policy(pem_root_certs_bytes=[pem(self.other_root_cert)])

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(self._packed_credential(), policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.TRUST_ROOT_MISSING,
        )

    def test_root_configured_for_other_format_cannot_validate_packed(self) -> None:
        # The same root bytes are trusted only under "tpm", so a packed statement must not use them
        policy = AttestationTrustPolicy(
            format_policies={
                AttestationFormat.TPM: FormatAttestationPolicy(
                    pem_root_certs_bytes=[pem(self.root_cert)]
                )
            }
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(self._packed_credential(), policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.FORMAT_UNSUPPORTED,
        )

    def test_unknown_format_is_rejected(self) -> None:
        from webauthn.helpers import encode_cbor, parse_cbor, bytes_to_base64url

        credential = self._packed_credential()
        attestation_object = parse_cbor(
            base64url_to_bytes(credential["response"]["attestationObject"])
        )
        attestation_object["fmt"] = "future-fmt"
        credential["response"]["attestationObject"] = bytes_to_base64url(
            encode_cbor(attestation_object)
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, self._packed_policy())

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.FORMAT_UNSUPPORTED,
        )

    def test_expired_leaf_certificate_is_rejected(self) -> None:
        expired_leaf_key, expired_leaf_cert = generate_leaf(
            issuer_key=self.intermediate_key,
            issuer_cert=self.intermediate_cert,
            expired=True,
        )
        credential = build_packed_credential(
            challenge=CHALLENGE,
            aaguid=ALLOWED_AAGUID,
            x5c=[der(expired_leaf_cert), der(self.intermediate_cert)],
            signing_key=expired_leaf_key,
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, self._packed_policy())

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.CERTIFICATE_EXPIRED,
        )

    def test_expired_intermediate_certificate_is_rejected(self) -> None:
        expired_intermediate_key, expired_intermediate_cert = generate_intermediate(
            issuer_key=self.root_key,
            issuer_cert=self.root_cert,
            expired=True,
        )
        leaf_key, leaf_cert = generate_leaf(
            issuer_key=expired_intermediate_key,
            issuer_cert=expired_intermediate_cert,
        )
        credential = build_packed_credential(
            challenge=CHALLENGE,
            aaguid=ALLOWED_AAGUID,
            x5c=[der(leaf_cert), der(expired_intermediate_cert)],
            signing_key=leaf_key,
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, self._packed_policy())

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.CERTIFICATE_EXPIRED,
        )

    def test_leaf_key_usage_violation_is_rejected(self) -> None:
        bad_leaf_key, bad_leaf_cert = generate_leaf(
            issuer_key=self.intermediate_key,
            issuer_cert=self.intermediate_cert,
            bad_key_usage=True,
        )
        credential = build_packed_credential(
            challenge=CHALLENGE,
            aaguid=ALLOWED_AAGUID,
            x5c=[der(bad_leaf_cert), der(self.intermediate_cert)],
            signing_key=bad_leaf_key,
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, self._packed_policy())

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.CERTIFICATE_KEY_USAGE,
        )

    def test_aaguid_deny_list_is_enforced(self) -> None:
        policy = self._packed_policy(rejected_aaguids=["02020202-0202-0202-0202-020202020202"])

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(self._packed_credential(aaguid=DENIED_AAGUID), policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.AAGUID_REJECTED,
        )

    def test_aaguid_allow_list_is_enforced(self) -> None:
        policy = self._packed_policy(allowed_aaguids=["01010101-0101-0101-0101-010101010101"])
        # Allowed AAGUID still verifies
        self._verify(self._packed_credential(aaguid=ALLOWED_AAGUID), policy)

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(self._packed_credential(aaguid=DENIED_AAGUID), policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.AAGUID_REJECTED,
        )

    def test_self_attestation_disabled_by_default(self) -> None:
        credential = build_packed_credential(
            challenge=CHALLENGE,
            aaguid=ALLOWED_AAGUID,
            x5c=None,
            signing_key=self.leaf_key,
            credential_key=self.leaf_key,
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, self._packed_policy())

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.SELF_ATTESTATION_REJECTED,
        )

    def test_self_attestation_accepted_when_enabled(self) -> None:
        policy = self._packed_policy(allow_self_attestation=True)
        credential = build_packed_credential(
            challenge=CHALLENGE,
            aaguid=ALLOWED_AAGUID,
            x5c=None,
            signing_key=self.leaf_key,
            credential_key=self.leaf_key,
        )

        result = self._verify(credential, policy)
        self.assertEqual(result.fmt, AttestationFormat.PACKED)

    def test_none_attestation_disabled_by_default(self) -> None:
        credential = build_none_credential(challenge=CHALLENGE, aaguid=ALLOWED_AAGUID)
        policy = AttestationTrustPolicy(
            format_policies={AttestationFormat.NONE: FormatAttestationPolicy()}
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.NONE_ATTESTATION_REJECTED,
        )

    def test_none_attestation_accepted_when_enabled(self) -> None:
        credential = build_none_credential(challenge=CHALLENGE, aaguid=ALLOWED_AAGUID)
        policy = AttestationTrustPolicy(
            format_policies={
                AttestationFormat.NONE: FormatAttestationPolicy(
                    allowed_aaguids=["01010101-0101-0101-0101-010101010101"]
                )
            },
            allow_none_attestation=True,
        )

        result = self._verify(credential, policy)
        self.assertEqual(result.fmt, AttestationFormat.NONE)

    def test_rejection_is_still_an_invalid_registration_response(self) -> None:
        policy = self._packed_policy(rejected_aaguids=["02020202-0202-0202-0202-020202020202"])
        with self.assertRaises(InvalidRegistrationResponse) as raised:
            self._verify(self._packed_credential(aaguid=DENIED_AAGUID), policy)

        self.assertIsInstance(raised.exception, AttestationTrustPolicyError)
        self.assertEqual(raised.exception.reason, AttestationRejectionReason.AAGUID_REJECTED)

    def test_intermediate_basic_constraints_violation_is_rejected(self) -> None:
        bad_intermediate_key, bad_intermediate_cert = generate_intermediate(
            issuer_key=self.root_key,
            issuer_cert=self.root_cert,
            not_ca=True,
        )
        leaf_key, leaf_cert = generate_leaf(
            issuer_key=bad_intermediate_key,
            issuer_cert=bad_intermediate_cert,
        )
        credential = build_packed_credential(
            challenge=CHALLENGE,
            aaguid=ALLOWED_AAGUID,
            x5c=[der(leaf_cert), der(bad_intermediate_cert)],
            signing_key=leaf_key,
        )

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(credential, self._packed_policy())

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.CERTIFICATE_BASIC_CONSTRAINTS,
        )

    def test_signature_algorithm_allow_list_is_enforced(self) -> None:
        from webauthn.helpers.cose import COSEAlgorithmIdentifier

        # ECDSA-SHA256 attestation restricted to a COSE alg neither the statement nor certificate use
        policy = self._packed_policy(allowed_signature_algs=[COSEAlgorithmIdentifier.EDDSA])

        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(self._packed_credential(), policy)

        self.assertEqual(
            raised.exception.reason,
            AttestationRejectionReason.SIGNATURE_ALGORITHM_REJECTED,
        )

    def test_error_messages_do_not_contain_certificate_material(self) -> None:
        policy = self._packed_policy(pem_root_certs_bytes=[pem(self.other_root_cert)])
        with self.assertRaises(AttestationTrustPolicyError) as raised:
            self._verify(self._packed_credential(), policy)

        message = str(raised.exception)
        self.assertNotIn("BEGIN CERTIFICATE", message)
        self.assertNotIn("END CERTIFICATE", message)
        self.assertNotIn(der(self.intermediate_cert), message.encode("utf-8", "ignore"))
