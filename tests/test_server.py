import unittest

import pytest

from fido2.attestation import (
    AttestationFailureStage,
    AttestationOutcome,
    AttestationPolicy,
    AttestationPolicyError,
)
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    RegistrationResponse,
    UserVerificationRequirement,
)

from .test_ctap2 import _ATT_CRED_DATA, _CRED_ID


class TestPublicKeyCredentialRpEntity(unittest.TestCase):
    def test_id_hash(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        rp_id_hash = (
            b"\xa3y\xa6\xf6\xee\xaf\xb9\xa5^7\x8c\x11\x804\xe2u\x1eh/"
            b"\xab\x9f-0\xab\x13\xd2\x12U\x86\xce\x19G"
        )
        self.assertEqual(rp.id_hash, rp_id_hash)


USER = {"id": b"user_id", "name": "A. User"}


class TestFido2Server(unittest.TestCase):
    def test_register_begin_rp(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        request, state = server.register_begin(USER)

        self.assertEqual(
            request["publicKey"]["rp"], {"id": "example.com", "name": "Example"}
        )

    def test_register_begin_custom_challenge(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"1234567890123456"
        request, state = server.register_begin(USER, challenge=challenge)

        self.assertEqual(request["publicKey"]["challenge"], websafe_encode(challenge))

    def test_register_begin_custom_challenge_too_short(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"123456789012345"
        with self.assertRaises(ValueError):
            request, state = server.register_begin(USER, challenge=challenge)

    def test_authenticate_complete_invalid_signature(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        state = {
            "challenge": "GAZPACHO!",
            "user_verification": UserVerificationRequirement.PREFERRED,
        }
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            "GAZPACHO!",
            "https://example.com",
        )
        _AUTH_DATA = bytes.fromhex(
            "A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947010000001D"
        )
        response = AuthenticationResponse(
            raw_id=_CRED_ID,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=AuthenticatorData(_AUTH_DATA),
                signature=b"INVALID",
            ),
        )

        with self.assertRaisesRegex(ValueError, "Invalid signature."):
            server.authenticate_complete(
                state,
                [AttestedCredentialData(_ATT_CRED_DATA)],
                response,
            )


def _registration_state_and_response(rp, fmt, att_stmt):
    challenge = b"0123456789abcdef"
    state = {
        "challenge": websafe_encode(challenge),
        "user_verification": None,
    }
    client_data = CollectedClientData.create(
        CollectedClientData.TYPE.CREATE, challenge, "https://example.com"
    )
    auth_data = AuthenticatorData(
        (rp.id_hash or b"") + b"\x41" + b"\0\0\0\1" + _ATT_CRED_DATA
    )
    attestation_object = AttestationObject.create(fmt, auth_data, att_stmt)
    response = RegistrationResponse(
        raw_id=_CRED_ID,
        response=AuthenticatorAttestationResponse(
            client_data=client_data,
            attestation_object=attestation_object,
        ),
    )
    return state, response


class TestFido2ServerAttestationPolicy(unittest.TestCase):
    def test_policy_and_verify_attestation_are_mutually_exclusive(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        with pytest.raises(ValueError):
            Fido2Server(
                rp,
                verify_attestation=lambda *args: None,
                attestation_policy=AttestationPolicy(),
            )

    def test_none_attestation_is_unattested_when_allowed(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(
            rp,
            attestation=AttestationConveyancePreference.NONE,
            attestation_policy=AttestationPolicy(allow_none=True),
        )
        state, response = _registration_state_and_response(rp, "none", {})
        auth_data = server.register_complete(state, response)
        self.assertIsNotNone(auth_data.credential_data)
        decision = server.last_attestation_decision
        self.assertIsNotNone(decision)
        self.assertEqual(decision.outcome, AttestationOutcome.UNATTESTED)

    def test_none_attestation_rejected_by_default_policy(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(
            rp,
            attestation_policy=AttestationPolicy(),
        )
        state, response = _registration_state_and_response(rp, "none", {})
        with pytest.raises(AttestationPolicyError) as ctx:
            server.register_complete(state, response)
        self.assertEqual(ctx.value.stage, AttestationFailureStage.POLICY)
        self.assertIsNone(server.last_attestation_decision)
