import unittest

from fido2.rpid import (
    InvalidConfigurationError,
    OriginMismatchError,
    RpIdMismatchError,
)
from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticationResponse,
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


class TestFido2ServerOriginPolicy(unittest.TestCase):
    ORIGIN = "https://example.com"
    AUTH_DATA = bytes.fromhex(
        "A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947010000001D"
    )

    def _server(self, allowed_origins=None):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        return Fido2Server(rp, allowed_origins=allowed_origins)

    def _assertion(self, origin):
        state = {
            "challenge": "GAZPACHO!",
            "user_verification": UserVerificationRequirement.PREFERRED,
        }
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            "GAZPACHO!",
            origin,
        )
        response = AuthenticationResponse(
            raw_id=_CRED_ID,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=AuthenticatorData(self.AUTH_DATA),
                signature=b"INVALID",
            ),
        )
        return state, response

    def test_allowed_origin_passes_origin_check(self):
        # The signature check fails afterwards, proving the origin was accepted.
        server = self._server([self.ORIGIN])
        state, response = self._assertion(self.ORIGIN)
        with self.assertRaisesRegex(ValueError, "Invalid signature"):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )

    def test_evil_subdomain_origin_rejected(self):
        server = self._server([self.ORIGIN])
        state, response = self._assertion("https://evil.login.example.com")
        with self.assertRaises(OriginMismatchError) as ctx:
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )
        self.assertNotIn("evil", str(ctx.exception))
        self.assertNotIn(_CRED_ID.hex(), str(ctx.exception))

    def test_empty_allow_list_denies_every_origin(self):
        server = self._server([])
        state, response = self._assertion(self.ORIGIN)
        with self.assertRaises(OriginMismatchError):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )

    def test_userinfo_and_trailing_dot_origin_handling(self):
        server = self._server([self.ORIGIN])
        state, response = self._assertion("https://user@example.com")
        with self.assertRaises(OriginMismatchError):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )
        # Trailing dot and default port normalize to the allowed origin.
        state, response = self._assertion("https://example.com.:443")
        with self.assertRaisesRegex(ValueError, "Invalid signature"):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )

    def test_non_default_port_must_match(self):
        server = self._server(["https://example.com:8443"])
        state, response = self._assertion("https://example.com")
        with self.assertRaises(OriginMismatchError):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )

    def test_rp_id_mismatch_is_distinct_error(self):
        # An RP configured for another.com rejects the example.com RP ID hash
        # with an RP ID specific error rather than an origin error.
        other_rp = PublicKeyCredentialRpEntity(name="Other", id="other.com")
        server = Fido2Server(
            other_rp, allowed_origins=[self.ORIGIN, "https://other.com"]
        )
        state, response = self._assertion(self.ORIGIN)
        with self.assertRaises(RpIdMismatchError):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )

    def test_invalid_configuration_raises_distinct_error(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="co.uk")
        with self.assertRaises(InvalidConfigurationError):
            Fido2Server(rp, allowed_origins=["https://foobar.co.uk"])
        rp2 = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        with self.assertRaises(InvalidConfigurationError):
            Fido2Server(rp2, allowed_origins=["https://user@example.com"])

    def test_legacy_mode_keeps_suffix_behavior(self):
        server = self._server()
        state, response = self._assertion("https://register.example.com")
        with self.assertRaisesRegex(ValueError, "Invalid signature"):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )
        state, response = self._assertion("http://example.com")
        with self.assertRaisesRegex(ValueError, "Invalid origin"):
            server.authenticate_complete(
                state, [AttestedCredentialData(_ATT_CRED_DATA)], response
            )

    def test_registration_uses_same_origin_policy(self):
        server = self._server([self.ORIGIN])
        _, state = server.register_begin(USER)
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.CREATE,
            state["challenge"],
            "https://evil.example.com",
        )
        attestation = AttestationObject.create(
            "none",
            AuthenticatorData.create(
                server.rp.id_hash or b"",
                AuthenticatorData.FLAG.UP,
                0,
            ),
            {},
        )
        response = RegistrationResponse(
            raw_id=_CRED_ID,
            response=AuthenticatorAttestationResponse(
                client_data=client_data,
                attestation_object=attestation,
            ),
        )
        with self.assertRaises(OriginMismatchError):
            server.register_complete(state, response)
