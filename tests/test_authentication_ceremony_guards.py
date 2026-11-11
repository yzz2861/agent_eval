from datetime import datetime, timedelta, timezone
from unittest import TestCase

from webauthn import AuthenticationCeremony
from webauthn.authentication.ceremony import (
    BackupStateChanged,
    CeremonyPurpose,
    ChallengeUserMismatch,
    ChallengePurposeMismatch,
    CredentialNotAllowed,
    InMemoryAuthenticationChallengeStore,
    InMemoryCredentialStore,
    StoredCredential,
)
from webauthn.authentication.ceremony.storage import AuthenticationChallengeRecord
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidBackupFlags,
)
from webauthn.helpers.structs import (
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from .helpers.synthetic_authenticator import SyntheticAuthenticator

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"
USER_A = b"user-a-handle"
CREDENTIAL_A_ID = b"credential-id-a"


class AuthenticationCeremonyGuardTestBase(TestCase):
    def setUp(self) -> None:
        self.challenge_store = InMemoryAuthenticationChallengeStore()
        self.credential_store = InMemoryCredentialStore()
        self.authenticator = SyntheticAuthenticator.create(
            credential_id=CREDENTIAL_A_ID,
            user_handle=USER_A,
            rp_id=RP_ID,
            origin=ORIGIN,
        )
        self.credential_store.store_credential(
            StoredCredential(
                credential_id=CREDENTIAL_A_ID,
                user_handle=USER_A,
                public_key=self.authenticator.public_key_cose,
                sign_count=0,
                device_type=CredentialDeviceType.SINGLE_DEVICE,
                backed_up=False,
            )
        )
        self.ceremony = AuthenticationCeremony(
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=self.challenge_store,
            credential_store=self.credential_store,
        )
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.now = now
        self.ceremony.time_provider = lambda: now

    def _store_challenge(
        self,
        *,
        challenge=b"stored-challenge",
        purpose=CeremonyPurpose.AUTHENTICATION,
        rp_id=RP_ID,
        user_handle=USER_A,
        allow_credentials=None,
    ):
        record = AuthenticationChallengeRecord(
            challenge=challenge,
            purpose=purpose,
            rp_id=rp_id,
            allow_credentials=allow_credentials
            if allow_credentials is not None
            else [PublicKeyCredentialDescriptor(id=CREDENTIAL_A_ID)],
            user_handle=user_handle,
            user_verification=UserVerificationRequirement.PREFERRED,
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=1),
        )
        self.challenge_store.store_challenge(record)
        return record


class TestCeremonyGuards(AuthenticationCeremonyGuardTestBase):
    def test_registration_purpose_challenge_cannot_be_used_for_login(self):
        self._store_challenge(purpose=CeremonyPurpose.REGISTRATION)
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1
        )
        with self.assertRaises(ChallengePurposeMismatch):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(b"stored-challenge")
        assert record is not None
        self.assertIsNone(record.consumed_at)

    def test_challenge_bound_to_another_rp_id_is_rejected(self):
        self._store_challenge(rp_id="example.com")
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1
        )
        with self.assertRaises(InvalidAuthenticationResponse):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(b"stored-challenge")
        assert record is not None
        self.assertIsNone(record.consumed_at)

    def test_unexpected_origin_is_rejected(self):
        other_origin_authenticator = SyntheticAuthenticator.create(
            credential_id=CREDENTIAL_A_ID,
            user_handle=USER_A,
            rp_id=RP_ID,
            origin="https://evil.example",
        )
        # Reuse the registered keypair so only the origin check can fail
        other_origin_authenticator.private_key = self.authenticator.private_key
        self._store_challenge()
        assertion = other_origin_authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1
        )
        with self.assertRaises(InvalidAuthenticationResponse):
            self.ceremony.verify_response(assertion)

    def test_credential_outside_allow_credentials_is_rejected(self):
        self._store_challenge(
            allow_credentials=[PublicKeyCredentialDescriptor(id=b"some-other-cred")]
        )
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1
        )
        with self.assertRaises(CredentialNotAllowed):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(b"stored-challenge")
        assert record is not None
        self.assertIsNone(record.consumed_at)

    def test_backup_eligibility_change_after_registration_is_rejected(self):
        self._store_challenge()
        # Registered as single-device (BE=0) but the assertion claims BE=1
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1, be=True, bs=False
        )
        with self.assertRaises(BackupStateChanged):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(b"stored-challenge")
        assert record is not None
        self.assertIsNone(record.consumed_at)

    def test_impossible_single_device_backed_up_state_is_rejected_before_consume(self):
        self._store_challenge()
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1, be=False, bs=True
        )
        with self.assertRaises(InvalidBackupFlags):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(b"stored-challenge")
        assert record is not None
        self.assertIsNone(record.consumed_at)
        self.assertGreaterEqual(
            record.failed_attempts.get("invalid_backup_flags", 0), 1
        )

    def test_usernameless_ceremony_uses_credential_owner_without_request_username(self):
        # No user bound to the challenge: the credential record determines the user
        self._store_challenge(user_handle=None)
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge", sign_count=1, user_handle=USER_A
        )
        result = self.ceremony.verify_response(assertion)
        self.assertEqual(result.user_handle, USER_A)

    def test_usernameless_ceremony_rejects_spoofed_user_handle(self):
        self._store_challenge(user_handle=None)
        assertion = self.authenticator.make_assertion(
            challenge=b"stored-challenge",
            sign_count=1,
            user_handle=b"attacker-handle",
        )
        with self.assertRaises(ChallengeUserMismatch):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(b"stored-challenge")
        assert record is not None
        self.assertIsNone(record.consumed_at)
