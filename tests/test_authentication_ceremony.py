from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest import TestCase

from webauthn import AuthenticationCeremony
from webauthn.authentication.ceremony import (
    ChallengeAlreadyConsumed,
    ChallengeExpired,
    ChallengeNotFound,
    ChallengeUserMismatch,
    CredentialUserMismatch,
    CredentialRevoked,
    InMemoryAuthenticationChallengeStore,
    InMemoryCredentialStore,
    SignCountReplay,
    StoredCredential,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
)

from .helpers.synthetic_authenticator import SyntheticAuthenticator


RP_ID = "localhost"
ORIGIN = "http://localhost:5000"
USER_A = b"user-a-handle"
USER_B = b"user-b-handle"
CREDENTIAL_A_ID = b"credential-id-a"
CREDENTIAL_B_ID = b"credential-id-b"


class AuthenticationCeremonyTestBase(TestCase):
    def setUp(self) -> None:
        self.challenge_store = InMemoryAuthenticationChallengeStore()
        self.credential_store = InMemoryCredentialStore()
        self.authenticator_a = SyntheticAuthenticator.create(
            credential_id=CREDENTIAL_A_ID,
            user_handle=USER_A,
            rp_id=RP_ID,
            origin=ORIGIN,
        )
        self.authenticator_b = SyntheticAuthenticator.create(
            credential_id=CREDENTIAL_B_ID,
            user_handle=USER_B,
            rp_id=RP_ID,
            origin=ORIGIN,
        )
        self.credential_store.store_credential(
            self._stored_credential(self.authenticator_a)
        )
        self.credential_store.store_credential(
            self._stored_credential(self.authenticator_b)
        )
        self.ceremony = AuthenticationCeremony(
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=self.challenge_store,
            credential_store=self.credential_store,
        )

    @staticmethod
    def _stored_credential(
        authenticator: SyntheticAuthenticator,
        *,
        sign_count: int = 0,
        revoked: bool = False,
    ) -> StoredCredential:
        return StoredCredential(
            credential_id=authenticator.credential_id,
            user_handle=authenticator.user_handle,
            public_key=authenticator.public_key_cose,
            sign_count=sign_count,
            device_type=authenticator.device_type,
            backed_up=authenticator.backed_up,
            revoked=revoked,
        )

    def _issue_options(self, *,
                       user_handle=USER_A,
                       credential_id=CREDENTIAL_A_ID):
        return self.ceremony.generate_options(
            user_handle=user_handle,
            allow_credentials=[PublicKeyCredentialDescriptor(id=credential_id)],
        )


class TestAuthenticationCeremonyHappyPath(AuthenticationCeremonyTestBase):
    def test_full_ceremony_persists_challenge_metadata_and_updates_counter(self):
        options = self._issue_options()

        record = self.challenge_store.get_challenge(options.challenge)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.rp_id, RP_ID)
        self.assertEqual(record.user_handle, USER_A)
        self.assertEqual([d.id for d in record.allow_credentials], [CREDENTIAL_A_ID])
        self.assertIsNone(record.consumed_at)
        self.assertGreater(record.expires_at, record.issued_at)

        assertion = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=1
        )
        result = self.ceremony.verify_response(assertion)

        self.assertEqual(result.user_handle, USER_A)
        self.assertEqual(result.verification.credential_id, CREDENTIAL_A_ID)
        self.assertEqual(result.verification.new_sign_count, 1)

        stored = self.credential_store.get_credential(CREDENTIAL_A_ID)
        assert stored is not None
        self.assertEqual(stored.sign_count, 1)

        consumed = self.challenge_store.get_challenge(options.challenge)
        assert consumed is not None
        self.assertIsNotNone(consumed.consumed_at)
        self.assertEqual(consumed.consumed_by_credential_id, CREDENTIAL_A_ID)


class TestChallengeReplay(AuthenticationCeremonyTestBase):
    def test_same_challenge_can_only_be_consumed_once(self):
        options = self._issue_options()
        assertion = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=1
        )

        first = self.ceremony.verify_response(assertion)
        self.assertEqual(first.verification.new_sign_count, 1)

        replay = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=2
        )
        with self.assertRaises(ChallengeAlreadyConsumed):
            self.ceremony.verify_response(replay)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNotNone(record.consumed_at)
        self.assertGreaterEqual(record.failed_attempts.get("replay", 0), 1)

    def test_unknown_challenge_is_rejected_without_any_state_change(self):
        assertion = self.authenticator_a.make_assertion(
            challenge=b"never-issued", sign_count=1
        )
        with self.assertRaises(ChallengeNotFound):
            self.ceremony.verify_response(assertion)


class TestCrossUserUserHandle(AuthenticationCeremonyTestBase):
    def test_user_handle_pointing_at_another_user_is_rejected_and_not_consumed(self):
        options = self._issue_options()
        assertion = self.authenticator_a.make_assertion(
            challenge=options.challenge,
            sign_count=1,
            user_handle=USER_B,
        )

        with self.assertRaises(ChallengeUserMismatch):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNone(record.consumed_at)
        self.assertGreaterEqual(
            record.failed_attempts.get("user_handle_mismatch", 0), 1
        )

        # The legitimate owner can still complete the ceremony with the same challenge
        legitimate = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=1, user_handle=USER_A
        )
        result = self.ceremony.verify_response(legitimate)
        self.assertEqual(result.user_handle, USER_A)

    def test_credential_from_another_user_cannot_consume_the_challenge(self):
        options = self.ceremony.generate_options(
            user_handle=USER_A,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=CREDENTIAL_A_ID),
                PublicKeyCredentialDescriptor(id=CREDENTIAL_B_ID),
            ],
        )
        # User B's credential and signature presented against user A's challenge
        assertion = self.authenticator_b.make_assertion(
            challenge=options.challenge, sign_count=1
        )
        with self.assertRaises(CredentialUserMismatch):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNone(record.consumed_at)


class TestConcurrentConsumption(AuthenticationCeremonyTestBase):
    def test_concurrent_submissions_have_a_single_winner(self):
        options = self._issue_options()

        def submit(_):
            assertion = self.authenticator_a.make_assertion(
                challenge=options.challenge, sign_count=1
            )
            try:
                self.ceremony.verify_response(assertion)
                return "success"
            except ChallengeAlreadyConsumed:
                return "replay"

        with ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(executor.map(submit, range(8)))

        self.assertEqual(outcomes.count("success"), 1)
        self.assertEqual(outcomes.count("replay"), 7)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNotNone(record.consumed_at)


class TestPostConsumeFailure(AuthenticationCeremonyTestBase):
    def test_signature_failure_is_observable_and_does_not_update_counter(self):
        options = self._issue_options()
        assertion = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=1
        )
        # Corrupt the signature after all pre-consume binding checks have run,
        # so the challenge gets consumed but the cryptographic check fails.
        assertion.response.signature = b"x" + assertion.response.signature[1:]

        with self.assertRaises(InvalidAuthenticationResponse):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNotNone(record.consumed_at)
        self.assertGreaterEqual(
            record.failed_attempts.get("post_consume_verification_failure", 0), 1
        )

        stored = self.credential_store.get_credential(CREDENTIAL_A_ID)
        assert stored is not None
        self.assertEqual(stored.sign_count, 0)


class TestSignCount(AuthenticationCeremonyTestBase):
    def test_legacy_authenticator_can_always_report_zero(self):
        options = self._issue_options()
        first = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=0
        )
        result = self.ceremony.verify_response(first)
        self.assertEqual(result.verification.new_sign_count, 0)

        stored = self.credential_store.get_credential(CREDENTIAL_A_ID)
        assert stored is not None
        self.assertEqual(stored.sign_count, 0)

        # A second ceremony also allows the all-zero authenticator
        second_options = self._issue_options()
        second = self.authenticator_a.make_assertion(
            challenge=second_options.challenge, sign_count=0
        )
        second_result = self.ceremony.verify_response(second)
        self.assertEqual(second_result.verification.new_sign_count, 0)

    def test_non_zero_counter_must_strictly_increase(self):
        self.credential_store = InMemoryCredentialStore()
        self.credential_store.store_credential(
            self._stored_credential(self.authenticator_a, sign_count=10)
        )
        self.ceremony = AuthenticationCeremony(
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=self.challenge_store,
            credential_store=self.credential_store,
        )
        options = self._issue_options()

        equal = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=10
        )
        with self.assertRaises(SignCountReplay):
            self.ceremony.verify_response(equal)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNone(record.consumed_at)
        self.assertGreaterEqual(record.failed_attempts.get("sign_count_replay", 0), 1)

        # A strictly higher counter on the same challenge still succeeds
        valid = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=11
        )
        result = self.ceremony.verify_response(valid)
        self.assertEqual(result.verification.new_sign_count, 11)


class TestCredentialRevocation(AuthenticationCeremonyTestBase):
    def test_revoked_credential_is_rejected_and_challenge_remains_usable(self):
        self.credential_store = InMemoryCredentialStore()
        self.credential_store.store_credential(
            self._stored_credential(self.authenticator_a, revoked=True)
        )
        self.ceremony = AuthenticationCeremony(
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=self.challenge_store,
            credential_store=self.credential_store,
        )
        options = self._issue_options()
        assertion = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=1
        )

        with self.assertRaises(CredentialRevoked):
            self.ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNone(record.consumed_at)


class TestOptionsExpiry(AuthenticationCeremonyTestBase):
    def test_expired_challenge_is_rejected_with_explicit_error(self):
        frozen_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        clock = {"now": frozen_now}
        ceremony = AuthenticationCeremony(
            rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_store=self.challenge_store,
            credential_store=self.credential_store,
            challenge_timeout=timedelta(minutes=1),
            time_provider=lambda: clock["now"],
        )
        options = ceremony.generate_options(
            user_handle=USER_A,
            allow_credentials=[PublicKeyCredentialDescriptor(id=CREDENTIAL_A_ID)],
        )

        clock["now"] = frozen_now + timedelta(minutes=2)
        assertion = self.authenticator_a.make_assertion(
            challenge=options.challenge, sign_count=1
        )
        with self.assertRaises(ChallengeExpired):
            ceremony.verify_response(assertion)

        record = self.challenge_store.get_challenge(options.challenge)
        assert record is not None
        self.assertIsNone(record.consumed_at)
        self.assertGreaterEqual(record.failed_attempts.get("expired", 0), 1)
