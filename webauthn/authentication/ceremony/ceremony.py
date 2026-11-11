from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Union

from webauthn.authentication.ceremony.exceptions import (
    BackupStateChanged,
    ChallengeAlreadyConsumed,
    ChallengeExpired,
    ChallengeNotFound,
    ChallengePurposeMismatch,
    ChallengeUserMismatch,
    CredentialNotAllowed,
    CredentialNotFound,
    CredentialRevoked,
    CredentialUserMismatch,
    SignCountReplay,
)
from webauthn.authentication.ceremony.storage import (
    AuthenticationChallengeRecord,
    AuthenticationChallengeStore,
    CeremonyPurpose,
    CredentialStore,
    InMemoryAuthenticationChallengeStore,
    InMemoryCredentialStore,
    StoredCredential,
)
from webauthn.authentication.generate_authentication_options import (
    generate_authentication_options,
)
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
    verify_authentication_response,
)
from webauthn.helpers.exceptions import (
    InvalidBackupFlags,
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
)
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.parse_authenticator_data import parse_authenticator_data
from webauthn.helpers.parse_client_data_json import parse_client_data_json
from webauthn.helpers.structs import (
    AuthenticationCredential,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)


@dataclass
class AuthenticationCeremonyResult:
    """The outcome of a successful stateful authentication ceremony.

    Wraps the stateless verification result together with the bound user so the
    caller never has to trust a userHandle from the request body.
    """

    verification: VerifiedAuthentication
    user_handle: Optional[bytes]
    challenge_record: AuthenticationChallengeRecord


class AuthenticationCeremony:
    """Stateful, transactional layer around WebAuthn authentication.

    Unlike the stateless `generate_authentication_options()` and
    `verify_authentication_response()` helpers, a ceremony persists every
    issued challenge and enforces single-use semantics. A challenge records
    its purpose, RP ID, allowed credentials, optional bound user, issuance
    time and expiry time, and verification consumes it atomically before the
    credential and its sign count are checked and updated.

    Both stores are injected, so applications can swap the in-memory
    implementations for database-backed ones implementing the same protocols.
    """

    def __init__(
        self,
        *,
        rp_id: str,
        expected_origin: Union[str, List[str]],
        challenge_store: Optional[AuthenticationChallengeStore] = None,
        credential_store: Optional[CredentialStore] = None,
        challenge_timeout: timedelta = timedelta(minutes=1),
        require_user_verification: bool = False,
        time_provider: Optional[Callable[[], datetime]] = None,
    ) -> None:
        """Args:
        - `rp_id`: The Relying Party ID used for every ceremony.
        - `expected_origin`: The origin (or list of origins) responses must use.
        - `challenge_store`: Storage for challenge records. Defaults to a
          thread-safe in-memory store, suitable mainly for tests.
        - `credential_store`: Storage for registered credentials. Defaults to a
          thread-safe in-memory store, suitable mainly for tests.
        - `challenge_timeout`: How long an issued challenge remains valid.
        - `require_user_verification`: Whether responses must set the UV flag.
        - `time_provider`: Injectable clock (must return timezone-aware
          datetimes); defaults to UTC now. Tests use this to exercise expiry.
        """
        if not rp_id:
            raise ValueError("rp_id cannot be an empty string")

        self.rp_id = rp_id
        self.expected_origin = expected_origin
        self.challenge_store = challenge_store or InMemoryAuthenticationChallengeStore()
        self.credential_store = credential_store or InMemoryCredentialStore()
        self.challenge_timeout = challenge_timeout
        self.require_user_verification = require_user_verification
        self.time_provider = time_provider or (lambda: datetime.now(timezone.utc))

    def generate_options(
        self,
        *,
        user_handle: Optional[bytes] = None,
        allow_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None,
        challenge: Optional[bytes] = None,
        timeout: int = 60000,
        user_verification: UserVerificationRequirement = (
            UserVerificationRequirement.PREFERRED
        ),
    ) -> PublicKeyCredentialRequestOptions:
        """Generate authentication options and persist a bound challenge record.

        The returned options are identical in shape to those produced by the
        stateless `generate_authentication_options()` helper; the difference
        is that a challenge record is written first, capturing the purpose,
        RP ID, allowed credentials, optional user handle and timing metadata.
        """
        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            timeout=timeout,
            allow_credentials=allow_credentials,
            user_verification=user_verification,
        )

        issued_at = self.time_provider()
        record = AuthenticationChallengeRecord(
            challenge=options.challenge,
            purpose=CeremonyPurpose.AUTHENTICATION,
            rp_id=self.rp_id,
            allow_credentials=list(options.allow_credentials or []),
            user_handle=user_handle,
            user_verification=user_verification,
            issued_at=issued_at,
            expires_at=issued_at + self.challenge_timeout,
        )
        self.challenge_store.store_challenge(record)

        return options

    def verify_response(
        self,
        credential: Union[str, Dict[str, Any], AuthenticationCredential],
    ) -> AuthenticationCeremonyResult:
        """Verify an authentication response against a stored, single-use challenge.

        All ownership checks happen before the challenge is consumed, so a
        rejected submission can never burn another user's challenge. The
        consume operation itself is atomic, so concurrent submissions of the
        same challenge have at most one winner. The sign count and backup
        state of the winning credential are persisted on success.
        """
        if isinstance(credential, (str, dict)):
            parsed_credential = parse_authentication_credential_json(credential)
        else:
            parsed_credential = credential

        response_challenge = self._extract_challenge(parsed_credential)
        record = self._load_valid_record(response_challenge)
        self._assert_credential_allowed(record, parsed_credential)

        stored_credential = self.credential_store.get_credential(
            parsed_credential.raw_id
        )
        if stored_credential is None:
            self._fail(record, "credential_not_found")
            raise CredentialNotFound(
                f"No registered credential with id {parsed_credential.id}"
            )

        self._assert_credential_binding(
            record, stored_credential, parsed_credential
        )
        self._assert_not_revoked(record, stored_credential)
        self._assert_backup_flags(
            record, stored_credential, parsed_credential
        )
        auth_data = parse_authenticator_data(
            parsed_credential.response.authenticator_data
        )
        self._assert_sign_count(record, stored_credential, auth_data.sign_count)

        # Atomic gate: from this point on the challenge cannot be consumed by
        # anyone else. Every check above this line leaves the record untouched.
        consumed = self.challenge_store.consume_challenge(
            response_challenge, parsed_credential.raw_id
        )
        if consumed is None:
            # Lost a race or the record was removed between the read and the
            # atomic update. There is deliberately nothing left to consume.
            raise ChallengeAlreadyConsumed(
                "Challenge has already been consumed or no longer exists"
            )

        try:
            verification = verify_authentication_response(
                credential=parsed_credential,
                expected_challenge=record.challenge,
                expected_rp_id=record.rp_id,
                expected_origin=self.expected_origin,
                credential_public_key=stored_credential.public_key,
                credential_current_sign_count=stored_credential.sign_count,
                require_user_verification=self.require_user_verification,
            )
        except InvalidAuthenticationResponse:
            # The challenge is already consumed; record the rejection so the
            # replay/forgery attempt remains observable to the RP.
            self.challenge_store.record_failed_attempt(
                record.challenge, "post_consume_verification_failure"
            )
            raise

        self.credential_store.update_sign_count_and_backup_state(
            credential_id=stored_credential.credential_id,
            sign_count=verification.new_sign_count,
            backed_up=verification.credential_backed_up,
        )

        return AuthenticationCeremonyResult(
            verification=verification,
            user_handle=stored_credential.user_handle,
            challenge_record=record,
        )

    def _extract_challenge(self, credential: AuthenticationCredential) -> bytes:
        try:
            client_data = parse_client_data_json(credential.response.client_data_json)
        except Exception as exc:
            raise InvalidJSONStructure(
                "clientDataJSON was malformed. See __cause__ for more info"
            ) from exc
        return client_data.challenge

    def _load_valid_record(self, challenge: bytes) -> AuthenticationChallengeRecord:
        record = self.challenge_store.get_challenge(challenge)
        if record is None:
            raise ChallengeNotFound("No challenge record found for response challenge")

        if record.consumed:
            # The second submission of the same challenge finds no consumable
            # record in the store; make that explicit to callers and monitors.
            self.challenge_store.record_failed_attempt(challenge, "replay")
            raise ChallengeAlreadyConsumed("Challenge has already been consumed")

        if record.purpose != CeremonyPurpose.AUTHENTICATION:
            self._fail(record, "purpose_mismatch")
            raise ChallengePurposeMismatch(
                f"Challenge purpose was {record.purpose}, expected authentication"
            )

        if record.rp_id != self.rp_id:
            self._fail(record, "rp_id_mismatch")
            raise InvalidAuthenticationResponse(
                f'Challenge was issued for RP ID "{record.rp_id}", '
                f'expected "{self.rp_id}"'
            )

        now = self.time_provider()
        if now >= record.expires_at:
            self._fail(record, "expired")
            raise ChallengeExpired(
                f"Challenge expired at {record.expires_at.isoformat()}"
            )

        return record

    def _assert_credential_allowed(
        self,
        record: AuthenticationChallengeRecord,
        credential: AuthenticationCredential,
    ) -> None:
        if not record.allow_credentials:
            return
        allowed_ids = {descriptor.id for descriptor in record.allow_credentials}
        if credential.raw_id not in allowed_ids:
            self._fail(record, "credential_not_allowed")
            raise CredentialNotAllowed(
                f"Credential {credential.id} was not included in allowCredentials"
            )

    def _assert_credential_binding(
        self,
        record: AuthenticationChallengeRecord,
        stored_credential: StoredCredential,
        credential: AuthenticationCredential,
    ) -> None:
        # The challenge binding is the authority for which user is logging in.
        # A userHandle in the request body can only confirm that binding and
        # can never override it, including when the challenge had no user.
        if record.user_handle is not None:
            if stored_credential.user_handle != record.user_handle:
                self._fail(record, "credential_user_mismatch")
                raise CredentialUserMismatch(
                    "Credential belongs to a different user than the challenge binding"
                )
            response_user_handle = credential.response.user_handle
            if (
                response_user_handle is not None
                and response_user_handle != record.user_handle
            ):
                self._fail(record, "user_handle_mismatch")
                raise ChallengeUserMismatch(
                    "Response userHandle did not match the user bound to the challenge"
                )
        elif credential.response.user_handle is not None:
            # A usernameless ceremony cannot be steered toward an account by a
            # userHandle supplied in the request body.
            if stored_credential.user_handle != credential.response.user_handle:
                self._fail(record, "user_handle_mismatch")
                raise ChallengeUserMismatch(
                    "Response userHandle did not match the credential's owner"
                )

    def _assert_not_revoked(
        self,
        record: AuthenticationChallengeRecord,
        stored_credential: StoredCredential,
    ) -> None:
        if stored_credential.revoked:
            self._fail(record, "credential_revoked")
            raise CredentialRevoked(
                f"Credential {stored_credential.credential_id.hex()} has been revoked"
            )

    def _assert_backup_flags(
        self,
        record: AuthenticationChallengeRecord,
        stored_credential: StoredCredential,
        credential: AuthenticationCredential,
    ) -> None:
        response_flags = parse_authenticator_data(
            credential.response.authenticator_data
        ).flags
        # A single-device (non-backup-eligible) credential reporting that it is
        # actually backed up is an impossible state and must fail closed.
        if not response_flags.be and response_flags.bs:
            self._fail(record, "invalid_backup_flags")
            raise InvalidBackupFlags(
                "Single-device credential indicated that it was backed up, "
                "which should be impossible."
            )
        # The BE flag is a fixed property of the authenticator at registration.
        # A change after registration indicates a confused/forged authenticator.
        expected_device_type = stored_credential.device_type
        response_is_multi_device = response_flags.be
        response_device_type = (
            CredentialDeviceType.MULTI_DEVICE
            if response_is_multi_device
            else CredentialDeviceType.SINGLE_DEVICE
        )
        if response_device_type != expected_device_type:
            self._fail(record, "backup_state_changed")
            raise BackupStateChanged(
                "Credential backup eligibility changed after registration"
            )

    def _assert_sign_count(
        self,
        record: AuthenticationChallengeRecord,
        stored_credential: StoredCredential,
        response_sign_count: int,
    ) -> None:
        # WebAuthn §6.1.1: an authenticator that always reports 0 is exempt from
        # the clone-detection check. Otherwise each non-zero count must strictly
        # exceed the stored one; equal or lower values are treated as replays.
        if response_sign_count == 0 and stored_credential.sign_count == 0:
            return
        if response_sign_count <= stored_credential.sign_count:
            self._fail(record, "sign_count_replay")
            raise SignCountReplay(
                f"Response sign count of {response_sign_count} was not greater than "
                f"current count of {stored_credential.sign_count}"
            )

    def _fail(self, record: AuthenticationChallengeRecord, reason: str) -> None:
        self.challenge_store.record_failed_attempt(record.challenge, reason)
