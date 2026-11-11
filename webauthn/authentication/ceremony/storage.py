from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Dict, List, Optional, Protocol, runtime_checkable

from webauthn.helpers.structs import (
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)


class CeremonyPurpose(str, Enum):
    """The kind of ceremony a challenge was issued for.

    A challenge issued for one purpose must never be accepted for another, so
    that e.g. a registration challenge cannot be replayed during login.
    """

    AUTHENTICATION = "authentication"
    REGISTRATION = "registration"


@dataclass
class AuthenticationChallengeRecord:
    """A server-side record of an issued authentication challenge.

    Attributes:
        `challenge`: The random challenge bytes shared with the authenticator.
        `purpose`: The ceremony this challenge was issued for.
        `rp_id`: The RP ID bound to the authentication options.
        `allow_credentials`: Credential descriptors the response is restricted to.
        `user_handle`: The user the challenge was bound to, when known. May be
          `None` for a usernameless (discoverable credential) ceremony.
        `user_verification`: The user verification requirement sent in the options.
        `issued_at`: When the challenge record was created.
        `expires_at`: When the challenge stops being valid.
        `consumed_at`: When the challenge was atomically consumed, if ever.
        `consumed_by_credential_id`: The credential that consumed the challenge.
        `failed_attempts`: Observability counter for rejected submissions, keyed
          by a short reason string. A failed verification never removes the
          challenge, so the legitimate owner can still complete the ceremony.
    """

    challenge: bytes
    purpose: CeremonyPurpose
    rp_id: str
    allow_credentials: List[PublicKeyCredentialDescriptor]
    user_handle: Optional[bytes]
    user_verification: UserVerificationRequirement
    issued_at: datetime
    expires_at: datetime
    consumed_at: Optional[datetime] = None
    consumed_by_credential_id: Optional[bytes] = None
    failed_attempts: Dict[str, int] = field(default_factory=dict)

    @property
    def consumed(self) -> bool:
        return self.consumed_at is not None


@dataclass
class StoredCredential:
    """A server-side record of a registered credential.

    Multi-credential users are supported by looking this record up through the
    credential store using the credential id submitted in the response.

    Attributes:
        `credential_id`: The credential's unique identifier.
        `user_handle`: The user the credential belongs to.
        `public_key`: The CBOR-encoded public key stored at registration time.
        `sign_count`: The last known authenticator sign count.
        `device_type`: Whether the credential is single- or multi-device.
        `backed_up`: The most recent backup state (`BS`) flag.
        `revoked`: Whether the credential has been revoked.
    """

    credential_id: bytes
    user_handle: bytes
    public_key: bytes
    sign_count: int
    device_type: CredentialDeviceType
    backed_up: bool
    revoked: bool = False


@runtime_checkable
class AuthenticationChallengeStore(Protocol):
    """Pluggable storage for authentication challenge records.

    Implementations backed by a database must ensure that `consume_challenge`
    is atomic: concurrent submissions of the same challenge may have at most
    one successful consumer. A typical implementation is a single conditional
    UPDATE ... WHERE challenge = ? AND consumed_at IS NULL statement.
    """

    def store_challenge(self, record: AuthenticationChallengeRecord) -> None:
        """Persist a newly issued challenge record."""
        ...

    def get_challenge(
        self, challenge: bytes
    ) -> Optional[AuthenticationChallengeRecord]:
        """Return the challenge record without mutating it, or `None` if absent."""
        ...

    def consume_challenge(
        self,
        challenge: bytes,
        credential_id: bytes,
    ) -> Optional[AuthenticationChallengeRecord]:
        """Atomically mark a challenge as consumed and return its record.

        Returns `None` when the challenge does not exist or was already
        consumed. Only the first caller receives the record. `credential_id`
        is recorded alongside the consumption for auditability.
        """
        ...

    def record_failed_attempt(self, challenge: bytes, reason: str) -> None:
        """Increment the observability counter for a rejected submission."""
        ...


@runtime_checkable
class CredentialStore(Protocol):
    """Pluggable storage for registered credentials."""

    def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]:
        """Return the stored credential for an id, or `None` if not registered."""
        ...

    def update_sign_count_and_backup_state(
        self,
        credential_id: bytes,
        sign_count: int,
        backed_up: bool,
    ) -> None:
        """Persist the new sign count and backup state after a successful login."""
        ...


class InMemoryAuthenticationChallengeStore:
    """Reference `AuthenticationChallengeStore` implementation for tests and
    single-process deployments.

    A single re-entrant lock makes every read and the consume operation atomic,
    so concurrent threads can consume a given challenge at most once.
    """

    def __init__(self) -> None:
        self._challenges: Dict[bytes, AuthenticationChallengeRecord] = {}
        self._lock = RLock()

    def store_challenge(self, record: AuthenticationChallengeRecord) -> None:
        with self._lock:
            self._challenges[record.challenge] = record

    def get_challenge(
        self, challenge: bytes
    ) -> Optional[AuthenticationChallengeRecord]:
        with self._lock:
            return self._challenges.get(challenge)

    def consume_challenge(
        self,
        challenge: bytes,
        credential_id: bytes,
    ) -> Optional[AuthenticationChallengeRecord]:
        with self._lock:
            record = self._challenges.get(challenge)
            if record is None or record.consumed:
                return None
            record.consumed_at = datetime.now(timezone.utc)
            record.consumed_by_credential_id = credential_id
            return record

    def record_failed_attempt(self, challenge: bytes, reason: str) -> None:
        with self._lock:
            record = self._challenges.get(challenge)
            if record is not None:
                record.failed_attempts[reason] = (
                    record.failed_attempts.get(reason, 0) + 1
                )


class InMemoryCredentialStore:
    """Reference `CredentialStore` implementation for tests and single-process
    deployments."""

    def __init__(self) -> None:
        self._credentials: Dict[bytes, StoredCredential] = {}
        self._lock = RLock()

    def store_credential(self, credential: StoredCredential) -> None:
        with self._lock:
            self._credentials[credential.credential_id] = credential

    def get_credential(self, credential_id: bytes) -> Optional[StoredCredential]:
        with self._lock:
            return self._credentials.get(credential_id)

    def update_sign_count_and_backup_state(
        self,
        credential_id: bytes,
        sign_count: int,
        backed_up: bool,
    ) -> None:
        with self._lock:
            credential = self._credentials.get(credential_id)
            if credential is not None:
                credential.sign_count = sign_count
                credential.backed_up = backed_up
