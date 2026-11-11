from dataclasses import dataclass
from typing import Optional, Protocol, Tuple, runtime_checkable

from .exceptions import InvalidCredentialBackupState
from .parse_backup_flags import (
    CredentialBackupStateDecision,
    evaluate_credential_backup_state,
)
from .structs import AuthenticatorDataFlags, CredentialBackupStateChange, CredentialDeviceType


@dataclass
class CredentialBackupState:
    """The backup-related portion of a credential record held by the Relying Party."""

    credential_device_type: Optional[CredentialDeviceType]
    credential_backed_up: Optional[bool]


@runtime_checkable
class CredentialBackupStateStore(Protocol):
    """Callbacks a Relying Party implements to connect the library to its credential store.

    No credential state is kept inside the library: every read and write goes through these
    callbacks, so concurrent requests and sharded storage are the caller's to control.
    """

    def get_credential_backup_state(
        self, credential_id: bytes
    ) -> Optional[CredentialBackupState]:
        """Return the persisted backup state for a credential ID.

        Conventions:
            - Return `None` when the credential ID is unknown (no record at all).
            - Raise `KeyError` to distinguish an unknown credential from a known one whose backup
              state has not been recorded yet; the latter is represented by a record whose
              `credential_device_type`/`credential_backed_up` are `None`.
        """
        ...

    def persist_credential_backup_state(
        self,
        credential_id: bytes,
        credential_device_type: CredentialDeviceType,
        credential_backed_up: bool,
    ) -> bool:
        """Persist the suggested new state, applying optimistic concurrency checks as needed.

        Return `False` (instead of raising) when an optimistic-lock/version check fails, e.g. a
        concurrent request updated the record first; the ceremony then fails with
        `CredentialBackupStateChange.STATE_UPDATE_CONFLICT`.
        """
        ...


@dataclass
class CredentialBackupStatePolicy:
    """Explicitly-opt-in policy governing credential backup state transitions.

    Pass an instance to `verify_registration_response` or `verify_authentication_response` to
    enable enforcement. When no policy is passed those entry points keep their historical behavior
    and return fields unchanged.

    Attributes:
        `store`: The injected read/write callbacks backed by the Relying Party's storage
        `fail_on_missing_state`: When True (default), a known credential without a recorded backup
          state fails authentication instead of silently bootstrapping a new state.
    """

    store: CredentialBackupStateStore
    fail_on_missing_state: bool = True


def apply_credential_backup_state_policy(
    *,
    policy: CredentialBackupStatePolicy,
    credential_id: bytes,
    flags: AuthenticatorDataFlags,
    is_registration: bool,
) -> Tuple[CredentialBackupStateDecision, Optional[CredentialBackupState]]:
    """Run the policy end-to-end for one ceremony and return the decision plus saved state.

    Raises:
        `InvalidCredentialBackupState` carrying a stable `CredentialBackupStateChange` reason for
        every rejected transition. The exception is never swallowed: callers surface it (wrapped in
        their own exception type) so business logic can alert on the stable reason code.
    """
    saved_state: Optional[CredentialBackupState] = None
    saved_device_type: Optional[CredentialDeviceType] = None
    saved_backed_up: Optional[bool] = None

    if is_registration:
        # Registration establishes the initial record; there is no prior state to compare to.
        decision = evaluate_credential_backup_state(flags)
        if not decision.allowed:
            raise InvalidCredentialBackupState(decision.reason.value)
        return decision, None

    try:
        saved_state = policy.store.get_credential_backup_state(credential_id)
    except KeyError as exc:
        raise InvalidCredentialBackupState(
            CredentialBackupStateChange.CREDENTIAL_NOT_FOUND.value
        ) from exc

    if saved_state is None:
        raise InvalidCredentialBackupState(
            CredentialBackupStateChange.CREDENTIAL_NOT_FOUND.value
        )

    if (
        saved_state.credential_device_type is None
        or saved_state.credential_backed_up is None
    ):
        if policy.fail_on_missing_state:
            raise InvalidCredentialBackupState(
                CredentialBackupStateChange.CREDENTIAL_STATE_MISSING.value
            )
        # Treat the record as a fresh bootstrap and continue evaluating the current flags below.
    else:
        saved_device_type = saved_state.credential_device_type
        saved_backed_up = saved_state.credential_backed_up

    decision = evaluate_credential_backup_state(
        flags,
        saved_device_type=saved_device_type,
        saved_backed_up=saved_backed_up,
    )

    if not decision.allowed:
        raise InvalidCredentialBackupState(decision.reason.value)

    if decision.state_changed:
        persisted = policy.store.persist_credential_backup_state(
            credential_id,
            decision.credential_device_type,
            decision.credential_backed_up,
        )
        if not persisted:
            raise InvalidCredentialBackupState(
                CredentialBackupStateChange.STATE_UPDATE_CONFLICT.value
            )

    return decision, saved_state
