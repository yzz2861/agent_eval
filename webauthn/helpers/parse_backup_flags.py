from dataclasses import dataclass
from typing import Optional

from .structs import (
    AuthenticatorDataFlags,
    CredentialBackupStateChange,
    CredentialDeviceType,
)
from .exceptions import InvalidBackupFlags


@dataclass
class ParsedBackupFlags:
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool


@dataclass
class CredentialBackupStateDecision:
    """The outcome of comparing current authenticator backup flags to a saved credential state.

    Attributes:
        `allowed`: Whether the transition is permitted to complete the ceremony
        `reason`: Stable audit code (a `CredentialBackupStateChange` member) for the decision
        `credential_device_type`: Device type implied by the current BE flag
        `credential_backed_up`: Backup state implied by the current BS flag
        `state_changed`: Whether the suggested state differs from the saved state. Always False for
            rejected transitions so that callers never persist a suspicious state.
    """

    allowed: bool
    reason: CredentialBackupStateChange
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool
    state_changed: bool


def parse_backup_flags(flags: AuthenticatorDataFlags) -> ParsedBackupFlags:
    """Convert backup eligibility and backup state flags into more useful representations

    Raises:
        `helpers.exceptions.InvalidBackupFlags` if an invalid backup state is detected
    """
    credential_device_type = CredentialDeviceType.SINGLE_DEVICE

    # A credential that can be backed up can typically be used on multiple devices
    if flags.be:
        credential_device_type = CredentialDeviceType.MULTI_DEVICE

    if credential_device_type == CredentialDeviceType.SINGLE_DEVICE and flags.bs:
        raise InvalidBackupFlags(
            "Single-device credential indicated that it was backed up, which should be impossible."
        )

    return ParsedBackupFlags(
        credential_device_type=credential_device_type,
        credential_backed_up=flags.bs,
    )


def evaluate_credential_backup_state(
    flags: AuthenticatorDataFlags,
    saved_device_type: Optional[CredentialDeviceType] = None,
    saved_backed_up: Optional[bool] = None,
) -> CredentialBackupStateDecision:
    """Compare current BE/BS flags against the persisted state of a credential.

    This is a pure, stateless function: every state it needs is passed in by the caller, which
    keeps the library free of any global registries or caches of credential records.

    Allowed migrations:
        - First registration / no saved state: every *valid* flag combination is accepted
        - Non-backup-eligible (BE=0) credentials remain single-device with BS=0
        - A single-device credential may gain backup eligibility (BE 0 -> 1)
        - A backup-eligible credential may become backed up (BS 0 -> 1)
        - A backed-up credential may continue to authenticate from a backup

    Rejected transitions:
        - BE=0 with BS=1 is an impossible flag combination
        - BS 1 -> 0 is a backup state rollback
        - BE 1 -> 0 is a backup eligibility rollback (cross-device clone suspected)

    Note:
        Saved state being entirely absent versus partially absent is the caller's responsibility;
        this function treats `None` saved values as "no prior state" (first registration).
    """
    current = parse_backup_flags_safe(flags)
    current_device_type = current.credential_device_type
    current_backed_up = current.credential_backed_up

    # BE=0 with BS=1 is forbidden by the WebAuthn spec regardless of any saved state
    if not flags.be and flags.bs:
        return CredentialBackupStateDecision(
            allowed=False,
            reason=CredentialBackupStateChange.INVALID_BACKUP_FLAGS,
            credential_device_type=current_device_type,
            credential_backed_up=current_backed_up,
            state_changed=False,
        )

    # No usable saved state: this is effectively a first registration / bootstrap
    if saved_device_type is None or saved_backed_up is None:
        return CredentialBackupStateDecision(
            allowed=True,
            reason=CredentialBackupStateChange.FIRST_REGISTRATION,
            credential_device_type=current_device_type,
            credential_backed_up=current_backed_up,
            state_changed=True,
        )

    state_changed = (
        saved_device_type != current_device_type or saved_backed_up != current_backed_up
    )

    if saved_device_type == CredentialDeviceType.SINGLE_DEVICE:
        if current_device_type == CredentialDeviceType.SINGLE_DEVICE:
            # BE stayed 0; BS is guaranteed 0 here, so the credential remains non-backupable
            reason = CredentialBackupStateChange.SINGLE_DEVICE
        else:
            # BE 0 -> 1: a platform may later mark an existing credential as backup-eligible
            reason = CredentialBackupStateChange.BACKUP_ELIGIBILITY_GAINED
        return CredentialBackupStateDecision(
            allowed=True,
            reason=reason,
            credential_device_type=current_device_type,
            credential_backed_up=current_backed_up,
            state_changed=state_changed,
        )

    # Saved credential was backup-eligible (multi-device); BE may never return to 0
    if current_device_type == CredentialDeviceType.SINGLE_DEVICE:
        return CredentialBackupStateDecision(
            allowed=False,
            reason=CredentialBackupStateChange.BACKUP_ELIGIBILITY_ROLLBACK,
            credential_device_type=current_device_type,
            credential_backed_up=current_backed_up,
            state_changed=False,
        )

    if saved_backed_up:
        if not current_backed_up:
            # BS 1 -> 0: an already backed-up credential claiming it is no longer backed up
            return CredentialBackupStateDecision(
                allowed=False,
                reason=CredentialBackupStateChange.BACKUP_STATE_ROLLBACK,
                credential_device_type=current_device_type,
                credential_backed_up=current_backed_up,
                state_changed=False,
            )
        # BS stayed 1: authentication is being performed from a restored/active backup
        reason = CredentialBackupStateChange.BACKUP_RECOVERED
    elif current_backed_up:
        # BS 0 -> 1: backup was enabled since the last ceremony
        reason = CredentialBackupStateChange.BACKUP_ENABLED
    else:
        # BE=1, BS=0 before and after: eligible but not yet backed up
        reason = CredentialBackupStateChange.STATE_UNCHANGED

    return CredentialBackupStateDecision(
        allowed=True,
        reason=reason,
        credential_device_type=current_device_type,
        credential_backed_up=current_backed_up,
        state_changed=state_changed,
    )


def parse_backup_flags_safe(flags: AuthenticatorDataFlags) -> ParsedBackupFlags:
    """Like `parse_backup_flags` but never raises.

    The impossible BE=0/BS=1 combination is represented as a single-device, not-backed-up result;
    callers of the state policy receive the precise rejection via the decision's `reason`. The
    strict `parse_backup_flags` remains available for callers that prefer an exception.
    """
    credential_device_type = (
        CredentialDeviceType.MULTI_DEVICE if flags.be else CredentialDeviceType.SINGLE_DEVICE
    )

    return ParsedBackupFlags(
        credential_device_type=credential_device_type,
        credential_backed_up=flags.bs,
    )
