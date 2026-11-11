import base64
import uuid
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .base64url_to_bytes import base64url_to_bytes
from .exceptions import AmbiguousCredentialIdError
from .structs import (
    AuthenticatorTransport,
    ExistingCredential,
    PublicKeyCredentialDescriptor,
    RegistrationPolicy,
)


_REVOKED_STATUSES = {
    "revoked",
    "disabled",
    "deleted",
    "invalid",
    "inactive",
}
_EXPIRED_STATUSES = {"expired"}


@dataclass
class _CredentialView:
    credential_id: bytes
    transports: Tuple[AuthenticatorTransport, ...]
    aaguid: Optional[str]
    revoked: bool
    expired: bool


def _lookup(source: Any, names: Sequence[str], default: Any = None) -> Any:
    if isinstance(source, dict):
        for name in names:
            if name in source and source[name] is not None:
                return source[name]
        return default

    for name in names:
        if hasattr(source, name):
            value = getattr(source, name)
            if value is not None:
                return value
    return default


def _coerce_bytes(value: Any, field_name: str = "credential id") -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return base64url_to_bytes(value)
        except Exception as exc:
            raise ValueError(f"{field_name} was a string but not valid base64url") from exc
    raise ValueError(f"{field_name} must be bytes")  # type: ignore[unreachable]


def _coerce_transport(value: Any) -> AuthenticatorTransport:
    if isinstance(value, AuthenticatorTransport):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower().replace("_", "-")
        try:
            return AuthenticatorTransport(normalized)
        except ValueError as exc:
            raise ValueError(f"Invalid authenticator transport {value!r}") from exc
    raise ValueError(f"Authenticator transport must be a string, got {type(value).__name__}")


def _coerce_transports(value: Any) -> Tuple[AuthenticatorTransport, ...]:
    if value is None:
        return tuple()
    if isinstance(value, (str, AuthenticatorTransport)):
        return (_coerce_transport(value),)
    if not isinstance(value, Iterable):
        raise ValueError("transports must be a list of authenticator transports")
    return tuple(_coerce_transport(item) for item in value)


def _normalize_aaguid(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, uuid.UUID):
        return str(value).lower()
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != 16:
            raise ValueError(f"AAGUID was {len(raw)} bytes, expected 16 bytes")
        return str(uuid.UUID(bytes=raw)).lower()
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.startswith("{") and normalized.endswith("}"):
            normalized = normalized[1:-1]
        try:
            return str(uuid.UUID(normalized)).lower()
        except ValueError as exc:
            raise ValueError(f"Invalid AAGUID {value!r}") from exc
    raise ValueError(f"AAGUID must be a UUID, 16-byte value, or string, got {type(value).__name__}")


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "revoked", "expired"}
    return bool(value)


def _as_utc_datetime(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = f"{normalized[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name} value {value!r}") from exc
    else:
        raise ValueError(f"Invalid {field_name} value {value!r}")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _current_time(value: Any) -> datetime:
    if value is None:
        return datetime.now(tz=timezone.utc)
    return _as_utc_datetime(value, "now")


def _to_credential_view(source: Any, now: datetime) -> _CredentialView:
    """Normalize supported credential records, including dicts and Duck-typed objects."""
    if isinstance(source, ExistingCredential):
        credential_id = source.credential_id
        transports = source.transports
        aaguid = source.aaguid
        revoked = source.revoked
        revoked_at = source.revoked_at
        expires_at = source.expires_at
        expired = source.expired
        status = source.status
    elif isinstance(source, PublicKeyCredentialDescriptor):
        credential_id = source.id
        transports = source.transports
        aaguid = None
        revoked = False
        revoked_at = None
        expires_at = None
        expired = None
        status = None
    else:
        credential_id = _lookup(
            source,
            ("credential_id", "credentialId", "credentialID", "cred_id", "id"),
        )
        if credential_id is None and not isinstance(source, dict):
            credential_id = _lookup(source, ("raw_id", "rawId"))
        transports = _lookup(source, ("transports", "transport"))
        aaguid = _lookup(source, ("aaguid", "AAGUID"))
        revoked = _lookup(source, ("revoked", "is_revoked", "isRevoked"), False)
        revoked_at = _lookup(source, ("revoked_at", "revokedAt", "revocation_date"))
        expires_at = _lookup(
            source,
            ("expires_at", "expiresAt", "expiration", "expiry", "expires_on"),
        )
        expired = _lookup(source, ("expired", "is_expired"), None)
        status = _lookup(source, ("status", "state"), None)

    if credential_id is None:
        raise ValueError("Credential record is missing a credential id")

    resolved_id = _coerce_bytes(credential_id)
    if not resolved_id:
        raise ValueError("Credential id cannot be empty")

    resolved_transports = _coerce_transports(transports)
    resolved_aaguid = _normalize_aaguid(aaguid)

    status_value = str(status).strip().lower() if status is not None else ""
    is_revoked = _truthy(revoked) or revoked_at is not None or status_value in _REVOKED_STATUSES
    is_expired = (
        _truthy(expired) if expired is not None else False
    ) or status_value in _EXPIRED_STATUSES

    if expires_at is not None:
        is_expired = is_expired or _as_utc_datetime(expires_at, "expires_at") <= now

    return _CredentialView(
        credential_id=resolved_id,
        transports=resolved_transports,
        aaguid=resolved_aaguid,
        revoked=is_revoked,
        expired=is_expired,
    )


def _transport_set(values: Optional[List[Any]]) -> Set[AuthenticatorTransport]:
    if not values:
        return set()
    if isinstance(values, (str, AuthenticatorTransport)):
        return {_coerce_transport(values)}
    return {_coerce_transport(value) for value in values}


def _aaguid_set(values: Optional[List[Any]]) -> Set[str]:
    if not values:
        return set()
    if isinstance(values, (str, bytes, bytearray, memoryview, uuid.UUID)):
        value = _normalize_aaguid(values)
        return {value} if value is not None else set()
    normalized = {_normalize_aaguid(value) for value in values}
    return {value for value in normalized if value is not None}


def resolve_exclude_credentials(
    existing_credentials: Optional[Iterable[Any]] = None,
    *,
    excluded_transports: Optional[List[Any]] = None,
    allowed_transports: Optional[List[Any]] = None,
    excluded_aaguids: Optional[List[Any]] = None,
    allowed_aaguids: Optional[List[Any]] = None,
    now: Any = None,
) -> List[PublicKeyCredentialDescriptor]:
    """Resolve stored credential records into safe ``excludeCredentials`` descriptors.

    Resolution is deterministic and safe to expose to clients:

    - revoked and expired records are dropped;
    - duplicate credential IDs are merged;
    - records with the same credential ID but different known AAGUIDs are rejected because
      they are ambiguous (multiple authenticators cannot legitimately share a credential ID);
    - incompatible transports/AAGUIDs are filtered; and
    - output descriptors are sorted by credential ID, with transports also sorted.

    Only the standard descriptor fields (``id``, ``type``, ``transports``) are returned. Internal
    database IDs, user handles, and labels are never copied into the descriptors.
    """
    if existing_credentials is None:
        return []

    current = _current_time(now)
    denied_transports = _transport_set(excluded_transports)
    permitted_transports = _transport_set(allowed_transports)
    denied_aaguids = _aaguid_set(excluded_aaguids)
    permitted_aaguids = _aaguid_set(allowed_aaguids)

    views: List[_CredentialView] = []
    for source in existing_credentials:
        view = _to_credential_view(source, current)

        if view.revoked or view.expired:
            continue
        if denied_transports and any(t in denied_transports for t in view.transports):
            continue
        if (
            permitted_transports
            and view.transports
            and not any(t in permitted_transports for t in view.transports)
        ):
            continue
        if view.aaguid is not None and view.aaguid in denied_aaguids:
            continue
        if (
            permitted_aaguids
            and view.aaguid is not None
            and view.aaguid not in permitted_aaguids
        ):
            continue

        views.append(view)

    grouped: Dict[bytes, List[_CredentialView]] = {}
    for view in views:
        grouped.setdefault(view.credential_id, []).append(view)

    descriptors: List[PublicKeyCredentialDescriptor] = []
    for credential_id in sorted(grouped):
        group = grouped[credential_id]
        known_aaguids = sorted({view.aaguid for view in group if view.aaguid is not None})
        if len(known_aaguids) > 1:
            encoded_id = base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode("ascii")
            raise AmbiguousCredentialIdError(
                "Multiple authenticators share credential id "
                f"{encoded_id!r} (known AAGUIDs: {', '.join(known_aaguids)}); "
                "duplicate credential ids must resolve to one authenticator"
            )

        all_transports: Set[AuthenticatorTransport] = set()
        for view in group:
            all_transports.update(view.transports)

        transports = sorted(all_transports, key=lambda transport: transport.value)
        descriptors.append(
            PublicKeyCredentialDescriptor(
                id=credential_id,
                transports=transports if transports else None,
            )
        )

    return descriptors


def resolve_policy_exclude_credentials(
    policy: Optional[RegistrationPolicy] = None,
    *,
    existing_credentials: Optional[Iterable[Any]] = None,
    excluded_credentials: Optional[Iterable[Any]] = None,
) -> List[PublicKeyCredentialDescriptor]:
    """Convenience wrapper that resolves a policy plus any additional descriptor records."""
    records: List[Any] = []
    if policy is not None and policy.existing_credentials is not None:
        records.extend(policy.existing_credentials)
    if existing_credentials is not None:
        records.extend(existing_credentials)
    if excluded_credentials is not None:
        records.extend(excluded_credentials)

    if policy is None:
        return resolve_exclude_credentials(records)

    return resolve_exclude_credentials(
        records,
        excluded_transports=policy.excluded_transports,
        allowed_transports=policy.allowed_transports,
        excluded_aaguids=policy.excluded_aaguids,
        allowed_aaguids=policy.allowed_aaguids,
        now=policy.now,
    )


def coerce_registration_policy(value: Any) -> Optional[RegistrationPolicy]:
    """Accept either a :class:`RegistrationPolicy` or a dict containing policy values."""
    if value is None:
        return None
    if isinstance(value, RegistrationPolicy):
        return value
    if not isinstance(value, dict):
        raise ValueError("registration_policy must be a RegistrationPolicy or a dict")

    def first_present(*keys: str) -> Any:
        for key in keys:
            if key in value and value[key] is not None:
                return value[key]
        return None

    return RegistrationPolicy(
        existing_credentials=first_present(
            "existing_credentials",
            "existingCredentials",
            "credentials",
            "excluded_credentials",
            "exclude_credentials",
            "credential_descriptions",
            "credential_descriptors",
            "existing_credential_records",
        ),
        resident_key=first_present("resident_key", "residentKey"),
        require_resident_key=first_present(
            "require_resident_key", "requireResidentKey"
        ),
        user_verification=first_present("user_verification", "userVerification"),
        authenticator_attachment=first_present(
            "authenticator_attachment", "authenticatorAttachment"
        ),
        excluded_transports=first_present(
            "excluded_transports", "exclude_transports", "excludeTransports"
        ),
        allowed_transports=first_present(
            "allowed_transports", "allowedTransports", "include_transports"
        ),
        excluded_aaguids=first_present(
            "excluded_aaguids", "exclude_aaguids", "excludeAaguids"
        ),
        allowed_aaguids=first_present(
            "allowed_aaguids", "allowedAaguids", "include_aaguids"
        ),
        now=first_present("now", "current_time"),
    )


# Public aliases that make the intent obvious in call sites.
build_exclude_credentials = resolve_exclude_credentials
generate_exclude_credentials = resolve_exclude_credentials
