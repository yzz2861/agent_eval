from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from . import api_jwt
from .api_jws import get_unverified_header
from .exceptions import (
    InvalidTypError,
    MissingRequiredClaimError,
    TokenTooOldError,
    UnknownIssuerError,
    UnknownKeyError,
)

if TYPE_CHECKING:
    from .api_jwt import AllowedPublicKeyTypes

__all__ = ["ProfileRegistry", "ValidationProfile"]


def _normalize_str_tuple(value: str | Iterable[str], name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    normalized = tuple(value)
    if not all(isinstance(item, str) for item in normalized):
        raise TypeError(f"{name} must be a string or an iterable of strings")
    return normalized


def _normalize_seconds(value: float | timedelta, name: str) -> float:
    if isinstance(value, timedelta):
        return value.total_seconds()
    return float(value)


@dataclass(frozen=True)
class ValidationProfile:
    """Immutable validation configuration for a single issuer (trust domain).

    A profile pins every security-relevant decision for tokens of one
    issuer: the allowed algorithms, the expected audience, the claims that
    must be present, the expected ``typ`` header, the maximum token age,
    the clock leeway, and the issuer's own key material.

    Instances are immutable: sequences are frozen into tuples and the
    ``keys`` mapping is copied into a read-only mapping, so a profile that
    is being used to validate a token can never change halfway through.

    :param issuer: the exact ``iss`` claim value this profile applies to.
    :param algorithms: allowed JWS ``alg`` values, e.g. ``("RS256",)``.
    :param audience: expected ``aud`` value(s). ``None`` means the token
        must not contain an ``aud`` claim.
    :param key: default verification key, used when the token has no
        ``kid`` header or when no ``keys`` mapping is configured.
    :param keys: mapping of ``kid`` to verification key. Key ids are only
        ever resolved inside this profile, so identical ``kid`` values
        under different issuers stay fully isolated.
    :param required_claims: claims that must be present in the payload.
    :param typ: required ``typ`` header value, e.g. ``"JWT"`` or
        ``"at+jwt"``. ``None`` disables the check.
    :param max_age: maximum token age in seconds (or ``timedelta``),
        computed from the ``iat`` claim. ``None`` disables the check.
        When set, ``iat`` is implicitly required.
    :param leeway: clock skew tolerance in seconds (or ``timedelta``)
        applied to time-based validations, including ``max_age``.
    """

    issuer: str
    algorithms: tuple[str, ...]
    audience: tuple[str, ...] | None = None
    key: AllowedPublicKeyTypes | None = None
    keys: Mapping[str, AllowedPublicKeyTypes] = field(
        default_factory=lambda: MappingProxyType({})
    )
    required_claims: tuple[str, ...] = ()
    typ: str | None = None
    max_age: float | None = None
    leeway: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer:
            raise TypeError("issuer must be a non-empty string")

        object.__setattr__(
            self, "algorithms", _normalize_str_tuple(self.algorithms, "algorithms")
        )
        if not self.algorithms:
            raise ValueError("algorithms must not be empty")

        if self.audience is not None:
            object.__setattr__(
                self, "audience", _normalize_str_tuple(self.audience, "audience")
            )

        object.__setattr__(
            self,
            "required_claims",
            _normalize_str_tuple(self.required_claims, "required_claims"),
        )

        # Copy the key mapping into a read-only mapping so the profile
        # cannot be mutated through a reference kept by the caller.
        object.__setattr__(self, "keys", MappingProxyType(dict(self.keys)))

        if self.key is None and not self.keys:
            raise ValueError("a profile needs key material: pass key and/or keys")

        if self.max_age is not None:
            object.__setattr__(
                self, "max_age", _normalize_seconds(self.max_age, "max_age")
            )
        object.__setattr__(self, "leeway", _normalize_seconds(self.leeway, "leeway"))

    def resolve_key(self, kid: str | None) -> AllowedPublicKeyTypes:
        """Return the verification key for ``kid`` from this profile only.

        The ``kid`` comes from an unverified header, so it is only ever
        used to *select* among keys already pinned to this issuer; it can
        never widen the key set or the algorithm list.
        """
        if kid is not None:
            try:
                return self.keys[kid]
            except KeyError:
                if self.keys:
                    raise UnknownKeyError(
                        f"Unknown key id {kid!r} for issuer {self.issuer!r}"
                    ) from None
        if self.key is not None:
            return self.key
        raise UnknownKeyError(
            f"Token for issuer {self.issuer!r} has no 'kid' header and the "
            "profile defines no default key"
        )

    def decode(self, token: str | bytes) -> dict[str, Any]:
        """Verify signature and all configured claims in a single decode.

        Returns the validated payload. Raises the usual ``jwt`` exceptions
        (``InvalidSignatureError``, ``ExpiredSignatureError``,
        ``InvalidAudienceError``, ...) for failures within this trust
        domain, and ``UnknownKeyError``/``InvalidTypError``/
        ``TokenTooOldError`` for profile-specific failures.
        """
        header = get_unverified_header(token)
        key = self.resolve_key(header.get("kid"))

        payload = api_jwt.decode(
            token,
            key=key,
            algorithms=list(self.algorithms),
            audience=list(self.audience) if self.audience is not None else None,
            issuer=self.issuer,
            leeway=self.leeway,
            options={"require": list(self.required_claims)},
        )

        if self.typ is not None and header.get("typ") != self.typ:
            raise InvalidTypError(
                f"Invalid typ header: expected {self.typ!r}, got {header.get('typ')!r}"
            )

        if self.max_age is not None:
            self._validate_max_age(payload)

        return payload

    def _validate_max_age(self, payload: dict[str, Any]) -> None:
        if "iat" not in payload:
            raise MissingRequiredClaimError("iat")
        # iat has already been validated as an integer by decode().
        max_age = self.max_age
        assert max_age is not None
        now = datetime.now(tz=timezone.utc).timestamp()
        age = now - int(payload["iat"])
        if age > max_age + self.leeway:
            raise TokenTooOldError(
                f"Token age {age:.0f}s exceeds the maximum of "
                f"{max_age:.0f}s for issuer {self.issuer!r}"
            )


class ProfileRegistry:
    """Thread-safe registry mapping issuers to immutable validation profiles.

    The registry is the only entry point that maps an unverified ``iss``
    claim to a trust domain. The unverified claim is used exclusively to
    look up an already-registered profile; it is never used to fetch keys
    or to relax algorithm/claim requirements. Tokens whose issuer has no
    registered profile are rejected with ``UnknownIssuerError``.

    Updates are copy-on-write: every mutation swaps in a complete new
    mapping, so a request that is mid-validation keeps seeing the full
    profile version it started with.
    """

    def __init__(self, profiles: Iterable[ValidationProfile] = ()) -> None:
        self._lock = threading.Lock()
        self._profiles: dict[str, ValidationProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: ValidationProfile) -> None:
        """Register ``profile``, replacing any profile for the same issuer."""
        if not isinstance(profile, ValidationProfile):
            raise TypeError("profile must be a ValidationProfile")
        with self._lock:
            updated = dict(self._profiles)
            updated[profile.issuer] = profile
            self._profiles = updated

    def unregister(self, issuer: str) -> None:
        """Remove the profile for ``issuer`` if one is registered."""
        with self._lock:
            if issuer in self._profiles:
                updated = dict(self._profiles)
                del updated[issuer]
                self._profiles = updated

    def get(self, issuer: str) -> ValidationProfile | None:
        """Return the profile registered for ``issuer``, or ``None``."""
        return self._profiles.get(issuer)

    def __contains__(self, issuer: str) -> bool:
        return issuer in self._profiles

    def __len__(self) -> int:
        return len(self._profiles)

    @property
    def issuers(self) -> tuple[str, ...]:
        """The currently registered issuers (a consistent snapshot)."""
        return tuple(self._profiles)

    def decode(self, token: str | bytes) -> dict[str, Any]:
        """Select a profile by the token's ``iss`` claim and validate.

        The unverified ``iss`` claim only selects an already-registered
        profile; signature and claim validation then happen entirely
        against that profile's pinned configuration.

        :raises UnknownIssuerError: if the token has no (string) ``iss``
            claim or no profile is registered for it. This signals a
            trust-domain mismatch, as opposed to errors like
            ``InvalidSignatureError`` which mean the token belongs to a
            known domain but failed validation within it.
        """
        unverified = api_jwt.decode(token, options={"verify_signature": False})
        issuer = unverified.get("iss")
        if not isinstance(issuer, str):
            raise UnknownIssuerError(
                "Token has no string 'iss' claim; cannot select a trust domain"
            )
        # Single atomic read: the profile we validate against is one
        # complete, immutable version even if it is replaced concurrently.
        profile = self._profiles.get(issuer)
        if profile is None:
            raise UnknownIssuerError(f"No validation profile for issuer {issuer!r}")
        return profile.decode(token)
