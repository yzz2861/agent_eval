from __future__ import annotations

import json
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from .api_jws import get_unverified_header
from .api_jwt import PyJWT
from .exceptions import (
    DecodeError,
    InvalidIssuedAtError,
    InvalidTokenTypeError,
    MissingRequiredClaimError,
    TokenTooOldError,
    UnknownIssuerError,
)
from .types import Options
from .utils import base64url_decode

if TYPE_CHECKING:
    from .api_jwt import AllowedPublicKeyTypes

__all__ = ["IssuerProfile", "IssuerProfileRegistry", "IssuerProfileDecoder"]


@dataclass(frozen=True)
class IssuerProfile:
    """Immutable validation configuration for a single trusted issuer.

    A profile pins everything needed to validate tokens from one issuer:
    the allowed algorithms, the expected audience, the claims that must be
    present, the accepted 'typ' header values, the verification keys, the
    maximum token age, and the clock leeway. Instances are frozen and every
    mutable argument is copied into an immutable structure, so a profile can
    be shared safely between threads and never changes once created.

    :param issuer: the exact 'iss' claim value this profile applies to.
    :param algorithms: allowed JWS algorithms for this issuer. Tokens signed
        with any other algorithm are rejected; the token's own 'alg' header
        can never widen this set.
    :param audience: expected 'aud' value(s). If None, the audience claim is
        not verified.
    :param keys: mapping of key ID ('kid') to verification key. Key IDs are
        scoped to this profile: the same 'kid' under a different issuer is a
        completely independent entry.
    :param default_key: key used when a token carries no 'kid' header.
    :param required_claims: claims that must be present in the payload.
    :param typ: allowed 'typ' header value(s), compared case-insensitively.
        If None, the 'typ' header is not checked.
    :param max_token_age: maximum age in seconds (or timedelta) of a token,
        measured from its 'iat' claim. If set, 'iat' becomes required.
    :param leeway: clock tolerance in seconds (or timedelta) applied to the
        time-based checks ('exp', 'nbf', 'iat' and 'max_token_age').
    :param strict_aud: require the 'aud' claim to be a single string that
        matches 'audience' exactly.
    """

    issuer: str
    algorithms: Iterable[str]
    audience: str | Iterable[str] | None = None
    keys: Mapping[str, AllowedPublicKeyTypes] | None = None
    default_key: AllowedPublicKeyTypes | None = None
    required_claims: Iterable[str] = ()
    typ: str | Iterable[str] | None = None
    max_token_age: float | timedelta | None = None
    leeway: float | timedelta = 0.0
    strict_aud: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer:
            raise ValueError("issuer must be a non-empty string")

        algorithms = tuple(self.algorithms)
        if not algorithms or any(not isinstance(alg, str) for alg in algorithms):
            raise ValueError("algorithms must be a non-empty iterable of strings")
        object.__setattr__(self, "algorithms", algorithms)

        if self.audience is not None and not isinstance(self.audience, str):
            audience = tuple(self.audience)
            if not audience or any(not isinstance(aud, str) for aud in audience):
                raise ValueError(
                    "audience must be a string or a non-empty iterable of strings"
                )
            object.__setattr__(self, "audience", audience)

        object.__setattr__(self, "required_claims", tuple(self.required_claims))

        if self.typ is not None:
            typ_values = (self.typ,) if isinstance(self.typ, str) else tuple(self.typ)
            if not typ_values or any(not isinstance(t, str) for t in typ_values):
                raise ValueError(
                    "typ must be a string or a non-empty iterable of strings"
                )
            object.__setattr__(self, "typ", typ_values)

        leeway = self.leeway
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()
        object.__setattr__(self, "leeway", float(leeway))

        max_token_age = self.max_token_age
        if max_token_age is not None:
            if isinstance(max_token_age, timedelta):
                max_token_age = max_token_age.total_seconds()
            max_token_age = float(max_token_age)
            if max_token_age <= 0:
                raise ValueError("max_token_age must be positive")
        object.__setattr__(self, "max_token_age", max_token_age)

        keys: dict[str, AllowedPublicKeyTypes] = {}
        if self.keys is not None:
            for kid, key in self.keys.items():
                if not isinstance(kid, str):
                    raise ValueError("keys must map string key IDs to keys")
                keys[kid] = key
        if not keys and self.default_key is None:
            raise ValueError(
                "at least one key must be provided via 'keys' or 'default_key'"
            )
        object.__setattr__(self, "keys", MappingProxyType(keys))

    def resolve_key(self, kid: Any) -> AllowedPublicKeyTypes:
        """Return the verification key registered for a token's 'kid' header.

        Only keys explicitly registered in this profile are considered; the
        lookup never falls back to another issuer's keys or to any external
        key source.
        """
        if kid is None:
            if self.default_key is not None:
                return self.default_key
            raise DecodeError(
                "Token header has no 'kid' and the profile for issuer "
                f"{self.issuer!r} defines no default key"
            )
        if not isinstance(kid, str):
            raise DecodeError("Token header 'kid' must be a string")
        try:
            return self.keys[kid]
        except KeyError:
            raise DecodeError(
                f"Token 'kid' {kid!r} is not registered for issuer {self.issuer!r}"
            ) from None

    def allows_typ(self, token_typ: Any) -> bool:
        """Return True if a token 'typ' header value is allowed by this profile."""
        if self.typ is None:
            return True
        return isinstance(token_typ, str) and token_typ.lower() in {
            allowed.lower() for allowed in self.typ
        }


class IssuerProfileRegistry:
    """Thread-safe registry mapping issuer names to immutable profiles.

    Updates are copy-on-write: registering or unregistering a profile swaps
    in a new mapping atomically, so a request that is already validating
    keeps seeing one complete, consistent version of the registry.
    """

    def __init__(self, profiles: Iterable[IssuerProfile] = ()) -> None:
        self._lock = threading.Lock()
        initial: dict[str, IssuerProfile] = {}
        for profile in profiles:
            if not isinstance(profile, IssuerProfile):
                raise TypeError("profiles must be IssuerProfile instances")
            if profile.issuer in initial:
                raise ValueError(f"Duplicate profile for issuer {profile.issuer!r}")
            initial[profile.issuer] = profile
        self._profiles: dict[str, IssuerProfile] = initial

    def register(self, profile: IssuerProfile) -> None:
        """Add or atomically replace the profile for 'profile.issuer'."""
        if not isinstance(profile, IssuerProfile):
            raise TypeError("profile must be an IssuerProfile")
        with self._lock:
            updated = dict(self._profiles)
            updated[profile.issuer] = profile
            self._profiles = updated

    def unregister(self, issuer: str) -> None:
        """Remove the profile for 'issuer'. Raises KeyError if absent."""
        with self._lock:
            if issuer not in self._profiles:
                raise KeyError(issuer)
            updated = dict(self._profiles)
            del updated[issuer]
            self._profiles = updated

    def snapshot(self) -> Mapping[str, IssuerProfile]:
        """Return an immutable, internally consistent view of the registry.

        The returned mapping never changes, even if the registry is updated
        afterwards.
        """
        return MappingProxyType(self._profiles)

    def get(self, issuer: str) -> IssuerProfile | None:
        """Return the profile registered for 'issuer', or None."""
        return self._profiles.get(issuer)

    def __contains__(self, issuer: object) -> bool:
        return issuer in self._profiles

    def __len__(self) -> int:
        return len(self._profiles)

    @property
    def issuers(self) -> tuple[str, ...]:
        """The currently registered issuer names."""
        return tuple(self._profiles)


class IssuerProfileDecoder:
    """Decode and validate JWTs against explicitly registered issuer profiles.

    The unverified 'iss' claim is used only to look up an already-registered
    profile in the registry. The verification key, allowed algorithms and
    every other validation parameter always come from that static profile,
    never from the token itself and never from a key source derived from
    token data. Tokens from issuers that are not registered are rejected
    with :class:`jwt.exceptions.UnknownIssuerError` (a trust-domain
    mismatch), while tokens from a registered issuer that fail validation
    raise the usual :class:`jwt.exceptions.InvalidTokenError` subclasses.
    """

    def __init__(
        self, registry: IssuerProfileRegistry, *, jwt_api: PyJWT | None = None
    ) -> None:
        if not isinstance(registry, IssuerProfileRegistry):
            raise TypeError("registry must be an IssuerProfileRegistry")
        self._registry = registry
        self._jwt = jwt_api if jwt_api is not None else PyJWT()

    @property
    def registry(self) -> IssuerProfileRegistry:
        return self._registry

    def decode(
        self,
        token: str | bytes,
        *,
        detached_payload: bytes | None = None,
    ) -> dict[str, Any]:
        """Verify the token against its issuer's profile and return its claims."""
        return cast(
            "dict[str, Any]",
            self._decode(token, complete=False, detached_payload=detached_payload),
        )

    def decode_complete(
        self,
        token: str | bytes,
        *,
        detached_payload: bytes | None = None,
    ) -> dict[str, Any]:
        """Like :meth:`decode`, but also return the header and signature."""
        return cast(
            "dict[str, Any]",
            self._decode(token, complete=True, detached_payload=detached_payload),
        )

    def _decode(
        self,
        token: str | bytes,
        *,
        complete: bool,
        detached_payload: bytes | None,
    ) -> dict[str, Any]:
        profile = self._resolve_profile(token)

        header = get_unverified_header(token)
        if not profile.allows_typ(header.get("typ")):
            raise InvalidTokenTypeError(
                f"Token 'typ' header {header.get('typ')!r} is not allowed "
                f"for issuer {profile.issuer!r}"
            )

        key = profile.resolve_key(header.get("kid"))

        options: Options = {
            "require": list(profile.required_claims),
            "strict_aud": profile.strict_aud,
            "verify_aud": profile.audience is not None,
        }

        if complete:
            decoded = self._jwt.decode_complete(
                token,
                key=key,
                algorithms=profile.algorithms,
                options=options,
                audience=profile.audience,
                issuer=profile.issuer,
                leeway=profile.leeway,
                detached_payload=detached_payload,
            )
            payload = cast("dict[str, Any]", decoded["payload"])
            self._validate_max_token_age(payload, profile)
            return decoded

        payload = self._jwt.decode(
            token,
            key=key,
            algorithms=profile.algorithms,
            options=options,
            audience=profile.audience,
            issuer=profile.issuer,
            leeway=profile.leeway,
            detached_payload=detached_payload,
        )
        self._validate_max_token_age(payload, profile)
        return payload

    def _resolve_profile(self, token: str | bytes) -> IssuerProfile:
        profiles = self._registry.snapshot()
        payload = self._unverified_payload(token)
        iss = payload.get("iss")
        if not isinstance(iss, str) or not iss:
            raise UnknownIssuerError(
                "Token has no valid 'iss' claim; the issuer cannot be "
                "matched to a registered profile"
            )
        profile = profiles.get(iss)
        if profile is None:
            raise UnknownIssuerError(f"Issuer {iss!r} is not registered")
        return profile

    @staticmethod
    def _unverified_payload(token: str | bytes) -> dict[str, Any]:
        if isinstance(token, bytes):
            try:
                token = token.decode("utf-8")
            except UnicodeDecodeError:
                raise DecodeError("Invalid token encoding") from None
        if not isinstance(token, str):
            raise DecodeError("Invalid token type. Token must be a bytes or string")
        segments = token.split(".")
        if len(segments) != 3:
            raise DecodeError(
                "Not enough segments" if len(segments) < 3 else "Too many segments"
            )
        try:
            payload = json.loads(base64url_decode(segments[1]))
        except (ValueError, TypeError) as exc:
            raise DecodeError(f"Invalid payload string: {exc}") from exc
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")
        return cast("dict[str, Any]", payload)

    @staticmethod
    def _validate_max_token_age(
        payload: dict[str, Any], profile: IssuerProfile
    ) -> None:
        if profile.max_token_age is None:
            return
        if "iat" not in payload:
            raise MissingRequiredClaimError("iat")
        try:
            iat = int(payload["iat"])
        except (ValueError, TypeError, OverflowError):
            raise InvalidIssuedAtError(
                "Issued At claim (iat) must be an integer."
            ) from None
        now = datetime.now(tz=timezone.utc).timestamp()
        if now - iat > profile.max_token_age + profile.leeway:
            raise TokenTooOldError(
                f"Token exceeds the maximum age allowed for issuer {profile.issuer!r}"
            )
