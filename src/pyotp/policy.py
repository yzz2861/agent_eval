"""
Opt-in registration-time enrollment policy.

This module is intentionally *not* wired into :class:`pyotp.OTP`,
:class:`pyotp.TOTP`, :class:`pyotp.HOTP` or :func:`pyotp.verify`. Existing
accounts keep working with whatever secret they were provisioned with. An
application that creates new accounts is expected to instantiate an
:class:`EnrollmentPolicy` once and explicitly call it before generating a
secret, constructing an OTP object or emitting a provisioning URI.

The policy distinguishes three outcomes:

* :class:`SecretError` (and its subclasses) - the secret is unusable: it is
  too short/low entropy or not a validly encoded base32 string.
* :class:`UnsupportedParameterError` - the requested digest/digits/interval/
  counter combination is rejected because common authenticator apps will not
  accept it.
* :class:`EnrollmentResult` - the secret and parameters are accepted. Any
  non-fatal compatibility concerns are returned in ``warnings`` instead of
  being raised so the caller can surface them to operators without blocking
  enrollment.

Exception messages never contain the inspected secret value, so it is safe to
log them.
"""

import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence

from .compat import random

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

# Unpadded base32 lengths that cannot encode a whole number of bytes. Python's
# decoder rejects these even after canonical padding is appended.
_INVALID_UNPADDED_REMAINDERS = frozenset((1, 3, 6))

_SUPPORTED_DIGESTS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

_WHITESPACE_RE = re.compile(r"\s")


class EnrollmentPolicyError(ValueError):
    """Base class for every error raised by the enrollment policy."""


class SecretError(EnrollmentPolicyError):
    """Base class for secret-strength and secret-encoding failures."""


class SecretTooShortError(SecretError):
    """Raised when the decoded secret does not provide enough entropy."""


class SecretEncodingError(SecretError):
    """Raised when the secret is not a cleanly encoded base32 value."""


class UnsupportedParameterError(EnrollmentPolicyError):
    """Raised when an OTP parameter combination is rejected by the policy."""


@dataclass
class EnrollmentResult:
    """
    Outcome of a successful policy evaluation.

    The same result can be passed back into :meth:`EnrollmentPolicy.validate`
    or used to build both a TOTP and an HOTP object, so a secret is only
    decoded and audited once per account.
    """

    #: Uppercase, unpadded canonical base32 representation of the secret.
    normalized_secret: str
    #: Decoded secret bytes.
    secret_bytes: bytes
    #: Estimated entropy in bits (currently the length-based capacity of the
    #: decoded key; lower bound a caller can rely on for a randomly generated
    #: secret).
    entropy_bits: int
    #: Non-fatal compatibility notices the caller may show to operators.
    warnings: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        # Never render the secret itself.
        return "EnrollmentResult(entropy_bits={}, bytes={}, warnings={})".format(
            self.entropy_bits, len(self.secret_bytes), len(self.warnings)
        )


class EnrollmentPolicy:
    """
    Explicitly enabled registration policy for new OTP enrollments.

    Construct once (for example as a module-level singleton) and call
    :meth:`validate_secret`, :meth:`validate`, :meth:`totp` or :meth:`hotp`
    from the registration/provisioning path. Nothing in the legacy
    constructor or ``verify()`` flow consults this policy.
    """

    def __init__(
        self,
        min_entropy_bits: int = 160,
        allowed_digits: Sequence[int] = (6, 7, 8),
        min_interval: int = 15,
        max_interval: int = 300,
        allowed_digests: Sequence[Any] = (hashlib.sha1, hashlib.sha256, hashlib.sha512),
        max_counter: int = 2**31 - 1,
    ) -> None:
        """
        :param min_entropy_bits: minimum decoded secret entropy. Defaults to
            160 bits to match :func:`pyotp.random_base32`.
        :param allowed_digits: OTP code lengths the policy accepts. Defaults
            to the 6/7/8 range accepted by mainstream authenticators.
        :param min_interval: smallest accepted TOTP period in seconds.
        :param max_interval: largest accepted TOTP period in seconds.
        :param allowed_digests: digest callables (or algorithm name strings)
            the policy accepts.
        :param max_counter: largest accepted HOTP initial counter.
        """
        if min_entropy_bits <= 0:
            raise ValueError("min_entropy_bits must be positive")
        if min_interval <= 0 or max_interval < min_interval:
            raise ValueError("invalid TOTP interval range")
        if not allowed_digits or not allowed_digests:
            raise ValueError("allowed_digits and allowed_digests must not be empty")
        if max_counter < 0:
            raise ValueError("max_counter must be non-negative")

        self.min_entropy_bits = min_entropy_bits
        self.allowed_digits = tuple(allowed_digits)
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.max_counter = max_counter

        normalized_digests = set()
        for digest in allowed_digests:
            normalized_digests.add(self._digest_name(digest))
        self._allowed_digest_names = frozenset(normalized_digests)

    def generate_secret(self, length: int = 32) -> EnrollmentResult:
        """
        Generate a random base32 secret and validate it against the policy.

        :param length: number of base32 characters to generate.
        :returns: a validated :class:`EnrollmentResult`.
        """
        secret = "".join(random.choice(BASE32_ALPHABET) for _ in range(length))
        return self.validate_secret(secret)

    def validate_secret(self, secret: Any) -> EnrollmentResult:
        """
        Audit a secret without considering OTP parameters.

        Use this at the point a secret is generated or imported. The returned
        result can be reused when the account is later turned into a TOTP or
        HOTP object.

        :raises SecretEncodingError: the secret is not valid base32 (bad
            characters, whitespace, mixed case, or illegal padding).
        :raises SecretTooShortError: the decoded secret is below the
            configured entropy floor.
        """
        if isinstance(secret, EnrollmentResult):
            return secret
        if not isinstance(secret, str):
            raise SecretEncodingError("secret must be a base32-encoded string")

        warnings: List[str] = []
        candidate = secret

        if _WHITESPACE_RE.search(candidate):
            raise SecretEncodingError("secret must not contain whitespace")
        if candidate == "":
            raise SecretEncodingError("secret must not be empty")

        has_padding = "=" in candidate
        if has_padding:
            first_pad = candidate.index("=")
            body = candidate[:first_pad]
            padding = candidate[first_pad:]
            if not body or any(ch != "=" for ch in padding):
                raise SecretEncodingError("secret contains illegal base32 padding")
            candidate = body
            required_padding = (8 - len(body) % 8) % 8
            if len(secret) % 8 != 0 or required_padding not in (1, 3, 4, 6) or len(padding) != required_padding:
                raise SecretEncodingError("secret contains illegal base32 padding")
            try:
                base64.b32decode(secret)
            except (ValueError, TypeError):
                raise SecretEncodingError("secret contains illegal base32 padding")
            warnings.append("base32 padding removed; provisioning URIs should use unpadded secrets")

        if candidate == "":
            raise SecretEncodingError("secret must not be empty")

        has_lower = any(ch.islower() for ch in candidate)
        has_upper = any(ch.isupper() for ch in candidate)
        if has_lower and has_upper:
            raise SecretEncodingError("secret must not mix upper and lower case")
        if has_lower:
            candidate = candidate.upper()
            warnings.append("lowercase base32 normalized to uppercase")

        if not re.fullmatch(r"[" + BASE32_ALPHABET + r"]+", candidate):
            raise SecretEncodingError("secret contains characters outside the base32 alphabet")
        if len(candidate) % 8 in _INVALID_UNPADDED_REMAINDERS:
            raise SecretEncodingError("secret length cannot encode a whole number of base32 bytes")
        if len(candidate) % 8 != 0:
            warnings.append("unpadded secret length is not a multiple of 8 and is rejected by some authenticators")

        canonical_padding = "=" * (-len(candidate) % 8)
        try:
            secret_bytes = base64.b32decode(candidate + canonical_padding)
        except (ValueError, TypeError):
            raise SecretEncodingError("secret is not valid base32")

        entropy_bits = len(secret_bytes) * 8
        if entropy_bits < self.min_entropy_bits:
            raise SecretTooShortError(
                "secret provides {} bits of entropy; the policy requires at least {}".format(
                    entropy_bits, self.min_entropy_bits
                )
            )

        return EnrollmentResult(
            normalized_secret=candidate,
            secret_bytes=secret_bytes,
            entropy_bits=entropy_bits,
            warnings=warnings,
        )

    def validate(
        self,
        secret: Any,
        otp_type: Optional[str] = None,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        interval: int = 30,
        initial_count: int = 0,
    ) -> EnrollmentResult:
        """
        Audit a secret together with the OTP parameters that will be issued.

        Call this immediately before constructing a TOTP/HOTP object or
        emitting a provisioning URI. ``otp_type`` is ``"totp"``, ``"hotp"``
        or ``None`` for a parameter-agnostic secret check.

        :raises SecretError: see :meth:`validate_secret`.
        :raises UnsupportedParameterError: a parameter is outside the ranges
            accepted by common authenticators.
        """
        result = self.validate_secret(secret)
        warnings = list(result.warnings)

        if otp_type is not None and otp_type not in ("totp", "hotp"):
            raise UnsupportedParameterError("otp_type must be 'totp', 'hotp' or None")

        digest_name = self._digest_name(digest)
        if digest_name not in self._allowed_digest_names:
            raise UnsupportedParameterError("digest {} is not allowed by the enrollment policy".format(digest_name))
        if digest_name != "sha1":
            warnings.append("non-SHA1 digest {} has limited authenticator support".format(digest_name))

        if isinstance(digits, bool) or not isinstance(digits, int):
            raise UnsupportedParameterError("digits must be an integer")
        if digits not in self.allowed_digits:
            raise UnsupportedParameterError(
                "digits={} is not accepted by common authenticators; allowed values: {}".format(
                    digits, ", ".join(str(value) for value in self.allowed_digits)
                )
            )

        if otp_type == "totp":
            if isinstance(interval, bool) or not isinstance(interval, int):
                raise UnsupportedParameterError("interval must be an integer number of seconds")
            if interval < self.min_interval or interval > self.max_interval:
                raise UnsupportedParameterError(
                    "interval={} is outside the supported {}-{} second range".format(
                        interval, self.min_interval, self.max_interval
                    )
                )
            if interval != 30:
                warnings.append("non-default interval={} is ignored by some authenticators".format(interval))

        if otp_type == "hotp":
            if isinstance(initial_count, bool) or not isinstance(initial_count, int):
                raise UnsupportedParameterError("counter must be an integer")
            if initial_count < 0:
                raise UnsupportedParameterError("counter must be non-negative")
            if initial_count > self.max_counter:
                raise UnsupportedParameterError(
                    "counter={} exceeds the supported maximum of {}".format(initial_count, self.max_counter)
                )

        return EnrollmentResult(
            normalized_secret=result.normalized_secret,
            secret_bytes=result.secret_bytes,
            entropy_bits=result.entropy_bits,
            warnings=warnings,
        )

    def totp(
        self,
        secret: Any,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
        interval: int = 30,
    ):
        """Validate the enrollment and return a constructed :class:`pyotp.TOTP`."""
        from .totp import TOTP

        result = self.validate(
            secret, otp_type="totp", digits=digits, digest=digest, interval=interval
        )
        return TOTP(result.normalized_secret, digits=digits, digest=digest, name=name, issuer=issuer, interval=interval)

    def hotp(
        self,
        secret: Any,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
        initial_count: int = 0,
    ):
        """Validate the enrollment and return a constructed :class:`pyotp.HOTP`."""
        from .hotp import HOTP

        result = self.validate(
            secret,
            otp_type="hotp",
            digits=digits,
            digest=digest,
            initial_count=initial_count,
        )
        return HOTP(
            result.normalized_secret,
            digits=digits,
            digest=digest,
            name=name,
            issuer=issuer,
            initial_count=initial_count,
        )

    @staticmethod
    def _digest_name(digest: Any) -> str:
        if isinstance(digest, str):
            name = digest.lower()
            if name not in _SUPPORTED_DIGESTS:
                raise UnsupportedParameterError("unknown digest algorithm: {}".format(digest))
            return name
        name = getattr(digest, "name", None)
        if name is None and callable(digest):
            try:
                name = digest().name
            except (TypeError, ValueError):
                name = None
        if name is None or name not in _SUPPORTED_DIGESTS:
            raise UnsupportedParameterError("unsupported digest function")
        return name
