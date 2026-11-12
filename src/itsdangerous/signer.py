from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import typing as t

from .encoding import _base64_alphabet
from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import AlgorithmDowngradeError

# Re-export policy errors from the signer module for integrations that keep
# their signing configuration imports together.
from .exc import AlgorithmNotAllowed as AlgorithmNotAllowed
from .exc import AlgorithmNotAllowedError as AlgorithmNotAllowedError
from .exc import BadSignature
from .exc import InsecureKeyDerivationError as InsecureKeyDerivationError
from .exc import InsecurePolicyError as InsecurePolicyError
from .exc import KeyTooShortError as KeyTooShortError
from .exc import MessageTampered as MessageTampered
from .exc import PolicyError
from .exc import PolicyFailure as PolicyFailure
from .exc import PolicyRejected as PolicyRejected
from .exc import PolicyRejection as PolicyRejection
from .exc import PolicyViolation as PolicyViolation
from .exc import PolicyViolationError as PolicyViolationError
from .exc import SignaturePolicyError as SignaturePolicyError
from .exc import SignatureTampered as SignatureTampered
from .exc import SignerPolicyError as SignerPolicyError
from .exc import SigningPolicyError as SigningPolicyError
from .exc import SigningPolicyViolation as SigningPolicyViolation
from .exc import TamperedSignature as TamperedSignature
from .exc import UnderivedKeyError
from .exc import UnsupportedAlgorithm
from .exc import UnsupportedAlgorithmError as UnsupportedAlgorithmError
from .exc import UnsupportedDigest as UnsupportedDigest
from .exc import UnsupportedDigestError as UnsupportedDigestError
from .exc import VerificationPolicyError as VerificationPolicyError
from .exc import VerificationPolicyViolation as VerificationPolicyViolation
from .exc import WeakAlgorithmError as WeakAlgorithmError
from .exc import WeakDigestError
from .exc import WeakKeyError


class SigningAlgorithm:
    """Subclasses must implement :meth:`get_signature` to provide
    signature generation functionality.
    """

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        """Returns the signature for the given key and value."""
        raise NotImplementedError()

    def verify_signature(self, key: bytes, value: bytes, sig: bytes) -> bool:
        """Verifies the given signature matches the expected
        signature.
        """
        return hmac.compare_digest(sig, self.get_signature(key, value))


class NoneAlgorithm(SigningAlgorithm):
    """Provides an algorithm that does not perform any signing and
    returns an empty signature.

    This exists for backwards compatibility with explicitly configured
    ``NoneAlgorithm`` instances. It must not be used by a signing policy
    and cannot create new tokens when a signer is in policy mode.
    """

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        return b""


def _lazy_sha1(string: bytes = b"") -> t.Any:
    """Don't access ``hashlib.sha1`` until runtime. FIPS builds may not include
    SHA-1, in which case the import and use as a default would fail before the
    developer can configure something else.
    """
    return hashlib.sha1(string)


class HMACAlgorithm(SigningAlgorithm):
    """Provides signature generation using HMACs."""

    #: The digest method to use with the MAC algorithm. This defaults to
    #: SHA1, but can be changed to any other function in the hashlib
    #: module.
    default_digest_method: t.Any = staticmethod(_lazy_sha1)

    def __init__(self, digest_method: t.Any = None):
        if digest_method is None:
            digest_method = self.default_digest_method

        self.digest_method: t.Any = digest_method

    def get_signature(self, key: bytes, value: bytes) -> bytes:
        mac = hmac.new(key, msg=value, digestmod=self.digest_method)
        return mac.digest()


def _make_keys_list(
    secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
) -> list[bytes]:
    if isinstance(secret_key, (str, bytes)):
        return [want_bytes(secret_key)]

    return [want_bytes(s) for s in secret_key]  # pyright: ignore


_NONE_ALGORITHM_NAMES = frozenset({"none", "null", "unsafe"})
_MISSING = object()
_WEAK_DIGEST_NAMES = frozenset({"md5", "sha1", "sha_1", "md5_sha1"})
_KNOWN_DERIVATIONS = frozenset({"concat", "django-concat", "hmac", "none"})
_DERIVED_KEYS = frozenset({"concat", "django-concat", "hmac"})
_DIGEST_ALIASES = {
    "sha1": hashlib.sha1,
    "sha_1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha_224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha_256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha_384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha_512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "sha3512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
    "md5": hashlib.md5,
}


def _is_none_digest(value: t.Any) -> bool:
    return value is None or (
        isinstance(value, str) and value.strip().lower() in _NONE_ALGORITHM_NAMES
    )


def _resolve_digest(value: t.Any) -> t.Any:
    """Return a hash constructor from a callable or a stable string name."""
    if value is None:
        return None

    if isinstance(value, HMACAlgorithm):
        value = value.digest_method
    elif isinstance(value, SigningAlgorithm):
        raise UnsupportedAlgorithm(
            f"algorithm {type(value).__name__!r} is not an HMAC digest"
        )

    if isinstance(value, (str, bytes)):
        if isinstance(value, bytes):
            try:
                value = value.decode("ascii")
            except UnicodeDecodeError as e:
                raise UnsupportedAlgorithm(
                    f"unsupported hash algorithm {value!r}"
                ) from e
        name = value.strip().lower().replace("-", "_")
        if name in _NONE_ALGORITHM_NAMES:
            return None
        if name.startswith("hmac_"):
            name = name[5:]
        try:
            return _DIGEST_ALIASES[name]
        except KeyError as e:
            raise UnsupportedAlgorithm(f"unsupported hash algorithm {value!r}") from e

    if not callable(value):
        raise UnsupportedAlgorithm(f"unsupported hash algorithm {value!r}")

    return value


def _digest_name(value: t.Any) -> str:
    try:
        digest = value(b"")
        name = getattr(digest, "name", None)
    except Exception as e:
        raise UnsupportedAlgorithm(f"hash algorithm {value!r} is unavailable") from e

    if name:
        return str(name).lower().replace("-", "_")

    return str(getattr(value, "__name__", value)).lower().replace("-", "_")


def _digest_size(value: t.Any) -> int | None:
    try:
        return int(value(b"").digest_size)
    except Exception as e:
        raise UnsupportedAlgorithm(f"hash algorithm {value!r} is unavailable") from e


def _is_weak_digest(value: t.Any) -> bool:
    name = _digest_name(value)
    if name in _WEAK_DIGEST_NAMES:
        return True

    # Signing policies require at least a 256-bit digest. This also catches
    # custom hash-like objects without relying on their name.
    return (_digest_size(value) or 0) < 32


def _same_digest(left: t.Any, right: t.Any) -> bool:
    return _digest_name(left) == _digest_name(right)


def _pop_alias(kwargs: dict[str, t.Any], names: tuple[str, ...]) -> t.Any:
    value = None
    found = False

    for name in names:
        if name in kwargs:
            candidate = kwargs.pop(name)
            if candidate is None:
                continue
            if found and candidate != value:
                raise PolicyError(f"conflicting values for {names[0]!r}")
            value = candidate
            found = True

    return value


class SigningPolicy:
    """An explicit, auditable policy for creating signatures.

    A signing policy always selects a strong HMAC digest, requires a key of
    at least ``min_key_bits`` bits, and requires a real key derivation method.
    ``NoneAlgorithm`` and the ``none`` key derivation are rejected when the
    signer is constructed.

    :param digest_method: The current HMAC digest used for new signatures.
        May be a :mod:`hashlib` callable, an ``HMACAlgorithm`` instance, or
        a name such as ``"sha256"``.
    :param min_key_bits: Minimum size of every configured secret key in bits.
    :param key_derivation: How to derive the signing key. One of ``concat``,
        ``django-concat``, or ``hmac``.
    """

    def __init__(
        self,
        digest_method: t.Any = _MISSING,
        min_key_bits: int | None = None,
        key_derivation: str | None = None,
        **kwargs: t.Any,
    ):
        if digest_method is None:
            raise PolicyError("signing policy cannot use the none algorithm")
        if digest_method is _MISSING:
            digest_method = None

        for none_key in ("algorithm", "digest", "current_digest", "current"):
            if none_key in kwargs and kwargs[none_key] is None:
                raise PolicyError("signing policy cannot use the none algorithm")

        if digest_method is not None and isinstance(
            digest_method, (tuple, list, set, frozenset)
        ):
            allowed_collection = tuple(digest_method)
            if "allowed_digests" in kwargs:
                raise PolicyError("conflicting signing digest configuration")
            kwargs["allowed_digests"] = allowed_collection
            digest_method = None

        digest_aliases = _pop_alias(
            kwargs, ("algorithm", "digest", "current_digest", "current")
        )
        if digest_aliases is not None:
            if digest_method is not None and not _same_digest(
                _resolve_digest(digest_method), _resolve_digest(digest_aliases)
            ):
                raise PolicyError("conflicting signing digest configuration")
            digest_method = digest_aliases

        allowed = _pop_alias(
            kwargs,
            (
                "allowed_digests",
                "digests",
                "digest_methods",
                "allowed_digest_methods",
                "allowed_algorithms",
                "algorithms",
                "hashes",
                "allowed_hmac_digests",
                "hmac_digests",
            ),
        )
        min_bits_alias = _pop_alias(
            kwargs,
            (
                "min_key_size",
                "minimum_key_bits",
                "minimum_key_size",
                "min_key_length",
                "minimum_key_length",
                "min_bits",
                "key_bits",
            ),
        )
        derivation_alias = _pop_alias(
            kwargs, ("derive", "derivation", "derive_key", "derivation_method")
        )
        allow_none = _pop_alias(
            kwargs,
            (
                "allow_none",
                "none",
                "allow_unsigned",
                "allow_verify_only",
                "allow_none_algorithm",
                "allow_none_digest",
            ),
        )
        verify_only = _pop_alias(
            kwargs, ("verify_only", "read_only", "verification_only")
        )

        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError(f"unexpected SigningPolicy argument {unexpected!r}")

        if allow_none:
            raise PolicyError("signing policy cannot allow the none algorithm")
        if verify_only:
            raise PolicyError("a signing policy cannot be verification-only")

        if allowed is None:
            allowed_values: tuple[t.Any, ...] = ()
        elif isinstance(allowed, (str, bytes)) or callable(allowed):
            allowed_values = (allowed,)
        else:
            allowed_values = tuple(allowed)

        resolved_allowed = tuple(_resolve_digest(item) for item in allowed_values)
        if any(item is None for item in resolved_allowed):
            raise PolicyError("signing policy cannot allow the none algorithm")

        if digest_method is None and resolved_allowed:
            # Prefer SHA-256 or a stronger digest when only a set is supplied.
            digest_method = max(
                resolved_allowed, key=lambda item: _digest_size(item) or 0
            )
        elif digest_method is None:
            digest_method = hashlib.sha256

        digest_method = _resolve_digest(digest_method)
        if digest_method is None:
            raise PolicyError("signing policy cannot use the none algorithm")

        if _is_weak_digest(digest_method):
            raise WeakDigestError(
                f"weak digest {_digest_name(digest_method)!r} is not allowed"
            )

        for item in resolved_allowed:
            if _is_weak_digest(item):
                raise WeakDigestError(
                    f"weak digest {_digest_name(item)!r} is not allowed"
                )

        if not resolved_allowed:
            resolved_allowed = (digest_method,)

        if min_bits_alias is not None:
            if min_key_bits is not None and min_key_bits != min_bits_alias:
                raise PolicyError("conflicting minimum key size configuration")
            min_key_bits = min_bits_alias
        if min_key_bits is None:
            min_key_bits = 128
        if (
            not isinstance(min_key_bits, int)
            or isinstance(min_key_bits, bool)
            or min_key_bits < 0
        ):
            raise PolicyError("min_key_bits must be a non-negative integer")

        if derivation_alias is not None:
            if key_derivation is not None and key_derivation != derivation_alias:
                raise PolicyError("conflicting key derivation configuration")
            key_derivation = derivation_alias
        if key_derivation is None:
            key_derivation = "hmac"
        if key_derivation == "none":
            raise UnderivedKeyError(
                "underived keys are not allowed by a signing policy"
            )
        if key_derivation not in _KNOWN_DERIVATIONS:
            raise PolicyError(f"unknown key derivation method {key_derivation!r}")

        self.digest_method = digest_method
        self.digest = digest_method
        self.current_digest = digest_method
        self.signing_digest = digest_method
        self.allowed_digests = resolved_allowed
        self.digests = self.allowed_digests
        self.digest_methods = self.allowed_digests
        self.allowed_digest_methods = self.allowed_digests
        self.min_key_bits = min_key_bits
        self.min_key_size = min_key_bits
        self.minimum_key_bits = min_key_bits
        self.minimum_key_size = min_key_bits
        self.key_derivation = key_derivation
        self.derive = key_derivation
        self.derivation = key_derivation
        self.derivations = (key_derivation,)
        self.allowed_derivations = self.derivations
        self.allow_none = False
        self.verify_only = False

    @property
    def algorithm(self) -> HMACAlgorithm:
        """The current HMAC algorithm. A new object is returned so callers
        cannot mutate shared signer state.
        """
        return HMACAlgorithm(self.digest_method)

    def __repr__(self) -> str:
        digest_name = _digest_name(self.digest_method)
        return (
            f"{type(self).__name__}(digest_method={digest_name!r}, "
            f"min_key_bits={self.min_key_bits}, key_derivation={self.key_derivation!r})"
        )


class VerificationPolicy:
    """An explicit policy for verifying signatures.

    Verification may list several HMAC digests and key derivations to read
    legacy tokens during a migration. New tokens are never produced by this
    policy. The ``none`` algorithm is only enabled with ``allow_none=True``
    (or by including ``None`` / ``"none"`` in ``allowed_digests``) and is
    always read-only.

    :param allowed_digests: HMAC digests accepted while verifying.
    :param min_key_bits: Minimum size of every configured secret key in bits.
    :param key_derivations: Key derivation methods accepted while verifying.
    :param allow_none: Explicitly permit empty signatures from the legacy
        ``NoneAlgorithm``. Signing remains disabled.
    """

    def __init__(
        self,
        allowed_digests: t.Any = _MISSING,
        min_key_bits: int | None = None,
        key_derivation: str | cabc.Iterable[str] | None = None,
        **kwargs: t.Any,
    ):
        explicit_none = allowed_digests is None
        for none_key in (
            "digest_method",
            "algorithm",
            "digest",
            "current_digest",
        ):
            if none_key in kwargs and kwargs[none_key] is None:
                explicit_none = True

        digest_alias = _pop_alias(
            kwargs,
            (
                "digest_method",
                "algorithm",
                "digest",
                "current_digest",
                "digests",
                "digest_methods",
                "algorithms",
                "allowed_algorithms",
                "hashes",
                "current",
                "allowed_hmac_digests",
                "hmac_digests",
            ),
        )
        if digest_alias is not None:
            if allowed_digests is _MISSING or allowed_digests is None:
                allowed_digests = digest_alias
                explicit_none = False
            elif tuple(_normalize_values(allowed_digests)) != tuple(
                _normalize_values(digest_alias)
            ):
                raise PolicyError("conflicting verification digest configuration")

        derivations_alias = _pop_alias(
            kwargs,
            (
                "key_derivations",
                "allowed_key_derivations",
                "derive",
                "derivation",
                "derive_key",
                "derivation_method",
                "derivation_methods",
            ),
        )
        min_bits_alias = _pop_alias(
            kwargs,
            (
                "min_key_size",
                "minimum_key_bits",
                "minimum_key_size",
                "min_key_length",
                "minimum_key_length",
                "min_bits",
                "key_bits",
            ),
        )
        allow_none = _pop_alias(
            kwargs,
            (
                "allow_none",
                "none",
                "allow_unsigned",
                "allow_none_algorithm",
                "allow_none_digest",
            ),
        )
        verify_only = _pop_alias(
            kwargs, ("verify_only", "read_only", "verification_only")
        )

        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError(f"unexpected VerificationPolicy argument {unexpected!r}")

        if explicit_none:
            # An explicitly supplied None is the read-only ``none`` mode.
            allow_none = True

        if allowed_digests is _MISSING:
            digest_values: tuple[t.Any, ...] = () if allow_none else (hashlib.sha256,)
        elif allowed_digests is None:
            digest_values = ()
        else:
            digest_values = tuple(_normalize_values(allowed_digests))

        resolved_digests: list[t.Any] = []
        resolved_none = bool(allow_none)
        for item in digest_values:
            resolved = _resolve_digest(item)
            if resolved is None:
                resolved_none = True
            else:
                if _digest_name(resolved) in {"md5", "md5_sha1"}:
                    raise WeakDigestError(
                        f"weak digest {_digest_name(resolved)!r} is not allowed"
                    )
                # SHA-1 is allowed here only because it appears in an
                # explicit verification list. It cannot be selected for
                # signing, and there is no implicit downgrade.
                if all(
                    not _same_digest(resolved, existing)
                    for existing in resolved_digests
                ):
                    resolved_digests.append(resolved)

        if min_bits_alias is not None:
            if min_key_bits is not None and min_key_bits != min_bits_alias:
                raise PolicyError("conflicting minimum key size configuration")
            min_key_bits = min_bits_alias
        if min_key_bits is None:
            min_key_bits = 128
        if (
            not isinstance(min_key_bits, int)
            or isinstance(min_key_bits, bool)
            or min_key_bits < 0
        ):
            raise PolicyError("min_key_bits must be a non-negative integer")

        if derivations_alias is not None:
            if key_derivation is not None and tuple(
                _normalize_values(key_derivation)
            ) != tuple(_normalize_values(derivations_alias)):
                raise PolicyError("conflicting key derivation configuration")
            key_derivation = derivations_alias

        if key_derivation is None:
            derivation_values: tuple[str, ...] = ("django-concat", "hmac", "concat")
        else:
            derivation_values = tuple(
                t.cast(str, value) for value in _normalize_values(key_derivation)
            )

        for derivation in derivation_values:
            if derivation == "none":
                raise UnderivedKeyError(
                    "underived keys are not allowed by a verification policy"
                )
            if derivation not in _KNOWN_DERIVATIONS:
                raise PolicyError(f"unknown key derivation method {derivation!r}")

        if not resolved_digests and not resolved_none:
            raise PolicyError(
                "verification policy must allow at least one digest or none"
            )

        self.allowed_digests = tuple(resolved_digests)
        self.digests = self.allowed_digests
        self.digest_methods = self.allowed_digests
        self.allowed_digest_methods = self.allowed_digests
        # A singular alias is useful to audit code that treats both policies
        # uniformly. It is the first explicitly allowed digest.
        self.digest_method = self.allowed_digests[0] if self.allowed_digests else None
        self.digest = self.digest_method
        self.current_digest = self.digest_method
        self.min_key_bits = min_key_bits
        self.min_key_size = min_key_bits
        self.minimum_key_bits = min_key_bits
        self.minimum_key_size = min_key_bits
        self.key_derivations = derivation_values
        self.allowed_key_derivations = derivation_values
        self.derivations = derivation_values
        self.allowed_derivations = derivation_values
        self.key_derivation = (
            derivation_values[0] if len(derivation_values) == 1 else derivation_values
        )
        self.derive = self.key_derivation
        self.derivation = self.key_derivation
        self.allow_none = resolved_none
        self.verify_only = True if verify_only is None else bool(verify_only)

    def __repr__(self) -> str:
        names = tuple(_digest_name(item) for item in self.allowed_digests)
        return (
            f"{type(self).__name__}(allowed_digests={names!r}, "
            f"min_key_bits={self.min_key_bits}, "
            f"key_derivations={self.key_derivations!r}, allow_none={self.allow_none})"
        )


def _normalize_values(value: t.Any) -> tuple[t.Any, ...]:
    if isinstance(value, (str, bytes)) or callable(value) or value is None:
        return (value,)
    return tuple(value)


class SignaturePolicy:
    """A paired signing and verification policy for one signing context."""

    def __init__(
        self,
        signing: SigningPolicy | None = None,
        verification: VerificationPolicy | None = None,
        **kwargs: t.Any,
    ):
        signing_alias = _pop_alias(kwargs, ("signing_policy", "sign", "sign_policy"))
        verification_alias = _pop_alias(
            kwargs, ("verification_policy", "verify", "verify_policy")
        )

        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError(f"unexpected SignaturePolicy argument {unexpected!r}")

        if signing_alias is not None:
            signing = signing_alias
        if verification_alias is not None:
            verification = verification_alias

        if signing is not None and not isinstance(signing, SigningPolicy):
            raise PolicyError("signing policy must be a SigningPolicy instance")
        if verification is not None and not isinstance(
            verification, VerificationPolicy
        ):
            raise PolicyError(
                "verification policy must be a VerificationPolicy instance"
            )

        self.signing = signing
        self.verification = verification
        self.signing_policy = signing
        self.verification_policy = verification
        self.sign = signing
        self.verify = verification


SignerPolicy = SignaturePolicy

# Descriptive aliases used by configuration modules. They are the same
# classes, so isinstance checks and exception handling remain unambiguous.
SigningConfig = SigningPolicy
VerificationConfig = VerificationPolicy
SignatureConfig = SignaturePolicy
SignerConfig = SignaturePolicy


def _key_bits(key: bytes) -> int:
    return len(key) * 8


class Signer:
    """A signer securely signs bytes, then unsigns them to verify that
    the value hasn't been changed.

    The secret key should be a random string of ``bytes`` and should not
    be saved to code or version control. Different salts should be used
    to distinguish signing in different contexts. See :doc:`/concepts`
    for information about the security of the secret key and salt.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation.
    :param salt: Extra key to combine with ``secret_key`` to distinguish
        signatures in different contexts.
    :param sep: Separator between the signature and value.
    :param key_derivation: How to derive the signing key from the secret
        key and salt. Possible values are ``concat``, ``django-concat``,
        or ``hmac``. Defaults to :attr:`default_key_derivation`, which
        defaults to ``django-concat``.
    :param digest_method: Hash function to use when generating the HMAC
        signature. Defaults to :attr:`default_digest_method`, which
        defaults to :func:`hashlib.sha1`. Note that the security of the
        hash alone doesn't apply when used intermediately in HMAC.
    :param algorithm: A :class:`SigningAlgorithm` instance to use
        instead of building a default :class:`HMACAlgorithm` with the
        ``digest_method``.
    :param signing_policy: A :class:`SigningPolicy` describing how new
        signatures are created.
    :param verification_policy: A :class:`VerificationPolicy` describing
        which legacy and current signatures may be verified.
    :param policy: A :class:`SignaturePolicy` pair, or a single policy that
        applies to the corresponding direction.
    :param verify_only: Explicitly disable token creation. This is required
        for ``none`` verification and is the default when only a
        verification policy is supplied.

    Passing no policy preserves the historical constructor behavior and
    signature format exactly. Policy mode rejects weak digests, short keys,
    underived keys, and algorithm downgrades during construction.

    .. versionchanged:: 2.3
        Added signing and verification policies and stable policy errors.

    .. versionchanged:: 2.0
        Added support for key rotation by passing a list to
        ``secret_key``.

    .. versionchanged:: 0.18
        ``algorithm`` was added as an argument to the class constructor.

    .. versionchanged:: 0.14
        ``key_derivation`` and ``digest_method`` were added as arguments
        to the class constructor.
    """

    #: The default digest method to use for the signer. The default is
    #: :func:`hashlib.sha1`, but can be changed to any :mod:`hashlib` or
    #: compatible object. Note that the security of the hash alone
    #: doesn't apply when used intermediately in HMAC.
    #:
    #: .. versionadded:: 0.14
    default_digest_method: t.Any = staticmethod(_lazy_sha1)

    #: The default scheme to use to derive the signing key from the
    #: secret key and salt. The default is ``django-concat``. Possible
    #: values are ``concat``, ``django-concat``, and ``hmac``.
    #:
    #: .. versionadded:: 0.14
    default_key_derivation: str = "django-concat"

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous.Signer",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: SigningAlgorithm | None = None,
        policy: SignaturePolicy | SigningPolicy | VerificationPolicy | None = None,
        *,
        signing_policy: SigningPolicy | None = None,
        verification_policy: VerificationPolicy | None = None,
        verify_only: bool = False,
        **kwargs: t.Any,
    ):
        sign_policy_alias = _pop_alias(
            kwargs,
            (
                "sign_policy",
                "signing",
                "security_policy",
                "signer_policy",
                "signing_config",
            ),
        )
        verify_policy_alias = _pop_alias(
            kwargs,
            (
                "verify_policy",
                "verify",
                "read_only_policy",
                "verification_config",
            ),
        )
        verify_only_alias = _pop_alias(
            kwargs, ("read_only", "verification_only", "no_sign")
        )
        policies_alias = _pop_alias(kwargs, ("policies", "signature_policy"))
        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError(f"unexpected Signer argument {unexpected!r}")

        if policies_alias is not None:
            if policy is not None:
                raise PolicyError("conflicting policy configuration")
            policy = policies_alias

        if sign_policy_alias is not None:
            if signing_policy is not None:
                raise PolicyError("conflicting signing policy configuration")
            if isinstance(sign_policy_alias, SignaturePolicy):
                signing_policy = sign_policy_alias.signing_policy
                if verification_policy is None:
                    verification_policy = sign_policy_alias.verification_policy
            else:
                signing_policy = sign_policy_alias
        if verify_policy_alias is not None:
            if verification_policy is not None:
                raise PolicyError("conflicting verification policy configuration")
            verification_policy = verify_policy_alias
        if verify_only_alias is not None:
            verify_only = bool(verify_only_alias)

        if isinstance(policy, tuple) and len(policy) == 2:
            if signing_policy is not None or verification_policy is not None:
                raise PolicyError("conflicting policy configuration")
            signing_policy, verification_policy = policy
        elif isinstance(policy, SignaturePolicy):
            if signing_policy is not None or verification_policy is not None:
                raise PolicyError("conflicting policy configuration")
            signing_policy = policy.signing_policy
            verification_policy = policy.verification_policy
        elif isinstance(policy, SigningPolicy):
            if signing_policy is not None:
                raise PolicyError("conflicting signing policy configuration")
            signing_policy = policy
        elif isinstance(policy, VerificationPolicy):
            if verification_policy is not None:
                raise PolicyError("conflicting verification policy configuration")
            verification_policy = policy
        elif policy is not None:
            raise PolicyError(
                "policy must be a SigningPolicy, VerificationPolicy, or SignaturePolicy"
            )

        if signing_policy is not None and not isinstance(signing_policy, SigningPolicy):
            raise PolicyError("signing_policy must be a SigningPolicy instance")
        if verification_policy is not None and not isinstance(
            verification_policy, VerificationPolicy
        ):
            raise PolicyError(
                "verification_policy must be a VerificationPolicy instance"
            )

        if isinstance(algorithm, str):
            if algorithm.strip().lower() in _NONE_ALGORITHM_NAMES:
                algorithm = NoneAlgorithm()
            else:
                algorithm = HMACAlgorithm(_resolve_digest(algorithm))

        if digest_method is not None:
            digest_method = _resolve_digest(digest_method)

        #: The list of secret keys to try for verifying signatures, from
        #: oldest to newest. The newest (last) key is used for signing.
        #:
        #: This allows a key rotation system to keep a list of allowed
        #: keys and remove expired ones.
        self.secret_keys: list[bytes] = _make_keys_list(secret_key)
        self.sep: bytes = want_bytes(sep)

        if self.sep in _base64_alphabet:
            raise ValueError(
                "The given separator cannot be used because it may be"
                " contained in the signature itself. ASCII letters,"
                " digits, and '-_=' must not be used."
            )

        if salt is not None:
            salt = want_bytes(salt)
        else:
            salt = b"itsdangerous.Signer"

        self.salt = salt

        self.signing_policy = signing_policy
        self.verification_policy = verification_policy
        self.policy = policy

        # A verification policy on its own is a read-only signer. Supplying
        # both policies keeps the explicit verify_only setting, which defaults
        # to false, so new tokens are produced with the current digest.
        if verification_policy is not None and signing_policy is None:
            verify_only = True
        elif verification_policy is not None and verification_policy.verify_only:
            # ``verify_only`` on a VerificationPolicy can still be set to
            # false when the caller supplies a matching SigningPolicy.
            verify_only = bool(verify_only)
        self.verify_only = bool(verify_only)

        policy_min_bits = 0
        if signing_policy is not None:
            policy_min_bits = max(policy_min_bits, signing_policy.min_key_bits)
        if verification_policy is not None:
            policy_min_bits = max(policy_min_bits, verification_policy.min_key_bits)

        if (
            signing_policy is not None or verification_policy is not None
        ) and not self.secret_keys:
            raise WeakKeyError("weak key: at least one secret key is required")

        if policy_min_bits and any(
            _key_bits(key) < policy_min_bits for key in self.secret_keys
        ):
            shortest = min(_key_bits(key) for key in self.secret_keys)
            raise WeakKeyError(
                f"weak key: secret key is {shortest} bits, policy requires at least "
                f"{policy_min_bits} bits"
            )

        if signing_policy is None:
            if key_derivation is None:
                key_derivation = self.default_key_derivation
            elif key_derivation == "none" and verification_policy is not None:
                raise UnderivedKeyError("underived keys are not allowed by policy")
        else:
            if key_derivation is None:
                key_derivation = signing_policy.key_derivation
            elif key_derivation != signing_policy.key_derivation:
                raise AlgorithmDowngradeError(
                    "algorithm downgrade: key derivation does not match"
                    " the signing policy"
                )
            if key_derivation == "none":
                raise UnderivedKeyError("underived keys are not allowed by policy")

        if key_derivation not in _KNOWN_DERIVATIONS:
            # Preserve the historical behavior for non-policy callers: the
            # error is raised by derive_key, not during construction.
            if signing_policy is not None or verification_policy is not None:
                raise PolicyError(f"unknown key derivation method {key_derivation!r}")
        self.key_derivation: str = key_derivation

        if signing_policy is not None:
            if digest_method is not None and not _same_digest(
                _resolve_digest(digest_method), signing_policy.digest_method
            ):
                raise AlgorithmDowngradeError(
                    "algorithm downgrade: digest method does not match"
                    " the signing policy"
                )

            if algorithm is None:
                algorithm = HMACAlgorithm(signing_policy.digest_method)
            elif isinstance(algorithm, NoneAlgorithm):
                raise PolicyError("signing policy cannot use the none algorithm")
            elif not isinstance(algorithm, HMACAlgorithm):
                raise UnsupportedAlgorithm(
                    f"unsupported algorithm {type(algorithm).__name__!r} for policy"
                )
            elif not _same_digest(
                algorithm.digest_method, signing_policy.digest_method
            ):
                raise AlgorithmDowngradeError(
                    "algorithm downgrade: algorithm digest does not match"
                    " the signing policy"
                )
        elif verification_policy is not None and algorithm is not None:
            if isinstance(algorithm, NoneAlgorithm):
                if not verification_policy.allow_none:
                    raise PolicyError(
                        "none algorithm is not allowed by verification policy"
                    )
            elif isinstance(algorithm, HMACAlgorithm):
                if not any(
                    _same_digest(algorithm.digest_method, item)
                    for item in verification_policy.allowed_digests
                ):
                    raise AlgorithmDowngradeError(
                        "algorithm downgrade: digest is not allowed by"
                        " verification policy"
                    )
            else:
                raise UnsupportedAlgorithm(
                    f"unsupported algorithm {type(algorithm).__name__!r} for policy"
                )

        if digest_method is None:
            if signing_policy is not None:
                digest_method = signing_policy.digest_method
            else:
                digest_method = self.default_digest_method

        self.digest_method: t.Any = digest_method

        if algorithm is None:
            algorithm = HMACAlgorithm(self.digest_method)

        self.algorithm: SigningAlgorithm = algorithm

        if signing_policy is not None and verification_policy is not None:
            if not any(
                _same_digest(signing_policy.digest_method, item)
                for item in verification_policy.allowed_digests
            ):
                raise AlgorithmDowngradeError(
                    "algorithm downgrade: signing digest is not allowed by"
                    " the verification policy"
                )
            if signing_policy.key_derivation not in verification_policy.key_derivations:
                raise AlgorithmDowngradeError(
                    "algorithm downgrade: signing key derivation is not"
                    " allowed by the verification policy"
                )

        if verification_policy is not None:
            self._verification_digests = verification_policy.allowed_digests
            self._verification_derivations = verification_policy.key_derivations
            self._verify_none = verification_policy.allow_none
        else:
            self._verification_digests = ()
            self._verification_derivations = (self.key_derivation,)
            self._verify_none = isinstance(self.algorithm, NoneAlgorithm)

    @property
    def secret_key(self) -> bytes:
        """The newest (last) entry in the :attr:`secret_keys` list. This
        is for compatibility from before key rotation support was added.
        """
        return self.secret_keys[-1]

    def derive_key(
        self,
        secret_key: str | bytes | None = None,
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
    ) -> bytes:
        """This method is called to derive the key. The default key
        derivation choices can be overridden here. Key derivation is not
        intended to be used as a security method to make a complex key
        out of a short password. Instead you should use large random
        secret keys.

        :param secret_key: A specific secret key to derive from.
            Defaults to the last item in :attr:`secret_keys`.
        :param key_derivation: Override the signer's derivation method.
            Used internally when a verification policy accepts legacy
            derivations.
        :param digest_method: Override the digest used while deriving.
            Used internally when verifying legacy digest formats.

        .. versionchanged:: 2.3
            Added the ``key_derivation`` and ``digest_method`` parameters.

        .. versionchanged:: 2.0
            Added the ``secret_key`` parameter.
        """
        if secret_key is None:
            secret_key = self.secret_keys[-1]
        else:
            secret_key = want_bytes(secret_key)

        if key_derivation is None:
            key_derivation = self.key_derivation
        if digest_method is None:
            digest_method = self.digest_method

        if key_derivation == "concat":
            return t.cast(bytes, digest_method(self.salt + secret_key).digest())
        elif key_derivation == "django-concat":
            return t.cast(
                bytes, digest_method(self.salt + b"signer" + secret_key).digest()
            )
        elif key_derivation == "hmac":
            mac = hmac.new(secret_key, digestmod=digest_method)
            mac.update(self.salt)
            return mac.digest()
        elif key_derivation == "none":
            if self.signing_policy is not None or self.verification_policy is not None:
                raise UnderivedKeyError("underived keys are not allowed by policy")
            return secret_key
        else:
            raise TypeError("Unknown key derivation method")

    def _get_signature_with_algorithm(
        self, value: bytes, algorithm: SigningAlgorithm
    ) -> bytes:
        key = self.derive_key()
        sig = algorithm.get_signature(key, value)
        return base64_encode(sig)

    def get_signature(self, value: str | bytes) -> bytes:
        """Returns the signature for the given value."""
        if self.verify_only:
            raise PolicyError("verify-only signers cannot create signatures")

        if isinstance(self.algorithm, NoneAlgorithm) and (
            self.signing_policy is not None or self.verification_policy is not None
        ):
            raise PolicyError("the none algorithm is read-only and cannot sign")

        value = want_bytes(value)
        return self._get_signature_with_algorithm(value, self.algorithm)

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string."""
        if self.verify_only:
            raise PolicyError("verify-only signers cannot create tokens")

        value = want_bytes(value)
        return value + self.sep + self.get_signature(value)

    def _verify_with_algorithm(
        self,
        secret_key: bytes,
        value: bytes,
        sig: bytes,
        key_derivation: str,
        digest_method: t.Any,
    ) -> bool:
        key = self.derive_key(secret_key, key_derivation, digest_method)
        algorithm = HMACAlgorithm(digest_method)
        return algorithm.verify_signature(key, value, sig)

    def verify_signature(self, value: str | bytes, sig: str | bytes) -> bool:
        """Verifies the signature for the given value."""
        try:
            sig = base64_decode(sig)
        except Exception:
            return False

        value = want_bytes(value)

        if self.verification_policy is None:
            for secret_key in reversed(self.secret_keys):
                try:
                    key = self.derive_key(secret_key)
                    if self.algorithm.verify_signature(key, value, sig):
                        return True
                except UnderivedKeyError:
                    continue
            return False

        if self._verify_none and sig == b"":
            return True

        for secret_key in reversed(self.secret_keys):
            for key_derivation in self._verification_derivations:
                for digest_method in self._verification_digests:
                    if self._verify_with_algorithm(
                        secret_key, value, sig, key_derivation, digest_method
                    ):
                        return True

        return False

    def unsign(self, signed_value: str | bytes) -> bytes:
        """Unsigns the given string."""
        signed_value = want_bytes(signed_value)

        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        value, sig = signed_value.rsplit(self.sep, 1)

        if self.verify_signature(value, sig):
            return value

        raise BadSignature(f"Signature {sig!r} does not match", payload=value)

    def validate(self, signed_value: str | bytes) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid.
        """
        try:
            self.unsign(signed_value)
            return True
        except BadSignature:
            return False
