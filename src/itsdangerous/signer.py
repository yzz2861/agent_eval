from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import typing as t
from dataclasses import dataclass

from .encoding import _base64_alphabet
from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadHeader
from .exc import BadSignature

_KeyId = str | bytes
_SecretKeyInput = (
    str
    | bytes
    | cabc.Iterable[str]
    | cabc.Iterable[bytes]
    | cabc.Mapping[_KeyId, str | bytes]
)


@dataclass(frozen=True)
class SignatureInfo:
    """Information about the key and format used to verify a signature."""

    version: int | None
    key_id: _KeyId | None
    active_key_id: _KeyId | None
    should_resign: bool


@dataclass(frozen=True)
class UnsignResult:
    """The unsigned value and information about its verified signature."""

    value: bytes
    info: SignatureInfo


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


def _make_key_bundle(
    secret_key: _SecretKeyInput,
) -> tuple[
    list[bytes],
    list[_KeyId | None],
    dict[bytes, tuple[_KeyId, bytes]] | None,
]:
    if isinstance(secret_key, cabc.Mapping):
        secret_keys: list[bytes] = []
        key_ids: list[_KeyId] = []
        key_map: dict[bytes, tuple[_KeyId, bytes]] = {}

        for key_id, secret in secret_key.items():
            if not isinstance(key_id, (str, bytes)):
                raise TypeError("Key ids must be strings or bytes")

            if not isinstance(secret, (str, bytes)):
                raise TypeError("Secret keys must be strings or bytes")

            if not want_bytes(key_id):
                raise ValueError("Key ids must not be empty")

            encoded_key_id = base64_encode(want_bytes(key_id))

            if encoded_key_id in key_map:
                raise ValueError("Key ids must be unique")

            key = want_bytes(secret)
            key_map[encoded_key_id] = (key_id, key)
            key_ids.append(key_id)
            secret_keys.append(key)

        if not key_ids:
            raise ValueError("At least one secret key is required")

        return secret_keys, key_ids, key_map

    secret_keys = _make_keys_list(secret_key)
    return secret_keys, [None] * len(secret_keys), None


class Signer:
    """A signer securely signs bytes, then unsigns them to verify that
    the value hasn't been changed.

    The secret key should be a random string of ``bytes`` and should not
    be saved to code or version control. Different salts should be used
    to distinguish signing in different contexts. See :doc:`/concepts`
    for information about the security of the secret key and salt.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation, or a
        mapping of key ids to secret keys to use versioned signatures.
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
    :param accept_legacy: Accept unversioned signatures when a mapping
        of keys is provided. This is useful while rotating to versioned
        signatures.

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
        secret_key: _SecretKeyInput,
        salt: str | bytes | None = b"itsdangerous.Signer",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: SigningAlgorithm | None = None,
        accept_legacy: bool = False,
    ):
        #: The list of secret keys to try for verifying signatures, from
        #: oldest to newest. The newest (last) key is used for signing.
        #:
        #: This allows a key rotation system to keep a list of allowed
        #: keys and remove expired ones.
        self.secret_keys, self.secret_key_ids, self._secret_key_map = _make_key_bundle(
            secret_key
        )
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

        if key_derivation is None:
            key_derivation = self.default_key_derivation

        self.key_derivation: str = key_derivation

        if digest_method is None:
            digest_method = self.default_digest_method

        self.digest_method: t.Any = digest_method

        if algorithm is None:
            algorithm = HMACAlgorithm(self.digest_method)

        self.algorithm: SigningAlgorithm = algorithm
        self.accept_legacy: bool = accept_legacy and self._secret_key_map is not None

    @property
    def secret_key(self) -> bytes:
        """The newest (last) entry in the :attr:`secret_keys` list. This
        is for compatibility from before key rotation support was added.
        """
        return self.secret_keys[-1]

    @property
    def active_key_id(self) -> _KeyId | None:
        """The id of the key used when creating new signatures."""
        return self.secret_key_ids[-1]

    def _version_header(self) -> bytes | None:
        key_id = self.secret_key_ids[-1]

        if key_id is None or self._secret_key_map is None:
            return None

        return b"v1." + base64_encode(want_bytes(key_id))

    def _wrap_value(self, value: bytes) -> bytes:
        header = self._version_header()

        if header is None:
            return value

        return header + self.sep + value

    def _get_versioned_key(
        self, value: bytes
    ) -> tuple[bytes, bytes, _KeyId, bytes] | None:
        if self._secret_key_map is None:
            return None

        first_dot = value.find(b".")

        if first_dot < 0:
            return None

        version_field = value[:first_dot]

        if version_field == b"v1":
            remainder = value[first_dot + 1 :]
            encoded_key_id, found, inner_value = remainder.partition(self.sep)

            if not found or not encoded_key_id:
                raise BadHeader("Malformed signature version header", payload=value)

            selected = self._secret_key_map.get(encoded_key_id)

            if selected is None:
                raise BadHeader(
                    f"Unknown key id {encoded_key_id.decode('ascii')!r}",
                    payload=inner_value,
                    header=version_field + b"." + encoded_key_id,
                )

            key_id, secret_key = selected
            return inner_value, encoded_key_id, key_id, secret_key

        if version_field.startswith(b"v") and version_field[1:].isdigit():
            raise BadHeader(
                f"Unsupported signature version {version_field[1:].decode('ascii')!r}",
                payload=value,
                header=version_field,
            )

        return None

    def _signature_matches(
        self, secret_key: bytes, value: bytes, sig: str | bytes
    ) -> bool:
        try:
            decoded_sig = base64_decode(sig)
        except Exception:
            return False

        key = self.derive_key(secret_key)
        return self.algorithm.verify_signature(key, value, decoded_sig)

    def _verify_legacy_signature(
        self, value: bytes, sig: str | bytes
    ) -> tuple[_KeyId | None, bytes] | None:
        for secret_key, key_id in zip(
            reversed(self.secret_keys),
            reversed(self.secret_key_ids),
            strict=True,
        ):
            if self._signature_matches(secret_key, value, sig):
                return key_id, secret_key

        return None

    def _unsign(self, signed_value: str | bytes) -> UnsignResult:
        signed_value = want_bytes(signed_value)

        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        authenticated_value, sig = signed_value.rsplit(self.sep, 1)
        versioned = self._get_versioned_key(authenticated_value)

        if versioned is not None:
            value, _, key_id, secret_key = versioned

            if not self._signature_matches(secret_key, authenticated_value, sig):
                raise BadHeader(f"Signature {sig!r} does not match", payload=value)

            active_key_id = self.active_key_id
            info = SignatureInfo(
                version=1,
                key_id=key_id,
                active_key_id=active_key_id,
                should_resign=key_id != active_key_id,
            )
            return UnsignResult(value, info)

        if self._secret_key_map is not None and not self.accept_legacy:
            raise BadHeader(
                "Legacy signatures are not accepted", payload=authenticated_value
            )

        matched = self._verify_legacy_signature(authenticated_value, sig)

        if matched is None:
            raise BadSignature(
                f"Signature {sig!r} does not match", payload=authenticated_value
            )

        key_id, _ = matched
        info = SignatureInfo(
            version=None,
            key_id=key_id,
            active_key_id=self.active_key_id,
            should_resign=self._secret_key_map is not None,
        )
        return UnsignResult(authenticated_value, info)

    def derive_key(self, secret_key: str | bytes | None = None) -> bytes:
        """This method is called to derive the key. The default key
        derivation choices can be overridden here. Key derivation is not
        intended to be used as a security method to make a complex key
        out of a short password. Instead you should use large random
        secret keys.

        :param secret_key: A specific secret key to derive from.
            Defaults to the last item in :attr:`secret_keys`.

        .. versionchanged:: 2.0
            Added the ``secret_key`` parameter.
        """
        if secret_key is None:
            secret_key = self.secret_keys[-1]
        else:
            secret_key = want_bytes(secret_key)

        if self.key_derivation == "concat":
            return t.cast(bytes, self.digest_method(self.salt + secret_key).digest())
        elif self.key_derivation == "django-concat":
            return t.cast(
                bytes, self.digest_method(self.salt + b"signer" + secret_key).digest()
            )
        elif self.key_derivation == "hmac":
            mac = hmac.new(secret_key, digestmod=self.digest_method)
            mac.update(self.salt)
            return mac.digest()
        elif self.key_derivation == "none":
            return secret_key
        else:
            raise TypeError("Unknown key derivation method")

    def get_signature(self, value: str | bytes) -> bytes:
        """Returns the signature for the given value."""
        value = want_bytes(value)
        key = self.derive_key()
        sig = self.algorithm.get_signature(key, value)
        return base64_encode(sig)

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string."""
        value = want_bytes(value)
        authenticated_value = self._wrap_value(value)
        return authenticated_value + self.sep + self.get_signature(authenticated_value)

    def verify_signature(self, value: str | bytes, sig: str | bytes) -> bool:
        """Verifies the signature for the given value."""
        value = want_bytes(value)

        try:
            versioned = self._get_versioned_key(value)
        except BadHeader:
            return False

        if versioned is not None:
            _, _, _, secret_key = versioned
            return self._signature_matches(secret_key, value, sig)

        if self._secret_key_map is not None and not self.accept_legacy:
            return False

        return self._verify_legacy_signature(value, sig) is not None

    def unsign(self, signed_value: str | bytes) -> bytes:
        """Unsigns the given string."""
        return self._unsign(signed_value).value

    def unsign_with_info(self, signed_value: str | bytes) -> UnsignResult:
        """Unsign a value and return key and format metadata."""
        return self._unsign(signed_value)

    def validate(self, signed_value: str | bytes) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid.
        """
        try:
            self.unsign(signed_value)
            return True
        except BadSignature:
            return False
