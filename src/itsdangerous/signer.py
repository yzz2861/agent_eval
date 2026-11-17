from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import typing as t

from .encoding import _base64_alphabet
from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadSignature


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


#: A secret key specification: a single key, a list of keys for
#: rotation, or a mapping of key id to key for identified rotation.
_TSecretKey = (
    str
    | bytes
    | cabc.Iterable[str]
    | cabc.Iterable[bytes]
    | cabc.Mapping[str | bytes, str | bytes]
)


def _make_keys_list(secret_key: _TSecretKey) -> list[bytes]:
    if isinstance(secret_key, (str, bytes)):
        return [want_bytes(secret_key)]

    if isinstance(secret_key, cabc.Mapping):
        return [want_bytes(key) for key in secret_key.values()]

    return [want_bytes(s) for s in secret_key]  # pyright: ignore


def _make_key_id_map(secret_key: _TSecretKey) -> dict[bytes, bytes] | None:
    """Build an ordered map of key id to secret key if ``secret_key``
    is a mapping, otherwise return ``None``.
    """
    if not isinstance(secret_key, cabc.Mapping):
        return None

    return {want_bytes(key_id): want_bytes(key) for key_id, key in secret_key.items()}


class Signer:
    """A signer securely signs bytes, then unsigns them to verify that
    the value hasn't been changed.

    The secret key should be a random string of ``bytes`` and should not
    be saved to code or version control. Different salts should be used
    to distinguish signing in different contexts. See :doc:`/concepts`
    for information about the security of the secret key and salt.

    :param secret_key: The secret key to sign and verify with. Can be a
        list of keys, oldest to newest, to support key rotation.
        Can also be a dict mapping a key id to each key, in which case
        the key id is embedded in the signed value so that verification
        and auditing can tell which key signed a value.
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

    .. versionchanged:: 2.0
        Added support for key rotation by passing a list to
        ``secret_key``.

    .. versionchanged:: 2.3
        Added support for identified key rotation by passing a dict of
        key ids to ``secret_key``.

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
        secret_key: _TSecretKey,
        salt: str | bytes | None = b"itsdangerous.Signer",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: SigningAlgorithm | None = None,
    ):
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

        #: A map of key id to secret key, ordered oldest to newest, if
        #: ``secret_key`` was given as a dict. The newest (last) id is
        #: embedded in signed values so that verification can look up
        #: the exact key, and audits can tell which key signed a value.
        #: ``None`` when key ids are not used.
        #:
        #: .. versionadded:: 2.3
        self.secret_key_map: dict[bytes, bytes] | None = _make_key_id_map(
            secret_key
        )

        if self.secret_key_map is not None:
            for key_id in self.secret_key_map:
                if not key_id or self.sep in key_id:
                    raise ValueError(
                        "Key ids must be non-empty and must not contain"
                        " the separator."
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

    @property
    def secret_key(self) -> bytes:
        """The newest (last) entry in the :attr:`secret_keys` list. This
        is for compatibility from before key rotation support was added.
        """
        return self.secret_keys[-1]

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

    def _signature_suffix(self, value: bytes) -> bytes:
        """The part appended after the value when signing: the
        signature, prefixed with the newest key id if key ids are used.
        """
        sig = self.get_signature(value)

        if self.secret_key_map is None:
            return sig

        key_id = next(reversed(self.secret_key_map))
        return key_id + self.sep + sig

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string."""
        value = want_bytes(value)
        return value + self.sep + self._signature_suffix(value)

    def verify_signature(
        self, value: str | bytes, sig: str | bytes, key_id: str | bytes | None = None
    ) -> bool:
        """Verifies the signature for the given value.

        :param key_id: If given, only the key with this id is tried.
            Otherwise all keys in :attr:`secret_keys` are tried, newest
            first.

        .. versionchanged:: 2.3
            Added the ``key_id`` parameter.
        """
        try:
            sig = base64_decode(sig)
        except Exception:
            return False

        value = want_bytes(value)

        if key_id is not None:
            if self.secret_key_map is None:
                return False

            secret_key = self.secret_key_map.get(want_bytes(key_id))

            if secret_key is None:
                return False

            keys: cabc.Iterable[bytes] = [secret_key]
        else:
            keys = reversed(self.secret_keys)

        for secret_key in keys:
            key = self.derive_key(secret_key)

            if self.algorithm.verify_signature(key, value, sig):
                return True

        return False

    def _split_signed_value(
        self, signed_value: bytes
    ) -> tuple[bytes, bytes, bytes | None]:
        """Split a signed value into ``(value, signature, key_id)``.
        ``key_id`` is ``None`` for values in the legacy format without
        an embedded key id.
        """
        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        rest, sig = signed_value.rsplit(self.sep, 1)

        if self.secret_key_map is not None:
            value, sep, candidate = rest.rpartition(self.sep)

            if sep and candidate in self.secret_key_map:
                return value, sig, candidate

        return rest, sig, None

    def get_key_id(self, signed_value: str | bytes) -> bytes | None:
        """The id of the key that signed the given value, or ``None``
        if the value uses the legacy format without an embedded key id.
        The signature is not verified.

        .. versionadded:: 2.3
        """
        signed_value = want_bytes(signed_value)

        try:
            return self._split_signed_value(signed_value)[2]
        except BadSignature:
            return None

    def unsign(self, signed_value: str | bytes) -> bytes:
        """Unsigns the given string."""
        signed_value = want_bytes(signed_value)
        value, sig, key_id = self._split_signed_value(signed_value)

        if self.verify_signature(value, sig, key_id=key_id):
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
