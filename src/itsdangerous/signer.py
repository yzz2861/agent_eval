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
from .exc import SignerUnavailable


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

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string."""
        value = want_bytes(value)
        return value + self.sep + self.get_signature(value)

    def verify_signature(self, value: str | bytes, sig: str | bytes) -> bool:
        """Verifies the signature for the given value."""
        try:
            sig = base64_decode(sig)
        except Exception:
            return False

        value = want_bytes(value)

        for secret_key in reversed(self.secret_keys):
            key = self.derive_key(secret_key)

            if self.algorithm.verify_signature(key, value, sig):
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


class AsyncSignerBackend(t.Protocol):
    """Protocol for an asynchronous signing backend, such as a client
    for a remote signing service that holds the secret key.

    The backend only ever receives the exact bytes to authenticate
    along with a ``purpose`` (the salt) that distinguishes signatures
    in different contexts. It never receives the secret key, and it
    never receives unparsed signed blobs.

    Implementations should raise an exception if the service cannot be
    reached. It will be wrapped in :class:`.SignerUnavailable`, which
    is distinct from :class:`.BadSignature`. A backend must not return
    ``False`` from :meth:`verify` merely because the service is
    unavailable, as that would be indistinguishable from a forged
    signature.

    .. versionadded:: 2.3
    """

    async def sign(self, value: bytes, *, purpose: bytes) -> bytes:
        """Returns the signature for the given value."""
        ...

    async def verify(
        self, value: bytes, signature: bytes, *, purpose: bytes
    ) -> bool:
        """Returns ``True`` if the signature is valid for the given
        value.
        """
        ...


class AsyncSigner:
    """An asynchronous counterpart to :class:`Signer` that delegates
    signature generation and verification to an
    :class:`AsyncSignerBackend`, such as a remote signing service.
    This is useful when the secret key is not available locally.

    The same encoding conventions as :class:`Signer` are used: the
    signature is base64 encoded and appended to the value, separated
    by ``sep``. Values produced by :class:`Signer` and this class are
    interchangeable if the backend uses the same key and algorithm.

    Failures are distinguished by exception type:

    -   An invalid signature raises :class:`.BadSignature`.
    -   An unreachable or failing backend raises
        :class:`.SignerUnavailable`.
    -   Cancellation of the surrounding task propagates as
        :exc:`asyncio.CancelledError`.

    :param backend: The :class:`AsyncSignerBackend` to call.
    :param salt: Passed to the backend as the ``purpose`` to
        distinguish signatures in different contexts.
    :param sep: Separator between the signature and value.

    .. versionadded:: 2.3
    """

    #: The default purpose passed to the backend if no salt is given.
    default_purpose: bytes = b"itsdangerous.Signer"

    def __init__(
        self,
        backend: AsyncSignerBackend,
        salt: str | bytes | None = None,
        sep: str | bytes = b".",
    ):
        #: The backend that performs signing and verification.
        self.backend: AsyncSignerBackend = backend
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
            salt = self.default_purpose

        self.salt = salt

    async def get_signature(self, value: str | bytes) -> bytes:
        """Returns the signature for the given value, base64 encoded."""
        value = want_bytes(value)

        try:
            sig = await self.backend.sign(value, purpose=self.salt)
        except SignerUnavailable:
            raise
        except Exception as e:
            raise SignerUnavailable(
                "The signing backend failed to produce a signature.",
                original_error=e,
            ) from e

        return base64_encode(sig)

    async def sign(self, value: str | bytes) -> bytes:
        """Signs the given string."""
        value = want_bytes(value)
        return value + self.sep + await self.get_signature(value)

    async def verify_signature(self, value: str | bytes, sig: str | bytes) -> bool:
        """Verifies the signature for the given value."""
        try:
            sig = base64_decode(sig)
        except Exception:
            return False

        value = want_bytes(value)

        try:
            return await self.backend.verify(value, sig, purpose=self.salt)
        except SignerUnavailable:
            raise
        except Exception as e:
            raise SignerUnavailable(
                "The signing backend failed to verify a signature.",
                original_error=e,
            ) from e

    async def unsign(self, signed_value: str | bytes) -> bytes:
        """Unsigns the given string."""
        signed_value = want_bytes(signed_value)

        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        value, sig = signed_value.rsplit(self.sep, 1)

        if await self.verify_signature(value, sig):
            return value

        raise BadSignature(f"Signature {sig!r} does not match", payload=value)

    async def validate(self, signed_value: str | bytes) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid.
        """
        try:
            await self.unsign(signed_value)
            return True
        except BadSignature:
            return False
