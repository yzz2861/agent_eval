from __future__ import annotations

import collections.abc as cabc
import dataclasses
import typing as t
from datetime import datetime

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import int_to_bytes
from .encoding import want_bytes
from .exc import BadSignature
from .exc import SignatureExpired
from .serializer import _TSerialized
from .serializer import Serializer
from .signer import Signer
from .signer import SigningAlgorithm
from .timed import TimedSerializer
from .timed import TimestampSigner
from .url_safe import URLSafeSerializerMixin


class UnknownKeyId(BadSignature):
    """Raised when a versioned signed value references a key id that is
    not known. Verification fails immediately, the remaining keys are
    not tried.

    .. versionadded:: 2.3
    """

    def __init__(self, key_id: str, payload: t.Any | None = None):
        super().__init__(f"Unknown key id {key_id!r}", payload=payload)

        #: The key id that was not found in the signer's key map.
        self.key_id: str = key_id


@dataclasses.dataclass(frozen=True)
class KeyedVerification:
    """Information about a successfully verified versioned signed
    value, returned by :meth:`~KeyedSigner.unsign_with_info` and
    :meth:`~KeyedSerializer.loads_with_info`.

    .. versionadded:: 2.3
    """

    #: The unsigned value. For timed signers the timestamp has already
    #: been removed.
    value: bytes

    #: The key id that verified the value, or ``None`` if the value
    #: was in the legacy unversioned format.
    key_id: str | None

    #: Whether the value was in the legacy unversioned format, which is
    #: only accepted when ``accept_legacy`` is enabled.
    legacy: bool

    #: Whether the value should be re-signed with the current version
    #: and active key. This is ``True`` for legacy values and for
    #: versioned values that use an older version or key id.
    resign_recommended: bool

    #: When the signature was created, for timed signers. ``None``
    #: for non-timed signers.
    timestamp: datetime | None = None


def _normalize_key_map(
    secret_keys: cabc.Mapping[str, str | bytes],
    active_key_id: str | None,
) -> tuple[dict[str, bytes], str, list[bytes]]:
    """Validate the key map and active key id. Returns the key map,
    the active key id, and the key values ordered with the active key
    last so that :attr:`~Signer.secret_key` refers to it.
    """
    if not isinstance(secret_keys, cabc.Mapping):
        raise TypeError(
            "secret_keys must be a mapping of key id to secret key,"
            " use Signer for a single key or list of keys"
        )

    key_map = {str(key_id): want_bytes(key) for key_id, key in secret_keys.items()}

    if not key_map:
        raise ValueError("At least one secret key is required")

    if active_key_id is None:
        active_key_id = next(reversed(key_map))

    if active_key_id not in key_map:
        raise ValueError(f"Active key id {active_key_id!r} is not in secret_keys")

    ordered = [key for key_id, key in key_map.items() if key_id != active_key_id]
    ordered.append(key_map[active_key_id])
    return key_map, active_key_id, ordered


def _validate_version(version: int) -> int:
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("version must be a positive integer")

    return version


class KeyedSigner(Signer):
    """A signer that wraps each signed value in a versioned envelope
    carrying a key id, so verification selects the correct key directly
    instead of trying every key in rotation.

    The signed value has the format
    ``v{version}{sep}{key_id}{sep}{value}{sep}{signature}``. The
    signature covers the version, key id, and value, so changing any
    outer identifier invalidates the signature. If the key id is not
    known, :exc:`UnknownKeyId` is raised immediately without trying
    any other key.

    Values in the legacy unversioned format produced by
    :class:`Signer` are rejected unless ``accept_legacy`` is
    enabled, in which case all keys are tried as before. Note that a
    legacy value starting with ``v{number}{sep}`` is
    indistinguishable from a versioned envelope and will be treated as
    one.

    :param secret_keys: A mapping of key id to secret key. Unknown key
        ids fail immediately during verification.
    :param active_key_id: The key id to sign new values with. Defaults
        to the last id in ``secret_keys``.
    :param version: The envelope version to write when signing. Other
        versions still verify, but are reported as needing a re-sign.
    :param accept_legacy: Accept values in the legacy unversioned
        format by trying all keys. Disabled by default.
    :param salt: Extra key to combine with each secret key to
        distinguish signatures in different contexts.
    :param sep: Separator between the envelope fields, value, and
        signature.
    :param key_derivation: How to derive the signing key from the
        secret key and salt.
    :param digest_method: Hash function to use when generating the HMAC
        signature.
    :param algorithm: A :class:`SigningAlgorithm` instance to use
        instead of building a default one.

    .. versionadded:: 2.3
    """

    def __init__(
        self,
        secret_keys: cabc.Mapping[str, str | bytes],
        active_key_id: str | None = None,
        version: int = 1,
        accept_legacy: bool = False,
        salt: str | bytes | None = b"itsdangerous.Signer",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: SigningAlgorithm | None = None,
    ):
        key_map, active_key_id, ordered = _normalize_key_map(secret_keys, active_key_id)
        super().__init__(
            ordered,
            salt=salt,
            sep=sep,
            key_derivation=key_derivation,
            digest_method=digest_method,
            algorithm=algorithm,
        )

        for key_id in key_map:
            if not key_id or any(c.isspace() for c in key_id):
                raise ValueError(f"Invalid key id {key_id!r}")

            if self.sep in key_id.encode("utf-8"):
                raise ValueError(
                    f"Key id {key_id!r} contains the separator {self.sep!r}"
                )

        #: The mapping of key id to secret key used for verification.
        self.key_map: dict[str, bytes] = key_map

        #: The key id used when signing new values.
        self.active_key_id: str = active_key_id

        #: The envelope version written when signing.
        self.version: int = _validate_version(version)

        #: Whether legacy unversioned values are accepted.
        self.accept_legacy: bool = accept_legacy

    def _envelope(self, value: bytes) -> bytes:
        """Prepend the version and key id to the value. The returned
        bytes are what gets signed.
        """
        return (
            b"v"
            + str(self.version).encode("ascii")
            + self.sep
            + self.active_key_id.encode("utf-8")
            + self.sep
            + value
        )

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string, wrapping it in a versioned
        envelope that carries the active key id.
        """
        value = want_bytes(value)
        env = self._envelope(value)
        return env + self.sep + self.get_signature(env)

    def _verify_envelope(self, signed_value: str | bytes) -> KeyedVerification:
        """Verify a signed value and return information about how it
        was verified. Raises :exc:`UnknownKeyId` if the envelope
        names an unknown key id, or :exc:`BadSignature` if the value
        is malformed, unversioned (and ``accept_legacy`` is
        disabled), or the signature does not match.
        """
        signed_value = want_bytes(signed_value)

        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        env, sig = signed_value.rsplit(self.sep, 1)
        head, _, rest = env.partition(self.sep)

        if head[:1] == b"v" and head[1:].isdigit():
            token_version = int(head[1:])
            key_id_b, found, value = rest.partition(self.sep)

            if not found:
                raise BadSignature("Malformed versioned value", payload=rest)

            try:
                key_id = key_id_b.decode("utf-8")
            except UnicodeDecodeError as e:
                raise BadSignature("Key id is not valid UTF-8", payload=value) from e

            if key_id not in self.key_map:
                raise UnknownKeyId(key_id, payload=value)

            key = self.derive_key(self.key_map[key_id])

            try:
                sig_bytes = base64_decode(sig)
            except Exception:
                raise BadSignature(
                    f"Signature {sig!r} does not match", payload=value
                ) from None

            if not self.algorithm.verify_signature(key, env, sig_bytes):
                raise BadSignature(f"Signature {sig!r} does not match", payload=value)

            return KeyedVerification(
                value=value,
                key_id=key_id,
                legacy=False,
                resign_recommended=(
                    key_id != self.active_key_id or token_version != self.version
                ),
            )

        if not self.accept_legacy:
            raise BadSignature(
                "Unversioned signed values are not accepted", payload=env
            )

        value = super().unsign(signed_value)

        return KeyedVerification(
            value=value, key_id=None, legacy=True, resign_recommended=True
        )

    def unsign(self, signed_value: str | bytes) -> bytes:
        """Unsigns the given string, selecting the key named by the
        envelope's key id.
        """
        return self._verify_envelope(signed_value).value

    def unsign_with_info(self, signed_value: str | bytes) -> KeyedVerification:
        """Like :meth:`unsign`, but returns a
        :class:`KeyedVerification` that identifies the key used and
        whether re-signing with the active key is recommended.
        """
        return self._verify_envelope(signed_value)


class KeyedTimestampSigner(TimestampSigner, KeyedSigner):
    """Works like :class:`KeyedSigner` but also records the time
    of the signing, like :class:`TimestampSigner`. The
    ``max_age`` and ``return_timestamp`` parameters of
    :meth:`~TimestampSigner.unsign` are supported.

    .. versionadded:: 2.3
    """

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string, attaching time information and
        wrapping it in a versioned envelope.
        """
        value = want_bytes(value)
        timestamp = base64_encode(int_to_bytes(self.get_timestamp()))
        return KeyedSigner.sign(self, value + self.sep + timestamp)

    # Ignore overlapping signatures check, return_timestamp is the only
    # parameter that affects the return type.

    @t.overload
    def unsign(  # pyright: ignore
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[False] = False,
    ) -> bytes: ...

    @t.overload
    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[True] = True,
    ) -> tuple[bytes, datetime]: ...

    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
    ) -> tuple[bytes, datetime] | bytes:
        try:
            self._verify_envelope(signed_value)
        except UnknownKeyId:
            # Report an unknown key id directly rather than wrapping it
            # in a BadTimeSignature.
            raise
        except BadSignature:
            # Let the timestamp-aware logic produce the proper error.
            pass

        return super().unsign(
            signed_value, max_age=max_age, return_timestamp=return_timestamp
        )

    def unsign_with_info(
        self, signed_value: str | bytes, max_age: int | None = None
    ) -> KeyedVerification:
        """Like :meth:`unsign`, but returns a
        :class:`KeyedVerification` that identifies the key used,
        whether re-signing is recommended, and when the value was
        signed.
        """
        value, timestamp = TimestampSigner.unsign(
            self, signed_value, max_age=max_age, return_timestamp=True
        )
        info = self._verify_envelope(signed_value)

        return KeyedVerification(
            value=value,
            key_id=info.key_id,
            legacy=info.legacy,
            resign_recommended=info.resign_recommended,
            timestamp=timestamp,
        )


class _KeyedSerializerMixin:
    """Passes a mapping of key ids to secret keys, an active key id,
    an envelope version, and the legacy compatibility flag through to
    the keyed signer, and adds :meth:`loads_with_info`.

    .. versionadded:: 2.3
    """

    key_map: dict[str, bytes]
    active_key_id: str
    version: int
    accept_legacy: bool

    def __init__(
        self,
        secret_keys: cabc.Mapping[str, str | bytes],
        active_key_id: str | None = None,
        version: int = 1,
        accept_legacy: bool = False,
        salt: str | bytes | None = b"itsdangerous",
        serializer: t.Any | None = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        signer: type[Signer] | None = None,
        signer_kwargs: dict[str, t.Any] | None = None,
        fallback_signers: list[
            dict[str, t.Any] | tuple[type[Signer], dict[str, t.Any]] | type[Signer]
        ]
        | None = None,
    ):
        key_map, active_key_id, ordered = _normalize_key_map(secret_keys, active_key_id)
        self.key_map = key_map
        self.active_key_id = active_key_id
        self.version = _validate_version(version)
        self.accept_legacy = accept_legacy
        super().__init__(
            ordered,
            salt=salt,
            serializer=serializer,
            serializer_kwargs=serializer_kwargs,
            signer=signer,
            signer_kwargs=signer_kwargs,
            fallback_signers=fallback_signers,
        )

    def make_signer(self, salt: str | bytes | None = None) -> KeyedSigner:
        """Creates a new instance of the keyed signer to be used."""
        if salt is None:
            salt = self.salt

        return t.cast(
            KeyedSigner,
            self.signer(
                self.key_map,
                active_key_id=self.active_key_id,
                version=self.version,
                accept_legacy=self.accept_legacy,
                salt=salt,
                **self.signer_kwargs,
            ),
        )

    def loads_with_info(
        self, s: str | bytes, salt: str | bytes | None = None, **kwargs: t.Any
    ) -> tuple[t.Any, KeyedVerification]:
        """Like :meth:`loads`, but returns ``(payload, info)``
        where ``info`` is a :class:`KeyedVerification` that
        identifies the key used and whether re-signing is recommended.
        Extra keyword arguments such as ``max_age`` are forwarded
        to the signer's ``unsign_with_info`` method.
        """
        s = want_bytes(s)
        last_exception = None

        for signer in self.iter_unsigners(salt):
            try:
                info = t.cast(KeyedSigner, signer).unsign_with_info(s, **kwargs)
                return self.load_payload(info.value), info
            except SignatureExpired:
                # The signature was unsigned successfully but was
                # expired. Do not try the next signer.
                raise
            except BadSignature as err:
                last_exception = err

        raise t.cast(BadSignature, last_exception)


class KeyedSerializer(_KeyedSerializerMixin, Serializer[_TSerialized]):
    """Works like :class:`Serializer` but uses
    :class:`KeyedSigner` to wrap signed values in a versioned
    envelope that carries a key id.

    :param secret_keys: A mapping of key id to secret key.
    :param active_key_id: The key id to sign new values with. Defaults
        to the last id in ``secret_keys``.
    :param version: The envelope version to write when signing.
    :param accept_legacy: Accept values in the legacy unversioned
        format. Disabled by default.

    .. versionadded:: 2.3
    """

    default_signer: type[KeyedSigner] = KeyedSigner  # pyright: ignore


class KeyedTimedSerializer(_KeyedSerializerMixin, TimedSerializer[_TSerialized]):
    """Works like :class:`TimedSerializer` but uses
    :class:`KeyedTimestampSigner` to wrap signed values in a
    versioned envelope that carries a key id. The ``max_age``
    parameter of :meth:`loads` and :meth:`loads_with_info` is
    supported.

    .. versionadded:: 2.3
    """

    default_signer: type[KeyedTimestampSigner] = KeyedTimestampSigner  # pyright: ignore


class KeyedURLSafeSerializer(URLSafeSerializerMixin, KeyedSerializer[str]):
    """Works like :class:`KeyedSerializer` but dumps and loads
    into a URL safe string, like :class:`URLSafeSerializer`.

    .. versionadded:: 2.3
    """


class KeyedURLSafeTimedSerializer(URLSafeSerializerMixin, KeyedTimedSerializer[str]):
    """Works like :class:`KeyedTimedSerializer` but dumps and
    loads into a URL safe string, like :class:`URLSafeTimedSerializer`.

    .. versionadded:: 2.3
    """
