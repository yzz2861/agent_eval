from __future__ import annotations

import json
import time
import typing as t
from datetime import datetime
from datetime import timezone

from ._json import _CompactJSON
from .encoding import _base64_alphabet
from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import bytes_to_int
from .encoding import int_to_bytes
from .encoding import want_bytes
from .exc import BadPayload
from .exc import BadSignature
from .exc import BadTimeSignature
from .exc import SignatureExpired
from .serializer import _PDataSerializer
from .serializer import _TSerialized
from .serializer import is_text_serializer
from .url_safe import _url_safe_decode
from .url_safe import _url_safe_encode


class AsyncSigner(t.Protocol):
    """Protocol for a signing service that is only available
    asynchronously, such as a remote signing service that holds the
    secret key.

    Implementations receive only the exact bytes to authenticate
    and a ``salt`` describing the purpose of the signature. The
    secret key never leaves the service.

    If the service cannot complete a request, implementations must
    raise :class:`.SignerUnavailable`, or let
    ``asyncio.CancelledError`` propagate if the call is cancelled.
    These must not be conflated with a signature mismatch.

    .. versionadded:: 2.3
    """

    async def get_signature(self, value: bytes, *, salt: bytes) -> bytes:
        """Return the signature for ``value``. The ``salt``
        describes the purpose of the signature and should be
        incorporated into the signed data by the service.
        """
        ...

    async def verify_signature(self, value: bytes, sig: bytes, *, salt: bytes) -> bool:
        """Return ``True`` if ``sig`` is a valid signature for
        ``value`` under the given ``salt``.
        """
        ...


class AsyncSerializer(t.Generic[_TSerialized]):
    """Like :class:`~itsdangerous.serializer.Serializer`, but signs
    and verifies through an :class:`AsyncSigner` service instead of
    a local secret key. All signing operations are ``async`` and
    must be awaited.

    The wire format matches the sync
    :class:`~itsdangerous.serializer.Serializer`, so a value signed
    by one can be verified by the other if the service uses the
    same key, salt, and algorithm.

    Only :class:`.BadSignature` indicates invalid data.
    :class:`.SignerUnavailable` and ``asyncio.CancelledError``
    propagate unchanged; they are never turned into a signature
    failure or silently retried with unverified data.

    :param signer: The :class:`AsyncSigner` service to sign and
        verify with.
    :param salt: Extra data passed to the signer to distinguish
        signatures in different contexts.
    :param serializer: An object that provides ``dumps`` and
        ``loads`` methods for serializing data to a string. Defaults
        to :attr:`default_serializer`, which defaults to
        :mod:`json`.
    :param serializer_kwargs: Keyword arguments to pass when calling
        ``serializer.dumps``.
    :param sep: Separator between the signature and value.

    .. versionadded:: 2.3
    """

    #: The default serialization module to use to serialize data to
    #: a string internally. The default is :mod:`json`, but can be
    #: changed to any object that provides ``dumps`` and ``loads``
    #: methods.
    default_serializer: _PDataSerializer[t.Any] = json

    #: The default separator placed between the value and the
    #: signature. Matches the sync signers.
    default_sep: bytes = b"."

    def __init__(
        self,
        signer: AsyncSigner,
        salt: str | bytes = b"itsdangerous",
        serializer: t.Any | None = None,
        serializer_kwargs: dict[str, t.Any] | None = None,
        sep: str | bytes | None = None,
    ):
        #: The async signing service to sign and verify with.
        self.signer: AsyncSigner = signer

        #: Passed to the signer as the purpose of the signature.
        self.salt: bytes = want_bytes(salt)

        if sep is None:
            sep = self.default_sep

        self.sep: bytes = want_bytes(sep)

        if self.sep in _base64_alphabet:
            raise ValueError(
                "The given separator cannot be used because it may be"
                " contained in the signature itself. ASCII letters,"
                " digits, and '-_=' must not be used."
            )

        if serializer is None:
            serializer = self.default_serializer

        self.serializer: _PDataSerializer[_TSerialized] = serializer
        self.is_text_serializer: bool = is_text_serializer(serializer)
        self.serializer_kwargs: dict[str, t.Any] = serializer_kwargs or {}

    def load_payload(
        self, payload: bytes, serializer: _PDataSerializer[t.Any] | None = None
    ) -> t.Any:
        """Loads the encoded object, like
        :meth:`itsdangerous.serializer.Serializer.load_payload`.
        This is a local, synchronous operation.
        """
        if serializer is None:
            use_serializer = self.serializer
            is_text = self.is_text_serializer
        else:
            use_serializer = serializer
            is_text = is_text_serializer(serializer)

        try:
            if is_text:
                return use_serializer.loads(payload.decode("utf-8"))  # type: ignore[arg-type]

            return use_serializer.loads(payload)  # type: ignore[arg-type]
        except Exception as e:
            raise BadPayload(
                "Could not load the payload because an exception"
                " occurred on unserializing the data.",
                original_error=e,
            ) from e

    def dump_payload(self, obj: t.Any) -> bytes:
        """Dumps the encoded object, like
        :meth:`itsdangerous.serializer.Serializer.dump_payload`.
        This is a local, synchronous operation.
        """
        return want_bytes(self.serializer.dumps(obj, **self.serializer_kwargs))

    def _resolve_salt(self, salt: str | bytes | None) -> bytes:
        """Use the given salt, or the configured one by default."""
        if salt is None:
            return self.salt

        return want_bytes(salt)

    async def _get_signature(self, value: bytes, salt: bytes) -> bytes:
        """Ask the signing service for the raw signature of
        ``value``. The result is checked so that a signer that
        forgot to await something fails loudly instead of producing
        garbage.
        """
        sig = await self.signer.get_signature(value, salt=salt)

        if not isinstance(sig, (bytes, bytearray)):
            raise TypeError(
                "The async signer's get_signature method must return"
                f" bytes, got {type(sig).__name__!r}. Did you forget"
                " to await something?"
            )

        return bytes(sig)

    async def _verify_signature(self, value: bytes, sig: bytes, salt: bytes) -> bool:
        """Ask the signing service to verify the raw signature
        ``sig`` for ``value``. The result is checked so that a
        signer that forgot to await something fails loudly instead
        of being treated as a successful verification.
        """
        result = await self.signer.verify_signature(value, sig, salt=salt)

        if not isinstance(result, bool):
            raise TypeError(
                "The async signer's verify_signature method must"
                f" return a bool, got {type(result).__name__!r}. Did"
                " you forget to await something?"
            )

        return result

    async def sign(
        self, value: str | bytes, *, salt: str | bytes | None = None
    ) -> bytes:
        """Signs the given string, in the same format as
        :meth:`itsdangerous.signer.Signer.sign`.
        """
        value = want_bytes(value)
        sig = await self._get_signature(value, self._resolve_salt(salt))
        return value + self.sep + base64_encode(sig)

    async def unsign(
        self, signed_value: str | bytes, *, salt: str | bytes | None = None
    ) -> bytes:
        """Unsigns the given string, like
        :meth:`itsdangerous.signer.Signer.unsign`. Raises
        :class:`.BadSignature` if the signature does not match.
        :class:`.SignerUnavailable` and ``asyncio.CancelledError``
        from the signing service propagate unchanged.
        """
        signed_value = want_bytes(signed_value)

        if self.sep not in signed_value:
            raise BadSignature(f"No {self.sep!r} found in value")

        value, sig = signed_value.rsplit(self.sep, 1)

        try:
            decoded_sig = base64_decode(sig)
        except Exception:
            raise BadSignature(
                f"Signature {sig!r} does not match", payload=value
            ) from None

        if await self._verify_signature(value, decoded_sig, self._resolve_salt(salt)):
            return value

        raise BadSignature(f"Signature {sig!r} does not match", payload=value)

    async def validate(
        self, signed_value: str | bytes, *, salt: str | bytes | None = None
    ) -> bool:
        """Only validates the given signed value. Returns ``True``
        if the signature exists and is valid.
        :class:`.SignerUnavailable` and ``asyncio.CancelledError``
        propagate unchanged.
        """
        try:
            await self.unsign(signed_value, salt=salt)
            return True
        except BadSignature:
            return False

    async def dumps(
        self, obj: t.Any, *, salt: str | bytes | None = None
    ) -> _TSerialized:
        """Returns a signed string serialized with the internal
        serializer, like
        :meth:`itsdangerous.serializer.Serializer.dumps`.
        """
        payload = want_bytes(self.dump_payload(obj))
        rv = await self.sign(payload, salt=salt)

        if self.is_text_serializer:
            return rv.decode("utf-8")  # type: ignore[return-value]

        return rv  # type: ignore[return-value]

    async def dump(
        self, obj: t.Any, f: t.IO[t.Any], *, salt: str | bytes | None = None
    ) -> None:
        """Like :meth:`dumps` but dumps into a file."""
        f.write(await self.dumps(obj, salt=salt))

    async def loads(
        self,
        s: str | bytes,
        *,
        salt: str | bytes | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        """Reverse of :meth:`dumps`. Raises :exc:`.BadSignature` if
        the signature validation fails. :class:`.SignerUnavailable`
        and ``asyncio.CancelledError`` propagate unchanged.
        """
        return self.load_payload(await self.unsign(s, salt=salt))

    async def load(self, f: t.IO[t.Any], *, salt: str | bytes | None = None) -> t.Any:
        """Like :meth:`loads` but loads from a file."""
        return await self.loads(f.read(), salt=salt)

    async def loads_unsafe(
        self, s: str | bytes, *, salt: str | bytes | None = None
    ) -> tuple[bool, t.Any]:
        """Like :meth:`loads` but without verifying the signature,
        like :meth:`itsdangerous.serializer.Serializer.loads_unsafe`.
        Only :class:`.BadSignature` is treated as an invalid
        signature; :class:`.SignerUnavailable` and
        ``asyncio.CancelledError`` propagate rather than returning
        unverified data.
        """
        return await self._loads_unsafe_impl(s, salt)

    async def _loads_unsafe_impl(
        self,
        s: str | bytes,
        salt: str | bytes | None,
        load_kwargs: dict[str, t.Any] | None = None,
        load_payload_kwargs: dict[str, t.Any] | None = None,
    ) -> tuple[bool, t.Any]:
        """Low level helper function to implement
        :meth:`loads_unsafe` in subclasses.
        """
        if load_kwargs is None:
            load_kwargs = {}

        try:
            return True, await self.loads(s, salt=salt, **load_kwargs)
        except BadSignature as e:
            if e.payload is None:
                return False, None

            if load_payload_kwargs is None:
                load_payload_kwargs = {}

            try:
                return (
                    False,
                    self.load_payload(e.payload, **load_payload_kwargs),
                )
            except BadPayload:
                return False, None

    async def load_unsafe(
        self, f: t.IO[t.Any], *, salt: str | bytes | None = None
    ) -> tuple[bool, t.Any]:
        """Like :meth:`loads_unsafe` but loads from a file."""
        return await self.loads_unsafe(f.read(), salt=salt)


class AsyncTimedSerializer(AsyncSerializer[_TSerialized]):
    """Like :class:`itsdangerous.timed.TimedSerializer`, but signs
    and verifies through an :class:`AsyncSigner` service.

    .. versionadded:: 2.3
    """

    def get_timestamp(self) -> int:
        """Returns the current timestamp. The function must return
        an integer. It is called exactly once per :meth:`sign`.
        """
        return int(time.time())

    def timestamp_to_datetime(self, ts: int) -> datetime:
        """Convert the timestamp from :meth:`get_timestamp` into an
        aware :class:`~datetime.datetime` in UTC.
        """
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    async def sign(
        self, value: str | bytes, *, salt: str | bytes | None = None
    ) -> bytes:
        """Signs the given string and also attaches time
        information, like
        :meth:`itsdangerous.timed.TimestampSigner.sign`. The
        timestamp is determined exactly once per call.
        """
        value = want_bytes(value)
        timestamp = base64_encode(int_to_bytes(self.get_timestamp()))
        value = value + self.sep + timestamp
        sig = await self._get_signature(value, self._resolve_salt(salt))
        return value + self.sep + base64_encode(sig)

    @t.overload
    def unsign(  # pyright: ignore
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[False] = False,
        *,
        salt: str | bytes | None = None,
    ) -> t.Coroutine[t.Any, t.Any, bytes]: ...

    @t.overload
    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[True] = True,
        *,
        salt: str | bytes | None = None,
    ) -> t.Coroutine[t.Any, t.Any, tuple[bytes, datetime]]: ...

    async def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
        *,
        salt: str | bytes | None = None,
    ) -> tuple[bytes, datetime] | bytes:
        """Works like :meth:`AsyncSerializer.unsign` but can also
        validate the time, like
        :meth:`itsdangerous.timed.TimestampSigner.unsign`. The
        ``max_age`` check only happens after the signature has been
        verified successfully.
        """
        try:
            result = await super().unsign(signed_value, salt=salt)
            sig_error = None
        except BadSignature as e:
            sig_error = e
            result = e.payload or b""

        # If there is no timestamp in the result there is something
        # seriously wrong, like the sync signer this mirrors.
        if self.sep not in result:
            if sig_error:
                raise sig_error

            raise BadTimeSignature("timestamp missing", payload=result)

        value, ts_bytes = result.rsplit(self.sep, 1)
        ts_int: int | None = None
        ts_dt: datetime | None = None

        try:
            ts_int = bytes_to_int(base64_decode(ts_bytes))
        except Exception:
            pass

        # Signature is *not* okay. Raise a proper error now that we
        # have split the value and the timestamp.
        if sig_error is not None:
            if ts_int is not None:
                try:
                    ts_dt = self.timestamp_to_datetime(ts_int)
                except (ValueError, OSError, OverflowError) as exc:
                    # Windows raises OSError
                    # 32-bit raises OverflowError
                    raise BadTimeSignature(
                        "Malformed timestamp", payload=value
                    ) from exc

            raise BadTimeSignature(str(sig_error), payload=value, date_signed=ts_dt)

        # Signature was okay but the timestamp is actually not there
        # or malformed. Should not happen, but we handle it anyway.
        if ts_int is None:
            raise BadTimeSignature("Malformed timestamp", payload=value)

        # Check timestamp is not older than max_age, only now that
        # the signature has been verified.
        if max_age is not None:
            age = self.get_timestamp() - ts_int

            if age > max_age:
                raise SignatureExpired(
                    f"Signature age {age} > {max_age} seconds",
                    payload=value,
                    date_signed=self.timestamp_to_datetime(ts_int),
                )

            if age < 0:
                raise SignatureExpired(
                    f"Signature age {age} < 0 seconds",
                    payload=value,
                    date_signed=self.timestamp_to_datetime(ts_int),
                )

        if return_timestamp:
            return value, self.timestamp_to_datetime(ts_int)

        return value

    async def validate(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        *,
        salt: str | bytes | None = None,
    ) -> bool:
        """Only validates the given signed value. Returns ``True``
        if the signature exists, is valid, and is not older than
        ``max_age``.
        """
        try:
            await self.unsign(signed_value, max_age=max_age, salt=salt)
            return True
        except BadSignature:
            return False

    async def loads(
        self,
        s: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
        *,
        salt: str | bytes | None = None,
    ) -> t.Any:
        """Reverse of :meth:`dumps`, like
        :meth:`itsdangerous.timed.TimedSerializer.loads`. Raises
        :exc:`.SignatureExpired` if the signature is older than
        ``max_age``. :class:`.SignerUnavailable` and
        ``asyncio.CancelledError`` propagate unchanged.
        """
        base64d, timestamp = await self.unsign(
            s, max_age=max_age, return_timestamp=True, salt=salt
        )
        payload = self.load_payload(base64d)

        if return_timestamp:
            return payload, timestamp

        return payload

    async def loads_unsafe(
        self,
        s: str | bytes,
        max_age: int | None = None,
        *,
        salt: str | bytes | None = None,
    ) -> tuple[bool, t.Any]:
        return await self._loads_unsafe_impl(s, salt, load_kwargs={"max_age": max_age})


class AsyncURLSafeSerializerMixin(AsyncSerializer[str]):
    """Mixed in with an async serializer to compress and base64
    encode the payload so it is safe to place in a URL, like
    :class:`itsdangerous.url_safe.URLSafeSerializerMixin`.

    .. versionadded:: 2.3
    """

    default_serializer: _PDataSerializer[str] = _CompactJSON

    def load_payload(
        self,
        payload: bytes,
        *args: t.Any,
        serializer: t.Any | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        return super().load_payload(_url_safe_decode(payload), *args, **kwargs)

    def dump_payload(self, obj: t.Any) -> bytes:
        return _url_safe_encode(super().dump_payload(obj))


class AsyncURLSafeSerializer(AsyncURLSafeSerializerMixin, AsyncSerializer[str]):
    """Works like :class:`AsyncSerializer` but dumps and loads into
    a URL-safe string, like
    :class:`itsdangerous.url_safe.URLSafeSerializer`.

    .. versionadded:: 2.3
    """


class AsyncURLSafeTimedSerializer(
    AsyncURLSafeSerializerMixin, AsyncTimedSerializer[str]
):
    """Works like :class:`AsyncTimedSerializer` but dumps and loads
    into a URL-safe string, like
    :class:`itsdangerous.url_safe.URLSafeTimedSerializer`.

    .. versionadded:: 2.3
    """
