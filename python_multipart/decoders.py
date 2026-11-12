import base64
import binascii
from typing import TYPE_CHECKING

from .exceptions import DecodeError

_BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BASE64_VALUES = {value: index for index, value in enumerate(_BASE64_ALPHABET)}
_HEX_DIGITS = frozenset(b"0123456789ABCDEFabcdef")

_EQUALS = ord("=")
_CR = ord("\r")
_LF = ord("\n")

_QP_NONE = 0
_QP_EQUALS = 1
_QP_HEX_ONE = 2
_QP_CR = 3

if TYPE_CHECKING:  # pragma: no cover
    from typing import Protocol, TypeVar

    _T_contra = TypeVar("_T_contra", contravariant=True)

    class SupportsWrite(Protocol[_T_contra]):
        def write(self, __b: _T_contra) -> object: ...

        # No way to specify optional methods. See
        # https://github.com/python/typing/issues/601
        # close() [Optional]
        # finalize() [Optional]


class Base64Decoder:
    """This object provides an interface to decode a stream of Base64 data.  It
    is instantiated with an "underlying object", and whenever a write()
    operation is performed, it will decode the incoming data as Base64, and
    call write() on the underlying object.  This is primarily used for decoding
    form data encoded as Base64, but can be used for other purposes::

        from python_multipart.decoders import Base64Decoder
        fd = open("notb64.txt", "wb")
        decoder = Base64Decoder(fd)
        try:
            decoder.write("Zm9vYmFy")       # "foobar" in Base64
            decoder.finalize()
        finally:
            decoder.close()

        # The contents of "notb64.txt" should be "foobar".

    This object will also pass all finalize() and close() calls to the
    underlying object, if the underlying object supports them.

    Note that this class maintains a cache of base64 chunks, so that a write of
    arbitrary size can be performed.  You must call :meth:`finalize` on this
    object after all writes are completed to ensure that all data is flushed
    to the underlying object.

    :param underlying: the underlying object to pass writes to
    :param strict: enable strict validation of the Base64 alphabet, padding,
        and unused trailing bits.  The default (``False``) keeps the historical
        permissive behaviour.
    :param allow_no_padding: whether strict mode accepts a final Base64 quantum
        without ``=`` padding.  Defaults to ``False`` in strict mode.
    :param allow_unpadded: an alias for ``allow_no_padding``.
    :param require_padding: the inverse of ``allow_no_padding``.
    """

    encoding = "base64"

    def __init__(
        self,
        underlying: "SupportsWrite[bytes]",
        strict: bool = False,
        allow_no_padding: bool | None = None,
        allow_unpadded: bool | None = None,
        require_padding: bool | None = None,
    ) -> None:
        self.cache = bytearray()
        self.underlying = underlying
        self.strict = bool(strict)

        if allow_unpadded is not None:
            allow_no_padding = allow_unpadded
        if require_padding is not None:
            allow_no_padding = not require_padding
        self.allow_no_padding = bool(allow_no_padding) if allow_no_padding is not None else False

        self._finished = False
        self._finalized = False
        self._underlying_finalized = False
        self._last_chunk_len = 0

    def _error(self, reason: str, offset: int) -> DecodeError:
        return DecodeError(
            f"{self.encoding} decoding error at chunk offset {offset}: {reason}", offset=offset, encoding=self.encoding
        )

    def _decoded_quartet(self, quartet: bytes, offset: int) -> None:
        values = [_BASE64_VALUES[value] for value in quartet if value != _EQUALS]

        if quartet[3] == _EQUALS:
            if quartet[2] == _EQUALS:
                if len(values) != 2:
                    raise self._error("invalid padding position", offset)
                if values[1] & 0x0F:
                    raise self._error("non-zero trailing bits in final Base64 quantum", offset)
                decoded = bytes([(values[0] << 2) | (values[1] >> 4)])
            else:
                if len(values) != 3:
                    raise self._error("invalid padding position", offset)
                if values[2] & 0x03:
                    raise self._error("non-zero trailing bits in final Base64 quantum", offset)
                decoded = bytes([(values[0] << 2) | (values[1] >> 4), ((values[1] & 0x0F) << 4) | (values[2] >> 2)])
        else:
            if len(values) != 4:
                raise self._error("invalid padding position", offset)
            decoded = bytes(
                [
                    (values[0] << 2) | (values[1] >> 4),
                    ((values[1] & 0x0F) << 4) | (values[2] >> 2),
                    ((values[2] & 0x03) << 6) | values[3],
                ]
            )

        self.underlying.write(decoded)

    def _decode_unpadded(self, offset: int) -> None:
        if any(value == _EQUALS for value in self.cache):
            raise self._error("incomplete Base64 padding", offset)
        values = [_BASE64_VALUES[value] for value in self.cache]
        if len(values) == 2:
            if values[1] & 0x0F:
                raise self._error("non-zero trailing bits in final Base64 quantum", offset)
            decoded = bytes([(values[0] << 2) | (values[1] >> 4)])
        elif len(values) == 3:
            if values[2] & 0x03:
                raise self._error("non-zero trailing bits in final Base64 quantum", offset)
            decoded = bytes([(values[0] << 2) | (values[1] >> 4), ((values[1] & 0x0F) << 4) | (values[2] >> 2)])
        else:
            raise self._error("incomplete Base64 quantum", offset)
        self.underlying.write(decoded)

    def _write_compat(self, data: bytes) -> int:
        original_len = len(data)
        if self.cache:
            data = bytes(self.cache) + data

        decode_len = (len(data) // 4) * 4
        encoded = data[:decode_len]

        if encoded:
            try:
                self.underlying.write(base64.b64decode(encoded))
            except binascii.Error:
                raise self._error("invalid Base64 data", 0) from None

        remaining_len = len(data) % 4
        self.cache[:] = data[-remaining_len:] if remaining_len else b""
        return original_len

    def write(self, data: bytes) -> int:
        """Takes any input data provided, decodes it as base64, and passes it
        on to the underlying object.  If the data provided is invalid base64
        data, then this method will raise
        a :class:`python_multipart.exceptions.DecodeError`

        :param data: base64 data to decode
        """

        self._last_chunk_len = len(data)
        if not self.strict:
            return self._write_compat(data)

        for offset, value in enumerate(data):
            if self._finished:
                raise self._error("data found after Base64 padding", offset)

            if value == _EQUALS:
                position = len(self.cache)
                if position < 2:
                    raise self._error("invalid padding position", offset)
                if position == 2:
                    self.cache.append(value)
                    continue

                # Position 3 is either a single ``=`` after three data
                # characters, or the second ``=`` after two data characters.
                self.cache.append(value)
                self._decoded_quartet(bytes(self.cache), offset)
                self.cache.clear()
                self._finished = True
                continue

            if len(self.cache) == 3 and self.cache[2] == _EQUALS:
                raise self._error("expected '=' padding at end of Base64 quantum", offset)

            if value not in _BASE64_VALUES:
                raise self._error("invalid Base64 character", offset)

            self.cache.append(value)
            if len(self.cache) == 4:
                self._decoded_quartet(bytes(self.cache), offset)
                self.cache.clear()

        return len(data)

    def close(self) -> None:
        """Close this decoder.  If the underlying object has a `close()`
        method, this function will call it.
        """
        if hasattr(self.underlying, "close"):
            self.underlying.close()

    def finalize(self) -> None:
        """Finalize this object.  This should be called when no more data
        should be written to the stream.  This function can raise a
        :class:`python_multipart.exceptions.DecodeError` if there is some remaining
        data in the cache.

        If the underlying object has a `finalize()` method, this function will
        call it.
        """
        if not self.strict:
            if len(self.cache) > 0:
                raise DecodeError(
                    "There are %d bytes remaining in the Base64Decoder cache when finalize() is called"
                    % len(self.cache),
                    offset=max(0, self._last_chunk_len - len(self.cache)),
                    encoding=self.encoding,
                )
        else:
            residual_offset = max(0, self._last_chunk_len - len(self.cache))
            if self.cache:
                if self.allow_no_padding:
                    self._decode_unpadded(residual_offset)
                    self.cache.clear()
                else:
                    raise self._error("missing Base64 padding at end of payload", residual_offset)

            self._finished = True

        if not self._underlying_finalized:
            if hasattr(self.underlying, "finalize"):
                self.underlying.finalize()
            self._underlying_finalized = True
        self._finalized = True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(underlying={self.underlying!r})"


class QuotedPrintableDecoder:
    """This object provides an interface to decode a stream of quoted-printable
    data.  It is instantiated with an "underlying object", in the same manner
    as the :class:`python_multipart.decoders.Base64Decoder` class.  This class behaves
    in exactly the same way, including maintaining a cache of quoted-printable
    chunks.

    :param underlying: the underlying object to pass writes to
    :param strict: enable strict validation of quoted-printable escapes and
        soft line breaks.  The default (``False``) keeps the historical
        permissive behaviour.
    """

    encoding = "quoted-printable"

    def __init__(self, underlying: "SupportsWrite[bytes]", strict: bool = False) -> None:
        self.cache = b""
        self.underlying = underlying
        self.strict = bool(strict)
        self._state = _QP_NONE
        self._finalized = False
        self._underlying_finalized = False
        self._last_chunk_len = 0

    def _error(self, reason: str, offset: int) -> DecodeError:
        return DecodeError(
            f"{self.encoding} decoding error at chunk offset {offset}: {reason}", offset=offset, encoding=self.encoding
        )

    def _write_compat(self, data: bytes) -> int:
        original_len = len(data)
        if self.cache:
            data = self.cache + data

        idx = data.find(b"=", max(0, len(data) - 2))
        if idx != -1:
            encoded, rest = data[:idx], data[idx:]
        else:
            encoded = data
            rest = b""

        if encoded:
            try:
                self.underlying.write(binascii.a2b_qp(encoded))
            except binascii.Error:
                raise self._error("invalid quoted-printable data", 0) from None

        self.cache = rest
        return original_len

    def _reset(self) -> None:
        self.cache = b""
        self._state = _QP_NONE

    def write(self, data: bytes) -> int:
        """Takes any input data provided, decodes it as quoted-printable, and
        passes it on to the underlying object.

        :param data: quoted-printable data to decode
        """
        self._last_chunk_len = len(data)
        if not self.strict:
            return self._write_compat(data)

        output = bytearray()

        for offset, value in enumerate(data):
            if self._state == _QP_NONE:
                if value == _EQUALS:
                    self._state = _QP_EQUALS
                    self.cache = b"="
                else:
                    output.append(value)
                continue

            if self._state == _QP_EQUALS:
                if value in _HEX_DIGITS:
                    self._state = _QP_HEX_ONE
                    self.cache += bytes([value])
                elif value == _CR:
                    self._state = _QP_CR
                    self.cache += b"\r"
                elif value == _LF:
                    raise self._error("invalid soft line break after '='; CRLF is required", offset)
                else:
                    raise self._error("invalid quoted-printable escape; two hexadecimal digits are required", offset)
                continue

            if self._state == _QP_HEX_ONE:
                if value not in _HEX_DIGITS:
                    raise self._error("invalid hexadecimal digit in quoted-printable escape", offset)
                output.append(int(self.cache[1:].decode("ascii") + chr(value), 16))
                self._reset()
                continue

            if self._state == _QP_CR:
                if value != _LF:
                    raise self._error("invalid soft line break; '=' followed by CR must be followed by LF", offset)
                self._reset()

        if output:
            self.underlying.write(bytes(output))
        return len(data)

    def close(self) -> None:
        """Close this decoder.  If the underlying object has a `close()`
        method, this function will call it.
        """
        if hasattr(self.underlying, "close"):
            self.underlying.close()

    def finalize(self) -> None:
        """Finalize this object.  This should be called when no more data
        should be written to the stream.  In strict mode this function raises
        a :class:`python_multipart.exceptions.DecodeError` if an escape or soft
        line break is still incomplete.  In compatibility mode it may write
        more data to the underlying object if there is data remaining in the
        cache.

        If the underlying object has a `finalize()` method, this function will
        call it.
        """
        if not self.strict:
            # Historical behaviour: flush the cached suffix through
            # binascii's permissive decoder.
            if len(self.cache) > 0:
                self.underlying.write(binascii.a2b_qp(self.cache))
                self.cache = b""
        else:
            residual_offset = max(0, self._last_chunk_len - len(self.cache))
            if self.cache:
                if self._state == _QP_EQUALS:
                    reason = "isolated '=' at end of quoted-printable payload"
                elif self._state == _QP_HEX_ONE:
                    reason = "incomplete hexadecimal escape at end of quoted-printable payload"
                else:
                    reason = "incomplete soft line break at end of quoted-printable payload"
                raise self._error(reason, residual_offset)
            self._state = _QP_NONE

        if not self._underlying_finalized:
            if hasattr(self.underlying, "finalize"):
                self.underlying.finalize()
            self._underlying_finalized = True
        self._finalized = True

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(underlying={self.underlying!r})"
