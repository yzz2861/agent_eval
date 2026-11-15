from __future__ import annotations

import codecs
from typing import Any

from .core import IDNAError, _max_domain_length, _unicode_dots_re, alabel, decode, encode, ulabel


def _incomplete_utf8_prefix(data: bytes) -> int:
    """Return the length of a dangling UTF-8 sequence at the end of ``data``.

    A chunk boundary can fall in the middle of a multi-byte UTF-8 sequence,
    so the trailing bytes may be a valid (for now) lead-byte prefix rather
    than an error. Return the number of bytes in that prefix, or 0 when the
    tail is not the start of an incomplete sequence. A complete sequence, a
    stray continuation byte with no lead, or a lead already followed by all
    of its continuation bytes returns 0, so the caller reports those instead
    of buffering them indefinitely.
    """
    cont = 0
    limit = min(len(data), 3)
    while cont < limit and (data[-1 - cont] & 0xC0) == 0x80:
        cont += 1
    lead_index = len(data) - 1 - cont
    if lead_index < 0:
        return 0  # continuation bytes with no lead anywhere: malformed
    lead = data[lead_index]
    # 0xC0-0xC1 are over-long encodings and 0xF8+ never lead a UTF-8 sequence;
    # neither can start a sequence that more bytes would complete.
    if not 0xC2 <= lead < 0xF8:
        return 0
    expected = 2 if lead < 0xE0 else (3 if lead < 0xF0 else 4)
    length = cont + 1
    if length >= expected:
        return 0  # the sequence is already complete: nothing is pending
    return length


class Codec(codecs.Codec):
    """Stateless IDNA 2008 codec.

    Implements the :class:`codecs.Codec` protocol so that the whole-domain
    encoder (:func:`idna.encode`) and decoder (:func:`idna.decode`) are
    accessible through the standard codec machinery as ``"idna2008"``.

    Only the ``"strict"`` error handler is supported; any other handler
    raises :exc:`~idna.IDNAError`.
    """

    def encode(self, data: str, errors: str = "strict") -> tuple[bytes, int]:  # ty: ignore[invalid-method-override]
        if errors != "strict":
            raise IDNAError(f'Unsupported error handling "{errors}"', code="unsupported_errors")

        if not data:
            return b"", 0

        return encode(data), len(data)

    def decode(self, data: bytes, errors: str = "strict") -> tuple[str, int]:  # ty: ignore[invalid-method-override]
        if errors != "strict":
            raise IDNAError(f'Unsupported error handling "{errors}"', code="unsupported_errors")

        if not data:
            return "", 0

        return decode(data), len(data)


class IncrementalEncoder(codecs.BufferedIncrementalEncoder):
    """Incremental IDNA 2008 encoder.

    Buffers a partial trailing label across calls until either the next
    label separator is seen or ``final=True``, so that streamed input is
    encoded one whole label at a time. Any of the four Unicode label
    separators (``U+002E``, ``U+3002``, ``U+FF0E``, ``U+FF61``) ends a
    label; the result always uses ``U+002E`` as the separator.

    The 253-octet domain length limit (254 with a trailing dot) that
    :func:`idna.encode` enforces is applied to the accumulated output, so
    that streaming a name and encoding it in one shot either both succeed
    with the same result or both raise :exc:`~idna.IDNAError`.

    Only the ``"strict"`` error handler is supported.
    """

    def __init__(self, errors: str = "strict") -> None:
        super().__init__(errors)
        self._emitted = 0  # octets returned so far
        self._trailing_dot = False  # whether the output so far ends with "."

    def reset(self) -> None:
        super().reset()
        self._emitted = 0
        self._trailing_dot = False

    def getstate(self) -> Any:
        if not self.buffer and not self._emitted:
            return 0
        return (self.buffer, self._emitted, self._trailing_dot)

    def setstate(self, state: Any) -> None:
        if state:
            self.buffer, self._emitted, self._trailing_dot = state
        else:
            self.reset()

    def _buffer_encode(self, data: str, errors: str, final: bool) -> tuple[bytes, int]:  # ty: ignore[invalid-method-override]
        if errors != "strict":
            raise IDNAError(f'Unsupported error handling "{errors}"', code="unsupported_errors")

        result_bytes = b""
        size = 0
        if data:
            labels = _unicode_dots_re.split(data)
            trailing_dot = b""
            if labels:
                if not labels[-1]:
                    trailing_dot = b"."
                    del labels[-1]
                elif not final:
                    # Keep potentially unfinished label until the next call
                    del labels[-1]
                    if labels:
                        trailing_dot = b"."

            result = []
            for label in labels:
                result.append(alabel(label))
                if size:
                    size += 1
                size += len(label)

            result_bytes = b".".join(result) + trailing_dot
            size += len(trailing_dot)

        # Mirror encode(): the whole name may not exceed 253 octets, or 254
        # when it ends with a dot. Until the input is final a trailing dot
        # may still arrive, so only the 254-octet ceiling applies before then.
        self._emitted += len(result_bytes)
        if result_bytes:
            self._trailing_dot = result_bytes.endswith(b".")
        may_end_with_dot = self._trailing_dot or not final
        if self._emitted > _max_domain_length + may_end_with_dot:
            raise IDNAError("Domain too long", code="domain_too_long")
        return result_bytes, size


class IncrementalDecoder(codecs.BufferedIncrementalDecoder):
    """Incremental IDNA 2008 decoder.

    Buffers a partial trailing label across calls until either the next
    label separator is seen or ``final=True``, so that streamed input is
    decoded one whole label at a time.

    The wire input to an IDNA 2008 decoder is pure ASCII. A chunk boundary
    can nevertheless fall in the middle of a multi-byte UTF-8 sequence (for
    example when a byte stream is split on the way in); a dangling lead-byte
    prefix that could still be completed is held back until the rest of the
    sequence arrives or ``final=True``, instead of being mistaken for the end
    of the input. Every other byte is validated as ASCII as soon as it is
    final, including bytes inside an as-yet unfinished label, so an illegal
    byte is rejected with the same ``invalid_ascii`` error and a chained
    :class:`UnicodeDecodeError` carrying its ``object``/``start``/``end`` as a
    one-shot :func:`idna.decode` call, however the input is chunked.

    Labels already terminated by a separator (including an empty label from a
    double separator) are validated immediately with :func:`ulabel`, in the
    same label order :func:`idna.decode` uses; only the unfinished trailing
    label is deferred to the next call or to ``final=True``. The 254-octet
    input length limit is applied to the accumulated input, so streaming a
    name and decoding it in one shot either both succeed with the same result
    or both raise :exc:`~idna.IDNAError`.

    Only the ``"strict"`` error handler is supported; any other handler
    raises :exc:`~idna.IDNAError` rather than silently dropping input.
    """

    def __init__(self, errors: str = "strict") -> None:
        super().__init__(errors)
        self._consumed = 0  # input octets fully consumed so far

    def reset(self) -> None:
        super().reset()
        self._consumed = 0

    def getstate(self) -> tuple[bytes, int]:
        return (self.buffer, self._consumed)

    def setstate(self, state: tuple[bytes, int]) -> None:
        self.buffer, self._consumed = state

    def _decode_ascii(self, data: bytes) -> str:
        """Decode final input as ASCII, preserving the error location."""
        try:
            return data.decode("ascii")
        except UnicodeDecodeError as err:
            raise IDNAError("Invalid ASCII in A-label", code="invalid_ascii") from err

    def _buffer_decode(self, data: Any, errors: str, final: bool) -> tuple[str, int]:  # ty: ignore[invalid-method-override]
        if errors != "strict":
            raise IDNAError(f'Unsupported error handling "{errors}"', code="unsupported_errors")

        if not data:
            return ("", 0)

        if isinstance(data, (bytes, bytearray, memoryview)):
            data = bytes(data)

        pending = 0
        if isinstance(data, bytes):
            # Only a dangling lead-byte prefix at the very end may be held
            # back until more bytes arrive. Every other byte is final and is
            # checked now, even inside an unfinished trailing label.
            if not final:
                pending = _incomplete_utf8_prefix(data)
            firm = data[: len(data) - pending]
            text = self._decode_ascii(firm) if firm else ""
        elif isinstance(data, str):
            text = data
        else:
            self._decode_ascii(str(data).encode("ascii", "strict"))
            text = ""

        # Mirror decode(), which rejects input longer than 254 characters
        # (253 plus a possible trailing dot) before looking at any label.
        # data is the previously buffered bytes plus the new input, so the
        # consumed total plus data is the number of distinct octets seen.
        if self._consumed + len(data) > _max_domain_length + 1:
            raise IDNAError("Domain too long", code="domain_too_long")

        held_back = 0
        labels = _unicode_dots_re.split(text)
        trailing_dot = ""
        if labels and not labels[-1]:
            # A trailing separator: every label is complete; emit the dot and
            # drop the empty final label the separator produced.
            trailing_dot = "."
            del labels[-1]
        elif not final and labels:
            # No trailing separator, so the final label may be continued in
            # the next chunk. Hold it back by subtracting its length from the
            # consumed count so the base class retains it in its buffer.
            held_back = len(labels[-1])
            del labels[-1]
            if labels:
                trailing_dot = "."
        else:
            held_back = 0

        result = [ulabel(label) for label in labels]
        result_str = ".".join(result) + trailing_dot

        # Everything in text is consumed except the deferred trailing label;
        # the dangling UTF-8 prefix was already excluded from text. The base
        # class keeps data[consumed:] (the held-back label plus any pending
        # UTF-8 bytes) as its buffer.
        consumed = len(text) - held_back
        self._consumed += consumed
        return (result_str, consumed)


class StreamWriter(Codec, codecs.StreamWriter):
    pass


class StreamReader(Codec, codecs.StreamReader):
    pass


def search_function(name: str) -> codecs.CodecInfo | None:
    """Codec search function registered with :mod:`codecs`.

    Returns a :class:`codecs.CodecInfo` for the ``"idna2008"`` codec name
    so that ``str.encode("idna2008")`` and ``bytes.decode("idna2008")``
    invoke the IDNA 2008 codec defined in this module.

    :param name: The codec name being looked up.
    :returns: A :class:`codecs.CodecInfo` instance if ``name`` is
        ``"idna2008"``, otherwise ``None``.
    """
    if name != "idna2008":
        return None
    return codecs.CodecInfo(
        name=name,
        encode=Codec().encode,
        decode=Codec().decode,  # type: ignore
        incrementalencoder=IncrementalEncoder,
        incrementaldecoder=IncrementalDecoder,
        streamwriter=StreamWriter,
        streamreader=StreamReader,
    )


codecs.register(search_function)
