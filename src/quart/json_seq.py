from __future__ import annotations

from collections.abc import AsyncIterator
from collections.abc import Callable
from typing import Any
from typing import Literal
from typing import TYPE_CHECKING

from werkzeug.exceptions import UnsupportedMediaType

if TYPE_CHECKING:
    from .wrappers.request import Request

#: The record separator (RS) byte that precedes every JSON text in an
#: ``application/json-seq`` stream (RFC 7464).
RECORD_SEPARATOR = b"\x1e"

JSON_SEQ_MIMETYPE = "application/json-seq"

_SKIP = object()


class JSONSeqError(ValueError):
    """Base class for errors raised while reading a JSON sequence.

    Attributes:
        record_index: The 0-based index of the offending record, counted
            by record separators from the start of the stream.
        byte_offset: The absolute byte offset in the request body at
            which the offending record's content starts (just after its
            record separator).
    """

    def __init__(self, message: str, *, record_index: int, byte_offset: int) -> None:
        super().__init__(message)
        self.record_index = record_index
        self.byte_offset = byte_offset


class JSONSeqDecodeError(JSONSeqError):
    """A record is not valid UTF-8 encoded JSON."""


class JSONSeqTruncatedError(JSONSeqDecodeError):
    """The stream ended in the middle of a record."""


class JSONSeqRecordTooLargeError(JSONSeqError):
    """A record exceeded the configured ``max_record_bytes`` limit."""


def iter_json_seq(
    request: Request,
    *,
    max_record_bytes: int | None = 1_048_576,
    on_error: Literal["abort", "skip"] = "abort",
    on_record_error: Callable[[JSONSeqError], None] | None = None,
    require_content_type: bool = True,
) -> AsyncIterator[Any]:
    """Iterate over the records of an ``application/json-seq`` request body.

    This reads the request body chunk by chunk (via ``request.body``)
    and yields each JSON text as it is decoded, without ever loading the
    whole request into memory. Records are framed by the record
    separator byte (``\\x1e``) that precedes each JSON text - never by
    newlines, as JSON texts may themselves span multiple lines. As the
    separator is an ASCII control character it cannot appear within
    UTF-8 multi-byte sequences, and JSON requires it to be escaped
    (``\\u001e``) within strings, so framing is safe at the byte level.

    .. code-block:: python

        @app.post("/events")
        async def events() -> ResponseReturnValue:
            async for record in iter_json_seq(request):
                await store(record)
            return ""

    Empty (whitespace-only) records are silently skipped. A final record
    terminated by the end of the stream rather than a line feed is
    accepted, as per RFC 7464.

    Arguments:
        request: The request to read from.
        max_record_bytes: Maximum size in bytes of a single record's
            encoded content (including surrounding whitespace), or None
            for no limit. Larger records raise
            :class:`JSONSeqRecordTooLargeError`.
        on_error: ``"abort"`` (default) raises the first
            :class:`JSONSeqError` encountered, ending the iteration.
            ``"skip"`` instead reports the error via ``on_record_error``
            and resumes at the next record separator.
        on_record_error: Callback invoked with each :class:`JSONSeqError`
            when ``on_error="skip"``. The error carries the bad record's
            ``record_index`` and ``byte_offset``.
        require_content_type: Raise
            :class:`~werkzeug.exceptions.UnsupportedMediaType` unless the
            request mimetype is ``application/json-seq``.

    Notes on mixing with the buffered API:

    * Call :meth:`~quart.wrappers.request.Request.get_data` or
      :meth:`~quart.wrappers.request.Request.get_json` *before* iterating
      to get the full body; the iterator will then see an already
      consumed (empty) stream and yield nothing.
    * After iterating, ``get_data()`` only returns whatever bytes remain
      unconsumed (typically ``b""``), and ``get_json()`` will fail or
      return ``None`` - the stream has been consumed. Note that
      ``get_json()`` also returns ``None`` without ``force=True`` as
      ``application/json-seq`` is not considered a JSON mimetype.
    * If the caller stops iterating early the remaining body is left
      unread; this iterator never drains the rest of the request.
    * If the client disconnects, iteration ends promptly by propagating
      :class:`~quart.wrappers.base.ClientDisconnectedError` (or
      :class:`asyncio.CancelledError` if the task is cancelled).
    """
    if on_error not in ("abort", "skip"):
        raise ValueError("on_error must be 'abort' or 'skip'")
    if require_content_type and request.mimetype != JSON_SEQ_MIMETYPE:
        raise UnsupportedMediaType(
            f"Expected a {JSON_SEQ_MIMETYPE!r} request, got {request.mimetype!r}"
        )
    return _iterate(request, max_record_bytes, on_error, on_record_error)


async def _iterate(
    request: Request,
    max_record_bytes: int | None,
    on_error: Literal["abort", "skip"],
    on_record_error: Callable[[JSONSeqError], None] | None,
) -> AsyncIterator[Any]:
    buffer = bytearray()
    record_open = False  # A record separator has been seen.
    skipping = False  # Discarding an oversized record until the next RS.
    preamble_bad = False  # Junk before the first RS already reported.
    record_index = -1
    record_offset = 0
    stream_offset = 0

    def report(error: JSONSeqError) -> None:
        if on_error == "abort":
            raise error
        if on_record_error is not None:
            on_record_error(error)

    def feed(data: bytes, offset: int) -> None:
        nonlocal preamble_bad, skipping
        if not record_open:
            if preamble_bad:
                return
            stripped = data.strip()
            if stripped:
                preamble_bad = True
                report(
                    JSONSeqDecodeError(
                        "Received data before the first record separator",
                        record_index=0,
                        byte_offset=offset + data.index(stripped[:1]),
                    )
                )
        elif not skipping:
            buffer.extend(data)
            if max_record_bytes is not None and len(buffer) > max_record_bytes:
                report(
                    JSONSeqRecordTooLargeError(
                        f"Record {record_index} exceeded the limit of "
                        f"{max_record_bytes} bytes",
                        record_index=record_index,
                        byte_offset=record_offset,
                    )
                )
                skipping = True
                buffer.clear()

    def decode(raw: bytearray, final: bool) -> Any:
        content = bytes(raw).strip()
        if not content:
            return _SKIP
        try:
            return request.json_module.loads(content.decode("utf-8"))
        except ValueError as error:
            if final:
                problem: JSONSeqError = JSONSeqTruncatedError(
                    f"Final record {record_index} is truncated or invalid",
                    record_index=record_index,
                    byte_offset=record_offset,
                )
            else:
                problem = JSONSeqDecodeError(
                    f"Record {record_index} is not valid JSON",
                    record_index=record_index,
                    byte_offset=record_offset,
                )
            problem.__cause__ = error
            report(problem)
            return _SKIP

    async for chunk in request.body:
        if not chunk:
            continue
        part_offset = stream_offset
        stream_offset += len(chunk)
        parts = chunk.split(RECORD_SEPARATOR)
        feed(parts[0], part_offset)
        part_offset += len(parts[0])
        for part in parts[1:]:
            # A record separator at part_offset ends the current record.
            if record_open and not skipping:
                value = decode(buffer, final=False)
                if value is not _SKIP:
                    yield value
            skipping = False
            buffer.clear()
            record_open = True
            record_index += 1
            record_offset = part_offset + 1
            part_offset += 1
            feed(part, part_offset)
            part_offset += len(part)

    if record_open and not skipping:
        value = decode(buffer, final=True)
        if value is not _SKIP:
            yield value
