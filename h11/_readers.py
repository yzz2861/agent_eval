# Code to read HTTP data
#
# Strategy: each reader is a callable which takes a ReceiveBuffer object, and
# either:
# 1) consumes some of it and returns an Event
# 2) raises a LocalProtocolError (for consistency -- e.g. we call validate()
#    and it might raise a LocalProtocolError, so simpler just to always use
#    this)
# 3) returns None, meaning "I need more data"
#
# If they have a .read_eof attribute, then this will be called if an EOF is
# received -- but this is optional. Either way, the actual ConnectionClosed
# event will be generated afterwards.
#
# READERS is a dict describing how to pick a reader. It maps states to either:
# - a reader
# - or, for body readers, a dict of per-framing reader factories

import re
from typing import Any, Callable, Dict, Iterable, NoReturn, Optional, Tuple, Type, Union

from ._abnf import chunk_header, header_field, request_line, status_line
from ._events import Data, EndOfMessage, InformationalResponse, Request, Response
from ._receivebuffer import ReceiveBuffer
from ._state import (
    CLIENT,
    CLOSED,
    DONE,
    IDLE,
    MUST_CLOSE,
    SEND_BODY,
    SEND_RESPONSE,
    SERVER,
)
from ._util import LocalProtocolError, RemoteProtocolError, Sentinel, validate

__all__ = ["READERS"]

header_field_re = re.compile(header_field.encode("ascii"))
obs_fold_re = re.compile(rb"[ \t]+")


def _obsolete_line_fold(
    lines: Iterable[bytes], strict: bool = False
) -> Iterable[bytes]:
    it = iter(lines)
    last: Optional[bytes] = None
    for line in it:
        match = obs_fold_re.match(line)
        if match:
            if strict:
                raise LocalProtocolError("obsolete line folding is not allowed")
            if last is None:
                raise LocalProtocolError("continuation line at start of headers")
            if not isinstance(last, bytearray):
                # Cast to a mutable type, avoiding copy on append to ensure O(n) time
                last = bytearray(last)
            last += b" "
            last += line[match.end() :]
        else:
            if last is not None:
                yield last
            last = line
    if last is not None:
        yield last


def _decode_header_lines(
    lines: Iterable[bytes],
    strict: bool = False,
) -> Iterable[Tuple[bytes, bytes]]:
    for line in _obsolete_line_fold(lines, strict=strict):
        matches = validate(header_field_re, line, "illegal header line: {!r}", line)
        yield (matches["field_name"], matches["field_value"])


request_line_re = re.compile(request_line.encode("ascii"))


def maybe_read_from_IDLE_client(buf: ReceiveBuffer) -> Optional[Request]:
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError("illegal request line")
        return None
    if not lines:
        raise LocalProtocolError("no request line received")
    matches = validate(
        request_line_re, lines[0], "illegal request line: {!r}", lines[0]
    )
    return Request(
        headers=list(_decode_header_lines(lines[1:], strict=buf.strict)),
        _parsed=True,
        **matches,
    )


status_line_re = re.compile(status_line.encode("ascii"))


def maybe_read_from_SEND_RESPONSE_server(
    buf: ReceiveBuffer,
) -> Union[InformationalResponse, Response, None]:
    lines = buf.maybe_extract_lines()
    if lines is None:
        if buf.is_next_line_obviously_invalid_request_line():
            raise LocalProtocolError("illegal request line")
        return None
    if not lines:
        raise LocalProtocolError("no response line received")
    matches = validate(status_line_re, lines[0], "illegal status line: {!r}", lines[0])
    http_version = (
        b"1.1" if matches["http_version"] is None else matches["http_version"]
    )
    reason = b"" if matches["reason"] is None else matches["reason"]
    status_code = int(matches["status_code"])
    class_: Union[Type[InformationalResponse], Type[Response]] = (
        InformationalResponse if status_code < 200 else Response
    )
    return class_(
        headers=list(_decode_header_lines(lines[1:], strict=buf.strict)),
        _parsed=True,
        status_code=status_code,
        reason=reason,
        http_version=http_version,
    )


class ContentLengthReader:
    def __init__(self, length: int) -> None:
        self._length = length
        self._remaining = length

    def __call__(self, buf: ReceiveBuffer) -> Union[Data, EndOfMessage, None]:
        if self._remaining == 0:
            return EndOfMessage()
        data = buf.maybe_extract_at_most(self._remaining)
        if data is None:
            return None
        self._remaining -= len(data)
        return Data(data=data)

    def read_eof(self) -> NoReturn:
        raise RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(received {} bytes, expected {})".format(
                self._length - self._remaining, self._length
            )
        )


chunk_header_re = re.compile(chunk_header.encode("ascii"))


class ChunkedReader:
    def __init__(self, strict: bool = False) -> None:
        self._strict = strict
        self._bytes_in_chunk = 0
        # After reading a chunk, we have to verify the trailing CRLF without
        # consuming it until both bytes are known.
        self._waiting_for_chunk_footer = False
        self._reading_trailer = False

    def __call__(self, buf: ReceiveBuffer) -> Union[Data, EndOfMessage, None]:
        if self._reading_trailer:
            lines = buf.maybe_extract_lines()
            if lines is None:
                return None
            return EndOfMessage(
                headers=list(_decode_header_lines(lines, strict=self._strict))
            )
        if self._waiting_for_chunk_footer:
            if not buf:
                return None
            data = bytes(buf)[:1]
            if data != b"\r":
                raise LocalProtocolError(
                    f"malformed chunk footer: {data!r} (expected b'\\r')"
                )
            if len(buf) < 2:
                return None
            data = bytes(buf)[:2]
            if data != b"\r\n":
                raise LocalProtocolError(
                    f"malformed chunk footer: {bytes(data)!r} (expected b'\\r\\n')"
                )
            buf.maybe_extract_at_most(2)
            self._waiting_for_chunk_footer = False
            # else, fall through and read some more
        assert not self._waiting_for_chunk_footer
        if self._bytes_in_chunk == 0:
            # We need to refill our chunk count
            chunk_header = buf.maybe_extract_next_line()
            if chunk_header is None:
                return None
            matches = validate(
                chunk_header_re,
                chunk_header,
                "illegal chunk header: {!r}",
                chunk_header,
            )
            # XX FIXME: we discard chunk extensions. Does anyone care?
            self._bytes_in_chunk = int(matches["chunk_size"], base=16)
            if self._bytes_in_chunk == 0:
                self._reading_trailer = True
                return self(buf)
            chunk_start = True
        else:
            chunk_start = False
        assert self._bytes_in_chunk > 0
        data = buf.maybe_extract_at_most(self._bytes_in_chunk)
        if data is None:
            return None
        self._bytes_in_chunk -= len(data)
        if self._bytes_in_chunk == 0:
            self._waiting_for_chunk_footer = True
            chunk_end = True
        else:
            chunk_end = False
        return Data(data=data, chunk_start=chunk_start, chunk_end=chunk_end)

    def read_eof(self) -> NoReturn:
        raise RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)"
        )


class Http10Reader:
    def __call__(self, buf: ReceiveBuffer) -> Optional[Data]:
        data = buf.maybe_extract_at_most(999999999)
        if data is None:
            return None
        return Data(data=data)

    def read_eof(self) -> EndOfMessage:
        return EndOfMessage()


def expect_nothing(buf: ReceiveBuffer) -> None:
    if buf:
        raise LocalProtocolError("Got data when expecting EOF")
    return None


ReadersType = Dict[
    Union[Type[Sentinel], Tuple[Type[Sentinel], Type[Sentinel]]],
    Union[Callable[..., Any], Dict[str, Callable[..., Any]]],
]

READERS: ReadersType = {
    (CLIENT, IDLE): maybe_read_from_IDLE_client,
    (SERVER, IDLE): maybe_read_from_SEND_RESPONSE_server,
    (SERVER, SEND_RESPONSE): maybe_read_from_SEND_RESPONSE_server,
    (CLIENT, DONE): expect_nothing,
    (CLIENT, MUST_CLOSE): expect_nothing,
    (CLIENT, CLOSED): expect_nothing,
    (SERVER, DONE): expect_nothing,
    (SERVER, MUST_CLOSE): expect_nothing,
    (SERVER, CLOSED): expect_nothing,
    SEND_BODY: {
        "chunked": ChunkedReader,
        "content-length": ContentLengthReader,
        "http/1.0": Http10Reader,
    },
}
