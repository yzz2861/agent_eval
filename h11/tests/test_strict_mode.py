"""Tests for the connection-level ``strict`` wire-syntax option.

In strict mode h11 only accepts the canonical CRLF line ending on request
lines, status lines, header fields, chunk headers/trailers and the chunk
separator, and rejects obsolete line folding (RFC 7230 section 3.2.4).

These tests feed the *same* raw bytes through a default (lenient) and a
strict connection, and also feed them under arbitrary ``receive_data``
splittings -- including one byte at a time, which splits every CRLF.
"""

from typing import Any, List, Optional, Tuple

import pytest

import h11
from h11._events import Event
from h11._receivebuffer import ReceiveBuffer
from h11._util import LocalProtocolError, RemoteProtocolError
from .helpers import normalize_data_events

# (role, raw bytes)
RequestCase = Tuple[Any, bytes]

REQUEST_CRLF: RequestCase = (
    h11.SERVER,
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
)
REQUEST_LF: RequestCase = (
    h11.SERVER,
    b"GET / HTTP/1.1\nHost: example.com\nConnection: close\n\n",
)
REQUEST_MIXED: RequestCase = (
    h11.SERVER,
    b"GET / HTTP/1.1\nHost: example.com\r\nConnection: close\n\n",
)
REQUEST_OBS_FOLD: RequestCase = (
    h11.SERVER,
    b"GET / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"X-Multi: one\r\n"
    b" two\r\n"
    b"Connection: close\r\n\r\n",
)

RESPONSE_CRLF: RequestCase = (
    h11.CLIENT,
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
)
RESPONSE_LF: RequestCase = (
    h11.CLIENT,
    b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
)
RESPONSE_OBS_FOLD: RequestCase = (
    h11.CLIENT,
    b"HTTP/1.1 200 OK\r\n"
    b"X-Multi: one\r\n"
    b" two\r\n"
    b"Content-Length: 0\r\n\r\n",
)

# Chunked request: chunk header/body/footer/trailer all present.
CHUNKED_CRLF: RequestCase = (
    h11.SERVER,
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n"
    b"0\r\n"
    b"X-Trailer: value\r\n\r\n",
)
# Bare LF on the first chunk header: rejected by both modes (the chunk
# header grammar requires CRLF), but strict mode must reject it the moment
# the LF arrives instead of waiting for later data.
CHUNKED_HEADER_LF: RequestCase = (
    h11.SERVER,
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\nhello\r\n0\r\n\r\n",
)
# Bare LF between chunk data and the next chunk header: strict rejects it,
# lenient rejects it too via the chunk footer comparison.
CHUNKED_FOOTER_LF: RequestCase = (
    h11.SERVER,
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\n0\r\n\r\n",
)
# Bare LF in the trailer section: lenient accepts (trailer is a header
# block), strict rejects.
CHUNKED_TRAILER_LF: RequestCase = (
    h11.SERVER,
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n"
    b"0\r\n"
    b"X-Trailer: value\n\n",
)
# Folded line in the trailer section.
CHUNKED_TRAILER_FOLD: RequestCase = (
    h11.SERVER,
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n"
    b"0\r\n"
    b"X-Trailer: one\r\n"
    b" two\r\n\r\n",
)

RESPONSE_CHUNKED_CRLF: RequestCase = (
    h11.CLIENT,
    b"HTTP/1.1 200 OK\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nworld\r\n0\r\n\r\n",
)
RESPONSE_CHUNKED_TRAILER_LF: RequestCase = (
    h11.CLIENT,
    b"HTTP/1.1 200 OK\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nworld\r\n0\r\nX-Trailer: value\n\n",
)

# Cases that parse successfully in the default (lenient) mode.
LENIENT_OK_CASES = [
    REQUEST_CRLF,
    REQUEST_LF,
    REQUEST_MIXED,
    REQUEST_OBS_FOLD,
    RESPONSE_CRLF,
    RESPONSE_LF,
    RESPONSE_OBS_FOLD,
    CHUNKED_CRLF,
    CHUNKED_TRAILER_LF,
    CHUNKED_TRAILER_FOLD,
    RESPONSE_CHUNKED_CRLF,
    RESPONSE_CHUNKED_TRAILER_LF,
]

# Cases that are strict violations.
STRICT_VIOLATION_CASES = [
    REQUEST_LF,
    REQUEST_MIXED,
    REQUEST_OBS_FOLD,
    RESPONSE_LF,
    RESPONSE_OBS_FOLD,
    CHUNKED_HEADER_LF,
    CHUNKED_FOOTER_LF,
    CHUNKED_TRAILER_LF,
    CHUNKED_TRAILER_FOLD,
    RESPONSE_CHUNKED_TRAILER_LF,
]

# Subset that the lenient mode also rejects (so a split test can assert the
# failure in both modes, at possibly different times).
BOTH_REJECT_CASES = [CHUNKED_HEADER_LF, CHUNKED_FOOTER_LF]


def _parse(
    role: Any,
    data: bytes,
    strict: bool,
    splits: Optional[List[int]] = None,
) -> Tuple[List[Event], Optional[RemoteProtocolError], bytes]:
    """Feed raw bytes to a connection, optionally split at given offsets.

    Returns the events produced, the first RemoteProtocolError (if any), and
    the bytes still held in the receive buffer when parsing stopped.
    """
    conn = h11.Connection(role, strict=strict)
    if splits is None:
        conn.receive_data(data)
    else:
        start = 0
        for cut in splits:
            conn.receive_data(data[start:cut])
            start = cut
        conn.receive_data(data[start:])

    events: List[Event] = []
    error: Optional[RemoteProtocolError] = None
    while True:
        try:
            event = conn.next_event()
        except RemoteProtocolError as exc:
            error = exc
            break
        if event in (h11.NEED_DATA, h11.PAUSED):
            break
        events.append(event)  # type: ignore[arg-type]
    return normalize_data_events(events), error, conn.trailing_data[0]


@pytest.mark.parametrize("role,data", LENIENT_OK_CASES)
def test_default_mode_is_lenient(role: Any, data: bytes) -> None:
    events, error, leftover = _parse(role, data, strict=False)
    assert error is None
    assert leftover == b""
    assert events


@pytest.mark.parametrize(
    "role,data",
    [
        REQUEST_CRLF,
        RESPONSE_CRLF,
        CHUNKED_CRLF,
        RESPONSE_CHUNKED_CRLF,
    ],
)
def test_same_events_in_both_modes_for_crlf(role: Any, data: bytes) -> None:
    lenient_events, lenient_error, _ = _parse(role, data, strict=False)
    strict_events, strict_error, _ = _parse(role, data, strict=True)
    assert lenient_error is None
    assert strict_error is None
    assert strict_events == lenient_events


@pytest.mark.parametrize("role,data", STRICT_VIOLATION_CASES)
def test_strict_rejects_violations_at_once(role: Any, data: bytes) -> None:
    _, error, _ = _parse(role, data, strict=True)
    assert isinstance(error, RemoteProtocolError)


@pytest.mark.parametrize("role,data", LENIENT_OK_CASES)
def test_any_splitting_does_not_change_result(role: Any, data: bytes) -> None:
    canonical_events, canonical_error, _ = _parse(role, data, strict=False)

    split_sets: List[List[int]] = [[]]
    for cut in range(1, len(data)):
        split_sets.append([cut])
    # A handful of multi-way splits.
    if len(data) > 4:
        split_sets += [
            [1],
            [2],
            [len(data) // 2],
            [1, 2],
            [1, len(data) - 1],
            [2, len(data) - 2],
        ]

    for splits in split_sets:
        events, error, leftover = _parse(role, data, strict=False, splits=splits)
        assert error is canonical_error
        assert events == canonical_events
        assert leftover == b""


@pytest.mark.parametrize(
    "role,data",
    [
        REQUEST_CRLF,
        RESPONSE_CRLF,
        CHUNKED_CRLF,
        RESPONSE_CHUNKED_CRLF,
    ],
)
def test_strict_accepts_crlf_split_byte_by_byte(role: Any, data: bytes) -> None:
    # Feeding one byte at a time splits every CR and LF into separate
    # receive_data() calls; strict must not report a false bare LF.
    splits = list(range(1, len(data)))
    lenient_events, _, _ = _parse(role, data, strict=False, splits=splits)
    strict_events, strict_error, leftover = _parse(
        role, data, strict=True, splits=splits
    )
    assert strict_error is None
    assert leftover == b""
    assert strict_events == lenient_events


@pytest.mark.parametrize("role,data", STRICT_VIOLATION_CASES)
def test_strict_rejects_under_byte_by_byte_split(role: Any, data: bytes) -> None:
    splits = list(range(1, len(data)))
    _, error, _ = _parse(role, data, strict=True, splits=splits)
    assert isinstance(error, RemoteProtocolError)


@pytest.mark.parametrize("role,data", BOTH_REJECT_CASES)
def test_both_modes_reject_under_all_splits(role: Any, data: bytes) -> None:
    for cut in range(len(data) + 1):
        splits = [cut] if cut else []
        _, lenient_error, _ = _parse(role, data, strict=False, splits=splits)
        _, strict_error, _ = _parse(role, data, strict=True, splits=splits)
        assert isinstance(lenient_error, RemoteProtocolError)
        assert isinstance(strict_error, RemoteProtocolError)


def _step(role: Any, strict: bool) -> Any:
    return h11.Connection(role, strict=strict)


def test_strict_detects_bare_lf_without_waiting_for_block() -> None:
    # Request line terminated by a bare LF arrives in two fragments. As soon
    # as the LF is visible strict mode must fail -- even though the rest of
    # the header block has not arrived yet.
    strict_conn = _step(h11.SERVER, strict=True)
    lenient_conn = _step(h11.SERVER, strict=False)
    strict_conn.receive_data(b"GET / HTTP/1.1\n")
    lenient_conn.receive_data(b"GET / HTTP/1.1\n")
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()
    # Lenient mode is still waiting for the rest of the (tolerated) headers.
    assert lenient_conn.next_event() is h11.NEED_DATA


def test_strict_detects_status_line_bare_lf_immediately() -> None:
    strict_conn = _step(h11.CLIENT, strict=True)
    strict_conn.receive_data(b"HTTP/1.1 200 OK\n")
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()


def test_strict_detects_chunk_header_bare_lf_without_later_data() -> None:
    # Only the (bare-LF) chunk header fragment is available. Strict mode
    # must fail immediately, whereas lenient mode has no complete chunk
    # header yet and is still waiting for data.
    header = (
        b"POST / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    strict_conn = _step(h11.SERVER, strict=True)
    lenient_conn = _step(h11.SERVER, strict=False)
    for conn in (strict_conn, lenient_conn):
        conn.receive_data(header)
        # Consume Request, then start reading the body.
        assert type(conn.next_event()) is h11.Request
        assert conn.next_event() is h11.NEED_DATA
        conn.receive_data(b"5\n")
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()
    assert lenient_conn.next_event() is h11.NEED_DATA


def test_split_crlf_is_not_a_false_positive() -> None:
    # CR and LF of every line ending arrive in separate receive_data calls.
    data = REQUEST_CRLF[1]
    strict_conn = _step(h11.SERVER, strict=True)
    assert data[0:1] == b"G"
    for index in range(len(data)):
        strict_conn.receive_data(data[index : index + 1])
        # No error while the message is still incomplete.
        if index < len(data) - 1:
            assert strict_conn.next_event() is h11.NEED_DATA
    assert type(strict_conn.next_event()) is h11.Request


def test_split_crlf_in_chunk_header_is_accepted() -> None:
    data = CHUNKED_CRLF[1]
    strict_conn = _step(h11.SERVER, strict=True)
    request_part, chunk_part = data.split(b"5\r\n", 1)
    strict_conn.receive_data(request_part)
    assert type(strict_conn.next_event()) is h11.Request
    # Feed the chunk-size and the CR one byte at a time.
    strict_conn.receive_data(b"5")
    assert strict_conn.next_event() is h11.NEED_DATA
    strict_conn.receive_data(b"\r")
    # CR without its LF is not yet a bare LF: no error, no complete header.
    assert strict_conn.next_event() is h11.NEED_DATA
    strict_conn.receive_data(b"\n")
    # The chunk header is now complete; the next call needs chunk data.
    assert strict_conn.next_event() is h11.NEED_DATA
    strict_conn.receive_data(chunk_part)
    events = []
    while True:
        event = strict_conn.next_event()
        if event in (h11.NEED_DATA, h11.PAUSED):
            break
        events.append(event)
    assert normalize_data_events(events) == [
        h11.Data(data=b"hello"),
        h11.EndOfMessage(headers=[("X-Trailer", "value")]),
    ]


def test_strict_obs_fold_detected_when_continuation_arrives() -> None:
    strict_conn = _step(h11.SERVER, strict=True)
    prefix = b"GET / HTTP/1.1\r\nHost: example.com\r\nX: one\r\n"
    strict_conn.receive_data(prefix)
    assert strict_conn.next_event() is h11.NEED_DATA
    # The first byte of the continuation line (SP) triggers the error.
    strict_conn.receive_data(b" folded\r\n\r\n")
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()


def test_no_bytes_consumed_before_strict_failure() -> None:
    # A strict violation in the first pipelined request must be detected
    # before any bytes of the header block are consumed; the valid pipelined
    # request after it stays buffered intact.
    bad_then_good = (
        b"GET /bad HTTP/1.1\nHost: a\n\n"
        b"GET /good HTTP/1.1\r\nHost: b\r\n\r\n"
    )
    strict_conn = _step(h11.SERVER, strict=True)
    strict_conn.receive_data(bad_then_good)
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()
    assert strict_conn.trailing_data == (bad_then_good, False)

    # Same raw bytes in lenient mode: the first request is parsed (it asked
    # to close, so the second stays untouched in the buffer).
    lenient_conn = _step(h11.SERVER, strict=False)
    lenient_conn.receive_data(bad_then_good)
    assert type(lenient_conn.next_event()) is h11.Request
    assert type(lenient_conn.next_event()) is h11.EndOfMessage
    assert lenient_conn.next_event() is h11.PAUSED
    assert lenient_conn.trailing_data == (
        b"GET /good HTTP/1.1\r\nHost: b\r\n\r\n",
        False,
    )


def test_good_pipeline_then_bad_consumes_only_good_request() -> None:
    good = b"GET /good HTTP/1.1\r\nHost: a\r\n\r\n"
    bad = b"GET /bad HTTP/1.1\nHost: b\n\n"
    strict_conn = _step(h11.SERVER, strict=True)
    strict_conn.receive_data(good + bad)
    assert type(strict_conn.next_event()) is h11.Request
    assert type(strict_conn.next_event()) is h11.EndOfMessage
    # Respond and recycle so the pipelined data is read.
    strict_conn.send(h11.Response(status_code=200, headers=[]))
    strict_conn.send(h11.EndOfMessage())
    strict_conn.start_next_cycle()
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()
    assert strict_conn.trailing_data == (bad, False)


def test_connection_state_after_strict_error() -> None:
    strict_conn = _step(h11.SERVER, strict=True)
    strict_conn.receive_data(REQUEST_LF[1])
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()
    assert strict_conn.their_state is h11.ERROR
    # Subsequent reads fail deterministically.
    with pytest.raises(RemoteProtocolError):
        strict_conn.next_event()
    # Further data can still be buffered; it is not lost.
    strict_conn.receive_data(b"extra")
    assert strict_conn.trailing_data == (REQUEST_LF[1] + b"extra", False)


def test_receivebuffer_strict_unit() -> None:
    # Completed lines with bare LF are rejected even without a header block.
    buf = ReceiveBuffer(strict=True)
    buf += b"GET / HTTP/1.1\n"
    with pytest.raises(LocalProtocolError):
        buf.maybe_extract_next_line()

    buf = ReceiveBuffer(strict=True)
    buf += b"GET / HTTP/1.1\r\n"
    assert buf.maybe_extract_next_line() == b"GET / HTTP/1.1\r\n"

    # Split CRLF across checks: the lone CR is fine, the LF completes it.
    buf = ReceiveBuffer(strict=True)
    buf += b"abc\r"
    assert buf.maybe_extract_next_line() is None
    buf += b"\n"
    assert buf.maybe_extract_next_line() == b"abc\r\n"

    # Header block: bare LF and obs-fold are rejected incrementally.
    buf = ReceiveBuffer(strict=True)
    buf += b"GET / HTTP/1.1\r\nX: one\r\n"
    assert buf.maybe_extract_lines() is None
    buf += b" folded\r\n\r\n"
    with pytest.raises(LocalProtocolError):
        buf.maybe_extract_lines()

    # The default buffer remains lenient.
    buf = ReceiveBuffer()
    buf += b"GET / HTTP/1.1\nHost: a\n\n"
    assert buf.maybe_extract_lines() == [b"GET / HTTP/1.1", b"Host: a"]


def test_strict_does_not_scan_chunk_payload() -> None:
    # A bare LF inside chunk data is opaque payload, not a line ending, so
    # strict framing checks must not flag it.
    data = (
        b"POST / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"3\r\na\nb\r\n0\r\n\r\n"
    )
    splits = list(range(1, len(data)))
    events, error, leftover = _parse(
        h11.SERVER, data, strict=True, splits=splits
    )
    assert error is None
    assert leftover == b""
    assert events == [
        h11.Request(
            method="POST",
            target="/",
            headers=[
                ("Host", "example.com"),
                ("Transfer-Encoding", "chunked"),
            ],
        ),
        h11.Data(data=b"a\nb"),
        h11.EndOfMessage(),
    ]
