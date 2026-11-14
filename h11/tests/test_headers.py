import pytest

from .._connection import Connection
from .._events import Request
from .._headers import (
    MAX_HEADER_BLOCK_SIZE,
    MAX_HEADER_FOLD_DEPTH,
    MAX_HEADER_LINE_SIZE,
    get_comma_header,
    has_expect_100_continue,
    Headers,
    normalize_and_validate,
    parse_header_lines,
    set_comma_header,
)
from .._state import ERROR, SERVER
from .._util import LocalProtocolError, RemoteProtocolError


def test_normalize_and_validate() -> None:
    assert normalize_and_validate([("foo", "bar")]) == [(b"foo", b"bar")]
    assert normalize_and_validate([(b"foo", b"bar")]) == [(b"foo", b"bar")]

    # no leading/trailing whitespace in names
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([(b"foo ", "bar")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([(b" foo", "bar")])

    # no weird characters in names
    with pytest.raises(LocalProtocolError) as excinfo:
        normalize_and_validate([(b"foo bar", b"baz")])
    assert "foo bar" not in str(excinfo.value)
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([(b"foo\x00bar", b"baz")])
    # Not even 8-bit characters:
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([(b"foo\xffbar", b"baz")])
    # And not even the control characters we allow in values:
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([(b"foo\x01bar", b"baz")])

    # no return, newline, NUL, or other control characters in values
    with pytest.raises(LocalProtocolError) as excinfo:
        normalize_and_validate([("foo", "bar\rbaz")])
    assert "bar" not in str(excinfo.value)
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "bar\nbaz")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "bar\x00baz")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "bar\x01baz")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "bar\x7fbaz")])
    # no leading/trailing whitespace
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "barbaz  ")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "  barbaz")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "barbaz\t")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("foo", "\tbarbaz")])

    valid_utf8 = "☃".encode("utf-8")
    assert normalize_and_validate([(b"foo", valid_utf8)]) == [(b"foo", valid_utf8)]
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([(b"foo", b"\xff")])

    # content-length
    assert normalize_and_validate([("Content-Length", "1")]) == [
        (b"content-length", b"1")
    ]
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("Content-Length", "asdf")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("Content-Length", "1x")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("Content-Length", "1"), ("Content-Length", "2")])
    assert normalize_and_validate(
        [("Content-Length", "0"), ("Content-Length", "0")]
    ) == [(b"content-length", b"0")]
    assert normalize_and_validate([("Content-Length", "0 , 0")]) == [
        (b"content-length", b"0")
    ]
    with pytest.raises(LocalProtocolError):
        normalize_and_validate(
            [("Content-Length", "1"), ("Content-Length", "1"), ("Content-Length", "2")]
        )
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("Content-Length", "1 , 1,2")])
    with pytest.raises(LocalProtocolError):
        normalize_and_validate([("Content-Length", "1" * 21)])  # 1 billion TB

    # transfer-encoding
    assert normalize_and_validate([("Transfer-Encoding", "chunked")]) == [
        (b"transfer-encoding", b"chunked")
    ]
    assert normalize_and_validate([("Transfer-Encoding", "cHuNkEd")]) == [
        (b"transfer-encoding", b"chunked")
    ]
    with pytest.raises(LocalProtocolError) as excinfo:
        normalize_and_validate([("Transfer-Encoding", "gzip")])
    assert excinfo.value.error_status_hint == 501  # Not Implemented
    with pytest.raises(LocalProtocolError) as excinfo:
        normalize_and_validate(
            [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "gzip")]
        )
    assert excinfo.value.error_status_hint == 501  # Not Implemented


def test_get_set_comma_header() -> None:
    headers = normalize_and_validate(
        [
            ("Connection", "close"),
            ("whatever", "something"),
            ("connectiON", "fOo,, , BAR"),
        ]
    )

    assert get_comma_header(headers, b"connection") == [b"close", b"foo", b"bar"]

    headers = set_comma_header(headers, b"newthing", ["a", "b"])  # type: ignore

    with pytest.raises(LocalProtocolError):
        set_comma_header(headers, b"newthing", ["  a", "b"])  # type: ignore

    assert headers == [
        (b"connection", b"close"),
        (b"whatever", b"something"),
        (b"connection", b"fOo,, , BAR"),
        (b"newthing", b"a"),
        (b"newthing", b"b"),
    ]

    headers = set_comma_header(
        headers, b"whatever", ["different thing"]
    )  # type: ignore

    assert headers == [
        (b"connection", b"close"),
        (b"connection", b"fOo,, , BAR"),
        (b"newthing", b"a"),
        (b"newthing", b"b"),
        (b"whatever", b"different thing"),
    ]


def test_parse_header_lines() -> None:
    lines = [
        b"X-Duplicate: first",
        b"X-Folded: multi",
        b"\tline",
        b" X-UTF-8: " + "☃".encode("utf-8"),
        b"X-Duplicate: second",
    ]
    assert parse_header_lines(lines) == [
        (b"X-Duplicate", b"first"),
        (b"X-Folded", b"multi line"),
        (b"X-UTF-8", "☃".encode("utf-8")),
        (b"X-Duplicate", b"second"),
    ]

    continuation_lines = [b"X: value"] + [
        b" folded" for _ in range(MAX_HEADER_FOLD_DEPTH)
    ]
    assert parse_header_lines(continuation_lines) == [
        (b"X", b"value" + b" folded" * MAX_HEADER_FOLD_DEPTH)
    ]
    too_deep = continuation_lines + [b" folded"]
    with pytest.raises(LocalProtocolError, match="folding too deep"):
        parse_header_lines(too_deep)

    with pytest.raises(LocalProtocolError, match="continuation line"):
        parse_header_lines([b" folded"])
    with pytest.raises(LocalProtocolError, match="illegal header name"):
        parse_header_lines([b"bad name: value"])
    with pytest.raises(LocalProtocolError, match="control character"):
        parse_header_lines([b"X: bad\x00value"])
    with pytest.raises(LocalProtocolError, match="non-UTF-8"):
        parse_header_lines([b"X: \xff"])

    boundary_value = b"a" * (MAX_HEADER_LINE_SIZE - len(b"X: "))
    assert parse_header_lines([b"X: " + boundary_value]) == [(b"X", boundary_value)]
    with pytest.raises(LocalProtocolError, match="line too long"):
        parse_header_lines(
            [b"X: " + b"a" * (MAX_HEADER_LINE_SIZE - len(b"X: ") + 1)]
        )

    long_headers = [b"X: " + b"a" * 255 for _ in range(64)]
    with pytest.raises(LocalProtocolError, match="block too long"):
        parse_header_lines(long_headers, max_block_size=16 * 1024)

    exact_line_size = MAX_HEADER_BLOCK_SIZE // 2
    exact_headers = [
        b"X: " + b"a" * (exact_line_size - len(b"X: ")) for _ in range(2)
    ]
    assert len(parse_header_lines(exact_headers)) == 2
    with pytest.raises(LocalProtocolError, match="block too long"):
        parse_header_lines(exact_headers + [b"Y: z"])


def test_header_error_does_not_echo_value() -> None:
    malicious = b"X: " + b"a" * 100 + b"\x00"
    with pytest.raises(LocalProtocolError) as excinfo:
        parse_header_lines([malicious])
    message = str(excinfo.value)
    assert malicious not in message.encode("ascii", "ignore")
    assert "safe preview ends at byte" in message


def test_received_header_security_limits() -> None:
    conn = Connection(SERVER)
    conn.receive_data(
        b"GET / HTTP/1.0\r\n"
        b"X-Folded: safe\r\n"
        b"\tcontinuation\r\n"
        b"X-Duplicate: one\r\n"
        b"X-Duplicate: two\r\n\r\n"
    )
    request = conn.next_event()
    assert isinstance(request, Request)
    assert request.headers == [
        (b"x-folded", b"safe continuation"),
        (b"x-duplicate", b"one"),
        (b"x-duplicate", b"two"),
    ]

    for payload in [
        b"GET / HTTP/1.0\nX: bad\n\n",
        b"GET / HTTP/1.0\r\nX: bad\n\n",
        b"GET / HTTP/1.0\r\nX: bad\rvalue\r\n\r\n",
        b"GET / HTTP/1.0\r\nX: bad\x00value\r\n\r\n",
        b"GET / HTTP/1.0\r\nX: "
        + b"a" * (MAX_HEADER_LINE_SIZE - len(b"X: ") + 1)
        + b"\r\n\r\n",
        b"GET / HTTP/1.0\r\n"
        + b"".join(b"X: " + b"a" * 255 + b"\r\n" for _ in range(64))
        + b"\r\n",
    ]:
        conn = Connection(SERVER)
        conn.receive_data(payload)
        with pytest.raises(RemoteProtocolError) as excinfo:
            conn.next_event()
        assert conn.their_state is ERROR
        with pytest.raises(RemoteProtocolError):
            conn.next_event()
        assert b"bad" not in str(excinfo.value).encode("ascii", "ignore")
        if len(payload) > MAX_HEADER_BLOCK_SIZE:
            assert excinfo.value.error_status_hint == 431

    boundary_value = b"a" * (MAX_HEADER_LINE_SIZE - len(b"X: "))
    conn = Connection(SERVER)
    conn.receive_data(
        b"GET / HTTP/1.0\r\nX: " + boundary_value + b"\r\n\r\n"
    )
    request = conn.next_event()
    assert isinstance(request, Request)
    assert request.headers == [(b"x", boundary_value)]


def test_has_100_continue() -> None:
    assert has_expect_100_continue(
        Request(
            method="GET",
            target="/",
            headers=[("Host", "example.com"), ("Expect", "100-continue")],
        )
    )
    assert not has_expect_100_continue(
        Request(method="GET", target="/", headers=[("Host", "example.com")])
    )
    # Case insensitive
    assert has_expect_100_continue(
        Request(
            method="GET",
            target="/",
            headers=[("Host", "example.com"), ("Expect", "100-Continue")],
        )
    )
    # Doesn't work in HTTP/1.0
    assert not has_expect_100_continue(
        Request(
            method="GET",
            target="/",
            headers=[("Host", "example.com"), ("Expect", "100-continue")],
            http_version="1.0",
        )
    )
