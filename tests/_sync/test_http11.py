import pytest

import httpcore


class RecordingStream(httpcore.MockStream):
    """
    A mock stream that records the order of `read()` and `write()` calls,
    so that tests can assert exactly when the request body was sent.

    The `script` is a list of `bytes` returned by successive `read()` calls.
    An exception instance may be included in the script, in which case the
    corresponding `read()` raises it.
    """

    def __init__(self, script):
        super().__init__([])
        self._script = list(script)
        self.record = []

    def read(self, max_bytes, timeout=None):
        self.record.append(("read", timeout))
        item = self._script.pop(0) if self._script else b""
        if isinstance(item, BaseException):
            raise item
        return item

    def write(self, buffer, timeout=None):
        self.record.append(("write", bytes(buffer)))

    def writes(self):
        return [data for event, data in self.record if event == "write"]

    def reads(self):
        return [timeout for event, timeout in self.record if event == "read"]

    def event_order(self):
        return [event for event, _ in self.record]



def test_http11_connection():
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b"Hello, world!"

        assert conn.is_idle()
        assert not conn.is_closed()
        assert conn.is_available()
        assert not conn.has_expired()
        assert (
            repr(conn)
            == "<HTTP11Connection ['https://example.com:443', IDLE, Request Count: 1]>"
        )



def test_http11_connection_unread_response():
    """
    If the client releases the response without reading it to termination,
    then the connection will not be reusable.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with conn.stream("GET", "https://example.com/") as response:
            assert response.status == 200

        assert not conn.is_idle()
        assert conn.is_closed()
        assert not conn.is_available()
        assert not conn.has_expired()
        assert (
            repr(conn)
            == "<HTTP11Connection ['https://example.com:443', CLOSED, Request Count: 1]>"
        )



def test_http11_connection_with_remote_protocol_error():
    """
    If a remote protocol error occurs, then no response will be returned,
    and the connection will not be reusable.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream([b"Wait, this isn't valid HTTP!", b""])
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.RemoteProtocolError):
            conn.request("GET", "https://example.com/")

        assert not conn.is_idle()
        assert conn.is_closed()
        assert not conn.is_available()
        assert not conn.has_expired()
        assert (
            repr(conn)
            == "<HTTP11Connection ['https://example.com:443', CLOSED, Request Count: 1]>"
        )



def test_http11_connection_with_incomplete_response():
    """
    We should be gracefully handling the case where the connection ends prematurely.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, wor",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.RemoteProtocolError):
            conn.request("GET", "https://example.com/")

        assert not conn.is_idle()
        assert conn.is_closed()
        assert not conn.is_available()
        assert not conn.has_expired()
        assert (
            repr(conn)
            == "<HTTP11Connection ['https://example.com:443', CLOSED, Request Count: 1]>"
        )



def test_http11_connection_with_local_protocol_error():
    """
    If a local protocol error occurs, then no response will be returned,
    and the connection will not be reusable.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.LocalProtocolError) as exc_info:
            conn.request("GET", "https://example.com/", headers={"Host": "\0"})

        assert str(exc_info.value) == "Illegal header value b'\\x00'"

        assert not conn.is_idle()
        assert conn.is_closed()
        assert not conn.is_available()
        assert not conn.has_expired()
        assert (
            repr(conn)
            == "<HTTP11Connection ['https://example.com:443', CLOSED, Request Count: 1]>"
        )



def test_http11_connection_handles_one_active_request():
    """
    Attempting to send a request while one is already in-flight will raise
    a ConnectionNotAvailable exception.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with conn.stream("GET", "https://example.com/"):
            with pytest.raises(httpcore.ConnectionNotAvailable):
                conn.request("GET", "https://example.com/")



def test_http11_connection_attempt_close():
    """
    A connection can only be closed when it is idle.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with conn.stream("GET", "https://example.com/") as response:
            response.read()
            assert response.status == 200
            assert response.content == b"Hello, world!"



def test_http11_request_to_incorrect_origin():
    """
    A connection can only send requests to whichever origin it is connected to.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream([])
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(RuntimeError):
            conn.request("GET", "https://other.com/")



def test_http11_expect_continue():
    """
    HTTP "100 Continue" is an interim response.
    We simply ignore it and return the final response.

    https://httpwg.org/specs/rfc9110.html#status.100
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/100
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 100 Continue\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "GET",
            "https://example.com/",
            headers={"Expect": "continue"},
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"



def test_http11_upgrade_connection():
    """
    HTTP "101 Switching Protocols" indicates an upgraded connection.

    We should return the response, so that the network stream
    may be used for the upgraded connection.

    https://httpwg.org/specs/rfc9110.html#status.101
    https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/101
    """
    origin = httpcore.Origin(b"wss", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 101 Switching Protocols\r\n",
            b"Connection: upgrade\r\n",
            b"Upgrade: custom\r\n",
            b"\r\n",
            b"...",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        with conn.stream(
            "GET",
            "wss://example.com/",
            headers={"Connection": "upgrade", "Upgrade": "custom"},
        ) as response:
            assert response.status == 101
            network_stream = response.extensions["network_stream"]
            content = network_stream.read(max_bytes=1024)
            assert content == b"..."



def test_http11_upgrade_with_trailing_data():
    """
    HTTP "101 Switching Protocols" indicates an upgraded connection.

    In `CONNECT` and `Upgrade:` requests, we need to handover the trailing data
    in the h11.Connection object.

    https://h11.readthedocs.io/en/latest/api.html#switching-protocols
    """
    origin = httpcore.Origin(b"wss", b"example.com", 443)
    stream = httpcore.MockStream(
        # The first element of this mock network stream buffer simulates networking
        # in which response headers and data are received at once.
        # This means that "foobar" becomes trailing data.
        [
            (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Connection: upgrade\r\n"
                b"Upgrade: custom\r\n"
                b"\r\n"
                b"foobar"
            ),
            b"baz",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        with conn.stream(
            "GET",
            "wss://example.com/",
            headers={"Connection": "upgrade", "Upgrade": "custom"},
        ) as response:
            assert response.status == 101
            network_stream = response.extensions["network_stream"]

            content = network_stream.read(max_bytes=3)
            assert content == b"foo"
            content = network_stream.read(max_bytes=3)
            assert content == b"bar"
            content = network_stream.read(max_bytes=3)
            assert content == b"baz"

            # Lazy tests for HTTP11UpgradeStream
            network_stream.write(b"spam")
            invalid = network_stream.get_extra_info("invalid")
            assert invalid is None
            network_stream.close()



def test_http11_early_hints():
    """
    HTTP "103 Early Hints" is an interim response.
    We simply ignore it and return the final response.

    https://datatracker.ietf.org/doc/rfc8297/
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 103 Early Hints\r\n",
            b"Link: </style.css>; rel=preload; as=style\r\n",
            b"Link: </script.js.css>; rel=preload; as=style\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: text/html; charset=utf-8\r\n",
            b"Content-Length: 30\r\n",
            b"Link: </style.css>; rel=preload; as=style\r\n",
            b"Link: </script.js>; rel=preload; as=script\r\n",
            b"\r\n",
            b"<html>Hello, world! ...</html>",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "GET",
            "https://example.com/",
            headers={"Expect": "continue"},
        )
        assert response.status == 200
        assert response.content == b"<html>Hello, world! ...</html>"



def test_http11_header_sub_100kb():
    """
    A connection should be able to handle a http header size up to 100kB.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.MockStream(
        [
            b"HTTP/1.1 200 OK\r\n",  # 17
            b"Content-Type: plain/text\r\n",  # 43
            b"Cookie: " + b"x" * (100 * 1024 - 72) + b"\r\n",  # 102381
            b"Content-Length: 0\r\n",  # 102400
            b"\r\n",
            b"",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b""



def test_http11_expect_100_continue():
    """
    An `Expect: 100-continue` request sends the headers first, then waits
    for a `100 Continue` informational response before sending the body.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 100 Continue\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue", "Content-Length": "5"},
            content=b"Hello",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"
        assert conn.is_idle()

    # The request headers are sent, then the server is read, and only
    # afterwards is the request body sent.
    writes = stream.writes()
    assert writes[0].startswith(b"POST / HTTP/1.1\r\n")
    assert b"expect: 100-continue" in writes[0].lower()
    assert writes[1] == b"Hello"
    assert stream.event_order()[:2] == ["write", "read"]



def test_http11_expect_100_continue_final_response():
    """
    If the server responds to an `Expect: 100-continue` request with a final
    response, such as a `401 Unauthorized`, then the request body is never
    sent, and the response is returned as-is.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 401 Unauthorized\r\n",
            b"Content-Length: 4\r\n",
            b"\r\n",
            b"Nope",
        ]
    )

    body_was_read = False

    def body():
        nonlocal body_was_read
        body_was_read = True
        yield b"Hello"

    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue", "Content-Length": "5"},
            content=body(),
        )
        assert response.status == 401
        assert response.content == b"Nope"
        # The connection cannot be reused, since the request body
        # was never sent.
        assert conn.is_closed()

    # The request body iterator was never consumed...
    assert not body_was_read
    # ...and only the request headers were written to the stream.
    writes = stream.writes()
    assert len(writes) == 1
    assert writes[0].startswith(b"POST / HTTP/1.1\r\n")



def test_http11_expect_100_continue_timeout():
    """
    If no `100 Continue` response arrives within the configured wait time,
    then the request body is sent anyway. The regular read timeout still
    applies to any reads outside of the `100 Continue` wait.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            httpcore.ReadTimeout(),
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue", "Content-Length": "5"},
            content=b"Hello",
            extensions={
                "timeout": {"read": 5.0},
                "expect_100_continue_timeout": 0.5,
            },
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    # The request body was sent once the wait had expired.
    writes = stream.writes()
    assert writes[1] == b"Hello"
    assert stream.event_order()[:3] == ["write", "read", "write"]
    # The `100 Continue` wait used the configured timeout...
    read_timeouts = stream.reads()
    assert 0.0 < read_timeouts[0] <= 0.5
    # ...while subsequent reads used the regular read timeout.
    assert read_timeouts[1] == 5.0



def test_http11_expect_100_continue_informational_responses():
    """
    Informational responses other than `100 Continue`, such as
    `103 Early Hints`, do not green-light sending the request body.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 103 Early Hints\r\n",
            b"Link: </style.css>; rel=preload; as=style\r\n",
            b"\r\n",
            b"HTTP/1.1 100 Continue\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue", "Content-Length": "5"},
            content=b"Hello",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    # The request body was only sent once the `100 Continue` arrived,
    # after both informational responses had been read.
    writes = stream.writes()
    assert writes[1] == b"Hello"
    assert stream.event_order()[:4] == ["write", "read", "read", "read"]



def test_http11_expect_100_continue_informational_then_final_response():
    """
    A final response following other informational responses still means
    that the request body must not be sent.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 103 Early Hints\r\n",
            b"Link: </style.css>; rel=preload; as=style\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )

    body_was_read = False

    def body():
        nonlocal body_was_read
        body_was_read = True
        yield b"Hello"

    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue", "Content-Length": "5"},
            content=body(),
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    assert not body_was_read
    assert len(stream.writes()) == 1



def test_http11_expect_100_continue_empty_body():
    """
    An `Expect: 100-continue` request with an empty body still performs
    the handshake, then sends the terminating chunk once accepted.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 100 Continue\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue", "Content-Length": "0"},
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"
        assert conn.is_idle()

    # The headers are sent, the `100 Continue` is read, and then the
    # request is terminated without any request body being sent.
    assert stream.event_order()[:2] == ["write", "read"]
    assert stream.writes()[1:] == [b"", b""]



def test_http11_expect_100_continue_server_disconnect():
    """
    If the server disconnects during the `100 Continue` wait, then a
    `RemoteProtocolError` is raised, and the request body is never sent.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream([b""])

    body_was_read = False

    def body():
        nonlocal body_was_read
        body_was_read = True
        yield b"Hello"

    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.RemoteProtocolError):
            conn.request(
                "POST",
                "https://example.com/",
                headers={"Expect": "100-continue", "Content-Length": "5"},
                content=body(),
            )
        assert conn.is_closed()

    assert not body_was_read
    assert len(stream.writes()) == 1



def test_http11_expect_100_continue_body_failure():
    """
    If sending the request body fails partway through, after a
    `100 Continue` was received, then the exception propagates and
    the connection is closed.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 100 Continue\r\n",
            b"\r\n",
        ]
    )

    def body():
        yield b"Hello"
        raise RuntimeError("Sending the request body was cancelled.")

    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(RuntimeError):
            conn.request(
                "POST",
                "https://example.com/",
                headers={"Expect": "100-continue", "Content-Length": "10"},
                content=body(),
            )
        assert conn.is_closed()



def test_http11_request_without_expect_100_continue():
    """
    Requests without an `Expect: 100-continue` header are unaffected.
    The request body is sent immediately, without waiting for the server.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )
    with httpcore.HTTP11Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Content-Length": "5"},
            content=b"Hello",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"
        assert conn.is_idle()

    # The request, including the body, is sent before any read occurs.
    events = stream.event_order()
    first_read = events.index("read")
    assert set(events[:first_read]) == {"write"}
    assert stream.writes()[1] == b"Hello"
