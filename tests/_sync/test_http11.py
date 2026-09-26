import typing

import pytest

import httpcore


class RecordingStream:
    """
    A network stream that records the ordering of reads and writes, so
    that tests can determine exactly when the request body was sent.

    Reads replay a scripted list of server responses. Script items that
    are exceptions are raised, and once the script is exhausted a
    `ReadTimeout` is raised, simulating a server that does not respond.
    """

    def __init__(self, script: typing.List[typing.Any]) -> None:
        self._script = list(script)
        self.log: typing.List[typing.Any] = []
        self._closed = False

    def read(
        self, max_bytes: int, timeout: typing.Optional[float] = None
    ) -> bytes:
        self.log.append(("read", timeout))
        if not self._script:
            raise httpcore.ReadTimeout("timed out")
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def write(
        self, buffer: bytes, timeout: typing.Optional[float] = None
    ) -> None:
        self.log.append(("write", buffer))

    def close(self) -> None:
        self._closed = True

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return self

    def get_extra_info(self, info: str):
        return None



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
    An "Expect: 100-continue" request sends the headers first, waits for
    the "100 Continue" response, and only then sends the request body.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue"},
            content=b"Hello, world!",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

        assert conn.is_idle()
        assert conn.is_available()

    operations = [operation for operation, _ in stream.log]
    assert operations == ["write", "read", "write", "write", "read"]
    assert b"expect: 100-continue" in stream.log[0][1].lower()
    assert stream.log[2][1] == b"Hello, world!"



def test_http11_expect_100_continue_rejected():
    """
    If the server sends a final response instead of "100 Continue", then
    the request body is never sent, and the response is returned as-is.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nUnauthorized"]
    )
    body_consumed = False

    def body() -> typing.Iterator[bytes]:
        nonlocal body_consumed
        body_consumed = True
        yield b"Hello, world!"

    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue"},
            content=body(),
        )
        assert response.status == 401
        assert response.content == b"Unauthorized"

        # The connection cannot be reused, since the request body was not sent.
        assert conn.is_closed()

    # The request body iterator was never consumed...
    assert not body_consumed
    # ...and only the request headers were written to the network.
    writes = [data for operation, data in stream.log if operation == "write"]
    assert len(writes) == 1
    assert b"expect: 100-continue" in writes[0].lower()



def test_http11_expect_100_continue_timeout():
    """
    If no "100 Continue" response arrives within the configured timeout,
    then the request body is sent anyway.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            httpcore.ReadTimeout("timed out"),
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue"},
            content=b"Hello, world!",
            extensions={"expect_100_continue_timeout": 5.0},
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    operations = [operation for operation, _ in stream.log]
    assert operations == ["write", "read", "write", "write", "read"]
    # The read during the wait uses the "100 Continue" timeout.
    assert 0.0 < stream.log[1][1] <= 5.0
    # The request body was sent once the wait had expired.
    assert stream.log[2][1] == b"Hello, world!"



def test_http11_expect_100_continue_read_timeout_still_applies():
    """
    A regular read timeout that is shorter than the "100 Continue" wait
    is not disabled by the handshake.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream([httpcore.ReadTimeout("timed out")])
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.ReadTimeout):
            conn.request(
                "POST",
                "https://example.com/",
                headers={"Expect": "100-continue"},
                content=b"Hello, world!",
                extensions={
                    "timeout": {"read": 1.0},
                    "expect_100_continue_timeout": 60.0,
                },
            )

    # The read during the wait used the regular read timeout.
    assert stream.log[1] == ("read", 1.0)
    # The request body was never sent.
    writes = [data for operation, data in stream.log if operation == "write"]
    assert len(writes) == 1



def test_http11_expect_100_continue_with_informational_responses():
    """
    Informational responses such as "103 Early Hints" do not authorize
    sending the request body. Only "100 Continue" does.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue"},
            content=b"Hello, world!",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    operations = [operation for operation, _ in stream.log]
    assert operations == ["write", "read", "read", "write", "write", "read"]
    # The request body was sent only after the "100 Continue" response.
    assert stream.log[3][1] == b"Hello, world!"



def test_http11_expect_100_continue_with_103_then_final_response():
    """
    A final response following other informational responses means the
    request body must not be sent.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
        ]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue"},
            content=b"Hello, world!",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    # Only the request headers were written to the network.
    writes = [data for operation, data in stream.log if operation == "write"]
    assert len(writes) == 1



def test_http11_expect_100_continue_with_empty_body():
    """
    A request with "Expect: 100-continue" but a known-empty body does
    not wait for "100 Continue", and sends everything immediately.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            headers={"Expect": "100-continue"},
            content=b"",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    # No read occurs before the request has been fully written.
    operations = [operation for operation, _ in stream.log]
    assert operations == ["write", "write", "write", "read"]



def test_http11_expect_100_continue_server_disconnect():
    """
    If the server disconnects while the client is waiting for
    "100 Continue", then a RemoteProtocolError is raised.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream([b""])
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.RemoteProtocolError):
            conn.request(
                "POST",
                "https://example.com/",
                headers={"Expect": "100-continue"},
                content=b"Hello, world!",
            )

    # The request body was never sent.
    writes = [data for operation, data in stream.log if operation == "write"]
    assert len(writes) == 1



def test_http11_request_body_sent_immediately_without_expect():
    """
    Requests without an "Expect: 100-continue" header are unaffected.
    The request body is sent immediately, without waiting.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingStream(
        [b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"]
    )
    with httpcore.HTTP11Connection(origin=origin, stream=stream) as conn:
        response = conn.request(
            "POST",
            "https://example.com/",
            content=b"Hello, world!",
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"

    operations = [operation for operation, _ in stream.log]
    assert operations == ["write", "write", "write", "read"]
