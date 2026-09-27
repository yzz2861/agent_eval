from __future__ import annotations

import hpack
import hyperframe.frame
import pytest

import httpcore

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def http2_server_settings() -> bytes:
    return hyperframe.frame.SettingsFrame(
        settings={hyperframe.frame.SettingsFrame.MAX_CONCURRENT_STREAMS: 1000}
    ).serialize()


def http2_response_headers(stream_id: int) -> bytes:
    return hyperframe.frame.HeadersFrame(
        stream_id=stream_id,
        data=hpack.Encoder().encode(
            [
                (b":status", b"200"),
                (b"content-type", b"plain/text"),
            ]
        ),
        flags=["END_HEADERS"],
    ).serialize()


def http2_response_data(stream_id: int, data: bytes, pad_length: int = 0) -> bytes:
    flags = ["END_STREAM", "PADDED"] if pad_length else ["END_STREAM"]
    return hyperframe.frame.DataFrame(
        stream_id=stream_id, data=data, flags=flags, pad_length=pad_length
    ).serialize()


class RecordingAsyncMockStream(httpcore.AsyncMockStream):
    """
    A mock stream that records everything the client writes to it,
    so that tests can inspect the frames sent to the server.
    """

    def __init__(self, buffer: list[bytes]) -> None:
        super().__init__(buffer)
        self.written: list[bytes] = []

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.written.append(buffer)

    def written_frames(self) -> list[hyperframe.frame.Frame]:
        data = b"".join(self.written)
        if data.startswith(CONNECTION_PREFACE):
            data = data[len(CONNECTION_PREFACE) :]
        frames = []
        while data:
            frame, length = hyperframe.frame.Frame.parse_frame_header(
                memoryview(data[:9])
            )
            frame.parse_body(memoryview(data[9 : 9 + length]))
            frames.append(frame)
            data = data[9 + length :]
        return frames

    def connection_window_updates(self) -> list[int]:
        return [
            frame.window_increment
            for frame in self.written_frames()
            if isinstance(frame, hyperframe.frame.WindowUpdateFrame)
            and frame.stream_id == 0
        ]


@pytest.mark.anyio
async def test_http2_connection():
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        response = await conn.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b"Hello, world!"

        assert conn.is_idle()
        assert conn.is_available()
        assert not conn.is_closed()
        assert not conn.has_expired()
        assert (
            conn.info() == "'https://example.com:443', HTTP/2, IDLE, Request Count: 1"
        )
        assert (
            repr(conn)
            == "<AsyncHTTP2Connection ['https://example.com:443', IDLE, Request Count: 1]>"
        )


@pytest.mark.anyio
async def test_http2_connection_closed():
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
            # Connection is closed after the first response
            hyperframe.frame.GoAwayFrame(
                stream_id=0, error_code=0, last_stream_id=1
            ).serialize(),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(
        origin=origin, stream=stream, keepalive_expiry=5.0
    ) as conn:
        await conn.request("GET", "https://example.com/")

        with pytest.raises(httpcore.ConnectionNotAvailable):
            await conn.request("GET", "https://example.com/")

        assert not conn.is_available()


@pytest.mark.anyio
async def test_http2_connection_post_request():
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        response = await conn.request(
            "POST",
            "https://example.com/",
            headers={b"content-length": b"17"},
            content=b'{"data": "upload"}',
        )
        assert response.status == 200
        assert response.content == b"Hello, world!"


@pytest.mark.anyio
async def test_http2_connection_with_remote_protocol_error():
    """
    If a remote protocol error occurs, then no response will be returned,
    and the connection will not be reusable.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream([b"Wait, this isn't valid HTTP!", b""])
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.RemoteProtocolError):
            await conn.request("GET", "https://example.com/")


@pytest.mark.anyio
async def test_http2_connection_with_rst_stream():
    """
    If a stream reset occurs, then no response will be returned,
    but the connection will remain reusable for other requests.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            # Stream is closed midway through the first response...
            hyperframe.frame.RstStreamFrame(stream_id=1, error_code=8).serialize(),
            # ...Which doesn't prevent the second response.
            hyperframe.frame.HeadersFrame(
                stream_id=3,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=3, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
            b"",
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(httpcore.RemoteProtocolError):
            await conn.request("GET", "https://example.com/")
        response = await conn.request("GET", "https://example.com/")
        assert response.status == 200


@pytest.mark.anyio
async def test_http2_connection_with_goaway():
    """
    If a GoAway frame occurs, then no response will be returned,
    and the connection will not be reusable for other requests.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            # Connection is closed midway through the first response...
            hyperframe.frame.GoAwayFrame(stream_id=0, error_code=0).serialize(),
            # ...We'll never get to this second response.
            hyperframe.frame.HeadersFrame(
                stream_id=3,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=3, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
            b"",
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        # The initial request has been closed midway, with an unrecoverable error.
        with pytest.raises(httpcore.RemoteProtocolError):
            await conn.request("GET", "https://example.com/")

        # The second request can receive a graceful `ConnectionNotAvailable`,
        # and may be retried on a new connection.
        with pytest.raises(httpcore.ConnectionNotAvailable):
            await conn.request("GET", "https://example.com/")


@pytest.mark.anyio
async def test_http2_connection_with_flow_control():
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            # Available flow: 65,535
            hyperframe.frame.WindowUpdateFrame(
                stream_id=0, window_increment=10_000
            ).serialize(),
            hyperframe.frame.WindowUpdateFrame(
                stream_id=1, window_increment=10_000
            ).serialize(),
            # Available flow: 75,535
            hyperframe.frame.WindowUpdateFrame(
                stream_id=0, window_increment=10_000
            ).serialize(),
            hyperframe.frame.WindowUpdateFrame(
                stream_id=1, window_increment=10_000
            ).serialize(),
            # Available flow: 85,535
            hyperframe.frame.WindowUpdateFrame(
                stream_id=0, window_increment=10_000
            ).serialize(),
            hyperframe.frame.WindowUpdateFrame(
                stream_id=1, window_increment=10_000
            ).serialize(),
            # Available flow: 95,535
            hyperframe.frame.WindowUpdateFrame(
                stream_id=0, window_increment=10_000
            ).serialize(),
            hyperframe.frame.WindowUpdateFrame(
                stream_id=1, window_increment=10_000
            ).serialize(),
            # Available flow: 105,535
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"100,000 bytes received", flags=["END_STREAM"]
            ).serialize(),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        response = await conn.request(
            "POST",
            "https://example.com/",
            content=b"x" * 100_000,
        )
        assert response.status == 200
        assert response.content == b"100,000 bytes received"


@pytest.mark.anyio
async def test_http2_connection_attempt_close():
    """
    A connection can only be closed when it is idle.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"Hello, world!", flags=["END_STREAM"]
            ).serialize(),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        async with conn.stream("GET", "https://example.com/") as response:
            await response.aread()
            assert response.status == 200
            assert response.content == b"Hello, world!"

        await conn.aclose()
        with pytest.raises(httpcore.ConnectionNotAvailable):
            await conn.request("GET", "https://example.com/")


@pytest.mark.anyio
async def test_http2_request_to_incorrect_origin():
    """
    A connection can only send requests to whichever origin it is connected to.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream([])
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        with pytest.raises(RuntimeError):
            await conn.request("GET", "https://other.com/")


@pytest.mark.anyio
async def test_http2_remote_max_streams_update():
    """
    If the remote server updates the maximum concurrent streams value, we should
    be adjusting how many streams we will allow.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame(
                settings={hyperframe.frame.SettingsFrame.MAX_CONCURRENT_STREAMS: 1000}
            ).serialize(),
            hyperframe.frame.HeadersFrame(
                stream_id=1,
                data=hpack.Encoder().encode(
                    [
                        (b":status", b"200"),
                        (b"content-type", b"plain/text"),
                    ]
                ),
                flags=["END_HEADERS"],
            ).serialize(),
            hyperframe.frame.DataFrame(stream_id=1, data=b"Hello, world!").serialize(),
            hyperframe.frame.SettingsFrame(
                settings={hyperframe.frame.SettingsFrame.MAX_CONCURRENT_STREAMS: 50}
            ).serialize(),
            hyperframe.frame.DataFrame(
                stream_id=1, data=b"Hello, world...again!", flags=["END_STREAM"]
            ).serialize(),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        async with conn.stream("GET", "https://example.com/") as response:
            i = 0
            async for chunk in response.aiter_stream():
                if i == 0:
                    assert chunk == b"Hello, world!"
                    assert conn._h2_state.remote_settings.max_concurrent_streams == 1000
                    assert conn._max_streams == min(
                        conn._h2_state.remote_settings.max_concurrent_streams,
                        conn._h2_state.local_settings.max_concurrent_streams,
                    )
                elif i == 1:
                    assert chunk == b"Hello, world...again!"
                    assert conn._h2_state.remote_settings.max_concurrent_streams == 50
                    assert conn._max_streams == min(
                        conn._h2_state.remote_settings.max_concurrent_streams,
                        conn._h2_state.local_settings.max_concurrent_streams,
                    )
                i += 1


@pytest.mark.anyio
async def test_http2_receive_budget_must_be_positive():
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream([])
    with pytest.raises(ValueError):
        httpcore.AsyncHTTP2Connection(
            origin=origin, stream=stream, stream_receive_budget=0
        )
    with pytest.raises(ValueError):
        httpcore.AsyncHTTP2Connection(
            origin=origin, stream=stream, connection_receive_budget=-1
        )


@pytest.mark.anyio
async def test_http2_receive_budget_allows_other_streams_to_complete():
    """
    A stream that is not being consumed must not prevent the other streams
    on the same connection from completing, since the receive budgets are
    enforced through HTTP/2 flow control rather than by pausing reads.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            http2_server_settings(),
            # A response on stream 1 that the client does not consume,
            # sized to exactly fill the per-stream receive budget.
            http2_response_headers(stream_id=1),
            http2_response_data(stream_id=1, data=b"x" * 1024),
            # Smaller responses on streams 3 and 5, which should complete.
            http2_response_headers(stream_id=3),
            http2_response_data(stream_id=3, data=b"response three"),
            http2_response_headers(stream_id=5),
            http2_response_data(stream_id=5, data=b"response five"),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(
        origin=origin,
        stream=stream,
        stream_receive_budget=1024,
        connection_receive_budget=65535 + 4096,
    ) as conn:
        async with conn.stream("GET", "https://example.com/slow") as slow_response:
            assert slow_response.status == 200

            # The slow stream is not consumed here. The other streams
            # must still be able to complete their responses.
            async with conn.stream("GET", "https://example.com/three") as response:
                assert await response.aread() == b"response three"
            async with conn.stream("GET", "https://example.com/five") as response:
                assert await response.aread() == b"response five"

            # The slow stream can still be consumed afterwards.
            assert await slow_response.aread() == b"x" * 1024


@pytest.mark.anyio
async def test_http2_receive_budget_released_on_close():
    """
    Closing a response that has not been fully consumed must release the
    receive budget it was holding, returning the connection-level flow
    control window to the server.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingAsyncMockStream(
        [
            http2_server_settings(),
            http2_response_headers(stream_id=1),
            http2_response_data(stream_id=1, data=b"x" * 1024),
            http2_response_headers(stream_id=3),
            http2_response_data(stream_id=3, data=b"Hello, world!"),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(
        origin=origin,
        stream=stream,
        stream_receive_budget=1024,
        connection_receive_budget=65535 + 4096,
    ) as conn:
        async with conn.stream("GET", "https://example.com/slow") as response:
            assert response.status == 200
            # A second request, so that the first response body has been
            # read off the network and is buffered against the budget.
            await conn.request("GET", "https://example.com/other")
        # The first response is closed here, without being consumed.

    # The initial connection-level WINDOW_UPDATE sizes the connection
    # receive budget. Closing the unconsumed response returns the 1024
    # bytes it was holding to the connection-level flow control window.
    assert stream.connection_window_updates() == [4096, 1024]


@pytest.mark.anyio
async def test_http2_receive_budget_released_on_reset():
    """
    If a stream is reset while response body data is still buffered, then
    closing the response must release the receive budget it was holding.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingAsyncMockStream(
        [
            http2_server_settings(),
            http2_response_headers(stream_id=1),
            http2_response_data(stream_id=1, data=b"x" * 512),
            hyperframe.frame.RstStreamFrame(stream_id=1).serialize(),
            http2_response_headers(stream_id=3),
            http2_response_data(stream_id=3, data=b"Hello, world!"),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(
        origin=origin,
        stream=stream,
        stream_receive_budget=1024,
        connection_receive_budget=65535 + 4096,
    ) as conn:
        async with conn.stream("GET", "https://example.com/reset") as response:
            assert response.status == 200
            # A second request, so that the first response body and the
            # stream reset have been read off the network.
            await conn.request("GET", "https://example.com/other")
        # The first response is closed here, without being consumed.

    assert stream.connection_window_updates() == [4096, 512]


@pytest.mark.anyio
async def test_http2_connection_with_padded_data():
    """
    DATA frames that include padding are received correctly, with the
    padding excluded from the response body.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = httpcore.AsyncMockStream(
        [
            hyperframe.frame.SettingsFrame().serialize(),
            http2_response_headers(stream_id=1),
            http2_response_data(stream_id=1, data=b"Hello, world!", pad_length=10),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(origin=origin, stream=stream) as conn:
        response = await conn.request("GET", "https://example.com/")
        assert response.status == 200
        assert response.content == b"Hello, world!"


@pytest.mark.anyio
async def test_http2_receive_budget_released_with_padded_data():
    """
    Releasing the receive budget for DATA frames that include padding must
    use the flow controlled length, which accounts for the padding.
    """
    origin = httpcore.Origin(b"https", b"example.com", 443)
    stream = RecordingAsyncMockStream(
        [
            http2_server_settings(),
            http2_response_headers(stream_id=1),
            # 13 bytes of data, plus 1 pad length byte and 10 bytes of
            # padding, gives a flow controlled length of 24 bytes.
            http2_response_data(stream_id=1, data=b"Hello, world!", pad_length=10),
            http2_response_headers(stream_id=3),
            http2_response_data(stream_id=3, data=b"other"),
        ]
    )
    async with httpcore.AsyncHTTP2Connection(
        origin=origin,
        stream=stream,
        connection_receive_budget=65535 + 4096,
    ) as conn:
        async with conn.stream("GET", "https://example.com/slow") as response:
            assert response.status == 200
            await conn.request("GET", "https://example.com/other")
        # The first response is closed here, without being consumed.

    assert stream.connection_window_updates() == [4096, 24]
