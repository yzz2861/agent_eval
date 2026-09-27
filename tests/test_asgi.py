import json

import anyio
import pytest

import httpx
from httpx._transports.asgi import _MAX_BUFFERED_MESSAGES


async def hello_world(scope, receive, send):
    status = 200
    output = b"Hello, World!"
    headers = [(b"content-type", "text/plain"), (b"content-length", str(len(output)))]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": output})


async def echo_path(scope, receive, send):
    status = 200
    output = json.dumps({"path": scope["path"]}).encode("utf-8")
    headers = [(b"content-type", "text/plain"), (b"content-length", str(len(output)))]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": output})


async def echo_raw_path(scope, receive, send):
    status = 200
    output = json.dumps({"raw_path": scope["raw_path"].decode("ascii")}).encode("utf-8")
    headers = [(b"content-type", "text/plain"), (b"content-length", str(len(output)))]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": output})


async def echo_body(scope, receive, send):
    status = 200
    headers = [(b"content-type", "text/plain")]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    more_body = True
    while more_body:
        message = await receive()
        body = message.get("body", b"")
        more_body = message.get("more_body", False)
        await send({"type": "http.response.body", "body": body, "more_body": more_body})


async def echo_headers(scope, receive, send):
    status = 200
    output = json.dumps(
        {"headers": [[k.decode(), v.decode()] for k, v in scope["headers"]]}
    ).encode("utf-8")
    headers = [(b"content-type", "text/plain"), (b"content-length", str(len(output)))]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": output})


async def raise_exc(scope, receive, send):
    raise RuntimeError()


async def raise_exc_after_response(scope, receive, send):
    status = 200
    output = b"Hello, World!"
    headers = [(b"content-type", "text/plain"), (b"content-length", str(len(output)))]

    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": output})
    raise RuntimeError()


@pytest.mark.anyio
async def test_asgi_transport():
    async with httpx.ASGITransport(app=hello_world) as transport:
        request = httpx.Request("GET", "http://www.example.com/")
        response = await transport.handle_async_request(request)
        await response.aread()
        assert response.status_code == 200
        assert response.content == b"Hello, World!"


@pytest.mark.anyio
async def test_asgi_transport_no_body():
    async with httpx.ASGITransport(app=echo_body) as transport:
        request = httpx.Request("GET", "http://www.example.com/")
        response = await transport.handle_async_request(request)
        await response.aread()
        assert response.status_code == 200
        assert response.content == b""


@pytest.mark.anyio
async def test_asgi():
    transport = httpx.ASGITransport(app=hello_world)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("http://www.example.org/")

    assert response.status_code == 200
    assert response.text == "Hello, World!"


@pytest.mark.anyio
async def test_asgi_urlencoded_path():
    transport = httpx.ASGITransport(app=echo_path)
    async with httpx.AsyncClient(transport=transport) as client:
        url = httpx.URL("http://www.example.org/").copy_with(path="/user@example.org")
        response = await client.get(url)

    assert response.status_code == 200
    assert response.json() == {"path": "/user@example.org"}


@pytest.mark.anyio
async def test_asgi_raw_path():
    transport = httpx.ASGITransport(app=echo_raw_path)
    async with httpx.AsyncClient(transport=transport) as client:
        url = httpx.URL("http://www.example.org/").copy_with(path="/user@example.org")
        response = await client.get(url)

    assert response.status_code == 200
    assert response.json() == {"raw_path": "/user@example.org"}


@pytest.mark.anyio
async def test_asgi_raw_path_should_not_include_querystring_portion():
    """
    See https://github.com/encode/httpx/issues/2810
    """
    transport = httpx.ASGITransport(app=echo_raw_path)
    async with httpx.AsyncClient(transport=transport) as client:
        url = httpx.URL("http://www.example.org/path?query")
        response = await client.get(url)

    assert response.status_code == 200
    assert response.json() == {"raw_path": "/path"}


@pytest.mark.anyio
async def test_asgi_upload():
    transport = httpx.ASGITransport(app=echo_body)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://www.example.org/", content=b"example")

    assert response.status_code == 200
    assert response.text == "example"


@pytest.mark.anyio
async def test_asgi_headers():
    transport = httpx.ASGITransport(app=echo_headers)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("http://www.example.org/")

    assert response.status_code == 200
    assert response.json() == {
        "headers": [
            ["host", "www.example.org"],
            ["accept", "*/*"],
            ["accept-encoding", "gzip, deflate, br, zstd"],
            ["connection", "keep-alive"],
            ["user-agent", f"python-httpx/{httpx.__version__}"],
        ]
    }


@pytest.mark.anyio
async def test_asgi_exc():
    transport = httpx.ASGITransport(app=raise_exc)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RuntimeError):
            await client.get("http://www.example.org/")


@pytest.mark.anyio
async def test_asgi_exc_after_response():
    transport = httpx.ASGITransport(app=raise_exc_after_response)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RuntimeError):
            await client.get("http://www.example.org/")


@pytest.mark.anyio
async def test_asgi_disconnect_after_response_complete():
    disconnect = False

    async def read_body(scope, receive, send):
        nonlocal disconnect

        status = 200
        headers = [(b"content-type", "text/plain")]

        await send(
            {"type": "http.response.start", "status": status, "headers": headers}
        )
        more_body = True
        while more_body:
            message = await receive()
            more_body = message.get("more_body", False)

        await send({"type": "http.response.body", "body": b"", "more_body": False})

        # The ASGI spec says of the Disconnect message:
        # "Sent to the application when a HTTP connection is closed or if receive is
        # called after a response has been sent."
        # So if receive() is called again, the disconnect message should be received
        message = await receive()
        disconnect = message.get("type") == "http.disconnect"

    transport = httpx.ASGITransport(app=read_body)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.post("http://www.example.org/", content=b"example")

    assert response.status_code == 200
    assert disconnect


@pytest.mark.anyio
async def test_asgi_exc_no_raise():
    transport = httpx.ASGITransport(app=raise_exc, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("http://www.example.org/")

        assert response.status_code == 500


async def raise_exc_mid_stream(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"partial", "more_body": True})
    raise RuntimeError()


@pytest.mark.anyio
async def test_asgi_exc_mid_stream():
    transport = httpx.ASGITransport(app=raise_exc_mid_stream)
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(RuntimeError):
            await client.get("http://www.example.org/")


@pytest.mark.anyio
async def test_asgi_exc_mid_stream_no_raise():
    transport = httpx.ASGITransport(
        app=raise_exc_mid_stream, raise_app_exceptions=False
    )
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("http://www.example.org/")

        assert response.status_code == 200
        assert response.content == b"partial"


@pytest.mark.anyio
async def test_asgi_streaming_first_chunk_received_before_app_completes():
    allow_app_to_finish = anyio.Event()
    app_finished = anyio.Event()

    async def app(scope, receive, send):
        headers = [(b"content-type", b"text/plain")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": b"first", "more_body": True})
        await allow_app_to_finish.wait()
        await send({"type": "http.response.body", "body": b"last", "more_body": False})
        app_finished.set()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "http://www.example.org/") as response:
            assert response.status_code == 200
            stream = response.aiter_raw()

            # The first chunk is available even though the application
            # has not completed yet.
            with anyio.fail_after(5):
                chunk = await stream.__anext__()
            assert chunk == b"first"
            assert not app_finished.is_set()

            allow_app_to_finish.set()
            remaining = b""
            async for chunk in stream:
                remaining += chunk
            assert remaining == b"last"

    assert app_finished.is_set()


@pytest.mark.anyio
async def test_asgi_streaming_backpressure():
    sends_completed = 0
    overflow_send_completed = anyio.Event()
    allow_app_to_finish = anyio.Event()

    async def app(scope, receive, send):
        nonlocal sends_completed
        await send({"type": "http.response.start", "status": 200, "headers": []})
        # Fill the buffer, then send one message more than it can hold.
        for _ in range(_MAX_BUFFERED_MESSAGES + 1):
            await send(
                {"type": "http.response.body", "body": b"chunk", "more_body": True}
            )
            sends_completed += 1
        overflow_send_completed.set()
        await allow_app_to_finish.wait()
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "http://www.example.org/") as response:
            # The application fills the buffer, then blocks on send().
            with anyio.fail_after(5):
                while sends_completed < _MAX_BUFFERED_MESSAGES:
                    await anyio.sleep(0.01)
            await anyio.sleep(0.1)
            assert sends_completed == _MAX_BUFFERED_MESSAGES
            assert not overflow_send_completed.is_set()

            # Reading from the response unblocks the application.
            stream = response.aiter_raw()
            assert await stream.__anext__() == b"chunk"
            with anyio.fail_after(5):
                await overflow_send_completed.wait()

            allow_app_to_finish.set()
            async for _chunk in stream:
                pass


@pytest.mark.anyio
async def test_asgi_streaming_early_close_cleans_up_app_task():
    app_exited = anyio.Event()

    async def app(scope, receive, send):
        try:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            while True:
                await send(
                    {"type": "http.response.body", "body": b"chunk", "more_body": True}
                )
        finally:
            app_exited.set()

    transport = httpx.ASGITransport(app=app)
    request = httpx.Request("GET", "http://www.example.org/")
    response = await transport.handle_async_request(request)
    stream = response.stream
    with anyio.fail_after(5):
        assert await stream.__anext__() == b"chunk"

    # Closing the response while the application is still producing
    # the body must stop the application.
    await response.aclose()
    with anyio.fail_after(5):
        await app_exited.wait()

    assert not transport._open_streams


@pytest.mark.anyio
async def test_asgi_streaming_close_without_reading_cleans_up_app_task():
    app_exited = anyio.Event()

    async def app(scope, receive, send):
        try:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            while True:
                await send(
                    {"type": "http.response.body", "body": b"chunk", "more_body": True}
                )
        finally:
            app_exited.set()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "http://www.example.org/") as response:
            assert response.status_code == 200
        # Exiting the context closes the response while the application
        # is still producing the body, which must stop the application.
        with anyio.fail_after(5):
            await app_exited.wait()

    assert not transport._open_streams


@pytest.mark.anyio
async def test_asgi_streaming_client_cancellation_cleans_up_app_task():
    first_chunk_sent = anyio.Event()
    app_exited = anyio.Event()

    async def app(scope, receive, send):
        try:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send(
                {"type": "http.response.body", "body": b"chunk", "more_body": True}
            )
            first_chunk_sent.set()
            await anyio.sleep_forever()
        finally:
            app_exited.set()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        async with anyio.create_task_group() as task_group:

            async def get() -> None:
                await client.get("http://www.example.org/")

            task_group.start_soon(get)
            with anyio.fail_after(5):
                await first_chunk_sent.wait()
            # Give the client a moment to start waiting for the next chunk.
            await anyio.sleep(0.1)
            task_group.cancel_scope.cancel()

        with anyio.fail_after(5):
            await app_exited.wait()

    assert not transport._open_streams


@pytest.mark.anyio
async def test_asgi_transport_aclose_cleans_up_app_task():
    app_exited = anyio.Event()

    async def app(scope, receive, send):
        try:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send(
                {"type": "http.response.body", "body": b"chunk", "more_body": True}
            )
            await anyio.sleep_forever()
        finally:
            app_exited.set()

    transport = httpx.ASGITransport(app=app)
    request = httpx.Request("GET", "http://www.example.org/")
    response = await transport.handle_async_request(request)
    assert response.status_code == 200

    # Closing the transport closes any responses that are still streaming.
    with anyio.fail_after(5):
        await transport.aclose()
    assert app_exited.is_set()
    assert not transport._open_streams


@pytest.mark.anyio
async def test_asgi_head_request():
    app_finished = anyio.Event()

    async def app(scope, receive, send):
        headers = [(b"content-length", b"50")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        for _ in range(10):
            await send(
                {"type": "http.response.body", "body": b"hello", "more_body": True}
            )
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        app_finished.set()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        # The body is dropped, and the application is not blocked sending it.
        with anyio.fail_after(5):
            response = await client.head("http://www.example.org/")
        assert response.status_code == 200
        assert response.content == b""
        assert app_finished.is_set()
