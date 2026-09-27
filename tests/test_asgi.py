import json

import anyio
import pytest
import sniffio

import httpx


def background_task_count() -> int:
    if sniffio.current_async_library() == "trio":
        import trio

        return trio.lowlevel.current_statistics().tasks_living

    import asyncio

    return len(asyncio.all_tasks())


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


@pytest.mark.anyio
async def test_asgi_streaming_response():
    """
    The response is returned as soon as the response headers arrive,
    with the body streaming as the application produces it.
    """
    first_chunk_sent = anyio.Event()
    allow_app_to_complete = anyio.Event()
    app_completed = anyio.Event()

    async def streaming_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"Hello", "more_body": True})
        first_chunk_sent.set()
        await allow_app_to_complete.wait()
        await send(
            {"type": "http.response.body", "body": b", World!", "more_body": False}
        )
        app_completed.set()

    transport = httpx.ASGITransport(app=streaming_app)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "http://www.example.org/") as response:
            assert response.status_code == 200

            # The first body chunk arrives before the app has completed.
            await first_chunk_sent.wait()
            assert not app_completed.is_set()

            stream = response.aiter_bytes()
            chunk = await stream.__anext__()
            assert chunk == b"Hello"
            assert not app_completed.is_set()

            allow_app_to_complete.set()
            chunks = [part async for part in stream]
            assert chunks == [b", World!"]
            await app_completed.wait()


@pytest.mark.anyio
async def test_asgi_streaming_backpressure():
    """
    If the client is slow to consume the response body then the
    application blocks on send() once the buffer is full.
    """
    sent = [anyio.Event() for _ in range(4)]

    async def streaming_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        for index in range(4):
            await send(
                {
                    "type": "http.response.body",
                    "body": bytes(2048),
                    "more_body": True,
                }
            )
            sent[index].set()
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    transport = httpx.ASGITransport(app=streaming_app, max_buffer_bytes=4096)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "http://www.example.org/") as response:
            # The first two chunks fill the buffer, and then the
            # application blocks, since nothing has been read yet.
            await sent[0].wait()
            await sent[1].wait()
            with anyio.move_on_after(0.1):
                await sent[2].wait()
            assert not sent[2].is_set()

            # Reading from the response allows the application to continue.
            stream = response.aiter_bytes()
            chunk = await stream.__anext__()
            assert len(chunk) == 2048
            await sent[2].wait()
            with anyio.move_on_after(0.1):
                await sent[3].wait()
            assert not sent[3].is_set()

            # Read the remaining chunks, allowing the app to complete.
            chunks = [chunk]
            async for chunk in stream:
                chunks.append(chunk)
            assert chunks == [bytes(2048)] * 4


@pytest.mark.anyio
async def test_asgi_streaming_early_close():
    """
    Closing the response stream early ends the background task
    running the application, leaving no tasks behind.
    """
    app_finished = anyio.Event()

    async def streaming_app(scope, receive, send):
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            while True:
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"x" * 1024,
                        "more_body": True,
                    }
                )
        finally:
            app_finished.set()

    baseline_tasks = background_task_count()
    transport = httpx.ASGITransport(app=streaming_app, max_buffer_bytes=1024)
    request = httpx.Request("GET", "http://www.example.org/")
    response = await transport.handle_async_request(request)
    assert response.status_code == 200

    # Read a single chunk, then close the response.
    stream = response.stream
    assert isinstance(stream, httpx.AsyncByteStream)
    chunk = await stream.__aiter__().__anext__()
    assert chunk == b"x" * 1024
    await response.aclose()

    assert app_finished.is_set()
    assert background_task_count() == baseline_tasks


@pytest.mark.anyio
async def test_asgi_head_response():
    """
    HEAD responses discard any body sent by the application,
    without blocking the application.
    """
    app_completed = anyio.Event()

    async def streaming_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        for _ in range(100):
            await send(
                {
                    "type": "http.response.body",
                    "body": b"x" * 1024,
                    "more_body": True,
                }
            )
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        app_completed.set()

    # A tiny buffer is used, so that the application would block if the
    # body of the HEAD response was not being discarded.
    transport = httpx.ASGITransport(app=streaming_app, max_buffer_bytes=1024)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.head("http://www.example.org/")

    assert response.status_code == 200
    assert response.content == b""
    assert app_completed.is_set()


@pytest.mark.anyio
async def test_asgi_request_cancellation():
    """
    Cancelling the request ends the background task running the application.
    """
    app_started = anyio.Event()
    app_finished = anyio.Event()

    async def streaming_app(scope, receive, send):
        try:
            app_started.set()
            await anyio.sleep_forever()
        finally:
            app_finished.set()

    transport = httpx.ASGITransport(app=streaming_app)
    async with httpx.AsyncClient(transport=transport) as client:
        with anyio.move_on_after(0.5):
            await client.get("http://www.example.org/")

    assert app_started.is_set()
    assert app_finished.is_set()


@pytest.mark.anyio
async def test_asgi_transport_aclose():
    """
    Closing the transport ends any background tasks running the application.
    """
    app_finished = anyio.Event()

    async def streaming_app(scope, receive, send):
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain")],
                }
            )
            await send(
                {"type": "http.response.body", "body": b"Hello", "more_body": True}
            )
            await anyio.sleep_forever()
        finally:
            app_finished.set()

    transport = httpx.ASGITransport(app=streaming_app)
    request = httpx.Request("GET", "http://www.example.org/")
    response = await transport.handle_async_request(request)
    assert response.status_code == 200

    await transport.aclose()
    assert app_finished.is_set()


@pytest.mark.anyio
async def test_asgi_exc_after_response_streaming():
    """
    An exception raised by the application after the response has
    started propagates to the client while streaming the body.
    """

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"Hello", "more_body": True})
        raise RuntimeError()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "http://www.example.org/") as response:
            assert response.status_code == 200
            stream = response.aiter_bytes()
            assert await stream.__anext__() == b"Hello"
            with pytest.raises(RuntimeError):
                async for _ in stream:
                    pass


@pytest.mark.anyio
async def test_asgi_exc_after_response_no_raise():
    """
    With raise_app_exceptions=False, an exception raised by the application
    after the response has started truncates the response body.
    """

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"Hello", "more_body": True})
        raise RuntimeError()

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("http://www.example.org/")

    assert response.status_code == 200
    assert response.content == b"Hello"
