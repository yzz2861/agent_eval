from __future__ import annotations

import asyncio
import logging

import pytest
import websockets.exceptions
from websockets.asyncio.client import connect

from tests.protocols.test_http import (
    SIMPLE_GET_REQUEST,
    UPGRADE_REQUEST,
    MockLoop,
    MockTransport,
    get_connected_protocol,
)
from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.server import Server, ServerState

pytestmark = pytest.mark.anyio

HTTP_PROTOCOLS = [pytest.param(H11Protocol, id="h11"), pytest.param(HttpToolsProtocol, id="httptools")]


class DrainDemoApp:
    """ASGI app with a slow streaming endpoint and lifespan accounting."""

    def __init__(self, slow_chunks: tuple[bytes, ...] = (b"chunk-1|", b"chunk-2|", b"chunk-3|")) -> None:
        self.http_paths: list[str] = []
        self.lifespan_shutdowns = 0
        self.request_started = asyncio.Event()
        self.slow_chunks = slow_chunks

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    self.lifespan_shutdowns += 1
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        elif scope["type"] == "http":
            self.http_paths.append(scope["path"])
            self.request_started.set()
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
            if scope["path"] == "/slow":
                for chunk in self.slow_chunks:
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                    await asyncio.sleep(0.1)
            elif scope["path"] == "/hang":
                await asyncio.Event().wait()  # never finishes
            await send({"type": "http.response.body", "body": b"done", "more_body": False})


async def start_server(config: Config) -> tuple[Server, asyncio.Task[None]]:
    server = Server(config=config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, task


@pytest.mark.parametrize("http_protocol", HTTP_PROTOCOLS)
async def test_drain_completes_in_flight_and_rejects_new_requests(
    http_protocol: type[H11Protocol | HttpToolsProtocol],
    unused_tcp_port: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A slow streaming response finishes while draining; later requests never reach the app."""
    caplog.set_level(logging.INFO, logger="uvicorn.error")
    app = DrainDemoApp()
    config = Config(app=app, host="127.0.0.1", port=unused_tcp_port, http=http_protocol, loop="asyncio")
    server, serve_task = await start_server(config)
    assert not server.draining

    # Start a slow streaming request on a real loopback connection.
    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(b"GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    await writer.drain()
    await asyncio.wait_for(app.request_started.wait(), timeout=5)

    # Enter drain mid-stream. Repeated triggers share one cleanup flow.
    drain_task = asyncio.create_task(server.drain(timeout=10))
    while not server.draining:
        await asyncio.sleep(0.01)
    duplicate_drain = asyncio.create_task(server.drain())

    # The in-flight response completes in full, then the connection is
    # closed instead of being kept alive.
    body = await asyncio.wait_for(reader.read(), timeout=5)
    for chunk in (b"chunk-1|", b"chunk-2|", b"chunk-3|", b"done"):
        assert chunk in body

    await asyncio.wait_for(drain_task, timeout=5)
    await duplicate_drain
    assert caplog.text.count("Draining server") == 1

    # New connections are refused: the listener has been closed.
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection("127.0.0.1", unused_tcp_port)

    # The application only ever saw the in-flight request.
    assert app.http_paths == ["/slow"]

    # Draining did not run the lifespan shutdown; the caller decides when to exit.
    assert app.lifespan_shutdowns == 0
    server.should_exit = True
    await asyncio.wait_for(serve_task, timeout=5)
    assert app.lifespan_shutdowns == 1

    # Shutting down again does not run the lifespan shutdown twice.
    await server.shutdown()
    assert app.lifespan_shutdowns == 1
    writer.close()


@pytest.mark.parametrize("http_protocol", HTTP_PROTOCOLS)
async def test_drain_timeout_cancels_in_flight_tasks(
    http_protocol: type[H11Protocol | HttpToolsProtocol],
    unused_tcp_port: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Once the drain deadline is reached, remaining work is cancelled."""
    app = DrainDemoApp()
    config = Config(
        app=app,
        host="127.0.0.1",
        port=unused_tcp_port,
        http=http_protocol,
        loop="asyncio",
        timeout_graceful_shutdown=5,
    )
    server, serve_task = await start_server(config)

    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(b"GET /hang HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    await writer.drain()
    await asyncio.wait_for(app.request_started.wait(), timeout=5)

    await server.drain(timeout=0.2)
    assert "drain timeout exceeded" in caplog.text

    # The server is still up to the caller; a normal exit still works.
    writer.close()
    server.should_exit = True
    await asyncio.wait_for(serve_task, timeout=10)
    assert app.lifespan_shutdowns == 1


@pytest.mark.parametrize("http_protocol", HTTP_PROTOCOLS)
async def test_drain_closes_established_websockets(
    http_protocol: type[H11Protocol | HttpToolsProtocol],
    ws_protocol_cls: type,
    unused_tcp_port: int,
) -> None:
    """Established WebSockets are closed with 1012 (service restart) on drain."""
    connected = asyncio.Event()

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        elif scope["type"] == "websocket":
            await receive()  # websocket.connect
            await send({"type": "websocket.accept"})
            connected.set()
            while True:
                message = await receive()
                if message["type"] == "websocket.disconnect":
                    return

    config = Config(
        app=app,
        host="127.0.0.1",
        port=unused_tcp_port,
        http=http_protocol,
        ws=ws_protocol_cls,
        loop="asyncio",
    )
    server, serve_task = await start_server(config)

    async with connect(f"ws://127.0.0.1:{unused_tcp_port}") as websocket:
        await asyncio.wait_for(connected.wait(), timeout=5)
        drain_task = asyncio.create_task(server.drain(timeout=5))
        with pytest.raises(websockets.exceptions.ConnectionClosed) as exc_info:
            await websocket.recv()
        assert exc_info.value.rcvd is not None
        assert exc_info.value.rcvd.code == 1012
        await asyncio.wait_for(drain_task, timeout=5)

    server.should_exit = True
    await asyncio.wait_for(serve_task, timeout=5)


@pytest.mark.parametrize("http_protocol", HTTP_PROTOCOLS)
async def test_keep_alive_next_request_rejected_while_draining(
    http_protocol: type[H11Protocol | HttpToolsProtocol],
) -> None:
    """The next request on an existing keep-alive connection gets a 503, not the app."""
    calls = 0

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        nonlocal calls
        calls += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    protocol = get_connected_protocol(app, http_protocol)
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()
    assert b"HTTP/1.1 200 OK" in protocol.transport.buffer
    assert calls == 1

    protocol.server_state.draining = True
    protocol.transport.clear_buffer()
    protocol.data_received(SIMPLE_GET_REQUEST)
    await protocol.loop.run_one()
    assert b"HTTP/1.1 503 Service Unavailable" in protocol.transport.buffer
    assert b"connection: close" in protocol.transport.buffer
    assert protocol.transport.closed
    assert calls == 1


@pytest.mark.parametrize("http_protocol", HTTP_PROTOCOLS)
async def test_websocket_handshake_rejected_while_draining(
    http_protocol: type[H11Protocol | HttpToolsProtocol],
) -> None:
    """A WebSocket handshake arriving during drain gets a 503, not an upgrade."""
    pytest.importorskip("wsproto")
    calls = 0

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        nonlocal calls
        calls += 1

    protocol = get_connected_protocol(app, http_protocol, ws="wsproto")
    protocol.server_state.draining = True
    protocol.data_received(UPGRADE_REQUEST)
    await protocol.loop.run_one()
    assert b"HTTP/1.1 503 Service Unavailable" in protocol.transport.buffer
    assert calls == 0


@pytest.mark.parametrize("http_protocol", HTTP_PROTOCOLS)
async def test_new_connection_closed_while_draining(
    http_protocol: type[H11Protocol | HttpToolsProtocol],
) -> None:
    """Connections that race the listener close are rejected on arrival."""

    async def app(scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:  # pragma: no cover
        pass

    config = Config(app=app)
    server_state = ServerState()
    server_state.draining = True
    loop = MockLoop()
    transport = MockTransport()
    protocol = http_protocol(config=config, server_state=server_state, app_state={}, _loop=loop)  # type: ignore[arg-type]
    protocol.connection_made(transport)  # type: ignore[arg-type]
    assert transport.closed
