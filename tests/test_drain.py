from __future__ import annotations

import asyncio
from typing import Any

import pytest
import websockets
from websockets.exceptions import ConnectionClosed

from uvicorn._types import ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.config import Config
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol
from uvicorn.server import Server

pytestmark = pytest.mark.anyio

HTTP_PROTOCOLS = [H11Protocol, HttpToolsProtocol]

SLOW_PARTS = [b"part-0;", b"part-1;", b"part-2;", b"part-3;"]
SLOW_BODY = b"".join(SLOW_PARTS)

WS_HANDSHAKE_REQUEST = (
    b"GET /ws HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)


class DrainApp:
    def __init__(self) -> None:
        self.http_calls: list[str] = []
        self.lifespan_shutdowns = 0
        self.cancelled = False

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            await self.lifespan(scope, receive, send)
        elif scope["type"] == "http":
            await self.http(scope, receive, send)
        elif scope["type"] == "websocket":
            await self.websocket(scope, receive, send)

    async def lifespan(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                self.lifespan_shutdowns += 1
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def http(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        self.http_calls.append(scope["path"])
        if scope["path"] == "/slow":
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/plain"), (b"content-length", str(len(SLOW_BODY)).encode())],
                }
            )
            for part in SLOW_PARTS:
                await send({"type": "http.response.body", "body": part, "more_body": True})
                await asyncio.sleep(0.1)
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        elif scope["path"] == "/hang":
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        else:
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
            await send({"type": "http.response.body", "body": b"ok"})

    async def websocket(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        message = await receive()
        assert message["type"] == "websocket.connect"
        await send({"type": "websocket.accept"})
        while True:
            message = await receive()
            if message["type"] == "websocket.disconnect":
                return


async def start_server(app: DrainApp, port: int, **kwargs: Any) -> tuple[Server, asyncio.Task[None]]:
    config = Config(app=app, host="127.0.0.1", port=port, loop="asyncio", **kwargs)
    server = Server(config)
    serve_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    return server, serve_task


async def stop_server(server: Server, serve_task: asyncio.Task[None]) -> None:
    server.should_exit = True
    await asyncio.wait_for(serve_task, timeout=5)


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS)
async def test_drain_completes_in_flight_response_and_rejects_new_requests(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
) -> None:
    app = DrainApp()
    server, serve_task = await start_server(app, unused_tcp_port, http=http_protocol_cls)

    # Start a slow streaming response over a real loopback connection.
    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(b"GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    head = await reader.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200")
    first = await reader.readexactly(len(SLOW_PARTS[0]))
    assert first == SLOW_PARTS[0]

    # Enter the drain state mid-stream.
    drain_task = asyncio.create_task(server.drain(timeout=5))
    await asyncio.sleep(0.05)
    assert server.draining
    assert not server.drained

    # The in-flight streaming response runs to completion.
    rest = await reader.readexactly(len(SLOW_BODY) - len(SLOW_PARTS[0]))
    assert rest == b"".join(SLOW_PARTS[1:])

    await asyncio.wait_for(drain_task, timeout=5)
    assert server.drained
    assert app.http_calls == ["/slow"]
    assert app.lifespan_shutdowns == 1

    # The next request on the same keep-alive connection is rejected
    # without giving the application a chance to run.
    writer.write(b"GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    head = await reader.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 503")
    assert b"connection: close" in head.lower()
    body = await reader.readexactly(len(b"Service Unavailable"))
    assert body == b"Service Unavailable"
    assert await reader.read() == b""  # The server closes the connection.
    writer.close()

    # Requests on new connections are rejected as well.
    reader2, writer2 = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer2.write(b"GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    head = await reader2.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 503")
    writer2.close()
    assert app.http_calls == ["/slow"]

    # The caller decides when to exit. Lifespan shutdown ran only once.
    await stop_server(server, serve_task)
    assert app.lifespan_shutdowns == 1


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS)
async def test_drain_is_idempotent(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
) -> None:
    app = DrainApp()
    server, serve_task = await start_server(app, unused_tcp_port, http=http_protocol_cls)

    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(b"GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    await reader.readuntil(b"\r\n\r\n")

    # Repeated triggers await the same cleanup flow instead of starting new ones.
    await asyncio.gather(server.drain(timeout=5), server.drain(), server.drain())
    assert server.drained
    assert app.lifespan_shutdowns == 1

    writer.close()
    await stop_server(server, serve_task)
    assert app.lifespan_shutdowns == 1


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS)
async def test_drain_timeout_cancels_in_flight_work(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
) -> None:
    app = DrainApp()
    server, serve_task = await start_server(app, unused_tcp_port, http=http_protocol_cls)

    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(b"GET /hang HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    await asyncio.sleep(0.1)
    assert app.http_calls == ["/hang"]

    # The drain deadline is hit, and the remaining work is cancelled.
    await asyncio.wait_for(server.drain(timeout=0.2), timeout=5)
    assert server.drained
    await asyncio.sleep(0.1)
    assert app.cancelled
    assert app.lifespan_shutdowns == 1

    writer.close()
    await stop_server(server, serve_task)
    assert app.lifespan_shutdowns == 1


@pytest.mark.parametrize("http_protocol_cls", HTTP_PROTOCOLS)
async def test_drain_rejects_websocket_handshake(
    http_protocol_cls: type[H11Protocol | HttpToolsProtocol], unused_tcp_port: int
) -> None:
    app = DrainApp()
    server, serve_task = await start_server(app, unused_tcp_port, http=http_protocol_cls)

    drain_task = asyncio.create_task(server.drain(timeout=5))
    await asyncio.sleep(0.1)
    assert server.draining

    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(WS_HANDSHAKE_REQUEST)
    head = await reader.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 503")
    writer.close()

    await drain_task
    await stop_server(server, serve_task)


async def test_drain_closes_established_websocket(unused_tcp_port: int) -> None:
    app = DrainApp()
    server, serve_task = await start_server(app, unused_tcp_port)

    async with websockets.connect(f"ws://127.0.0.1:{unused_tcp_port}/ws") as ws:
        drain_task = asyncio.create_task(server.drain(timeout=5))
        # The established connection is closed with a 1012 (service restart) close code.
        with pytest.raises(ConnectionClosed):
            async for _ in ws:
                pass  # pragma: no cover
        assert ws.close_code == 1012

    await drain_task
    assert server.drained
    await stop_server(server, serve_task)


async def test_shutdown_without_drain_still_works(unused_tcp_port: int) -> None:
    app = DrainApp()
    server, serve_task = await start_server(app, unused_tcp_port)

    reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
    writer.write(b"GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    head = await reader.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200")
    writer.close()

    assert not server.draining
    await stop_server(server, serve_task)
    assert app.lifespan_shutdowns == 1
