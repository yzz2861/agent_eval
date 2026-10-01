import asyncio
import contextlib
import socket
from collections.abc import AsyncIterator

import pytest

from aiohttp import web


def _connect_request() -> bytes:
    return b"CONNECT echo.local:4000 HTTP/1.1\r\nHost: echo.local\r\n\r\n"


async def _read_headers(reader: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)


@pytest.fixture
async def tunnel_runner(
    unused_port_socket: socket.socket,
) -> AsyncIterator[tuple[web.AppRunner, int, asyncio.Event]]:
    connected = asyncio.Event()

    async def connect_handler(request: web.Request) -> web.TunnelResponse:
        if request.headers.get("x-allow") != "yes":
            raise web.HTTPForbidden(text="forbidden")

        response = web.TunnelResponse()
        tunnel = await response.prepare(request)
        connected.set()
        while True:
            chunk = await tunnel.readany()
            if not chunk:
                break
            await tunnel.write(chunk)
        await tunnel.write_eof()
        await tunnel.wait_closed()
        return response

    async def second_handler(request: web.Request) -> web.Response:
        return web.Response(text="second-ok")

    app = web.Application()
    app.router.add_route("CONNECT", "/{target:.*}", connect_handler)
    app.router.add_get("/second", second_handler)
    runner = web.AppRunner(app, shutdown_timeout=0.05)
    await runner.setup()
    site = web.SockSite(runner, unused_port_socket)
    await site.start()
    try:
        yield runner, unused_port_socket.getsockname()[1], connected
    finally:
        await runner.cleanup()


async def test_authorized_tunnel_echoes_merged_first_packet(
    tunnel_runner,
) -> None:
    _, port, connected = tunnel_runner
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            b"CONNECT echo.local:4000 HTTP/1.1\r\n"
            b"Host: echo.local\r\n"
            b"X-Allow: yes\r\n\r\n"
            b"first-packet"
        )
        await writer.drain()
        await asyncio.wait_for(connected.wait(), timeout=5)

        headers = await _read_headers(reader)
        assert headers.startswith(b"HTTP/1.1 200 ")
        assert await asyncio.wait_for(reader.read(12), timeout=5) == b"first-packet"

        writer.write(b"second")
        await writer.drain()
        assert await asyncio.wait_for(reader.read(6), timeout=5) == b"second"
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def test_rejected_tunnel_keeps_http_semantics_and_connection(
    tunnel_runner,
) -> None:
    _, port, _ = tunnel_runner
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            b"CONNECT echo.local:4000 HTTP/1.1\r\nHost: echo.local\r\n\r\n"
            b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        await writer.drain()

        error = await _read_headers(reader)
        assert error.startswith(b"HTTP/1.1 403 ")
        assert b"content-length: 9" in error.lower()
        assert await reader.read(9) == b"forbidden"

        second = await _read_headers(reader)
        assert second.startswith(b"HTTP/1.1 200 ")
        body = await asyncio.wait_for(reader.read(9), timeout=5)
        assert body == b"second-ok"
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def test_tunnel_supports_independent_eof(tunnel_runner) -> None:
    _, port, connected = tunnel_runner
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            b"CONNECT echo.local:4000 HTTP/1.1\r\n"
            b"Host: echo.local\r\n"
            b"X-Allow: yes\r\n\r\n"
            b"half-close"
        )
        await writer.drain()
        writer.write_eof()
        await asyncio.wait_for(connected.wait(), timeout=5)

        await _read_headers(reader)
        assert await asyncio.wait_for(reader.read(10), timeout=5) == b"half-close"
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    finally:
        writer.close()


async def test_tunnel_connection_count_and_shutdown(
    unused_port_socket: socket.socket,
) -> None:
    accepted = asyncio.Event()
    release = asyncio.Event()

    async def connect_handler(request: web.Request) -> web.TunnelResponse:
        assert runner.server is not None
        response = web.TunnelResponse()
        tunnel = await response.prepare(request)
        assert request.protocol in runner.server.connections
        accepted.set()
        await release.wait()
        return response

    app = web.Application()
    app.router.add_route("CONNECT", "/{target:.*}", connect_handler)
    runner = web.AppRunner(app, shutdown_timeout=0.05)
    await runner.setup()
    site = web.SockSite(runner, unused_port_socket)
    await site.start()
    port = unused_port_socket.getsockname()[1]
    server = runner.server
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_connect_request())
        await writer.drain()
        await asyncio.wait_for(accepted.wait(), timeout=5)
        assert len(runner.server.connections) == 1
        await _read_headers(reader)

        await runner.cleanup()
        assert server is not None
        assert not server.connections
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()
