import asyncio

from aiohttp import web


CONNECT_REQUEST = (
    b"CONNECT example.com:443 HTTP/1.1\r\n"
    b"Host: example.com:443\r\n"
    b"X-Auth: ok\r\n\r\n"
)


async def _read_headers(reader):
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b""):
            return


async def test_connect_tunnel_accepted_with_coalesced_first_chunk(
    aiohttp_raw_server,
):
    async def handler(request):
        if request.headers.get("X-Auth") != "ok":
            return web.Response(status=403, text="forbidden")
        tunnel = web.TunnelResponse()
        await tunnel.prepare(request)
        async for chunk in tunnel:
            await tunnel.write(chunk)
        await tunnel.write_eof()
        return tunnel

    server = await aiohttp_raw_server(handler)
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        # First tunnel bytes arrive together with the CONNECT request.
        writer.write(CONNECT_REQUEST + b"hello world")
        status = await reader.readline()
        assert status.rstrip().endswith(b"200")
        headers = await _read_headers(reader)
        assert headers is None
        head = await reader.read(11)
        assert head == b"hello world"
        writer.write_eof()
        assert await reader.read() == b""
    finally:
        writer.close()


async def test_connect_tunnel_rejected_keeps_http_semantics(aiohttp_raw_server):
    async def handler(request):
        return web.Response(status=403, text="forbidden")

    server = await aiohttp_raw_server(handler)
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        bad = CONNECT_REQUEST.replace(b"X-Auth: ok", b"X-Auth: bad")
        writer.write(bad)
        status = await reader.readline()
        assert status.rstrip().endswith(b"403")
        await _read_headers(reader)
        assert await reader.read() == b"forbidden"
    finally:
        writer.close()


async def test_connect_tunnel_independent_eofs(aiohttp_raw_server):
    server_half_closed = asyncio.Event()

    async def handler(request):
        tunnel = web.TunnelResponse()
        await tunnel.prepare(request)
        # Half-close our side first; the client can still send data.
        await tunnel.write_eof()
        server_half_closed.set()
        data = await tunnel.read()
        assert data == b"late"
        return tunnel

    server = await aiohttp_raw_server(handler)
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(CONNECT_REQUEST)
        assert (await reader.readline()).rstrip().endswith(b"200")
        await _read_headers(reader)
        await server_half_closed.wait()
        assert await reader.read() == b""
        writer.write(b"late")
        writer.write_eof()
    finally:
        writer.close()


async def test_connect_tunnel_write_backpressure(aiohttp_raw_server):
    async def handler(request):
        tunnel = web.TunnelResponse()
        await tunnel.prepare(request)
        try:
            while True:
                await tunnel.write(bytes(64 * 1024))
        except (ConnectionError, asyncio.CancelledError):
            pass
        return tunnel

    server = await aiohttp_raw_server(handler)
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(CONNECT_REQUEST)
        assert (await reader.readline()).rstrip().endswith(b"200")
        await _read_headers(reader)
        # The server pumps indefinitely while we never read: the tunnel
        # writer must block on transport backpressure rather than raise.
        await asyncio.sleep(0.3)
        drained = 0
        while drained < 2 * 1024 * 1024:
            drained += len(await reader.read(64 * 1024))
    finally:
        writer.close()


async def test_connect_tunnel_client_disconnect_releases_connection(aiohttp_raw_server):
    accepted = asyncio.Event()

    async def handler(request):
        tunnel = web.TunnelResponse()
        await tunnel.prepare(request)
        accepted.set()
        try:
            await tunnel.read(10)
        except ConnectionError:
            tunnel.close()
        return tunnel

    server = await aiohttp_raw_server(handler)
    assert len(server.runner.server.connections) == 0
    reader, writer = await asyncio.open_connection(server.host, server.port)
    try:
        writer.write(CONNECT_REQUEST)
        assert (await reader.readline()).rstrip().endswith(b"200")
        await _read_headers(reader)
        await accepted.wait()
        assert len(server.runner.server.connections) == 1
    finally:
        writer.close()
    # Give the server a moment to notice and release the connection.
    deadline = asyncio.get_running_loop().time() + 2
    while server.runner.server.connections:
        await asyncio.sleep(0.01)
        assert asyncio.get_running_loop().time() < deadline
