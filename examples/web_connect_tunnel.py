"""Authorized HTTP CONNECT tunnel to a local echo service."""

import asyncio
import os

from aiohttp import web


ALLOWED_TOKEN = os.environ.get("TUNNEL_TOKEN", "secret")


async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        writer.write_eof()
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def copy(
    source: web.TunnelConnection | asyncio.StreamReader,
    destination: web.TunnelConnection | asyncio.StreamWriter,
) -> None:
    while True:
        data = await source.read(65536)
        if not data:
            break
        destination.write(data)
        await destination.drain()
    destination.write_eof()


async def connect(request: web.Request) -> web.TunnelResponse:
    if request.headers.get("X-Tunnel-Token") != ALLOWED_TOKEN:
        raise web.HTTPForbidden(text="authorization required")

    host = request.url.host
    port = request.url.port
    if (
        host not in {"127.0.0.1", "localhost"}
        or port != request.app["echo_port"]
    ):
        raise web.HTTPForbidden(text="only the local echo service is allowed")
    assert host is not None
    assert port is not None

    response = web.TunnelResponse()
    tunnel = await response.prepare(request)

    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except OSError:
        raise web.HTTPBadGateway(text="cannot reach echo service")

    client_to_remote = asyncio.create_task(copy(tunnel, remote_writer))
    remote_to_client = asyncio.create_task(copy(remote_reader, tunnel))
    try:
        await asyncio.gather(
            client_to_remote, remote_to_client, return_exceptions=True
        )
    finally:
        remote_writer.close()
        tunnel.close()
    return response


async def create_app() -> web.Application:
    echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
    echo_port = echo_server.sockets[0].getsockname()[1]

    app = web.Application()
    app["echo_port"] = echo_port
    app["echo_server"] = echo_server
    app.router.add_route("CONNECT", "/{target:.*}", connect)

    async def close_echo(app: web.Application) -> None:
        app["echo_server"].close()
        await app["echo_server"].wait_closed()

    app.on_cleanup.append(close_echo)
    return app


if __name__ == "__main__":
    web.run_app(create_app())
