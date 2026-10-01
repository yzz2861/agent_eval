"""Local HTTP CONNECT tunnel that authorizes requests and echoes bytes.

Run::

    python examples/connect_tunnel_echo.py

Then, in another shell, exercise an accepted tunnel (the request's first
data bytes are sent together with the CONNECT headers)::

    printf 'CONNECT local:1080 HTTP/1.1\r\nHost: local:1080\r\nX-Auth: ok\r\n\r\nhello' | nc 127.0.0.1 1080

A missing or wrong ``X-Auth`` header gets a normal ``403`` response::

    printf 'CONNECT local:1080 HTTP/1.1\r\nHost: local:1080\r\n\r\n' | nc 127.0.0.1 1080

The handler demonstrates independent EOFs: the client half-closes with its
FIN, echoed data is fully drained, and only then does the server half-close.
It never dials ``request.rel_url``; choosing and connecting to the upstream
authority is the application's responsibility.
"""

from aiohttp import web


async def connect_echo(request: web.Request) -> web.StreamResponse:
    if request.headers.get("X-Auth") != "ok":
        # Rejecting with a normal response keeps regular HTTP semantics.
        return web.Response(status=403, text="proxy authorization required\n")

    tunnel = web.TunnelResponse()
    await tunnel.prepare(request)
    try:
        async for chunk in tunnel:
            await tunnel.write(chunk)
    except ConnectionError:
        tunnel.close()
        return tunnel
    await tunnel.write_eof()
    return tunnel


def make_app() -> web.Application:
    app = web.Application()
    app.router.add_route("CONNECT", "/", connect_echo)
    return app


if __name__ == "__main__":
    web.run_app(make_app(), host="127.0.0.1", port=1080)
