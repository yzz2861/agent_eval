import asyncio
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_server import Server
from aiohttp.web_tunnel import TunnelResponse


class FakeTransport:
    def __init__(self, loop, *, eof=True, write_capacity=1024 * 1024):
        self._loop = loop
        self.buffer = bytearray()
        self.closed = False
        self.eof = eof
        self._read_paused = False
        self._write_paused = False
        self._lost = False
        self._write_capacity = write_capacity
        self.protocol = None
        self.write_eof_called = False

    def set_protocol(self, protocol):
        self.protocol = protocol

    def get_protocol(self):
        return self.protocol

    def is_closing(self):
        return self.closed

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.protocol is not None and not self._lost:
            self._lost = True
            self.protocol.connection_lost(None)

    def write(self, data):
        self.buffer.extend(data)
        if self.protocol is not None and not self._write_paused:
            # Pretend the kernel buffer filled after 1 MiB.
            if len(self.buffer) > self._write_capacity:
                self._write_paused = True
                self.protocol.pause_writing()

    def can_write_eof(self):
        return self.eof

    def write_eof(self):
        self.write_eof_called = True

    def is_reading(self):
        return not self._read_paused

    def pause_reading(self):
        self._read_paused = True

    def resume_reading(self):
        self._read_paused = False

    def pause_writing(self):
        self._write_paused = True
        if self.protocol is not None:
            self.protocol.pause_writing()

    def resume_writing(self):
        self._write_paused = False
        if self.protocol is not None and self.protocol.writing_paused:
            self.protocol.resume_writing()

    def clear(self):
        self.buffer.clear()
        self._write_paused = False
        self._write_capacity = 10**9

    def abort(self):
        self.close()

    def get_extra_info(self, name, default=None):
        return default


CONNECT = (
    b"CONNECT example.com:443 HTTP/1.1\r\n"
    b"Host: example.com:443\r\n\r\n"
)


def _make_server(handler):
    return Server(handler)


@pytest.fixture
async def protocol():
    async def handler(request):
        raise AssertionError("should be replaced per test")

    loop = asyncio.get_running_loop()
    server = Server(handler)
    proto = RequestHandler(server, loop=loop)
    transport = FakeTransport(loop)
    transport.set_protocol(proto)
    proto.connection_made(transport)
    yield proto, transport
    proto.connection_lost(ConnectionResetError())


async def test_prepare_responds_and_delivers_coalesced_bytes(protocol):
    proto, transport = protocol
    captured = {}

    async def handler(request):
        tunnel = TunnelResponse()
        await tunnel.prepare(request)
        captured["tunnel"] = tunnel
        first = await tunnel.read(5)
        assert first == b"hello"
        rest = await tunnel.read()
        await tunnel.write(b"ack:" + first + rest)
        await tunnel.wait_eof()
        await tunnel.write_eof()
        return tunnel

    proto._request_handler = handler
    proto.data_received(CONNECT + b"hello world")
    proto.eof_received()
    await asyncio.wait_for(proto._task_handler, timeout=2)
    response = bytes(transport.buffer)
    head, _, body = response.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200")
    assert b"content-length" not in head.lower()
    assert body == b"ack:hello world"
    assert transport.write_eof_called
    captured["tunnel"].close()


async def test_rejected_connect_is_plain_http_and_closes(protocol):
    proto, transport = protocol

    async def handler(request):
        return web.Response(status=403, text="nope")

    proto._request_handler = handler
    proto.data_received(CONNECT)
    await asyncio.wait_for(proto._task_handler, timeout=2)
    response = bytes(transport.buffer)
    assert response.startswith(b"HTTP/1.1 403")
    assert response.endswith(b"nope")
    assert transport.closed


async def test_backpressure_pauses_tunnel_write(protocol):
    proto, transport = protocol
    transport._write_capacity = 256 * 1024
    finished = asyncio.Event()

    async def handler(request):
        tunnel = TunnelResponse()
        await tunnel.prepare(request)
        count = 0
        while count < 32:
            await tunnel.write(b"x" * 128 * 1024)
            count += 1
        finished.set()
        tunnel.close()
        return tunnel

    proto._request_handler = handler
    proto.data_received(CONNECT)
    proto.eof_received()
    deadline = asyncio.get_running_loop().time() + 2
    while not proto.writing_paused:
        assert asyncio.get_running_loop().time() < deadline
        await asyncio.sleep(0.01)
    transport.clear()
    proto.resume_writing()
    await asyncio.wait_for(finished.wait(), timeout=2)
    await asyncio.wait_for(proto._task_handler, timeout=2)


async def test_prepare_rejects_non_connect():
    from aiohttp.test_utils import make_mocked_request

    request = make_mocked_request("GET", "/")
    tunnel = TunnelResponse()
    with pytest.raises(web.HTTPBadRequest):
        await tunnel.prepare(request)


async def test_connect_authority_form_routes_to_root():
    from aiohttp.test_utils import make_mocked_request
    from yarl import URL

    async def handler(request):
        return web.Response()

    app = web.Application()
    app.router.add_route("CONNECT", "/", handler)

    message_url = URL.build(authority="example.com:443", encoded=True)
    request = make_mocked_request(
        "CONNECT",
        str(message_url),
        {"Host": "example.com:443"},
        app=app,
    )
    assert request.rel_url.path_safe == ""
    match_info = await app.router.resolve(request)
    assert match_info.route.resource.canonical == "/"


async def test_connection_counted_and_released():
    async def handler(request):
        return web.Response()

    server = Server(handler)
    loop = asyncio.get_running_loop()
    proto = RequestHandler(server, loop=loop)
    transport = FakeTransport(loop)
    transport.set_protocol(proto)
    proto.connection_made(transport)
    assert proto in server.connections
    proto.connection_lost(None)
    for _ in range(5):
        if proto not in server.connections:
            break
        await asyncio.sleep(0)
    assert proto not in server.connections


async def test_rejected_connect_does_not_poison_followup(protocol):
    # A rejected CONNECT closes its connection; normal HTTP handling on a
    # fresh connection still works and stays keep-alive.
    async def handler(request):
        if request.method == "CONNECT":
            return web.Response(status=403)
        return web.Response(text="ok")

    loop = asyncio.get_running_loop()
    server = Server(handler)
    proto = RequestHandler(server, loop=loop)
    transport = FakeTransport(loop)
    transport.set_protocol(proto)
    proto.connection_made(transport)

    proto.data_received(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    await asyncio.sleep(0.05)
    response = bytes(transport.buffer)
    assert response.startswith(b"HTTP/1.1 200")
    assert not transport.closed
    proto.connection_lost(None)


async def test_shutdown_cancels_active_tunnel():
    entered = asyncio.Event()

    async def handler(request):
        tunnel = TunnelResponse()
        await tunnel.prepare(request)
        entered.set()
        with pytest.raises(asyncio.CancelledError):
            await tunnel.read()

    loop = asyncio.get_running_loop()
    server = Server(handler, handler_cancellation=True)
    proto = RequestHandler(server, loop=loop)
    transport = FakeTransport(loop)
    transport.set_protocol(proto)
    proto.connection_made(transport)
    proto.data_received(CONNECT)
    await entered.wait()
    await proto.shutdown(timeout=1)
    assert proto._task_handler is None or proto._task_handler.cancelled()


async def test_websocket_set_parser_does_not_consume_pending_eof():
    # Regression: a bare FIN buffered before the upgrade is handed to the
    # tunnel parser but never to a WebSocket frame queue.
    from aiohttp.web_protocol import RequestHandler
    from aiohttp.web_server import Server

    async def handler(request):
        return web.Response()

    server = Server(handler)
    proto = RequestHandler(server, loop=asyncio.get_running_loop())
    ws_parser = mock.Mock()
    ws_parser.feed_data.return_value = (False, b"")
    proto._pending_eof = True
    proto.set_parser(ws_parser)
    ws_parser.feed_eof.assert_not_called()
