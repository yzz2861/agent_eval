import asyncio
from contextlib import suppress
from unittest import mock

import pytest

from aiohttp import hdrs
from aiohttp import web
from aiohttp.http import StreamWriter, WebSocketReader
from aiohttp.streams import StreamReader
from aiohttp.web_protocol import RequestHandler
from aiohttp.web_request import BaseRequest
from aiohttp.web_server import Server


@pytest.fixture
def dummy_manager() -> Server[BaseRequest]:
    return mock.create_autospec(Server[BaseRequest], request_handler=mock.Mock(), request_factory=mock.Mock(), instance=True)  # type: ignore[no-any-return]


@pytest.fixture
def dummy_reader() -> tuple[WebSocketReader, mock.Mock]:
    m = mock.create_autospec(WebSocketReader, spec_set=True, instance=True)
    m.feed_data.return_value = False, b""
    return m, m


def test_set_parser_does_not_call_data_received_cb_for_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler._message_tail = b"tail"
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)

    cb.assert_not_called()
    dummy_reader[1].feed_data.assert_called_once_with(b"tail")


def test_data_received_calls_data_received_cb(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    handler = RequestHandler(dummy_manager, loop=event_loop)
    cb = mock.Mock()

    handler.set_parser(dummy_reader[0], data_received_cb=cb)
    handler.data_received(b"x")

    cb.assert_called_once()
    dummy_reader[1].feed_data.assert_called_once_with(b"x")


class _FakeTunnelTransport(asyncio.Transport):
    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False
        self.read_paused = False
        self.eof_written = False

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    def writelines(self, data: list[bytes]) -> None:
        for chunk in data:
            self.write(chunk)

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def pause_reading(self) -> None:
        self.read_paused = True
        self.paused = True

    def resume_reading(self) -> None:
        self.read_paused = False
        self.paused = False

    def write_eof(self) -> None:
        self.eof_written = True

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default


async def test_connect_tunnel_acceptance_preserves_merged_tail() -> None:
    accepted = asyncio.Event()

    async def handler(request: web.Request) -> web.TunnelResponse:
        response = web.TunnelResponse()
        tunnel = await response.prepare(request)
        accepted.set()
        first = await tunnel.readany()
        await tunnel.write(first)
        await tunnel.write_eof()
        return response

    manager = Server(handler)
    proto = RequestHandler(
        manager, loop=asyncio.get_running_loop(), access_log=None
    )
    transport = _FakeTunnelTransport()
    proto.connection_made(transport)
    proto.data_received(
        b"CONNECT echo.local:4000 HTTP/1.1\r\nHost: echo.local\r\n\r\nabc"
    )
    await asyncio.wait_for(accepted.wait(), timeout=5)
    proto.eof_received()
    for _ in range(100):
        if transport.closed:
            break
        await asyncio.sleep(0)
    assert b"HTTP/1.1 200" in transport.written
    assert transport.written.endswith(b"abc")
    assert transport.eof_written


async def test_connect_tunnel_rejection_replays_tail_as_http() -> None:
    async def handler(request: web.Request) -> web.StreamResponse:
        if request.method == hdrs.METH_CONNECT:
            return web.Response(status=403, text="no")
        return web.Response(text="ok")

    manager = Server(handler)
    proto = RequestHandler(
        manager, loop=asyncio.get_running_loop(), access_log=None
    )
    transport = _FakeTunnelTransport()
    proto.connection_made(transport)
    try:
        proto.data_received(
            b"CONNECT echo.local:4000 HTTP/1.1\r\nHost: echo.local\r\n\r\n"
            b"GET / HTTP/1.1\r\nHost: echo.local\r\n\r\n"
        )
        for _ in range(100):
            if b"HTTP/1.1 200" in transport.written:
                break
            await asyncio.sleep(0)
        assert b"HTTP/1.1 403" in transport.written
        assert b"HTTP/1.1 200" in transport.written
    finally:
        with suppress(Exception):
            proto.connection_lost(None)


async def test_connect_tunnel_read_backpressure() -> None:
    accepted = asyncio.Event()

    async def handler(request: web.Request) -> web.TunnelResponse:
        response = web.TunnelResponse()
        tunnel = await response.prepare(request)
        accepted.set()
        await tunnel.read()
        return response

    manager = Server(handler)
    proto = RequestHandler(
        manager,
        loop=asyncio.get_running_loop(),
        access_log=None,
        read_bufsize=64,
    )
    transport = _FakeTunnelTransport()
    proto.connection_made(transport)
    proto.data_received(
        b"CONNECT echo.local:4000 HTTP/1.1\r\nHost: echo\r\n\r\n"
    )
    await accepted.wait()

    proto.data_received(b"x" * 200)
    assert transport.read_paused
    data = await proto._payload_parser.payload.read(200)
    assert data == b"x" * 200
    assert not transport.read_paused


async def test_connect_tunnel_write_backpressure() -> None:
    manager = Server(mock.AsyncMock())
    proto = RequestHandler(
        manager, loop=asyncio.get_running_loop(), access_log=None
    )
    transport = _FakeTunnelTransport()
    proto.connection_made(transport)
    writer = StreamWriter(proto, asyncio.get_running_loop())
    reader = StreamReader(proto, limit=64, loop=asyncio.get_running_loop())
    tunnel = web.TunnelConnection(reader, writer)
    proto.pause_writing()

    write = asyncio.ensure_future(tunnel.write(b"x" * 70000))
    await asyncio.sleep(0)
    assert not write.done()
    proto.resume_writing()
    await asyncio.wait_for(write, timeout=5)
    assert transport.written.endswith(b"x" * 70000)

    await tunnel.write_eof()
    assert transport.eof_written


def test_pause_reading_for_buffer_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Pausing with no transport still records the paused state."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None

    handler._pause_reading_for_buffer()

    assert handler._buffer_paused is True


def test_resume_reading_if_drained_after_upgrade_skips_reparse(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume after an upgrade clears the pause and resumes without reparsing."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._reading_paused = False

    with mock.patch.object(RequestHandler, "data_received") as data_received:
        handler._resume_reading_if_drained()

    data_received.assert_not_called()
    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_if_drained_without_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume clears the pause but does not touch a missing transport."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    handler.transport = None
    handler._upgraded = True  # skip the reparse branch
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False


def test_resume_reading_if_drained_stays_paused_for_full_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Resume is refused while an in-flight upgrade holds read_bufsize of tail.

    The tail is drained by set_parser()/finish_response(), so resuming before
    then would let the buffer grow past its ceiling one read at a time.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1024

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is True
    transport.resume_reading.assert_not_called()


def test_resume_reading_if_drained_with_room_left_in_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A tail under read_bufsize does not hold the transport paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1023

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_if_drained_with_zero_read_bufsize(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """An empty tail resumes even when read_bufsize leaves it no room.

    Guards the degenerate ``read_bufsize=0`` case: comparing sizes alone would
    match an empty tail and wedge the connection paused for good.
    """
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=0)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_set_parser_resumes_reading_paused_for_tail(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
    dummy_reader: tuple[WebSocketReader, mock.Mock],
) -> None:
    """Handing a full tail to the upgraded protocol resumes reading."""
    handler = RequestHandler(dummy_manager, loop=event_loop, read_bufsize=1024)
    transport = mock.create_autospec(asyncio.Transport, spec_set=True, instance=True)
    handler.transport = transport
    handler._upgraded = True
    handler._buffer_paused = True
    handler._message_tail = b"x" * 1024

    handler.set_parser(dummy_reader[0])

    dummy_reader[1].feed_data.assert_called_once_with(b"x" * 1024)
    assert handler._message_tail == b""
    assert handler._buffer_paused is False
    transport.resume_reading.assert_called_once_with()


def test_resume_reading_stays_paused_for_msg_queue(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """Base resume_reading must not un-pause the transport while queue-paused."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    transport = mock.Mock()
    handler.transport = transport
    handler._buffer_paused = True

    handler.resume_reading()

    transport.resume_reading.assert_not_called()


def test_pause_reading_for_buffer_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on pause is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.pause_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()

    handler._pause_reading_for_buffer()

    assert handler._buffer_paused is True


def test_resume_reading_if_drained_ignores_unsupported_transport(
    event_loop: asyncio.AbstractEventLoop,
    dummy_manager: Server[BaseRequest],
) -> None:
    """A transport without flow control raising on resume is ignored."""
    handler = RequestHandler(dummy_manager, loop=event_loop)
    # Bare asyncio.Transport.resume_reading() raises NotImplementedError.
    handler.transport = asyncio.Transport()
    handler._upgraded = True  # skip the reparse branch
    handler._buffer_paused = True

    handler._resume_reading_if_drained()

    assert handler._buffer_paused is False
