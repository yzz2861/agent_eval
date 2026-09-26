from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, call, Mock

import pytest
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, PushedStreamReceived, StreamReset
from h2.settings import SettingCodes

from hypercorn.asyncio.worker_context import EventWrapper, WorkerContext
from hypercorn.config import Config
from hypercorn.events import Closed, RawData
from hypercorn.protocol.h2 import BUFFER_HIGH_WATER, BufferCompleteError, H2Protocol, StreamBuffer
from hypercorn.protocol.events import Request
from hypercorn.typing import ConnectionState


@pytest.mark.asyncio
async def test_stream_buffer_push_and_pop() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    stream_buffer = StreamBuffer(EventWrapper)

    async def _push_over_limit() -> bool:
        await stream_buffer.push(b"a" * (BUFFER_HIGH_WATER + 1))
        return True

    task = event_loop.create_task(_push_over_limit())
    assert not task.done()  # Blocked as over high water
    await stream_buffer.pop(BUFFER_HIGH_WATER // 4)
    assert not task.done()  # Blocked as over low water
    await stream_buffer.pop(BUFFER_HIGH_WATER // 4)
    assert (await task) is True


@pytest.mark.asyncio
async def test_stream_buffer_drain() -> None:
    event_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    stream_buffer = StreamBuffer(EventWrapper)
    await stream_buffer.push(b"a" * 10)

    async def _drain() -> bool:
        await stream_buffer.drain()
        return True

    task = event_loop.create_task(_drain())
    assert not task.done()  # Blocked
    await stream_buffer.pop(20)
    assert (await task) is True


@pytest.mark.asyncio
async def test_stream_buffer_closed() -> None:
    stream_buffer = StreamBuffer(EventWrapper)
    await stream_buffer.close()
    await stream_buffer._is_empty.wait()
    await stream_buffer._paused.wait()
    assert True
    with pytest.raises(BufferCompleteError):
        await stream_buffer.push(b"a")


@pytest.mark.asyncio
async def test_stream_buffer_complete() -> None:
    stream_buffer = StreamBuffer(EventWrapper)
    await stream_buffer.push(b"a" * 10)
    assert not stream_buffer.complete
    stream_buffer.set_complete()
    assert not stream_buffer.complete
    await stream_buffer.pop(20)
    assert stream_buffer.complete


@pytest.mark.asyncio
async def test_protocol_handle_protocol_error() -> None:
    protocol = H2Protocol(
        Mock(),
        Config(),
        WorkerContext(None),
        AsyncMock(),
        ConnectionState({}),
        False,
        None,
        None,
        AsyncMock(),
    )
    await protocol.handle(RawData(data=b"broken nonsense\r\n\r\n"))
    protocol.send.assert_awaited()  # type: ignore
    assert protocol.send.call_args_list == [call(Closed())]  # type: ignore


@pytest.mark.asyncio
async def test_protocol_keep_alive_max_requests() -> None:
    protocol = H2Protocol(
        Mock(),
        Config(),
        WorkerContext(None),
        AsyncMock(),
        ConnectionState({}),
        False,
        None,
        None,
        AsyncMock(),
    )
    protocol.config.keep_alive_max_requests = 0
    client = H2Connection()
    client.initiate_connection()
    headers = [
        (":method", "GET"),
        (":path", "/reqinfo"),
        (":authority", "hypercorn"),
        (":scheme", "https"),
    ]
    client.send_headers(1, headers, end_stream=True)
    await protocol.handle(RawData(data=client.data_to_send()))
    protocol.send.assert_awaited()  # type: ignore
    events = client.receive_data(protocol.send.call_args_list[1].args[0].data)  # type: ignore
    assert isinstance(events[-1], ConnectionTerminated)


def _push_protocol(config: Config | None = None) -> H2Protocol:
    protocol = H2Protocol(
        Mock(),
        config or Config(),
        WorkerContext(None),
        AsyncMock(),
        ConnectionState({}),
        False,
        None,
        None,
        AsyncMock(),
    )
    protocol.config._log = AsyncMock()
    return protocol


async def _receive_request(protocol: H2Protocol, client: H2Connection, stream_id: int) -> None:
    client.send_headers(
        stream_id,
        [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "hypercorn"),
            (":scheme", "https"),
        ],
        end_stream=True,
    )
    await protocol.handle(RawData(data=client.data_to_send()))
    _client_events(protocol, client)


async def _send_push(protocol: H2Protocol, stream_id: int, path: bytes) -> None:
    await protocol.stream_send(
        Request(
            stream_id=stream_id,
            headers=[(b":scheme", b"https"), (b":authority", b"hypercorn")],
            http_version="2",
            method="GET",
            raw_path=path,
            state=ConnectionState({}),
        )
    )


def _client_events(protocol: H2Protocol, client: H2Connection) -> list:
    data = b"".join(
        call.args[0].data  # type: ignore
        for call in protocol.send.call_args_list  # type: ignore
        if isinstance(call.args[0], RawData)
    )
    protocol.send.reset_mock()  # type: ignore
    return client.receive_data(data)


@pytest.mark.asyncio
async def test_server_push_duplicate_target_skipped() -> None:
    protocol = _push_protocol()
    client = H2Connection()
    client.initiate_connection()
    await _receive_request(protocol, client, 1)

    await _send_push(protocol, 1, b"/asset")
    events = _client_events(protocol, client)
    assert len([event for event in events if isinstance(event, PushedStreamReceived)]) == 1

    await _send_push(protocol, 1, b"/asset")
    events = _client_events(protocol, client)
    assert not [event for event in events if isinstance(event, PushedStreamReceived)]
    assert "already pushed" in protocol.config.log.info.call_args.args[3]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_per_request_limit() -> None:
    config = Config()
    config.h2_max_pushes_per_request = 1
    protocol = _push_protocol(config)
    client = H2Connection()
    client.initiate_connection()
    await _receive_request(protocol, client, 1)

    await _send_push(protocol, 1, b"/one")
    await _send_push(protocol, 1, b"/two")
    events = _client_events(protocol, client)
    assert len([event for event in events if isinstance(event, PushedStreamReceived)]) == 1
    assert "h2_max_pushes_per_request" in protocol.config.log.info.call_args.args[3]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_connection_limit_and_recovery() -> None:
    config = Config()
    config.h2_max_concurrent_pushes = 1
    protocol = _push_protocol(config)
    client = H2Connection()
    client.initiate_connection()
    await _receive_request(protocol, client, 1)

    await _send_push(protocol, 1, b"/one")
    # A normal request is unaffected by the push quota
    await _receive_request(protocol, client, 3)
    assert 3 in protocol.streams

    await _send_push(protocol, 3, b"/two")
    events = _client_events(protocol, client)
    assert not [event for event in events if isinstance(event, PushedStreamReceived)]
    assert "h2_max_concurrent_pushes" in protocol.config.log.info.call_args.args[3]  # type: ignore

    # Resetting the pushed stream frees the quota
    client.reset_stream(2)
    await protocol.handle(RawData(data=client.data_to_send()))
    await _send_push(protocol, 3, b"/two")
    events = _client_events(protocol, client)
    pushed = [event for event in events if isinstance(event, PushedStreamReceived)]
    assert len(pushed) == 1
    assert pushed[0].parent_stream_id == 3


@pytest.mark.asyncio
async def test_server_push_client_disables_push() -> None:
    protocol = _push_protocol()
    client = H2Connection()
    client.initiate_connection()
    await _receive_request(protocol, client, 1)

    await _send_push(protocol, 1, b"/one")
    events = _client_events(protocol, client)
    assert len([event for event in events if isinstance(event, PushedStreamReceived)]) == 1

    client.update_settings({SettingCodes.ENABLE_PUSH: 0})
    await protocol.handle(RawData(data=client.data_to_send()))
    # The in flight push is cancelled
    events = _client_events(protocol, client)
    resets = [event for event in events if isinstance(event, StreamReset)]
    assert [event.stream_id for event in resets] == [2]
    assert 2 not in protocol.streams

    # Further pushes are rejected rather than left hanging
    await _send_push(protocol, 1, b"/two")
    events = _client_events(protocol, client)
    assert not [event for event in events if isinstance(event, PushedStreamReceived)]
    assert "ENABLE_PUSH" in protocol.config.log.info.call_args.args[3]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_parent_stream_reset_cancels_pushes() -> None:
    protocol = _push_protocol()
    client = H2Connection()
    client.initiate_connection()
    await _receive_request(protocol, client, 1)

    await _send_push(protocol, 1, b"/one")
    _client_events(protocol, client)
    assert 2 in protocol.streams

    client.reset_stream(1)
    await protocol.handle(RawData(data=client.data_to_send()))
    events = _client_events(protocol, client)
    resets = [event for event in events if isinstance(event, StreamReset)]
    assert [event.stream_id for event in resets] == [2]
    assert 2 not in protocol.streams
    assert protocol._push_streams == {}
    assert protocol._parent_push_counts == {}


@pytest.mark.asyncio
async def test_server_push_client_max_concurrent_streams() -> None:
    protocol = _push_protocol()
    client = H2Connection()
    client.initiate_connection()
    await _receive_request(protocol, client, 1)

    client.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: 1})
    await protocol.handle(RawData(data=client.data_to_send()))
    _client_events(protocol, client)

    await _send_push(protocol, 1, b"/one")
    await _send_push(protocol, 1, b"/two")
    events = _client_events(protocol, client)
    assert len([event for event in events if isinstance(event, PushedStreamReceived)]) == 1
    assert "concurrent streams" in protocol.config.log.info.call_args.args[3]  # type: ignore
