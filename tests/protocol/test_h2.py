from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, call, Mock

import pytest
import h2.events
import h2.settings
from h2.connection import H2Connection
from h2.events import ConnectionTerminated

from hypercorn.asyncio.worker_context import EventWrapper, WorkerContext
from hypercorn.config import Config
from hypercorn.events import Closed, RawData
from hypercorn.protocol.events import Request
from hypercorn.protocol.h2 import BUFFER_HIGH_WATER, BufferCompleteError, H2Protocol, StreamBuffer
from hypercorn.typing import ConnectionState


def _push_request(stream_id: int, path: bytes, authority: bytes = b"hypercorn") -> Request:
    return Request(
        stream_id=stream_id,
        headers=[(b":scheme", b"https"), (b":authority", authority)],
        http_version="2",
        method="GET",
        raw_path=path,
        state=ConnectionState({}),
    )


def _server_events(protocol: H2Protocol, client: H2Connection) -> list[h2.events.Event]:
    data = b"".join(
        call_.args[0].data
        for call_ in protocol.send.call_args_list  # type: ignore
        if isinstance(call_.args[0], RawData)
    )
    protocol.send.reset_mock()  # type: ignore
    return client.receive_data(data)


async def _initiate_push_connection(config: Config) -> tuple[H2Protocol, H2Connection]:
    config._log = AsyncMock()
    protocol = H2Protocol(
        Mock(),
        config,
        WorkerContext(None),
        AsyncMock(),
        ConnectionState({}),
        False,
        None,
        None,
        AsyncMock(),
    )
    client = H2Connection()
    client.initiate_connection()
    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":authority", "hypercorn"),
        (":scheme", "https"),
    ]
    client.send_headers(1, headers, end_stream=True)
    await protocol.handle(RawData(data=client.data_to_send()))
    _server_events(protocol, client)
    return protocol, client


def _pushed_paths(events: list[h2.events.Event]) -> list[bytes]:
    paths = []
    for event in events:
        if isinstance(event, h2.events.PushedStreamReceived):
            paths.append(dict(event.headers)[b":path"])
    return paths


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


@pytest.mark.asyncio
async def test_server_push_deduplicates_target() -> None:
    protocol, client = await _initiate_push_connection(Config())

    await protocol.stream_send(_push_request(1, b"/style.css"))
    await protocol.stream_send(_push_request(1, b"/style.css"))
    await protocol.stream_send(_push_request(1, b"/other.css"))
    # The same path on another authority is a distinct target
    await protocol.stream_send(_push_request(1, b"/style.css", authority=b"other"))

    events = _server_events(protocol, client)
    assert _pushed_paths(events) == [b"/style.css", b"/other.css", b"/style.css"]
    protocol.config.log.info.assert_awaited_once()  # type: ignore
    assert "already pushed" in protocol.config.log.info.call_args.args[-1]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_per_stream_limit() -> None:
    config = Config()
    config.h2_max_pushes_per_stream = 1
    protocol, client = await _initiate_push_connection(config)

    await protocol.stream_send(_push_request(1, b"/a"))
    await protocol.stream_send(_push_request(1, b"/b"))

    # A new parent request has its own push allowance
    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":authority", "hypercorn"),
        (":scheme", "https"),
    ]
    client.send_headers(3, headers, end_stream=True)
    await protocol.handle(RawData(data=client.data_to_send()))
    await protocol.stream_send(_push_request(3, b"/b"))

    events = _server_events(protocol, client)
    assert _pushed_paths(events) == [b"/a", b"/b"]
    protocol.config.log.info.assert_awaited_once()  # type: ignore
    assert "parent stream push limit" in protocol.config.log.info.call_args.args[-1]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_connection_limit_recovers() -> None:
    config = Config()
    config.h2_max_concurrent_pushes = 1
    protocol, client = await _initiate_push_connection(config)

    await protocol.stream_send(_push_request(1, b"/a"))
    events = _server_events(protocol, client)
    assert _pushed_paths(events) == [b"/a"]

    task = asyncio.get_running_loop().create_task(protocol.stream_send(_push_request(1, b"/b")))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert not task.done()  # Waiting for push capacity

    # Client resets the in-flight push stream, freeing capacity
    pushed_stream_id = 2
    client.reset_stream(pushed_stream_id)
    await protocol.handle(RawData(data=client.data_to_send()))

    await asyncio.wait_for(task, timeout=1)
    events = _server_events(protocol, client)
    assert _pushed_paths(events) == [b"/b"]


@pytest.mark.asyncio
async def test_server_push_rejected_when_client_disables_push() -> None:
    config = Config()
    config.h2_max_concurrent_pushes = 1
    protocol, client = await _initiate_push_connection(config)

    await protocol.stream_send(_push_request(1, b"/a"))
    _server_events(protocol, client)

    task = asyncio.get_running_loop().create_task(protocol.stream_send(_push_request(1, b"/b")))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert not task.done()  # Waiting for push capacity

    client.update_settings({h2.settings.SettingCodes.ENABLE_PUSH: 0})
    await protocol.handle(RawData(data=client.data_to_send()))

    await asyncio.wait_for(task, timeout=1)  # Rejected rather than stuck
    events = _server_events(protocol, client)
    assert _pushed_paths(events) == []

    # New pushes are skipped straight away as well
    await protocol.stream_send(_push_request(1, b"/c"))
    events = _server_events(protocol, client)
    assert _pushed_paths(events) == []
    assert protocol.config.log.info.await_count == 2  # type: ignore
    assert "disabled push" in protocol.config.log.info.call_args.args[-1]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_rejected_when_parent_stream_resets() -> None:
    config = Config()
    config.h2_max_concurrent_pushes = 1
    protocol, client = await _initiate_push_connection(config)

    await protocol.stream_send(_push_request(1, b"/a"))
    _server_events(protocol, client)

    task = asyncio.get_running_loop().create_task(protocol.stream_send(_push_request(1, b"/b")))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert not task.done()  # Waiting for push capacity

    client.reset_stream(1)
    await protocol.handle(RawData(data=client.data_to_send()))

    await asyncio.wait_for(task, timeout=1)  # Rejected rather than stuck
    events = _server_events(protocol, client)
    assert _pushed_paths(events) == []
    protocol.config.log.info.assert_awaited_once()  # type: ignore
    assert "parent stream" in protocol.config.log.info.call_args.args[-1]  # type: ignore


@pytest.mark.asyncio
async def test_server_push_rejected_when_client_shrinks_concurrent_streams() -> None:
    config = Config()
    config.h2_max_concurrent_pushes = 1
    protocol, client = await _initiate_push_connection(config)

    await protocol.stream_send(_push_request(1, b"/a"))
    _server_events(protocol, client)

    task = asyncio.get_running_loop().create_task(protocol.stream_send(_push_request(1, b"/b")))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert not task.done()  # Waiting for push capacity

    client.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 1})
    await protocol.handle(RawData(data=client.data_to_send()))

    await asyncio.wait_for(task, timeout=1)  # Rejected rather than stuck
    events = _server_events(protocol, client)
    assert _pushed_paths(events) == []
    protocol.config.log.info.assert_awaited_once()  # type: ignore
    assert "concurrent streams" in protocol.config.log.info.call_args.args[-1]  # type: ignore


@pytest.mark.asyncio
async def test_requests_unaffected_by_push_limits() -> None:
    config = Config()
    config.h2_max_concurrent_pushes = 1
    config.h2_max_pushes_per_stream = 1
    protocol, client = await _initiate_push_connection(config)

    await protocol.stream_send(_push_request(1, b"/a"))
    await protocol.stream_send(_push_request(1, b"/b"))  # Over the per-stream limit
    _server_events(protocol, client)

    # Ordinary requests are not subject to the push allowances
    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":authority", "hypercorn"),
        (":scheme", "https"),
    ]
    client.send_headers(3, headers, end_stream=True)
    await protocol.handle(RawData(data=client.data_to_send()))
    assert 3 in protocol.streams
