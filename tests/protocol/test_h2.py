from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, call, Mock

import h2.events
import h2.settings
import pytest
from h2.connection import H2Connection
from h2.events import ConnectionTerminated

from hypercorn.asyncio.worker_context import EventWrapper, WorkerContext
from hypercorn.config import Config
from hypercorn.events import Closed, RawData
from hypercorn.protocol.events import Body, EndBody, Response, StreamClosed, Trailers
from hypercorn.protocol.h2 import (
    BUFFER_HIGH_WATER,
    BufferCompleteError,
    H2Protocol,
    StreamBuffer,
    StreamScheduler,
)
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


class H2ClientHarness:
    def __init__(self) -> None:
        self.connection = H2Connection()
        self.data_stream_ids: list[int] = []
        self._consumed = 0

    def receive(self, protocol: H2Protocol) -> None:
        calls = protocol.send.call_args_list  # type: ignore
        for call_ in calls[self._consumed :]:
            event = call_.args[0]
            if isinstance(event, RawData):
                for h2_event in self.connection.receive_data(event.data):
                    if isinstance(h2_event, h2.events.DataReceived):
                        self.data_stream_ids.append(h2_event.stream_id)
        self._consumed = len(calls)


async def _priority_setup(
    config: Config | None = None, initial_window: int = 2**20
) -> tuple[H2Protocol, H2ClientHarness]:
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
    client = H2ClientHarness()
    await protocol.initiate()
    client.connection.initiate_connection()
    client.connection.update_settings(
        {h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: initial_window}
    )
    if initial_window > 2**16 - 1:
        client.connection.increment_flow_control_window(initial_window - (2**16 - 1))
    await protocol.handle(RawData(data=client.connection.data_to_send()))
    client.receive(protocol)
    return protocol, client


async def _open_stream(
    protocol: H2Protocol, client: H2ClientHarness, stream_id: int, end_stream: bool = True
) -> None:
    client.connection.send_headers(
        stream_id,
        [
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":authority", b"hypercorn"),
            (b":scheme", b"https"),
        ],
        end_stream=end_stream,
    )
    await protocol.handle(RawData(data=client.connection.data_to_send()))


async def _pump(protocol: H2Protocol) -> None:
    # Drive the sending logic as send_task would, without waiting on
    # the has_data event.
    while True:
        stream_id = protocol.scheduler.next_stream()
        if stream_id is None:
            return
        await protocol._send_data(stream_id)


@pytest.mark.asyncio
async def test_response_priority_hint_sent_first() -> None:
    protocol, client = await _priority_setup()
    await _open_stream(protocol, client, 1)
    await _open_stream(protocol, client, 3)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 32767))
    await protocol.stream_send(Response(stream_id=3, headers=[], status_code=200, priority=10))
    await protocol.stream_send(Body(stream_id=3, data=b"small"))
    end_body = asyncio.create_task(protocol.stream_send(EndBody(stream_id=3)))
    await asyncio.sleep(0)  # Let the EndBody handler reach the drain
    await _pump(protocol)
    await end_body
    client.receive(protocol)
    # The small high priority response is sent before the queued large
    # response's DATA frames.
    assert client.data_stream_ids == [3, 3, 1, 1]
    # Completing the body cleans up the scheduling state
    assert 3 not in protocol.scheduler._hints
    assert 3 not in protocol.scheduler._ready


@pytest.mark.asyncio
async def test_response_priority_aging_prevents_starvation() -> None:
    protocol, client = await _priority_setup()
    await _open_stream(protocol, client, 1)
    await _open_stream(protocol, client, 3)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200, priority=0))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 2**14))
    await protocol.stream_send(Response(stream_id=3, headers=[], status_code=200, priority=2))
    await protocol.stream_send(Body(stream_id=3, data=b"y" * 2**14))
    # Top up the buffers so each stream has three frames worth of data
    protocol.stream_buffers[1].buffer.extend(b"x" * 2 * 2**14)
    protocol.stream_buffers[3].buffer.extend(b"y" * 2 * 2**14)
    await _pump(protocol)
    client.receive(protocol)
    # The lower priority stream is served despite the higher priority
    # stream having data queued throughout.
    assert client.data_stream_ids == [3, 3, 1, 3, 1, 1]


@pytest.mark.asyncio
async def test_response_priority_default_scheduling_without_hints() -> None:
    protocol, client = await _priority_setup()
    await _open_stream(protocol, client, 1)
    await _open_stream(protocol, client, 3)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 32767))
    await protocol.stream_send(Response(stream_id=3, headers=[], status_code=200))
    await protocol.stream_send(Body(stream_id=3, data=b"y" * 32767))
    await _pump(protocol)
    client.receive(protocol)
    # No hints declared, the original client priority tree scheduling
    # (round robin) is used.
    assert client.data_stream_ids == [1, 3, 1, 3]


@pytest.mark.asyncio
async def test_response_priority_disabled_ignores_hints() -> None:
    config = Config()
    config.h2_response_priority = False
    protocol, client = await _priority_setup(config)
    await _open_stream(protocol, client, 1)
    await _open_stream(protocol, client, 3)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 32767))
    await protocol.stream_send(Response(stream_id=3, headers=[], status_code=200, priority=10))
    await protocol.stream_send(Body(stream_id=3, data=b"y" * 32767))
    await _pump(protocol)
    client.receive(protocol)
    assert client.data_stream_ids == [1, 3, 1, 3]


@pytest.mark.asyncio
async def test_response_priority_blocked_stream_does_not_spin() -> None:
    protocol, client = await _priority_setup(initial_window=0)
    await _open_stream(protocol, client, 1, end_stream=False)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200, priority=5))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 100))
    await _pump(protocol)  # The stream cannot send, this must not spin
    client.receive(protocol)
    assert client.data_stream_ids == []
    assert protocol.scheduler.next_stream() is None
    # A window update makes the stream schedulable again
    client.connection.increment_flow_control_window(2**14, stream_id=1)
    await protocol.handle(RawData(data=client.connection.data_to_send()))
    await _pump(protocol)
    client.receive(protocol)
    assert client.data_stream_ids == [1]


@pytest.mark.asyncio
async def test_response_priority_stream_reset_cleans_state() -> None:
    protocol, client = await _priority_setup()
    await _open_stream(protocol, client, 1)
    await _open_stream(protocol, client, 3)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200, priority=10))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 100))
    await protocol.stream_send(Response(stream_id=3, headers=[], status_code=200, priority=1))
    await protocol.stream_send(Body(stream_id=3, data=b"y" * 100))
    client.connection.reset_stream(1)
    await protocol.handle(RawData(data=client.connection.data_to_send()))
    assert 1 not in protocol.scheduler._hints
    assert 1 not in protocol.scheduler._ready
    await _pump(protocol)
    client.receive(protocol)
    assert client.data_stream_ids == [3]


@pytest.mark.asyncio
async def test_response_priority_trailers_clean_state() -> None:
    protocol, client = await _priority_setup()
    await _open_stream(protocol, client, 1)
    await protocol.stream_send(Response(stream_id=1, headers=[], status_code=200, priority=7))
    await protocol.stream_send(Body(stream_id=1, data=b"x" * 100))
    await _pump(protocol)  # Drain the body
    await protocol.stream_send(Trailers(stream_id=1, headers=[(b"x-trailer", b"value")]))
    await protocol.stream_send(StreamClosed(stream_id=1))
    assert 1 not in protocol.scheduler._hints
    assert 1 not in protocol.scheduler._ready
    client.receive(protocol)
    assert client.data_stream_ids == [1]


def test_stream_scheduler_disabled_ignores_hints() -> None:
    scheduler = StreamScheduler(response_priority=False)
    scheduler.insert_stream(1)
    scheduler.insert_stream(3)
    scheduler.set_hint(3, 100)
    scheduler.unblock(1)
    scheduler.unblock(3)
    assert scheduler.next_stream() == 1
    assert scheduler.next_stream() == 3


def test_stream_scheduler_next_stream_none_when_blocked() -> None:
    scheduler = StreamScheduler(response_priority=True)
    scheduler.insert_stream(1)
    scheduler.set_hint(1, 10)
    scheduler.block(1)
    assert scheduler.next_stream() is None
