from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import h2
import h2.connection
import h2.events
import h2.exceptions
import priority

from .events import (
    Body,
    Data,
    EndBody,
    EndData,
    Event as StreamEvent,
    InformationalResponse,
    Request,
    Response,
    StreamClosed,
    Trailers,
)
from .http_stream import HTTPStream
from .ws_stream import WSStream
from ..config import Config
from ..events import Closed, Event, RawData, Updated
from ..typing import AppWrapper, ConnectionState, Event as IOEvent, TaskGroup, WorkerContext
from ..utils import filter_pseudo_headers

BUFFER_HIGH_WATER = 2 * 2**14  # Twice the default max frame size (two frames worth)
BUFFER_LOW_WATER = BUFFER_HIGH_WATER / 2


class BufferCompleteError(Exception):
    pass


class StreamScheduler:
    """Chooses which stream may send DATA frames next.

    This wraps the client-driven HTTP/2 priority tree and, when
    ``response_priority`` is enabled, response priority hints provided
    by the application via the ``http.response.priority`` extension.

    Whilst any hint is active all ready streams are scheduled by their
    effective priority (hint plus an aging boost), with streams that
    did not declare a hint treated as priority 0. Every time a stream
    is chosen the waiting streams' boosts increase, so a steady stream
    of high priority responses cannot starve lower priority streams.
    When no hints are declared the client priority tree is used
    directly, preserving the original scheduling behaviour.
    """

    def __init__(self, response_priority: bool = False) -> None:
        self._tree = priority.PriorityTree()
        self._response_priority = response_priority
        self._hints: dict[int, int] = {}
        self._ready: set[int] = set()
        self._waits: dict[int, int] = {}

    def insert_stream(self, stream_id: int, **kwargs: Any) -> None:
        self._tree.insert_stream(stream_id, **kwargs)

    def reprioritize(self, stream_id: int, **kwargs: Any) -> None:
        self._tree.reprioritize(stream_id, **kwargs)

    def block(self, stream_id: int) -> None:
        self._tree.block(stream_id)
        self._ready.discard(stream_id)

    def unblock(self, stream_id: int) -> None:
        self._tree.unblock(stream_id)
        self._ready.add(stream_id)

    def remove_stream(self, stream_id: int) -> None:
        try:
            self._tree.remove_stream(stream_id)
        except priority.MissingStreamError:
            pass
        self._discard(stream_id)

    def set_hint(self, stream_id: int, hint: int) -> None:
        if self._response_priority:
            self._hints[stream_id] = hint

    def next_stream(self) -> int | None:
        if self._response_priority and self._hints:
            if not self._ready:
                return None
            chosen = max(
                self._ready,
                key=lambda stream_id: (
                    self._hints.get(stream_id, 0) + self._waits.get(stream_id, 0),
                    -stream_id,
                ),
            )
            for stream_id in self._ready:
                if stream_id == chosen:
                    self._waits[stream_id] = 0
                else:
                    self._waits[stream_id] = self._waits.get(stream_id, 0) + 1
            return chosen
        try:
            return next(self._tree)
        except priority.DeadlockError:
            return None

    def _discard(self, stream_id: int) -> None:
        self._hints.pop(stream_id, None)
        self._ready.discard(stream_id)
        self._waits.pop(stream_id, None)


class StreamBuffer:
    def __init__(self, event_class: type[IOEvent]) -> None:
        self.buffer = bytearray()
        self._complete = False
        self._is_empty = event_class()
        self._paused = event_class()

    async def drain(self) -> None:
        await self._is_empty.wait()

    def set_complete(self) -> None:
        self._complete = True

    async def close(self) -> None:
        self._complete = True
        self.buffer = bytearray()
        await self._is_empty.set()
        await self._paused.set()

    @property
    def complete(self) -> bool:
        return self._complete and len(self.buffer) == 0

    async def push(self, data: bytes) -> None:
        if self._complete:
            raise BufferCompleteError()
        self.buffer.extend(data)
        await self._is_empty.clear()
        if len(self.buffer) >= BUFFER_HIGH_WATER:
            await self._paused.wait()
            await self._paused.clear()

    async def pop(self, max_length: int) -> bytes:
        length = min(len(self.buffer), max_length)
        data = bytes(self.buffer[:length])
        del self.buffer[:length]
        if len(data) < BUFFER_LOW_WATER:
            await self._paused.set()
        if len(self.buffer) == 0:
            await self._is_empty.set()
        return data


class H2Protocol:
    def __init__(
        self,
        app: AppWrapper,
        config: Config,
        context: WorkerContext,
        task_group: TaskGroup,
        connection_state: ConnectionState,
        ssl: bool,
        client: tuple[str, int] | None,
        server: tuple[str, int] | None,
        send: Callable[[Event], Awaitable[None]],
    ) -> None:
        self.app = app
        self.client = client
        self.closed = False
        self.config = config
        self.context = context
        self.task_group = task_group
        self.connection_state = connection_state

        self.connection = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding=None)
        )
        self.connection.DEFAULT_MAX_INBOUND_FRAME_SIZE = config.h2_max_inbound_frame_size
        self.connection.local_settings = h2.settings.Settings(
            client=False,
            initial_values={
                h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: config.h2_max_concurrent_streams,
                h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: config.h2_max_header_list_size,
                h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,
            },
        )

        self.keep_alive_requests = 0
        self.send = send
        self.server = server
        self.ssl = ssl
        self.streams: dict[int, HTTPStream | WSStream] = {}
        # The below are used by the sending task
        self.has_data = self.context.event_class()
        self.scheduler = StreamScheduler(response_priority=config.h2_response_priority)
        self.stream_buffers: dict[int, StreamBuffer] = {}

    @property
    def idle(self) -> bool:
        return len(self.streams) == 0 or all(stream.idle for stream in self.streams.values())

    async def initiate(
        self, headers: list[tuple[bytes, bytes]] | None = None, settings: bytes | None = None
    ) -> None:
        if settings is not None:
            self.connection.initiate_upgrade_connection(settings)
        else:
            self.connection.initiate_connection()
        await self._flush()
        if headers is not None:
            event = h2.events.RequestReceived(stream_id=1, headers=headers)
            await self._create_stream(event)
            await self.streams[event.stream_id].handle(EndBody(stream_id=event.stream_id))
        self.task_group.spawn(self.send_task)

    async def send_task(self) -> None:
        # This should be run in a separate task to the rest of this
        # class. This allows it separately choose when to send,
        # crucially in what order.
        while not self.closed:
            stream_id = self.scheduler.next_stream()
            if stream_id is None:
                await self.has_data.wait()
                await self.has_data.clear()
            else:
                await self._send_data(stream_id)

    async def _send_data(self, stream_id: int) -> None:
        try:
            chunk_size = min(
                self.connection.local_flow_control_window(stream_id),
                self.connection.max_outbound_frame_size,
            )
            chunk_size = max(0, chunk_size)
            data = await self.stream_buffers[stream_id].pop(chunk_size)
            if data:
                self.connection.send_data(stream_id, data)
                await self._flush()
            else:
                self.scheduler.block(stream_id)

            if self.stream_buffers[stream_id].complete:
                self.connection.end_stream(stream_id)
                await self._flush()
                del self.stream_buffers[stream_id]
                self.scheduler.remove_stream(stream_id)
        except (h2.exceptions.StreamClosedError, KeyError, h2.exceptions.ProtocolError):
            # Stream or connection has closed whilst waiting to send
            # data, not a problem - just force close it.
            buffer = self.stream_buffers.pop(stream_id, None)
            if buffer is not None:
                await buffer.close()
            self.scheduler.remove_stream(stream_id)

    async def handle(self, event: Event) -> None:
        if isinstance(event, RawData):
            try:
                events = self.connection.receive_data(event.data)
            except h2.exceptions.ProtocolError:
                await self._flush()
                await self.send(Closed())
            else:
                await self._handle_events(events)
        elif isinstance(event, Closed):
            self.closed = True
            stream_ids = list(self.streams.keys())
            for stream_id in stream_ids:
                await self._close_stream(stream_id)
            await self.has_data.set()

    async def stream_send(self, event: StreamEvent) -> None:
        try:
            if isinstance(event, (InformationalResponse, Response)):
                if (
                    isinstance(event, Response)
                    and event.priority is not None
                    and event.stream_id in self.streams
                ):
                    self.scheduler.set_hint(event.stream_id, event.priority)
                self.connection.send_headers(
                    event.stream_id,
                    [(b":status", b"%d" % event.status_code)]
                    + event.headers
                    + self.config.response_headers("h2"),
                )
                await self._flush()
            elif isinstance(event, (Body, Data)):
                self.scheduler.unblock(event.stream_id)
                await self.has_data.set()
                await self.stream_buffers[event.stream_id].push(event.data)
            elif isinstance(event, (EndBody, EndData)):
                self.stream_buffers[event.stream_id].set_complete()
                self.scheduler.unblock(event.stream_id)
                await self.has_data.set()
                await self.stream_buffers[event.stream_id].drain()
            elif isinstance(event, Trailers):
                self.scheduler.unblock(event.stream_id)
                await self.has_data.set()
                await self.stream_buffers[event.stream_id].drain()
                self.connection.send_headers(event.stream_id, event.headers, end_stream=True)
                await self._flush()
            elif isinstance(event, StreamClosed):
                await self._close_stream(event.stream_id)
                idle = len(self.streams) == 0 or all(
                    stream.idle for stream in self.streams.values()
                )
                if idle and self.context.terminated.is_set():
                    self.connection.close_connection()
                    await self._flush()
                await self.send(Updated(idle=idle))
            elif isinstance(event, Request):
                await self._create_server_push(event.stream_id, event.raw_path, event.headers)
        except (
            BufferCompleteError,
            KeyError,
            priority.MissingStreamError,
            h2.exceptions.ProtocolError,
        ):
            # Connection has closed whilst blocked on flow control or
            # connection has advanced ahead of the last emitted event.
            return

    async def _handle_events(self, events: list[h2.events.Event]) -> None:
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                if self.context.terminated.is_set():
                    self.connection.reset_stream(event.stream_id)
                    self.connection.update_settings(
                        {h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 0}
                    )
                else:
                    await self._create_stream(event)
                    await self.send(Updated(idle=False))

                if self.keep_alive_requests > self.config.keep_alive_max_requests:
                    self.connection.close_connection()
            elif isinstance(event, h2.events.DataReceived):
                await self.streams[event.stream_id].handle(
                    Body(stream_id=event.stream_id, data=event.data)
                )
                self.connection.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            elif isinstance(event, h2.events.StreamEnded):
                try:
                    await self.streams[event.stream_id].handle(EndBody(stream_id=event.stream_id))
                except KeyError:
                    # Response sent before full request received,
                    # nothing to do already closed.
                    pass
            elif isinstance(event, h2.events.StreamReset):
                await self._close_stream(event.stream_id)
                await self._window_updated(event.stream_id)
            elif isinstance(event, h2.events.WindowUpdated):
                await self._window_updated(event.stream_id)
            elif isinstance(event, h2.events.PriorityUpdated):
                await self._priority_updated(event)
            elif isinstance(event, h2.events.RemoteSettingsChanged):
                if h2.settings.SettingCodes.INITIAL_WINDOW_SIZE in event.changed_settings:
                    await self._window_updated(None)
            elif isinstance(event, h2.events.ConnectionTerminated):
                await self.send(Closed())
        await self._flush()

    async def _flush(self) -> None:
        data = self.connection.data_to_send()
        if data != b"":
            await self.send(RawData(data=data))

    async def _window_updated(self, stream_id: int | None) -> None:
        if stream_id is None or stream_id == 0:
            # Unblock all streams
            for stream_id in list(self.stream_buffers.keys()):
                self.scheduler.unblock(stream_id)
        elif stream_id is not None and stream_id in self.stream_buffers:
            self.scheduler.unblock(stream_id)
        await self.has_data.set()

    async def _priority_updated(self, event: h2.events.PriorityUpdated) -> None:
        try:
            self.scheduler.reprioritize(
                stream_id=event.stream_id,
                depends_on=event.depends_on or None,
                weight=event.weight,
                exclusive=event.exclusive,
            )
        except priority.MissingStreamError:
            # Received PRIORITY frame before HEADERS frame
            self.scheduler.insert_stream(
                stream_id=event.stream_id,
                depends_on=event.depends_on or None,
                weight=event.weight,
                exclusive=event.exclusive,
            )
            self.scheduler.block(event.stream_id)
        await self.has_data.set()

    async def _create_stream(self, request: h2.events.RequestReceived) -> None:
        for name, value in request.headers:
            if name == b":method":
                method = value.decode("ascii").upper()
            elif name == b":path":
                raw_path = value

        if method == "CONNECT":
            self.streams[request.stream_id] = WSStream(
                self.app,
                self.config,
                self.context,
                self.task_group,
                self.ssl,
                self.client,
                self.server,
                self.stream_send,
                request.stream_id,
            )
        else:
            self.streams[request.stream_id] = HTTPStream(
                self.app,
                self.config,
                self.context,
                self.task_group,
                self.ssl,
                self.client,
                self.server,
                self.stream_send,
                request.stream_id,
            )
        self.stream_buffers[request.stream_id] = StreamBuffer(self.context.event_class)
        try:
            self.scheduler.insert_stream(request.stream_id)
        except priority.DuplicateStreamError:
            # Received PRIORITY frame before HEADERS frame
            pass
        else:
            self.scheduler.block(request.stream_id)

        await self.streams[request.stream_id].handle(
            Request(
                stream_id=request.stream_id,
                headers=filter_pseudo_headers(request.headers),
                http_version="2",
                method=method,
                raw_path=raw_path,
                state=self.connection_state,
            )
        )
        self.keep_alive_requests += 1
        await self.context.mark_request()

    async def _create_server_push(
        self, stream_id: int, path: bytes, headers: list[tuple[bytes, bytes]]
    ) -> None:
        push_stream_id = self.connection.get_next_available_stream_id()
        request_headers = [(b":method", b"GET"), (b":path", path)]
        request_headers.extend(headers)
        request_headers.extend(self.config.response_headers("h2"))
        try:
            self.connection.push_stream(
                stream_id=stream_id,
                promised_stream_id=push_stream_id,
                request_headers=request_headers,
            )
            await self._flush()
        except h2.exceptions.ProtocolError:
            # Client does not accept push promises or we are trying to
            # push on a push promises request.
            pass
        else:
            event = h2.events.RequestReceived(stream_id=push_stream_id, headers=request_headers)
            await self._create_stream(event)
            await self.streams[event.stream_id].handle(EndBody(stream_id=event.stream_id))
            self.keep_alive_requests += 1

    async def _close_stream(self, stream_id: int) -> None:
        if stream_id in self.streams:
            stream = self.streams.pop(stream_id)
            self.scheduler.remove_stream(stream_id)
            buffer = self.stream_buffers.pop(stream_id, None)
            if buffer is not None:
                await buffer.close()
            await stream.handle(StreamClosed(stream_id=stream_id))
            await self.has_data.set()
