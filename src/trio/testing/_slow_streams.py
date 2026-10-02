from __future__ import annotations

import math
import operator
from collections import deque

import attrs

from .. import _core, _util
from .._highlevel_generic import StapledStream
from .._sync import Event
from .._timeouts import move_on_at, sleep_until
from ..abc import ReceiveStream, SendStream

_DEFAULT_RECEIVE_SIZE = 65536
_TIME_EPSILON = 1e-9


@attrs.frozen
class SlowStreamSettings:
    """Configuration for one direction of a slow in-memory stream.
    """

    bandwidth: float = float("inf")
    delay: float = 0.0
    buffer_capacity: int = 1
    disconnect_after_bytes: int | None = None

    def __attrs_post_init__(self) -> None:
        bandwidth = float(self.bandwidth)
        if bandwidth <= 0 or bandwidth != bandwidth:
            raise ValueError("bandwidth must be a positive number or infinity")

        delay = float(self.delay)
        if delay < 0 or delay != delay:
            raise ValueError("delay must be non-negative and not NaN")

        buffer_capacity = operator.index(self.buffer_capacity)
        if buffer_capacity < 0:
            raise ValueError("buffer_capacity must be >= 0")

        disconnect_after_bytes = self.disconnect_after_bytes
        if disconnect_after_bytes is not None:
            disconnect_after_bytes = operator.index(disconnect_after_bytes)
            if disconnect_after_bytes < 0:
                raise ValueError("disconnect_after_bytes must be >= 0")

        object.__setattr__(self, "bandwidth", bandwidth)
        object.__setattr__(self, "delay", delay)
        object.__setattr__(self, "buffer_capacity", buffer_capacity)
        object.__setattr__(
            self,
            "disconnect_after_bytes",
            disconnect_after_bytes,
        )


class _SlowByteLink:
    def __init__(self, settings: SlowStreamSettings) -> None:
        self._settings = settings
        self._ready = bytearray()
        self._in_flight: deque[tuple[float, float, int, bytearray]] = deque()
        self._in_flight_bytes = 0
        self._next_send_time: float | None = None
        self._accepted_bytes = 0
        self._delivered_bytes = 0
        self._eof_arrival_time: float | None = None
        self._eof_delivered = False
        self._send_closed = False
        self._receiver_closed = False
        self._send_force_closed = False
        self._receiver_locally_closed = False
        self._broken = False
        self._receiver_waiting = False
        self._receiver_max_bytes: int | None = None
        self._send_busy = False
        self._send_event: Event | None = None
        self._receive_event: Event | None = None

    def _wake_send_waiter(self) -> None:
        if self._send_event is not None:
            self._send_event.set()

    def _wake_receive_waiter(self) -> None:
        if self._receive_event is not None:
            self._receive_event.set()

    @property
    def buffered_bytes(self) -> int:
        return len(self._ready) + self._in_flight_bytes

    def _check_receive_max_bytes(self, max_bytes: int | None) -> None:
        if max_bytes is not None:
            max_bytes = operator.index(max_bytes)
            if max_bytes < 1:
                raise ValueError("max_bytes must be >= 1")

    def _pump_due(self) -> None:
        now = _core.current_time()
        while self._in_flight:
            start, arrival_time, first_offset, chunk = self._in_flight[0]
            chunk_first_arrival_time = start + self._settings.delay
            if now + _TIME_EPSILON < chunk_first_arrival_time:
                break

            if math.isinf(self._settings.bandwidth):
                delivered_count = len(chunk)
            else:
                transmitted_bytes = (
                    (now - start - self._settings.delay)
                    * self._settings.bandwidth
                )
                if first_offset == 0 and transmitted_bytes < _TIME_EPSILON:
                    delivered_count = 1
                else:
                    delivered_count = min(
                        len(chunk),
                        math.floor(
                            transmitted_bytes - first_offset + _TIME_EPSILON,
                        )
                        + 1,
                    )
                if delivered_count <= 0:
                    break

            delivered = chunk[:delivered_count]
            self._ready += delivered
            self._delivered_bytes += delivered_count
            self._in_flight_bytes -= delivered_count
            if delivered_count == len(chunk):
                self._in_flight.popleft()
            else:
                remaining = chunk[delivered_count:]
                self._in_flight[0] = (
                    start,
                    arrival_time,
                    first_offset + delivered_count,
                    remaining,
                )

        made_progress = self._in_flight or self._ready
        if made_progress:
            self._wake_send_waiter()
            if self._ready:
                self._wake_receive_waiter()

        if (
            self._eof_arrival_time is not None
            and self._eof_arrival_time <= now
            and not self._in_flight
            and not self._eof_delivered
        ):
            self._eof_delivered = True
            self._wake_receive_waiter()

        if self._auto_disconnect_due():
            self._force_disconnect()

        if not self._in_flight and self._eof_delivered:
            self._wake_send_waiter()

    def _auto_disconnect_due(self) -> bool:
        limit = self._settings.disconnect_after_bytes
        return (
            limit is not None
            and self._accepted_bytes >= limit
            and self._delivered_bytes >= limit
            and not self._in_flight
        )

    def _force_disconnect(self) -> None:
        if self._broken:
            return
        self._broken = True
        self._send_closed = True
        self._receiver_closed = True
        self._eof_arrival_time = None
        self._eof_delivered = False
        self._wake_send_waiter()
        self._wake_receive_waiter()

    def _abort_send_side(self) -> None:
        self._send_force_closed = True
        self._ready.clear()
        self._in_flight.clear()
        self._in_flight_bytes = 0
        self._force_disconnect()

    def _abort_receive_side(self) -> None:
        self._receiver_locally_closed = True
        self._ready.clear()
        self._in_flight.clear()
        self._in_flight_bytes = 0
        self._eof_arrival_time = None
        self._eof_delivered = False
        self._broken = True
        self._receiver_closed = True
        self._wake_send_waiter()
        self._wake_receive_waiter()

    def _check_send_state(self) -> None:
        self._pump_due()
        if self._send_force_closed:
            raise _core.ClosedResourceError("virtual connection closed")
        if self._receiver_closed:
            raise _core.BrokenResourceError("virtual connection closed")
        if self._broken:
            raise _core.BrokenResourceError("virtual connection closed")
        if self._send_closed:
            raise _core.ClosedResourceError("virtual connection closed")

    def _earliest_send_time(self, size: int) -> float:
        now = _core.current_time()
        if self._next_send_time is None:
            self._next_send_time = now
        start = max(now, self._next_send_time)
        self._next_send_time = start + size / self._settings.bandwidth
        return start

    async def _wait_for_send_space(self) -> None:
        while True:
            self._pump_due()
            if self._send_force_closed or self._broken or self._receiver_closed:
                return
            if self._send_closed:
                return
            capacity = self._settings.buffer_capacity
            if self.buffered_bytes < capacity:
                return
            event = Event()
            self._send_event = event
            if capacity == 0:
                if self._receiver_waiting and not self._in_flight:
                    return
                self._pump_due()
                if self.buffered_bytes < capacity or (
                    self._receiver_waiting and not self._in_flight
                ):
                    continue
                await self._wait_for_send_event(event)
            else:
                self._pump_due()
                if self.buffered_bytes < capacity:
                    continue
                if self._ready:
                    if self._in_flight:
                        _, _, first_offset, _ = self._in_flight[0]
                        deadline = (
                            self._in_flight[0][0]
                            + first_offset / self._settings.bandwidth
                            + self._settings.delay
                        )
                        await self._wait_for_send_event(event, deadline)
                    else:
                        await self._wait_for_send_event(event)
                else:
                    start, _, first_offset, _ = self._in_flight[0]
                    next_space_at = (
                        start
                        + first_offset / self._settings.bandwidth
                        + self._settings.delay
                    )
                    await self._wait_for_send_event(event, next_space_at)
            self._send_event = None

    def _remaining_bytes(self) -> int | None:
        limit = self._settings.disconnect_after_bytes
        if limit is None:
            return None
        return limit - self._accepted_bytes

    async def _wait_for_send_event(
        self,
        event: Event,
        deadline: float | None = None,
    ) -> None:
        if deadline is None:
            await event.wait()
        else:
            with move_on_at(deadline):
                await event.wait()

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        if self._send_busy:
            raise _core.BusyResourceError("another task is using this stream")
        self._send_busy = True
        try:
            with memoryview(data) as view:
                payload = bytearray(view)
            await _core.checkpoint()
            await _core.checkpoint()

            offset = 0
            while offset < len(payload):
                self._check_send_state()
                remaining_limit = self._remaining_bytes()
                if remaining_limit is not None and remaining_limit <= 0:
                    self._force_disconnect()
                    raise _core.BrokenResourceError("virtual connection disconnected")

                capacity = self._settings.buffer_capacity
                if capacity == 0:
                    await self._wait_for_send_space()
                    self._check_send_state()
                    size = 1
                    self._receiver_waiting = False

                    start = self._earliest_send_time(size)
                    arrival_time = (
                        start
                        + self._settings.delay
                        + (size - 1) / self._settings.bandwidth
                    )
                    chunk = bytearray(payload[offset : offset + size])
                    self._in_flight.append((start, arrival_time, 0, chunk))
                    self._in_flight_bytes += size
                    self._accepted_bytes += size
                    offset += size
                    self._wake_receive_waiter()
                    await sleep_until(arrival_time)
                    continue

                available = capacity - self.buffered_bytes
                size = min(len(payload) - offset, available)
                if remaining_limit is not None:
                    size = min(size, remaining_limit)

                if size <= 0:
                    await self._wait_for_send_space()
                    continue

                start = self._earliest_send_time(size)
                arrival_time = (
                    start
                    + self._settings.delay
                    + (size - 1) / self._settings.bandwidth
                )
                chunk = bytearray(payload[offset : offset + size])
                self._in_flight.append((start, arrival_time, 0, chunk))
                self._in_flight_bytes += size
                self._accepted_bytes += size
                offset += size
                self._wake_receive_waiter()

                if self.buffered_bytes >= capacity:
                    await self._wait_for_send_space()
                    self._check_send_state()
                    continue

            self._pump_due()
            if self._send_force_closed:
                raise _core.ClosedResourceError("virtual connection closed")
            if self._broken:
                raise _core.BrokenResourceError("virtual connection closed")
            if self._receiver_closed:
                raise _core.BrokenResourceError("virtual connection closed")
            if self._send_closed:
                raise _core.ClosedResourceError("virtual connection closed")
        finally:
            self._send_busy = False

    async def wait_send_all_might_not_block(self) -> None:
        if self._send_busy:
            raise _core.BusyResourceError("another task is using this stream")
        self._send_busy = True
        try:
            await _core.checkpoint()
            await _core.checkpoint()
            self._check_send_state()
            if self._settings.buffer_capacity == 0:
                await self._wait_for_send_space()
                self._check_send_state()
            elif self.buffered_bytes >= self._settings.buffer_capacity:
                await self._wait_for_send_space()
                self._check_send_state()
        finally:
            self._send_busy = False

    def schedule_eof(self) -> None:
        if self._send_closed:
            raise _core.ClosedResourceError("virtual connection closed")
        if self._send_force_closed or self._broken or self._receiver_closed:
            raise _core.BrokenResourceError("virtual connection closed")
        remaining = self._remaining_bytes()
        if remaining is not None and remaining <= 0:
            self._force_disconnect()
            raise _core.BrokenResourceError("virtual connection disconnected")

        self._send_closed = True
        now = _core.current_time()
        if self._in_flight:
            arrival_time = max(now, self._in_flight[-1][1])
        else:
            arrival_time = now + self._settings.delay
        self._eof_arrival_time = arrival_time

    async def receive_some(self, max_bytes: int | None = None) -> bytes | bytearray:
        self._check_receive_max_bytes(max_bytes)
        requested = max_bytes or _DEFAULT_RECEIVE_SIZE
        await _core.checkpoint()
        await _core.checkpoint()

        while True:
            self._pump_due()
            if self._ready:
                chunk = self._ready[:requested]
                del self._ready[:requested]
                self._wake_send_waiter()
                self._send_event = None
                return chunk
            if self._receiver_locally_closed:
                raise _core.ClosedResourceError("virtual connection closed")
            if self._eof_delivered:
                return b""
            if self._broken:
                raise _core.BrokenResourceError("virtual connection closed")
            if self._receiver_closed:
                raise _core.ClosedResourceError("virtual connection closed")

            deadline = (
                self._in_flight[0][0]
                + self._in_flight[0][2] / self._settings.bandwidth
                + self._settings.delay
                if self._in_flight
                else float("inf")
            )
            if self._eof_arrival_time is not None and not self._in_flight:
                eof_deadline = self._eof_arrival_time
                if deadline == float("inf"):
                    deadline = eof_deadline
                else:
                    deadline = min(deadline, eof_deadline)

            self._receiver_waiting = True
            self._receiver_max_bytes = requested
            self._wake_send_waiter()
            try:
                if deadline == float("inf"):
                    event = Event()
                    self._receive_event = event
                    await event.wait()
                else:
                    await sleep_until(deadline)
            finally:
                self._receive_event = None
                self._receiver_waiting = False
                self._receiver_max_bytes = None


@_util.final
class SlowStreamSendStream(SendStream):
    """Send side of a deterministic slow in-memory stream."""

    def __init__(self, link: _SlowByteLink) -> None:
        self._link = link
        self._closed = False
        self._conflict_detector = _util.ConflictDetector(
            "another task is using this stream",
        )

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        with self._conflict_detector:
            await self._link.send_all(data)

    async def wait_send_all_might_not_block(self) -> None:
        with self._conflict_detector:
            await self._link.wait_send_all_might_not_block()

    async def send_eof(self) -> None:
        with self._conflict_detector:
            await _core.checkpoint()
            await _core.checkpoint()
            if not self._closed:
                self._link.schedule_eof()
                self._closed = True

    def close(self) -> None:
        if self._closed:
            return
        self._link.schedule_eof()
        self._closed = True

    async def aclose(self) -> None:
        if self._closed:
            await _core.checkpoint()
            return
        try:
            await _core.checkpoint()
        except _core.Cancelled:
            self._link._abort_send_side()
            self._closed = True
            raise
        if self._link._send_busy:
            self._link._abort_send_side()
        else:
            try:
                self._link.schedule_eof()
            except _core.BrokenResourceError:
                self._link._abort_send_side()
        self._closed = True
        try:
            await _core.checkpoint()
        except _core.Cancelled:
            self._link._abort_send_side()
            raise


@_util.final
class SlowStreamReceiveStream(ReceiveStream):
    """Receive side of a deterministic slow in-memory stream."""

    def __init__(self, link: _SlowByteLink) -> None:
        self._link = link
        self._closed = False
        self._conflict_detector = _util.ConflictDetector(
            "another task is using this stream",
        )

    async def receive_some(self, max_bytes: int | None = None) -> bytes | bytearray:
        with self._conflict_detector:
            return await self._link.receive_some(max_bytes)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._link._abort_receive_side()

    async def aclose(self) -> None:
        self.close()
        await _core.checkpoint()


def slow_stream_one_way_pair(
    settings: SlowStreamSettings | None = None,
) -> tuple[SlowStreamSendStream, SlowStreamReceiveStream]:
    """Create one deterministic, rate-limited in-memory stream direction."""
    link = _SlowByteLink(settings or SlowStreamSettings())
    return SlowStreamSendStream(link), SlowStreamReceiveStream(link)


def slow_stream_pair(
    left_to_right: SlowStreamSettings | None = None,
    right_to_left: SlowStreamSettings | None = None,
) -> tuple[
    StapledStream[SlowStreamSendStream, SlowStreamReceiveStream],
    StapledStream[SlowStreamSendStream, SlowStreamReceiveStream],
]:
    """Create deterministic, rate-limited in-memory half-closeable streams.

    Each argument configures one independent direction. Time is read from the
    current Trio clock, so tests can use a regular clock, :class:`MockClock`,
    or autojumping without real-time sleeps. Graceful half-close delivers
    already accepted data before EOF.

    """
    left_send, right_recv = slow_stream_one_way_pair(left_to_right)
    right_send, left_recv = slow_stream_one_way_pair(right_to_left)
    left = StapledStream(left_send, left_recv)
    right = StapledStream(right_send, right_recv)
    return left, right


SlowStreamSendStream.__module__ = "trio.testing"
SlowStreamReceiveStream.__module__ = "trio.testing"
SlowStreamSettings.__module__ = "trio.testing"
