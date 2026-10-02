# Simulated network links for testing protocols against realistic
# transmission conditions (bandwidth, latency, buffering, mid-stream
# disconnects) without involving the operating system or real time.
from __future__ import annotations

import operator
from collections import deque
from math import inf

from .. import _core, _util
from .._abc import HalfCloseableStream
from .._timeouts import move_on_at


@_util.final
class LinkConfig:
    """Configuration for one direction of a simulated link, as used by
    :func:`simulated_stream_pair`.

    Args:
      bandwidth (float): The rate at which the link transmits bytes, in
          bytes per second. :data:`math.inf` (the default) means bytes
          depart the moment they are accepted.
      latency (float): Propagation delay in seconds. Each transmitted
          segment becomes visible to the receiver this long after it
          finishes departing the sender.
      buffer_size (int): Capacity of the send buffer, in bytes. Once this
          many bytes have been accepted by
          :meth:`~trio.abc.SendStream.send_all` but not yet transmitted,
          ``send_all`` blocks (backpressure) until the link has
          transmitted enough bytes to free up space.
      disconnect_after (int or None): If not None, the link forcefully
          breaks after this many bytes have been delivered to the receiver:
          all still-undelivered data is discarded, the receiver gets
          :exc:`trio.BrokenResourceError` once it has consumed the
          delivered bytes, and the send side gets
          :exc:`trio.BrokenResourceError` from subsequent or blocked
          send calls. ``None`` (the default) means the link never
          breaks on its own.

    The link is a perfectly ordered, lossless byte stream (until it breaks);
    it does not simulate reordering, duplication, or corruption of data.

    """

    __slots__ = ("bandwidth", "buffer_size", "disconnect_after", "latency")

    def __init__(
        self,
        *,
        bandwidth: float = inf,
        latency: float = 0.0,
        buffer_size: int = 65536,
        disconnect_after: int | None = None,
    ) -> None:
        bandwidth = float(bandwidth)
        if not bandwidth > 0:
            raise ValueError("bandwidth must be > 0")
        latency = float(latency)
        if not latency >= 0:
            raise ValueError("latency must be >= 0")
        buffer_size = operator.index(buffer_size)
        if buffer_size < 1:
            raise ValueError("buffer_size must be >= 1")
        if disconnect_after is not None:
            disconnect_after = operator.index(disconnect_after)
            if disconnect_after < 0:
                raise ValueError("disconnect_after must be >= 0 or None")
        self.bandwidth = bandwidth
        self.latency = latency
        self.buffer_size = buffer_size
        self.disconnect_after = disconnect_after

    def __repr__(self) -> str:
        return (
            f"trio.testing.LinkConfig(bandwidth={self.bandwidth!r}, "
            f"latency={self.latency!r}, buffer_size={self.buffer_size!r}, "
            f"disconnect_after={self.disconnect_after!r})"
        )


class _Segment:
    """A run of bytes accepted into a link, with its transmission schedule.

    A segment occupies send-buffer space from when it is accepted until
    ``depart`` (when its last byte has been transmitted), and is
    delivered to the receiver as a single chunk at ``arrive``.
    """

    __slots__ = ("arrive", "data", "depart", "departed")

    def __init__(self, data: bytes, depart: float, arrive: float) -> None:
        self.data = data
        self.depart = depart
        self.arrive = arrive
        self.departed = False


class _Link:
    """One simulated unidirectional link, shared between the sending
    endpoint's send side and the receiving endpoint's receive side.

    All time-based progress is computed lazily: :meth:`_refresh` is
    called from the stream methods, and blocked callers park themselves
    until the next scheduled event (using the current clock, so
    :class:`MockClock` works) or until the peer changes the link state.
    """

    def __init__(self, config: LinkConfig) -> None:
        self._config = config
        # Accepted but not yet delivered segments, ordered by departure time
        # (and hence also by arrival time). Includes in-flight segments
        # (departed but not yet arrived).
        self._segments: deque[_Segment] = deque()
        # Bytes accepted but not yet departed. Bounded by buffer_size.
        self._buffered = 0
        # Time at which the transmitter finishes sending everything accepted
        # so far; used to serialize transmissions at the configured rate.
        self._transmitter_free = -inf
        # Arrived but not yet received bytes.
        self._delivered = bytearray()
        self._delivered_total = 0
        self._send_eof = False  # send_eof() called: graceful half-close
        self._send_closed = False  # send side closed: also delivers EOF
        self._recv_closed = False  # receive side closed: send side breaks
        self._broken = False  # link forcefully broken (disconnect_after)
        self._lot = _core.ParkingLot()

    def _wake_all(self) -> None:
        self._lot.unpark_all()

    def _break(self) -> None:
        # Forceful break: everything accepted but not yet delivered is
        # discarded; already-delivered bytes can still be read before the
        # receiver sees BrokenResourceError.
        if not self._broken:
            self._broken = True
            self._segments.clear()
            self._buffered = 0
            self._wake_all()

    def _refresh(self, now: float) -> None:
        # Free buffer space for segments that have finished departing.
        for seg in self._segments:
            if seg.depart > now:
                break
            if not seg.departed:
                seg.departed = True
                self._buffered -= len(seg.data)
        # Deliver segments that have arrived, in order.
        while self._segments and self._segments[0].arrive <= now:
            seg = self._segments.popleft()
            data = seg.data
            if self._config.disconnect_after is not None:
                remaining = self._config.disconnect_after - self._delivered_total
                if remaining <= 0:
                    self._break()
                    return
                if len(data) > remaining:
                    data = data[:remaining]
                    self._delivered += data
                    self._delivered_total += len(data)
                    self._break()
                    return
            self._delivered += data
            self._delivered_total += len(data)
        # Once the byte limit has been delivered, the link breaks, even if
        # no further data is scheduled to arrive.
        if (
            self._config.disconnect_after is not None
            and self._delivered_total >= self._config.disconnect_after
        ):
            self._break()

    def _accept(self, data: bytes, now: float) -> None:
        if self._config.bandwidth == inf:
            depart = now
        else:
            start = max(self._transmitter_free, now)
            depart = start + len(data) / self._config.bandwidth
            self._transmitter_free = depart
        self._segments.append(_Segment(data, depart, depart + self._config.latency))
        self._buffered += len(data)
        # Wake any parked receivers so they can re-park until the arrival
        # time of the newly scheduled data (or consume it right away).
        self._wake_all()

    def _next_departure(self) -> float:
        for seg in self._segments:
            if not seg.departed:
                return seg.depart
        # Unreachable: callers only wait when the buffer is full, which
        # implies there is a segment that hasn't departed yet.
        return inf  # pragma: no cover

    def _next_arrival(self) -> float:
        if self._segments:
            return self._segments[0].arrive
        return inf

    async def _park_until(self, deadline: float) -> None:
        # Wait until the next scheduled link event, or until the peer
        # changes the link state (close, EOF, break) and wakes us.
        if deadline == inf:
            await self._lot.park()
        else:
            with move_on_at(deadline):
                await self._lot.park()

    def _check_sendable(self) -> None:
        if self._send_closed or self._send_eof:
            raise _core.ClosedResourceError("send side of stream is closed")
        if self._recv_closed:
            raise _core.BrokenResourceError(
                "receive side of connection was closed",
            )
        if self._broken:
            raise _core.BrokenResourceError("connection was disconnected")

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        if self._send_closed or self._send_eof:
            raise _core.ClosedResourceError("send side of stream is closed")
        # Copy now, so later mutation of the caller's buffer can't affect us.
        view = memoryview(bytes(data))
        while view:
            now = _core.current_time()
            self._refresh(now)
            self._check_sendable()
            free = self._config.buffer_size - self._buffered
            if free <= 0:
                await self._park_until(self._next_departure())
                continue
            amount = min(len(view), free)
            self._accept(bytes(view[:amount]), now)
            view = view[amount:]

    async def wait_send_all_might_not_block(self) -> None:
        while True:
            now = _core.current_time()
            self._refresh(now)
            self._check_sendable()
            if self._buffered < self._config.buffer_size:
                return
            await self._park_until(self._next_departure())

    def send_eof(self) -> None:
        self._send_eof = True
        self._wake_all()

    def close_sender(self) -> None:
        # Graceful close of the send side: like send_eof, all accepted data
        # is delivered before the receiver sees EOF.
        self._send_closed = True
        self._wake_all()

    def close_receiver(self) -> None:
        # Closing the receive side discards all undelivered and unread data,
        # and the send side sees BrokenResourceError.
        self._recv_closed = True
        self._segments.clear()
        self._buffered = 0
        self._delivered = bytearray()
        self._wake_all()

    def receive_some(self, max_bytes: int | None) -> bytearray | None:
        """Non-blocking part of receive_some; returns None if the caller
        needs to wait for more data to arrive."""
        now = _core.current_time()
        self._refresh(now)
        if self._delivered:
            if max_bytes is None:
                max_bytes = len(self._delivered)
            data = self._delivered[:max_bytes]
            del self._delivered[:max_bytes]
            return data
        if self._broken:
            raise _core.BrokenResourceError("connection was disconnected")
        if (self._send_eof or self._send_closed) and not self._segments:
            return bytearray()  # EOF: all accepted data has been delivered
        return None


@_util.final
class SimulatedStream(
    HalfCloseableStream, metaclass=_util.NoPublicConstructor
):
    """A bidirectional stream connected to a peer over simulated links, as
    created by :func:`simulated_stream_pair`.

    Each direction of the connection is an independent simulated link (see
    :class:`LinkConfig`), so one direction stalling (e.g. a full send
    buffer) never blocks progress in the other direction.

    """

    def __init__(self, outgoing: _Link, incoming: _Link) -> None:
        self._outgoing = outgoing
        self._incoming = incoming
        self._send_conflict_detector = _util.ConflictDetector(
            "another task is using this stream's send side",
        )
        self._receive_conflict_detector = _util.ConflictDetector(
            "another task is using this stream's receive side",
        )
        self._closed = False

    async def send_all(self, data: bytes | bytearray | memoryview) -> None:
        """Accepts data into the outgoing link's send buffer, blocking if
        the buffer is full until the link has transmitted enough bytes to
        make room (backpressure).

        If the call is cancelled partway through, the bytes that were
        already accepted into the buffer remain accepted and will be
        transmitted as usual; only the remainder is discarded.

        """
        with self._send_conflict_detector:
            await _core.checkpoint()
            await _core.checkpoint()
            await self._outgoing.send_all(data)

    async def wait_send_all_might_not_block(self) -> None:
        """Blocks until the outgoing link's send buffer has room for at
        least one more byte."""
        with self._send_conflict_detector:
            await _core.checkpoint()
            await _core.checkpoint()
            await self._outgoing.wait_send_all_might_not_block()

    async def send_eof(self) -> None:
        """Gracefully half-closes the send side: all data accepted so far
        will be delivered to the peer, followed by end-of-file. Idempotent.
        """
        with self._send_conflict_detector:
            await _core.checkpoint()
            await _core.checkpoint()
            if self._closed:
                raise _core.ClosedResourceError("stream is closed")
            self._outgoing.send_eof()

    async def receive_some(self, max_bytes: int | None = None) -> bytearray:
        """Receives data that has arrived on the incoming link, blocking if
        necessary. Raises :exc:`trio.BrokenResourceError` if the link
        broke (see :attr:`LinkConfig.disconnect_after`) after all data
        delivered before the break has been consumed.
        """
        with self._receive_conflict_detector:
            await _core.checkpoint()
            await _core.checkpoint()
            if max_bytes is not None:
                max_bytes = operator.index(max_bytes)
                if max_bytes < 1:
                    raise ValueError("max_bytes must be >= 1")
            while True:
                if self._closed:
                    raise _core.ClosedResourceError("stream is closed")
                data = self._incoming.receive_some(max_bytes)
                if data is not None:
                    return data
                await self._incoming._park_until(self._incoming._next_arrival())

    def close(self) -> None:
        """Closes both directions. The send side is closed gracefully (all
        accepted data is delivered, then EOF); the receive side discards any
        unread data, and the peer's send side will see
        :exc:`trio.BrokenResourceError`. Idempotent.
        """
        if not self._closed:
            self._closed = True
            self._outgoing.close_sender()
            self._incoming.close_receiver()

    async def aclose(self) -> None:
        """Same as :meth:`close`, but async."""
        self.close()
        await _core.checkpoint()


def simulated_stream_pair(
    *,
    forward: LinkConfig | None = None,
    backward: LinkConfig | None = None,
) -> tuple[SimulatedStream, SimulatedStream]:
    """Create a connected, pure-Python, bidirectional stream pair that
    simulates a network connection with configurable transmission
    characteristics.

    Args:
      forward (LinkConfig): Configuration for the left-to-right direction.
      backward (LinkConfig): Configuration for the right-to-left direction.

    Returns:
      A pair ``(left, right)`` of :class:`SimulatedStream`
      objects. Data sent on ``left`` is received on ``right``
      subject to the ``forward`` link configuration, and vice versa.
      The two directions are fully independent: one of them stalling never
      blocks the other.

    Unlike :func:`memory_stream_pair`, this models a finite-bandwidth,
    non-zero-latency, finitely-buffered link, so it's useful for testing how
    a protocol implementation behaves on slow or constrained connections:
    :meth:`~trio.abc.SendStream.send_all` applies backpressure once the
    send buffer fills up, and data takes time to arrive at the peer.

    All timing is done through the current Trio clock, so tests can use
    :class:`MockClock` (e.g. with ``autojump_threshold=0``) to
    simulate hours of network time in milliseconds of real time.

    The link is an ordered, lossless byte stream: it does not simulate
    packet loss, reordering, or corruption. The only disorderly event it
    models is a forceful disconnect (see
    :attr:`LinkConfig.disconnect_after`), which discards all undelivered
    data in that direction and surfaces as
    :exc:`trio.BrokenResourceError` on both ends.

    Example::

        left, right = simulated_stream_pair(
            forward=LinkConfig(bandwidth=1000, latency=0.05),
            backward=LinkConfig(bandwidth=1000, latency=0.05),
        )
        await left.send_all(b"hello")
        assert await right.receive_some(5) == b"hello"  # arrives 55 ms later

    """
    if forward is None:
        forward = LinkConfig()
    if backward is None:
        backward = LinkConfig()
    forward_link = _Link(forward)
    backward_link = _Link(backward)
    left = SimulatedStream._create(outgoing=forward_link, incoming=backward_link)
    right = SimulatedStream._create(outgoing=backward_link, incoming=forward_link)
    return left, right


# TODO: investigate why this is necessary for the docs
SimulatedStream.__module__ = SimulatedStream.__module__.replace(
    "._simulated_streams", ""
)
LinkConfig.__module__ = LinkConfig.__module__.replace("._simulated_streams", "")
