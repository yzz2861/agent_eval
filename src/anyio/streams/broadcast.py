from __future__ import annotations

__all__ = (
    "BroadcastOverflowError",
    "BroadcastReceiveStream",
    "BroadcastStream",
)

import math
import warnings
from collections import deque
from dataclasses import dataclass, field
from types import TracebackType
from typing import Generic, Literal, TypeVar

from .._core._exceptions import (
    BrokenResourceError,
    ClosedResourceError,
    EndOfStream,
    WouldBlock,
)
from .._core._synchronization import Event
from ..abc import ObjectReceiveStream, ObjectSendStream
from ..lowlevel import checkpoint

T_Item = TypeVar("T_Item")


class BroadcastOverflowError(BrokenResourceError):
    """
    Raised when trying to receive from a broadcast subscriber that was dropped from
    the broadcast because its buffer overflowed.

    This only happens when the broadcast stream was created with
    ``on_overflow="close"``.

    .. versionadded:: 4.16.0
    """


@dataclass(eq=False)
class _BroadcastSubscriber(Generic[T_Item]):
    buffer: deque[T_Item] = field(init=False, default_factory=deque)
    receive_events: set[Event] = field(init=False, default_factory=set)
    overflow_error: BroadcastOverflowError | None = field(init=False, default=None)


@dataclass(eq=False)
class _BroadcastStreamState(Generic[T_Item]):
    max_buffer_size: float
    on_overflow: Literal["wait", "close"]
    subscribers: list[_BroadcastSubscriber[T_Item]] = field(
        init=False, default_factory=list
    )
    space_waiters: set[Event] = field(init=False, default_factory=set)
    closed: bool = field(init=False, default=False)

    def wake_space_waiters(self) -> None:
        waiters = self.space_waiters
        self.space_waiters = set()
        for event in waiters:
            event.set()


def _wake_subscriber(subscriber: _BroadcastSubscriber[T_Item]) -> None:
    if subscriber.receive_events:
        events = subscriber.receive_events
        subscriber.receive_events = set()
        for event in events:
            event.set()


def _deliver(subscriber: _BroadcastSubscriber[T_Item], item: T_Item) -> None:
    subscriber.buffer.append(item)
    _wake_subscriber(subscriber)


class BroadcastStream(ObjectSendStream[T_Item], Generic[T_Item]):
    """
    A broadcast (publish-subscribe) object stream.

    Every item sent to this stream is delivered to *every* currently subscribed
    receive stream (created via :meth:`subscribe`). This is the opposite of cloning
    a memory object stream, where each item is distributed to only one of the clones.

    Each subscriber has its own buffer of at most ``max_buffer_size`` items and only
    receives items whose delivery takes place after it subscribed. Delivery is
    atomic: an item is always delivered to either all or none of the current
    subscribers, so if :meth:`send` returns normally, every subscriber received the
    item, and if it is cancelled while waiting for buffer space, no subscriber
    received it.

    Closing a subscriber unsubscribes it; closing this stream lets subscribers drain
    their remaining buffered items before they see the end of the stream.

    :param max_buffer_size: maximum number of items held in each subscriber's buffer
        before the overflow policy kicks in (with 0, every send waits until all
        subscribers are ready to receive)
    :param on_overflow: what to do when a subscriber's buffer is full: ``"wait"``
        (the default) makes :meth:`send` wait until every subscriber has room, while
        ``"close"`` drops the lagging subscriber, causing its
        :meth:`~BroadcastReceiveStream.receive` to raise
        :class:`BroadcastOverflowError`

    .. versionadded:: 4.16.0
    """

    def __init__(
        self,
        max_buffer_size: float = 0,
        *,
        on_overflow: Literal["wait", "close"] = "wait",
    ) -> None:
        if max_buffer_size != math.inf and not isinstance(max_buffer_size, int):
            raise ValueError("max_buffer_size must be either an integer or math.inf")
        if max_buffer_size < 0:
            raise ValueError("max_buffer_size cannot be negative")
        if on_overflow not in ("wait", "close"):
            raise ValueError('on_overflow must be either "wait" or "close"')

        self._state: _BroadcastStreamState[T_Item] = _BroadcastStreamState(
            max_buffer_size, on_overflow
        )

    def subscribe(self) -> BroadcastReceiveStream[T_Item]:
        """
        Create a new subscription to this broadcast stream.

        The returned receive stream will receive every item whose delivery takes
        place after this method has returned. Items published earlier are not
        replayed.

        :return: the receive stream of the new subscriber
        :raises ~anyio.ClosedResourceError: if this broadcast stream has been closed

        """
        if self._state.closed:
            raise ClosedResourceError

        subscriber = _BroadcastSubscriber[T_Item]()
        self._state.subscribers.append(subscriber)
        return BroadcastReceiveStream(self._state, subscriber)

    def send_nowait(self, item: T_Item) -> None:
        """
        Deliver an item to every subscriber, if that can be done without waiting.

        The item is delivered atomically: if any subscriber cannot accept it (and
        the overflow policy is ``"wait"``), :exc:`~anyio.WouldBlock` is raised and
        the item is not delivered to any subscriber. With the ``"close"`` overflow
        policy this method never blocks; subscribers with a full buffer are dropped
        instead.

        If there are no subscribers, the item is silently discarded.

        :param item: the item to send
        :raises ~anyio.ClosedResourceError: if this broadcast stream has been closed
        :raises ~anyio.WouldBlock: if the overflow policy is ``"wait"`` and at
            least one subscriber's buffer is full

        """
        state = self._state
        if state.closed:
            raise ClosedResourceError

        if state.on_overflow == "close":
            for subscriber in list(state.subscribers):
                if (
                    len(subscriber.buffer) < state.max_buffer_size
                    or subscriber.receive_events
                ):
                    _deliver(subscriber, item)
                else:
                    # Drop the lagging subscriber
                    state.subscribers.remove(subscriber)
                    subscriber.buffer.clear()
                    subscriber.overflow_error = BroadcastOverflowError(
                        "subscriber was dropped from the broadcast because its "
                        f"buffer of {state.max_buffer_size} items overflowed"
                    )
                    _wake_subscriber(subscriber)

            return

        for subscriber in state.subscribers:
            if (
                len(subscriber.buffer) >= state.max_buffer_size
                and not subscriber.receive_events
            ):
                raise WouldBlock

        for subscriber in state.subscribers:
            _deliver(subscriber, item)

    async def send(self, item: T_Item) -> None:
        """
        Deliver an item to every subscriber.

        If the overflow policy is ``"wait"`` and at least one subscriber's buffer
        is full, this method blocks until every subscriber has room for the item.

        The item is delivered atomically: if this method returns normally, the item
        was delivered to every subscriber, and if it is cancelled while waiting,
        the item is guaranteed to not have been delivered to any subscriber.

        If there are no subscribers, the item is silently discarded.

        :param item: the item to send
        :raises ~anyio.ClosedResourceError: if this broadcast stream has been closed

        """
        await checkpoint()
        while True:
            try:
                self.send_nowait(item)
            except WouldBlock:
                space_event = Event()
                self._state.space_waiters.add(space_event)
                try:
                    await space_event.wait()
                finally:
                    self._state.space_waiters.discard(space_event)
            else:
                return

    def close(self) -> None:
        """
        Close the stream.

        Subscribers will see the end of the stream once they have received the
        items remaining in their buffers. This works the exact same way as
        :meth:`aclose`, but is provided as a special case for the benefit of
        synchronous callbacks.

        """
        state = self._state
        if not state.closed:
            state.closed = True
            for subscriber in state.subscribers:
                _wake_subscriber(subscriber)

            state.wake_space_waiters()

    async def aclose(self) -> None:
        self.close()

    def __enter__(self) -> BroadcastStream[T_Item]:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        # The attribute may be missing if __init__ raised an exception
        if (state := getattr(self, "_state", None)) is not None and not state.closed:
            warnings.warn(
                f"Unclosed <{self.__class__.__name__} at {id(self):x}>",
                ResourceWarning,
                stacklevel=1,
                source=self,
            )


@dataclass(eq=False)
class BroadcastReceiveStream(ObjectReceiveStream[T_Item], Generic[T_Item]):
    """
    The receiving end of a subscription to a :class:`BroadcastStream`.

    Instances of this class are created by :meth:`BroadcastStream.subscribe`.
    Closing the stream unsubscribes it from the broadcast; any items still in its
    buffer are discarded.

    .. versionadded:: 4.16.0
    """

    _state: _BroadcastStreamState[T_Item]
    _subscriber: _BroadcastSubscriber[T_Item]
    _closed: bool = field(init=False, default=False)

    def receive_nowait(self) -> T_Item:
        """
        Receive the next item if it can be done without waiting.

        :return: the received item
        :raises ~anyio.ClosedResourceError: if this receive stream has been closed
        :raises ~anyio.streams.broadcast.BroadcastOverflowError: if this subscriber
            was dropped from the broadcast because its buffer overflowed
        :raises ~anyio.EndOfStream: if the buffer is empty and the broadcast stream
            has been closed
        :raises ~anyio.WouldBlock: if there are no items in the buffer

        """
        if self._closed:
            raise ClosedResourceError

        subscriber = self._subscriber
        if subscriber.buffer:
            item = subscriber.buffer.popleft()
            self._state.wake_space_waiters()
            return item

        if subscriber.overflow_error is not None:
            raise subscriber.overflow_error

        if self._state.closed:
            raise EndOfStream

        raise WouldBlock

    async def receive(self) -> T_Item:
        """
        Receive the next item.

        This blocks until an item is published to this subscriber, the broadcast
        stream is closed, or this subscriber is dropped due to a buffer overflow.

        :return: the received item
        :raises ~anyio.ClosedResourceError: if this receive stream has been closed
        :raises ~anyio.streams.broadcast.BroadcastOverflowError: if this subscriber
            was dropped from the broadcast because its buffer overflowed
        :raises ~anyio.EndOfStream: if the buffer is empty and the broadcast stream
            has been closed

        """
        await checkpoint()
        if self._closed:
            raise ClosedResourceError

        subscriber = self._subscriber
        state = self._state
        while True:
            if self._closed:
                raise ClosedResourceError

            if subscriber.buffer:
                item = subscriber.buffer.popleft()
                state.wake_space_waiters()
                return item

            if subscriber.overflow_error is not None:
                raise subscriber.overflow_error

            if state.closed:
                raise EndOfStream

            receive_event = Event()
            subscriber.receive_events.add(receive_event)
            # A send may be waiting for this subscriber to become ready to receive
            state.wake_space_waiters()
            try:
                await receive_event.wait()
            finally:
                subscriber.receive_events.discard(receive_event)

    def close(self) -> None:
        """
        Close the stream and unsubscribe from the broadcast.

        Any items remaining in the buffer are discarded. This works the exact same
        way as :meth:`aclose`, but is provided as a special case for the benefit of
        synchronous callbacks.

        """
        if not self._closed:
            self._closed = True
            state = self._state
            if self._subscriber in state.subscribers:
                state.subscribers.remove(self._subscriber)

            _wake_subscriber(self._subscriber)
            state.wake_space_waiters()

    async def aclose(self) -> None:
        self.close()

    def __enter__(self) -> BroadcastReceiveStream[T_Item]:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if (
            not self._closed
            and not self._state.closed
            and self._subscriber.overflow_error is None
        ):
            warnings.warn(
                f"Unclosed <{self.__class__.__name__} at {id(self):x}>",
                ResourceWarning,
                stacklevel=1,
                source=self,
            )
