from __future__ import annotations

__all__ = (
    "BroadcastReceiveStream",
    "BroadcastSendStream",
    "BroadcastStreamStatistics",
)

import warnings
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from types import TracebackType
from typing import Generic, Literal, NamedTuple, TypeVar

from .._core._exceptions import (
    ClosedResourceError,
    EndOfStream,
    SubscriberOverflowError,
    WouldBlock,
)
from .._core._synchronization import Event
from .._core._testing import TaskInfo, get_current_task
from ..abc import ObjectReceiveStream, ObjectSendStream
from ..lowlevel import checkpoint

T_Item = TypeVar("T_Item")
T_co = TypeVar("T_co", covariant=True)
T_contra = TypeVar("T_contra", contravariant=True)

#: The policy applied when a subscriber's buffer is full: `"wait"` makes senders
#: wait until every subscriber has room in its buffer, while `"close"` disconnects
#: the lagging subscribers
OverflowPolicy = Literal["wait", "close"]


class BroadcastStreamStatistics(NamedTuple):
    open_subscribers: int  #: number of subscribers still receiving items
    #: number of tasks blocked on :meth:`BroadcastSendStream.send`
    tasks_waiting_send: int
    #: number of tasks blocked on :meth:`BroadcastReceiveStream.receive`
    tasks_waiting_receive: int


@dataclass(eq=False)
class _BroadcastItemReceiver(Generic[T_Item]):
    task_info: TaskInfo = field(init=False, default_factory=get_current_task)
    item: T_Item = field(init=False)


@dataclass(eq=False)
class _BroadcastStreamState(Generic[T_Item]):
    max_buffer_size: int = field()
    overflow_policy: OverflowPolicy = field()
    send_stream_open: bool = field(init=False, default=True)
    subscribers: list[BroadcastReceiveStream[T_Item]] = field(
        init=False, default_factory=list
    )
    waiting_senders: set[Event] = field(init=False, default_factory=set)

    def statistics(self) -> BroadcastStreamStatistics:
        return BroadcastStreamStatistics(
            len(self.subscribers),
            len(self.waiting_senders),
            sum(len(subscriber._waiting_receivers) for subscriber in self.subscribers),
        )

    def all_subscribers_have_room(self) -> bool:
        return all(
            subscriber._waiting_receivers
            or len(subscriber._buffer) < self.max_buffer_size
            for subscriber in self.subscribers
        )

    def wake_waiting_senders(self) -> None:
        if self.waiting_senders and self.all_subscribers_have_room():
            waiting_senders = list(self.waiting_senders)
            for event in waiting_senders:
                event.set()


@dataclass(eq=False)
class BroadcastReceiveStream(ObjectReceiveStream[T_co], Generic[T_co]):
    """
    The receiving end of a broadcast stream subscription.

    Each subscriber receives its own copy of every item sent via
    :meth:`BroadcastSendStream.send` after the subscription was created, in the
    original send order. Items are buffered per subscriber, up to the maximum buffer
    size of the broadcast stream.

    .. versionadded:: 4.16
    """

    _state: _BroadcastStreamState[T_co]
    _closed: bool = field(init=False, default=False)
    _overflowed: bool = field(init=False, default=False)
    _buffer: deque[T_co] = field(init=False, default_factory=deque)
    _waiting_receivers: OrderedDict[Event, _BroadcastItemReceiver[T_co]] = field(
        init=False, default_factory=OrderedDict
    )

    def receive_nowait(self) -> T_co:
        """
        Receive the next item if it can be done without waiting.

        :return: the received item
        :raises ~anyio.ClosedResourceError: if this stream has been closed
        :raises ~anyio.SubscriberOverflowError: if the buffer has been drained after
            this subscriber was disconnected due to a buffer overflow
        :raises ~anyio.EndOfStream: if the buffer is empty and the send stream has
            been closed
        :raises ~anyio.WouldBlock: if there are no items in the buffer

        """
        if self._closed:
            raise ClosedResourceError

        if self._buffer:
            item = self._buffer.popleft()
            self._state.wake_waiting_senders()
            return item

        if self._overflowed:
            raise SubscriberOverflowError

        if not self._state.send_stream_open:
            raise EndOfStream

        raise WouldBlock

    async def receive(self) -> T_co:
        await checkpoint()
        try:
            return self.receive_nowait()
        except WouldBlock:
            # Add ourselves in the queue
            receive_event = Event()
            receiver = _BroadcastItemReceiver[T_co]()
            self._waiting_receivers[receive_event] = receiver
            # A waiting receiver counts as room in the buffer
            self._state.wake_waiting_senders()

            try:
                await receive_event.wait()
            finally:
                self._waiting_receivers.pop(receive_event, None)

            try:
                return receiver.item
            except AttributeError:
                if self._closed:
                    raise ClosedResourceError from None

                if self._overflowed:
                    raise SubscriberOverflowError from None

                raise EndOfStream from None

    def close(self) -> None:
        """
        Close the stream.

        This works the exact same way as :meth:`aclose`, but is provided as a special
        case for the benefit of synchronous callbacks.

        """
        if not self._closed:
            self._closed = True
            if self in self._state.subscribers:
                self._state.subscribers.remove(self)

            receive_events = list(self._waiting_receivers.keys())
            self._waiting_receivers.clear()
            for event in receive_events:
                event.set()

            self._state.wake_waiting_senders()

    async def aclose(self) -> None:
        self.close()

    def statistics(self) -> BroadcastStreamStatistics:
        """
        Return statistics about the current state of the broadcast stream.

        .. versionadded:: 4.16
        """
        return self._state.statistics()

    def __enter__(self) -> BroadcastReceiveStream[T_co]:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            warnings.warn(
                f"Unclosed <{self.__class__.__name__} at {id(self):x}>",
                ResourceWarning,
                stacklevel=1,
                source=self,
            )

    def _deliver(self, item: T_co) -> None:
        while self._waiting_receivers:
            receive_event, receiver = self._waiting_receivers.popitem(last=False)
            if not receiver.task_info.has_pending_cancellation():
                receiver.item = item
                receive_event.set()
                return

        if len(self._buffer) < self._state.max_buffer_size:
            self._buffer.append(item)
        else:
            self._overflow()

    def _overflow(self) -> None:
        self._overflowed = True
        self._state.subscribers.remove(self)
        receive_events = list(self._waiting_receivers.keys())
        self._waiting_receivers.clear()
        for event in receive_events:
            event.set()


@dataclass(eq=False)
class BroadcastSendStream(ObjectSendStream[T_contra], Generic[T_contra]):
    """
    The sending end of a broadcast stream.

    Every item sent is delivered to every current subscriber. Subscriptions are
    created with :meth:`subscribe`. The send stream can be safely shared by multiple
    publisher tasks; each call to :meth:`send` takes effect atomically, so if it is
    cancelled or otherwise raises, the item is guaranteed not to have been delivered
    to any subscriber.

    .. versionadded:: 4.16
    """

    _state: _BroadcastStreamState[T_contra]
    _closed: bool = field(init=False, default=False)

    def subscribe(self) -> BroadcastReceiveStream[T_contra]:
        """
        Create a new subscription to this broadcast stream.

        The subscriber will only receive items sent after this method has returned.

        :return: the receive stream of the new subscriber
        :raises ~anyio.ClosedResourceError: if this send stream has been closed

        """
        if self._closed:
            raise ClosedResourceError

        subscriber: BroadcastReceiveStream[T_contra] = BroadcastReceiveStream(
            self._state
        )
        self._state.subscribers.append(subscriber)
        return subscriber

    def send_nowait(self, item: T_contra) -> None:
        """
        Send an item immediately if it can be done without waiting.

        The item is delivered to every current subscriber. If there are no
        subscribers, the item is silently discarded.

        :param item: the item to send
        :raises ~anyio.ClosedResourceError: if this send stream has been closed
        :raises ~anyio.WouldBlock: if the overflow policy is `"wait"` and at least
            one subscriber's buffer is full

        """
        if self._closed:
            raise ClosedResourceError

        if (
            self._state.overflow_policy == "wait"
            and not self._state.all_subscribers_have_room()
        ):
            raise WouldBlock

        for subscriber in list(self._state.subscribers):
            subscriber._deliver(item)

    async def send(self, item: T_contra) -> None:
        """
        Send an item to every current subscriber.

        If the overflow policy is `"wait"` and at least one subscriber's buffer is
        full, this method blocks until every subscriber has room in its buffer. With
        the `"close"` overflow policy, this method never blocks, but subscribers
        whose buffers are full are disconnected and will raise
        :exc:`~anyio.SubscriberOverflowError` once they have drained their buffers.

        The delivery is atomic: if this method returns, the item was delivered to
        every subscriber that was subscribed at the moment of delivery, and if it is
        cancelled or raises, the item was not delivered to any subscriber.

        :param item: the item to send
        :raises ~anyio.ClosedResourceError: if this send stream has been closed

        """
        await checkpoint()
        while True:
            try:
                self.send_nowait(item)
            except WouldBlock:
                # Wait until every subscriber has room in its buffer
                send_event = Event()
                self._state.waiting_senders.add(send_event)
                try:
                    await send_event.wait()
                finally:
                    self._state.waiting_senders.discard(send_event)
            else:
                return

    def close(self) -> None:
        """
        Close the stream.

        This works the exact same way as :meth:`aclose`, but is provided as a special
        case for the benefit of synchronous callbacks.

        """
        if not self._closed:
            self._closed = True
            self._state.send_stream_open = False

            send_events = list(self._state.waiting_senders)
            self._state.waiting_senders.clear()
            for event in send_events:
                event.set()

            for subscriber in list(self._state.subscribers):
                receive_events = list(subscriber._waiting_receivers.keys())
                subscriber._waiting_receivers.clear()
                for event in receive_events:
                    event.set()

    async def aclose(self) -> None:
        self.close()

    def statistics(self) -> BroadcastStreamStatistics:
        """
        Return statistics about the current state of the broadcast stream.

        .. versionadded:: 4.16
        """
        return self._state.statistics()

    def __enter__(self) -> BroadcastSendStream[T_contra]:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if not self._closed:
            warnings.warn(
                f"Unclosed <{self.__class__.__name__} at {id(self):x}>",
                ResourceWarning,
                stacklevel=1,
                source=self,
            )

