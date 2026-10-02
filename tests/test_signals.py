from __future__ import annotations

import asyncio
import collections.abc as c
import gc
import sys
import threading
import typing as t

import pytest

import blinker


def collect_acyclic_refs() -> None:
    # cpython releases these immediately without a collection
    if sys.implementation.name == "pypy":
        gc.collect()


class Sentinel(list):  # type: ignore[type-arg]
    """A signal receipt accumulator."""

    def make_receiver(self, key: t.Any) -> c.Callable[..., t.Any]:
        """Return a generic signal receiver function logging as *key*

        When connected to a signal, appends (key, sender, kw) to the Sentinel.

        """

        def receiver(*sentby: t.Any, **kw: t.Any) -> None:
            self.append((key, sentby[0], kw))

        return receiver


def _test_signal_signals(sender: t.Any) -> None:
    sentinel = Sentinel()
    sig = blinker.Signal()

    connected = sentinel.make_receiver("receiver_connected")
    disconnected = sentinel.make_receiver("receiver_disconnected")
    receiver1 = sentinel.make_receiver("receiver1")
    receiver2 = sentinel.make_receiver("receiver2")

    assert not sig.receiver_connected.receivers
    assert not sig.receiver_disconnected.receivers
    sig.receiver_connected.connect(connected)
    sig.receiver_disconnected.connect(disconnected)

    assert sig.receiver_connected.receivers
    assert not sentinel

    for receiver, weak in [(receiver1, True), (receiver2, False)]:
        sig.connect(receiver, sender=sender, weak=weak)

        expected = (
            "receiver_connected",
            sig,
            {"receiver": receiver, "sender": sender, "weak": weak},
        )

        assert sentinel[-1] == expected

    # disconnect from explicit sender
    sig.disconnect(receiver1, sender=sender)

    expected = ("receiver_disconnected", sig, {"receiver": receiver1, "sender": sender})
    assert sentinel[-1] == expected

    # disconnect from ANY and all senders (implicit disconnect signature)
    sig.disconnect(receiver2)
    assert sentinel[-1] == (
        "receiver_disconnected",
        sig,
        {"receiver": receiver2, "sender": blinker.ANY},
    )


def test_signal_signals_any_sender() -> None:
    _test_signal_signals(blinker.ANY)


def test_signal_signals_strong_sender() -> None:
    _test_signal_signals("squiznart")


def test_signal_weak_receiver_vanishes() -> None:
    # non-edge-case path for weak receivers is exercised in the ANY sender
    # test above.
    sentinel = Sentinel()
    sig = blinker.Signal()

    connected = sentinel.make_receiver("receiver_connected")
    disconnected = sentinel.make_receiver("receiver_disconnected")
    receiver1 = sentinel.make_receiver("receiver1")
    receiver2 = sentinel.make_receiver("receiver2")

    sig.receiver_connected.connect(connected)
    sig.receiver_disconnected.connect(disconnected)

    # explicit disconnect on a weak does emit the signal
    sig.connect(receiver1, weak=True)
    sig.disconnect(receiver1)

    assert len(sentinel) == 2
    assert sentinel[-1][2]["receiver"] is receiver1

    del sentinel[:]
    sig.connect(receiver2, weak=True)
    assert len(sentinel) == 1

    del sentinel[:]  # holds a ref to receiver2
    del receiver2
    collect_acyclic_refs()

    # no disconnect signal is fired
    assert len(sentinel) == 0

    # and everything really is disconnected
    sig.send("abc")
    assert len(sentinel) == 0


def test_signal_signals_weak_sender() -> None:
    sentinel = Sentinel()
    sig = blinker.Signal()

    connected = sentinel.make_receiver("receiver_connected")
    disconnected = sentinel.make_receiver("receiver_disconnected")
    receiver1 = sentinel.make_receiver("receiver1")
    receiver2 = sentinel.make_receiver("receiver2")

    class Sender:
        """A weakref-able object."""

    sig.receiver_connected.connect(connected)
    sig.receiver_disconnected.connect(disconnected)

    sender1 = Sender()
    sig.connect(receiver1, sender=sender1, weak=False)
    # regular disconnect of weak-able sender works fine
    sig.disconnect(receiver1, sender=sender1)

    assert len(sentinel) == 2

    del sentinel[:]
    sender2 = Sender()
    sig.connect(receiver2, sender=sender2, weak=False)

    # force sender2 to go out of scope
    del sender2
    collect_acyclic_refs()

    # no disconnect signal is fired
    assert len(sentinel) == 1

    # and everything really is disconnected
    sig.send("abc")
    assert len(sentinel) == 1


def test_empty_bucket_growth() -> None:
    def senders() -> tuple[int, int]:
        return (
            len(sig._by_sender),
            sum(len(i) for i in sig._by_sender.values()),
        )

    def receivers() -> tuple[int, int]:
        return (
            len(sig._by_receiver),
            sum(len(i) for i in sig._by_receiver.values()),
        )

    sentinel = Sentinel()
    sig = blinker.Signal()
    receiver1 = sentinel.make_receiver("receiver1")
    receiver2 = sentinel.make_receiver("receiver2")

    class Sender:
        """A weakref-able object."""

    sender = Sender()
    sig.connect(receiver1, sender=sender)
    sig.connect(receiver2, sender=sender)

    assert senders() == (1, 2)
    assert receivers() == (2, 2)

    sig.disconnect(receiver1, sender=sender)

    assert senders() == (1, 1)
    assert receivers() == (2, 1)

    sig.disconnect(receiver2, sender=sender)

    assert senders() == (1, 0)
    assert receivers() == (2, 0)

    sig._cleanup_bookkeeping()
    assert senders() == (0, 0)
    assert receivers() == (0, 0)


def test_namespace() -> None:
    ns = blinker.Namespace()
    assert not ns
    s1 = ns.signal("abc")
    assert s1 is ns.signal("abc")
    assert s1 is not ns.signal("def")
    assert "abc" in ns

    del s1
    collect_acyclic_refs()

    assert "def" in ns
    assert "abc" in ns


def test_weak_receiver() -> None:
    sentinel = []

    def received(sender: t.Any, **kw: t.Any) -> None:
        sentinel.append(kw)

    sig = blinker.Signal()

    sig.connect(received, weak=True)

    del received
    collect_acyclic_refs()

    assert not sentinel
    sig.send()
    assert not sentinel
    assert not sig.receivers
    values_are_empty_sets_(sig._by_receiver)
    values_are_empty_sets_(sig._by_sender)


def test_strong_receiver() -> None:
    sentinel = []

    def received(sender: t.Any) -> None:
        sentinel.append(sender)

    fn_id = id(received)

    sig = blinker.Signal()
    sig.connect(received, weak=False)

    del received
    collect_acyclic_refs()

    assert not sentinel
    sig.send()
    assert sentinel
    assert [id(fn) for fn in sig.receivers.values()] == [fn_id]


async def test_async_receiver() -> None:
    sentinel = []

    async def received_async(sender: t.Any) -> None:
        sentinel.append(sender)

    def received(sender: t.Any) -> None:
        sentinel.append(sender)

    def wrapper(func: c.Callable[..., t.Any]) -> c.Callable[..., None]:
        async def inner(*args: t.Any, **kwargs: t.Any) -> None:
            func(*args, **kwargs)

        return inner  # type: ignore[return-value]

    sig = blinker.Signal()
    sig.connect(received)
    sig.connect(received_async)

    await sig.send_async(_sync_wrapper=wrapper)  # type: ignore[arg-type]
    assert len(sentinel) == 2

    with pytest.raises(RuntimeError):
        sig.send()


def test_connect_once() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    sig.connect_once(received, weak=False)

    sig.send(1)
    sig.send(2)

    assert calls == [1]
    assert not sig.receivers
    assert not sig._once_connections


def test_connect_once_preserves_custom_receiver_order() -> None:
    class OrderedSet:
        _values: list[t.Any]

        def __init__(self, values: c.Iterable[t.Any] = ()) -> None:
            self._values = list(dict.fromkeys(values))

        def __iter__(self) -> c.Iterator[t.Any]:
            return iter(self._values)

        def add(self, value: t.Any) -> None:
            if value not in self._values:
                self._values.append(value)

        def discard(self, value: t.Any) -> None:
            if value in self._values:
                self._values.remove(value)

        def __ior__(self, other: c.Iterable[t.Any]) -> OrderedSet:
            for value in other:
                self.add(value)

            return self

    calls = []

    class OrderedSignal(blinker.Signal):
        set_class = OrderedSet  # type: ignore[assignment]

    sig = OrderedSignal()
    sig.connect_once(lambda sender: calls.append("first"), weak=False)
    sig.connect_once(lambda sender: calls.append("second"), weak=False)

    sig.send()

    assert calls == ["first", "second"]


def test_connect_once_filtered_sender() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    sig.connect_once(received, sender=123, weak=False)

    sig.send()
    sig.send(456)
    assert calls == []

    sig.send(123)
    sig.send(123)
    assert calls == [123]


def test_connect_once_is_claimed_before_reentrant_send() -> None:
    calls = []
    sig = blinker.Signal()

    def received(sender: t.Any) -> None:
        calls.append(sender)
        sig.send(sender)

    sig.connect_once(received, weak=False)
    sig.send(123)

    assert calls == [123]
    assert not sig.receivers
    assert not sig._once_connections


def test_connect_once_is_consumed_when_receiver_raises() -> None:
    def received(sender: t.Any) -> None:
        raise RuntimeError(sender)

    sig = blinker.Signal()
    sig.connect_once(received, weak=False)

    with pytest.raises(RuntimeError):
        sig.send(123)

    sig.send(456)

    assert not sig.receivers
    assert not sig._once_connections
    sig._cleanup_bookkeeping()
    values_are_empty_sets_(sig._by_receiver)
    values_are_empty_sets_(sig._by_sender)


def test_connect_once_concurrent_send() -> None:
    sig = blinker.Signal()
    barrier = threading.Barrier(2)
    calls: list[t.Any] = []
    calls_lock = threading.Lock()

    def received(sender: t.Any) -> None:
        with calls_lock:
            calls.append(sender)

    sig.connect_once(received, weak=False)

    def send() -> None:
        barrier.wait(5)
        sig.send(123)

    def second_send() -> None:
        barrier.wait(5)
        sig.send(123)

    first_thread = threading.Thread(target=send)
    second_thread = threading.Thread(target=second_send)
    threads = [first_thread, second_thread]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()

    assert calls == [123]
    assert not sig.receivers
    assert not sig._once_connections


def test_once_and_normal_connections_are_independent() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    receiver_id = blinker.base.make_id(received)
    sender_id = blinker.base.make_id(123)

    sig.connect(received, sender=123, weak=False)
    sig.connect_once(received, sender=123, weak=False)
    sig.send(123)
    sig.send(123)

    assert calls == [123, 123]
    assert (sender_id, receiver_id) not in sig._once_connections
    assert (sender_id, receiver_id) in sig._connections


def test_once_any_and_normal_sender_are_independent() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    receiver_id = blinker.base.make_id(received)
    sender_id = blinker.base.make_id(123)

    sig.connect_once(received, sender=blinker.ANY, weak=False)
    sig.connect(received, sender=123, weak=False)

    sig.send(123)
    sig.send(456)
    sig.send(123)

    assert calls == [123, 123]
    assert (blinker.base.ANY_ID, receiver_id) not in sig._once_connections
    assert (sender_id, receiver_id) in sig._connections


def test_once_any_and_sender_are_independent() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    receiver_id = blinker.base.make_id(received)
    sender_id = blinker.base.make_id(123)

    sig.connect_once(received, sender=blinker.ANY, weak=False)
    sig.connect_once(received, sender=123, weak=False)

    sig.send(123)
    sig.send(456)
    sig.send(123)

    assert calls == [123]
    assert (blinker.base.ANY_ID, receiver_id) not in sig._once_connections
    assert (sender_id, receiver_id) not in sig._once_connections


def test_once_sender_and_normal_any_are_independent() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    receiver_id = blinker.base.make_id(received)
    sender_id = blinker.base.make_id(123)

    sig.connect_once(received, sender=123, weak=False)
    sig.connect(received, sender=blinker.ANY, weak=False)

    sig.send(123)
    sig.send(456)

    assert calls == [123, 456]
    assert (sender_id, receiver_id) not in sig._once_connections
    assert (blinker.base.ANY_ID, receiver_id) in sig._connections


def test_once_sender_disconnect_does_not_remove_any() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    sig.connect_once(received, sender=123, weak=False)
    sig.connect_once(received, sender=blinker.ANY, weak=False)

    sig.disconnect(received, sender=123)
    assert sig._by_sender[blinker.base.ANY_ID]
    sig.send(456)

    assert calls == [456]
    assert not sig._by_sender[blinker.base.make_id(123)]
    assert not sig._by_sender[blinker.base.ANY_ID]


async def test_async_connect_once() -> None:
    calls = []

    async def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    sig.connect_once(received)

    await sig.send_async()
    await sig.send_async()

    assert calls == [None]
    assert not sig.receivers
    assert not sig._once_connections


async def test_async_connect_once_is_consumed_when_receiver_raises() -> None:
    async def received(sender: t.Any) -> None:
        raise RuntimeError(sender)

    sig = blinker.Signal()
    sig.connect_once(received)

    with pytest.raises(RuntimeError):
        await sig.send_async()

    await sig.send_async()

    assert not sig.receivers
    assert not sig._once_connections


def test_sync_send_connect_once_async_receiver() -> None:
    calls = []

    async def received(sender: t.Any) -> None:
        calls.append(sender)

    sig = blinker.Signal()
    sig.connect_once(received)

    def wrapper(func: c.Callable[..., t.Any]) -> c.Callable[..., None]:
        def inner(*args: t.Any, **kwargs: t.Any) -> None:
            asyncio.run(func(*args, **kwargs))

        return inner

    result = sig.send(123, _async_wrapper=wrapper)
    assert len(result) == 1
    assert calls == [123]
    assert not sig.receivers
    assert not sig._once_connections


async def test_async_connect_once_releases_lock_while_waiting() -> None:
    sig = blinker.Signal()
    receiver_entered = asyncio.Event()
    release_receiver = asyncio.Event()
    calls = []

    async def received(sender: t.Any) -> None:
        calls.append(sender)
        receiver_entered.set()
        await release_receiver.wait()

    sig.connect_once(received)
    sending = asyncio.create_task(sig.send_async())
    await receiver_entered.wait()
    await sig.send_async()
    release_receiver.set()
    await sending

    assert calls == [None]
    assert not sig.receivers
    assert not sig._once_connections


def test_connect_once_weak_receiver_cleanup() -> None:
    calls = []

    class Receiver:
        def received(self, sender: t.Any) -> None:
            calls.append(sender)

    receiver = Receiver()
    sig = blinker.Signal()
    sig.connect_once(receiver.received)

    del receiver
    collect_acyclic_refs()

    assert not calls
    assert not sig.receivers
    assert not sig._once_connections
    sig._cleanup_bookkeeping()
    values_are_empty_sets_(sig._by_receiver)
    values_are_empty_sets_(sig._by_sender)
    sig.send(123)
    assert not calls


def test_connect_once_weak_sender_cleanup() -> None:
    calls = []

    def received(sender: t.Any) -> None:
        calls.append(sender)

    class Sender:
        pass

    sender = Sender()
    sig = blinker.Signal()
    sig.connect_once(received, sender=sender, weak=False)

    del sender
    collect_acyclic_refs()

    assert not sig._once_connections
    values_are_empty_sets_(sig._by_receiver)
    assert not any(bucket for bucket in sig._by_sender.values())
    sig.send(123)
    assert not calls


def test_instancemethod_receiver() -> None:
    sentinel: list[t.Any] = []

    class Receiver:
        def __init__(self, bucket: list[t.Any]) -> None:
            self.bucket = bucket

        def received(self, sender: t.Any) -> None:
            self.bucket.append(sender)

    receiver = Receiver(sentinel)

    sig = blinker.Signal()
    sig.connect(receiver.received)

    assert not sentinel
    sig.send()
    assert sentinel
    del receiver
    collect_acyclic_refs()

    sig.send()
    assert len(sentinel) == 1


def test_filtered_receiver() -> None:
    sentinel = []

    def received(sender: t.Any) -> None:
        sentinel.append(sender)

    sig = blinker.Signal()

    sig.connect(received, 123)

    assert not sentinel
    sig.send()
    assert not sentinel
    sig.send(123)
    assert sentinel == [123]
    sig.send()
    assert sentinel == [123]

    sig.disconnect(received, 123)
    sig.send(123)
    assert sentinel == [123]

    sig.connect(received, 123)
    sig.send(123)
    assert sentinel == [123, 123]

    sig.disconnect(received)
    sig.send(123)
    assert sentinel == [123, 123]


def test_filtered_receiver_weakref() -> None:
    sentinel = []

    def received(sender: t.Any) -> None:
        sentinel.append(sender)

    class Object:
        pass

    obj = Object()

    sig = blinker.Signal()
    sig.connect(received, obj)

    assert not sentinel
    sig.send(obj)
    assert sentinel == [obj]
    del sentinel[:]
    del obj
    collect_acyclic_refs()

    # general index isn't cleaned up
    assert sig.receivers
    # but receiver/sender pairs are
    values_are_empty_sets_(sig._by_receiver)
    values_are_empty_sets_(sig._by_sender)


def test_decorated_receiver() -> None:
    sentinel = []

    class Object:
        pass

    obj = Object()

    sig = blinker.Signal()

    @sig.connect_via(obj)
    def receiver(sender: t.Any, **kw: t.Any) -> None:
        sentinel.append(kw)

    assert not sentinel
    sig.send()
    assert not sentinel
    sig.send(1)
    assert not sentinel
    sig.send(obj)
    assert sig.receivers

    del receiver
    collect_acyclic_refs()
    assert sig.receivers


def test_no_double_send() -> None:
    sentinel = []

    def received(sender: t.Any) -> None:
        sentinel.append(sender)

    sig = blinker.Signal()

    sig.connect(received, 123)
    sig.connect(received)

    assert not sentinel
    sig.send()
    assert sentinel == [None]
    sig.send(123)
    assert sentinel == [None, 123]
    sig.send()
    assert sentinel == [None, 123, None]


def test_has_receivers() -> None:
    def received(_: t.Any) -> None:
        return None

    sig = blinker.Signal()
    assert not sig.has_receivers_for(None)
    assert not sig.has_receivers_for(blinker.ANY)

    sig.connect(received, "xyz")
    assert not sig.has_receivers_for(None)
    assert not sig.has_receivers_for(blinker.ANY)
    assert sig.has_receivers_for("xyz")

    class Object:
        pass

    o = Object()

    sig.connect(received, o)
    assert sig.has_receivers_for(o)

    del received
    collect_acyclic_refs()

    assert not sig.has_receivers_for("xyz")
    assert list(sig.receivers_for("xyz")) == []
    assert list(sig.receivers_for(o)) == []

    sig.connect(lambda sender: None, weak=False)
    assert sig.has_receivers_for("xyz")
    assert sig.has_receivers_for(o)
    assert sig.has_receivers_for(None)
    assert sig.has_receivers_for(blinker.ANY)
    assert sig.has_receivers_for("xyz")


def test_instance_doc() -> None:
    sig = blinker.Signal(doc="x")
    assert sig.__doc__ == "x"

    sig = blinker.Signal("x")
    assert sig.__doc__ == "x"


def test_named_blinker() -> None:
    sig = blinker.NamedSignal("squiznart")
    assert "squiznart" in repr(sig)


def test_mute_signal() -> None:
    sentinel = []

    def received(sender: t.Any) -> None:
        sentinel.append(sender)

    sig = blinker.Signal()
    sig.connect(received)

    sig.send(123)
    assert 123 in sentinel

    with sig.muted():
        sig.send(456)
    assert 456 not in sentinel


def values_are_empty_sets_(dictionary: dict[t.Any, t.Any]) -> None:
    for val in dictionary.values():
        assert val == set()


def test_int_sender() -> None:
    count = 0

    def received(sender: t.Any) -> None:
        nonlocal count
        count += 1

    sig = blinker.Signal()
    sig.connect(received, sender=123456789)
    sig.send(123456789)  # Python compiler uses same instance for same literal value.
    assert count == 1
    sig.send(int("123456789"))  # Force different instance with same value.
    assert count == 2
