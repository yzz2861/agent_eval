from __future__ import annotations

import collections.abc as c
import gc
import sys
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


def test_priority_order() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def low(sender: t.Any) -> None:
        calls.append("low")

    def high(sender: t.Any) -> None:
        calls.append("high")

    def middle(sender: t.Any) -> None:
        calls.append("middle")

    sig.connect(low, weak=False, priority=-1)
    sig.connect(high, weak=False, priority=10)
    sig.connect(middle, weak=False, priority=5)

    sig.send()
    assert calls == ["high", "middle", "low"]


def test_same_priority_stable_connection_order() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def first(sender: t.Any) -> None:
        calls.append("first")

    def second(sender: t.Any) -> None:
        calls.append("second")

    def third(sender: t.Any) -> None:
        calls.append("third")

    sig.connect(first, weak=False, priority=5)
    sig.connect(second, weak=False, priority=5)
    sig.connect(third, weak=False, priority=5)

    sig.send()
    assert calls == ["first", "second", "third"]


def test_priority_mixed_with_connection_order() -> None:
    sig = blinker.Signal()
    calls2: list[str] = []

    def recv(name: str) -> c.Callable[..., None]:
        def receiver(sender: t.Any) -> None:
            calls2.append(name)

        return receiver

    sig2 = blinker.Signal()
    r0 = recv("0")
    r1 = recv("1")
    r2 = recv("2")
    r3 = recv("3")
    sig2.connect(r0, weak=False, priority=0)
    sig2.connect(r1, weak=False, priority=10)
    sig2.connect(r2, weak=False, priority=10)
    sig2.connect(r3, weak=False, priority=-5)
    sig2.send()
    assert calls2 == ["1", "2", "0", "3"]


def test_any_and_specific_called_once_with_highest_priority() -> None:
    calls: list[str] = []
    sig = blinker.Signal()
    sender = object()

    def both(sender: t.Any) -> None:
        calls.append("both")

    def only_any(sender: t.Any) -> None:
        calls.append("any")

    def only_sender(sender: t.Any) -> None:
        calls.append("sender")

    sig.connect(both, sender=blinker.ANY, weak=False, priority=1)
    sig.connect(both, sender=sender, weak=False, priority=10)
    sig.connect(only_any, weak=False, priority=5)
    sig.connect(only_sender, sender=sender, weak=False, priority=5)

    sig.send(sender)
    assert calls == ["both", "any", "sender"]


def test_any_specific_tie_uses_earliest_order() -> None:
    calls: list[str] = []
    sig = blinker.Signal()
    sender = object()

    def both(sender: t.Any) -> None:
        calls.append("both")

    def other(sender: t.Any) -> None:
        calls.append("other")

    sig.connect(both, sender=sender, weak=False, priority=5)
    sig.connect(other, weak=False, priority=5)
    sig.connect(both, weak=False, priority=5)

    sig.send(sender)
    assert calls == ["both", "other"]


def test_reconnect_updates_priority_but_keeps_order() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def a(sender: t.Any) -> None:
        calls.append("a")

    def b(sender: t.Any) -> None:
        calls.append("b")

    sig.connect(a, weak=False, priority=0)
    sig.connect(b, weak=False, priority=0)

    sig.send()
    assert calls == ["a", "b"]  # equal priority keeps connection order

    # Updating the priority applies to the next send.
    calls.clear()
    sig.connect(a, weak=False, priority=5)
    sig.connect(b, weak=False, priority=10)
    sig.send()
    assert calls == ["b", "a"]

    # Equal priority again: a still keeps its earlier connection position.
    calls.clear()
    sig.connect(b, weak=False, priority=5)
    sig.send()
    assert calls == ["a", "b"]

    # A full disconnect/reconnect counts as a new connection, so a moves last.
    calls.clear()
    sig.disconnect(a)
    sig.connect(a, weak=False, priority=5)
    sig.send()
    assert calls == ["b", "a"]


def test_reconnect_counts_as_new_connection_order() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def a(sender: t.Any) -> None:
        calls.append("a")

    def b(sender: t.Any) -> None:
        calls.append("b")

    sig.connect(a, weak=False)
    sig.connect(b, weak=False)
    assert calls == []
    sig.send()
    assert calls == ["a", "b"]

    calls.clear()
    sig.disconnect(a)
    sig.connect(a, weak=False)
    sig.send()
    assert calls == ["b", "a"]


def test_send_uses_subscription_snapshot() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def late(sender: t.Any) -> None:
        calls.append("late")

    def dynamic(sender: t.Any) -> None:
        calls.append("dynamic")
        sig.connect(late, weak=False, priority=100)
        sig.disconnect(static)
        sig.connect(dynamic, weak=False, priority=100)

    def static(sender: t.Any) -> None:
        calls.append("static")

    sig.connect(static, weak=False, priority=10)
    sig.connect(dynamic, weak=False, priority=0)

    sig.send()
    assert calls == ["static", "dynamic"]

    calls.clear()
    sig.send()
    assert calls == ["dynamic", "late"]


def test_reentrant_send_reads_current_state() -> None:
    calls: list[str] = []
    sig = blinker.Signal()
    depth = 0

    def late(sender: t.Any) -> None:
        calls.append("late")

    def reentrant(sender: t.Any) -> None:
        nonlocal depth
        depth += 1
        calls.append(f"enter{depth}")

        if depth == 1:
            sig.connect(late, weak=False, priority=10)
            sig.send(sender)
        else:
            calls.append("nested")

        calls.append(f"exit{depth}")
        depth -= 1

    sig.connect(reentrant, weak=False)
    sig.send()
    assert calls == [
        "enter1",
        "late",
        "enter2",
        "nested",
        "exit2",
        "exit1",
    ]


def test_priority_with_weak_bound_method_receivers() -> None:
    class Recorder:
        def __init__(self, name: str, bucket: list[str]) -> None:
            self.name = name
            self.bucket = bucket

        def received(self, sender: t.Any) -> None:
            self.bucket.append(self.name)

    calls: list[str] = []
    sig = blinker.Signal()
    low = Recorder("low", calls)
    high = Recorder("high", calls)
    sig.connect(low.received, weak=True, priority=-1)
    sig.connect(high.received, weak=True, priority=1)

    sig.send()
    assert calls == ["high", "low"]


async def test_send_async_priority_order() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    async def high(sender: t.Any) -> None:
        calls.append("high")

    async def low(sender: t.Any) -> None:
        calls.append("low")

    sig.connect(low, priority=-1)
    sig.connect(high, priority=1)
    await sig.send_async()
    assert calls == ["high", "low"]


def test_send_exception_propagation_unchanged() -> None:
    sig = blinker.Signal()
    calls: list[str] = []

    def boom(sender: t.Any) -> None:
        calls.append("boom")
        raise ValueError("boom")

    def after(sender: t.Any) -> None:
        calls.append("after")

    sig.connect(boom, weak=False, priority=1)
    sig.connect(after, weak=False, priority=0)

    with pytest.raises(ValueError, match="boom"):
        sig.send()

    assert calls == ["boom"]
