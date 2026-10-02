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
            {
                "receiver": receiver,
                "sender": sender,
                "weak": weak,
                "once": False,
            },
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


def test_once_receiver_concurrent_and_reentrant() -> None:
    calls: list[str] = []
    results: list[list[tuple[c.Callable[..., t.Any], t.Any]]] = []
    sig = blinker.Signal()
    start = threading.Barrier(2)
    attempted = threading.Event()
    finished = threading.Event()
    entered = threading.Event()
    errors: list[BaseException] = []

    def receiver(sender: str) -> None:
        calls.append(sender)

        if not entered.is_set():
            entered.set()
            sig.disconnect(receiver)
            assert sig.send(sender) == []
            attempted.wait(timeout=5)
            finished.wait(timeout=5)

    def worker() -> None:
        try:
            start.wait(timeout=5)
            attempted.set()
            results.append(sig.send("ready"))
            finished.set()
        except BaseException as exc:  # pragma: no cover - test failure reporting
            errors.append(exc)

    sig.connect_once(receiver, weak=False)
    threads = [threading.Thread(target=worker) for _ in range(2)]

    for thread in threads:
        thread.start()

    assert entered.wait(timeout=5)

    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert errors == []
    assert calls == ["ready"]
    assert sorted(len(result) for result in results) == [0, 1]
    assert sig.send("ready") == []


async def test_once_async_receiver_concurrent_and_reentrant() -> None:
    calls: list[str] = []
    sig = blinker.Signal()
    attempted = asyncio.Event()
    finished = asyncio.Event()
    entered = asyncio.Event()

    async def receiver(sender: str) -> None:
        calls.append(sender)

        if not entered.is_set():
            entered.set()
            sig.disconnect(receiver)
            assert await sig.send_async(sender) == []
            await attempted.wait()
            await finished.wait()

    async def send_once() -> list[tuple[c.Callable[..., t.Any], t.Any]]:
        attempted.set()

        try:
            return await sig.send_async("ready")
        finally:
            finished.set()

    sig.connect_once(receiver, weak=False)
    first = asyncio.create_task(send_once())
    await entered.wait()
    second = asyncio.create_task(send_once())
    results = await asyncio.gather(first, second)

    assert calls == ["ready"]
    assert sorted(len(result) for result in results) == [0, 1]
    assert await sig.send_async("ready") == []


def test_once_receiver_exception_is_consumed() -> None:
    class ReceiverError(Exception):
        pass

    sig = blinker.Signal()

    def receiver(sender: str) -> None:
        raise ReceiverError

    sig.connect_once(receiver, weak=False)

    with pytest.raises(ReceiverError):
        sig.send("ready")

    assert sig.send("ready") == []
    assert not sig.receivers
    assert not sig._once_receivers
    assert not sig._once_by_sender
    assert not sig._once_by_receiver


def test_connect_once_keyword() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def receiver(sender: str) -> None:
        calls.append(sender)

    returned = sig.connect(receiver, weak=False, once=True)
    assert returned is receiver
    sig.send("ready")
    sig.send("ready")
    assert calls == ["ready"]


async def test_once_async_receiver_exception_is_consumed() -> None:
    class ReceiverError(Exception):
        pass

    sig = blinker.Signal()

    async def receiver(sender: str) -> None:
        raise ReceiverError

    sig.connect_once(receiver, weak=False)

    with pytest.raises(ReceiverError):
        await sig.send_async("ready")

    assert await sig.send_async("ready") == []
    assert not sig.receivers
    assert not sig._once_receivers


def test_once_weak_receiver_cleanup() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def receiver(sender: str) -> None:
        calls.append(sender)

    sig.connect_once(receiver)
    del receiver
    collect_acyclic_refs()

    sig.send("ready")
    assert calls == []
    assert not sig.receivers
    assert not sig._once_receivers
    assert not sig._once_by_sender
    assert not sig._once_by_receiver


def test_once_weak_receiver_cleanup_with_regular_weak_subscription() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def receiver(sender: str) -> None:
        calls.append(sender)

    sig.connect(receiver, sender="regular", weak=True)
    sig.connect_once(receiver, sender=blinker.ANY, weak=True)
    del receiver
    collect_acyclic_refs()

    sig.send("regular")
    assert calls == []
    assert not sig.receivers
    assert not sig._once_receivers
    assert not sig._once_by_sender
    assert not sig._once_by_receiver


def test_once_weak_sender_cleanup() -> None:
    calls: list[object] = []
    sig = blinker.Signal()

    class Sender:
        pass

    def receiver(sender: object) -> None:
        calls.append(sender)

    sender = Sender()
    sig.connect_once(receiver, sender=sender, weak=False)
    del sender
    collect_acyclic_refs()

    sig.send("ready")
    assert calls == []
    assert not sig.receivers
    assert not sig._once_receivers
    assert not sig._once_by_sender
    assert not sig._once_by_receiver


def test_once_independent_from_regular_and_sender_subscriptions() -> None:
    calls: list[str] = []
    sig = blinker.Signal()

    def regular(sender: str) -> None:
        calls.append(f"regular:{sender}")

    def once_any(sender: str) -> None:
        calls.append(f"once-any:{sender}")

    def once_specific(sender: str) -> None:
        calls.append(f"once-specific:{sender}")

    sig.connect(regular, sender="specific", weak=False)
    sig.connect_once(once_any, sender=blinker.ANY, weak=False)
    sig.connect_once(once_specific, sender="specific", weak=False)

    sig.send("other")
    assert calls == ["once-any:other"]

    sig.send("specific")
    assert calls == [
        "once-any:other",
        "regular:specific",
        "once-specific:specific",
    ]

    sig.send("specific")
    assert calls == [
        "once-any:other",
        "regular:specific",
        "once-specific:specific",
        "regular:specific",
    ]


def test_once_sender_subscriptions_are_independent() -> None:
    sig = blinker.Signal()
    calls: list[str] = []

    def receiver(sender: str) -> None:
        calls.append(sender)

    receiver_id = blinker.base.make_id(receiver)
    specific_id = blinker.base.make_id("specific")

    sig.connect_once(receiver, sender=blinker.ANY, weak=False)
    sig.connect_once(receiver, sender="specific", weak=False)
    sig._disconnect_once_locked(receiver_id, specific_id)

    assert (receiver_id, blinker.base.ANY_ID) in sig._once_receivers
    assert (receiver_id, specific_id) not in sig._once_receivers
    sig.send("other")
    assert calls == ["other"]

    sig.connect_once(receiver, sender="specific", weak=False)
    sig.send("other")

    assert (receiver_id, blinker.base.ANY_ID) not in sig._once_receivers
    assert calls == ["other"]
    assert (receiver_id, specific_id) in sig._once_receivers
    sig.send("specific")
    assert calls == ["other", "specific"]


def test_once_cleanup_does_not_remove_regular_subscription() -> None:
    sig = blinker.Signal()
    calls: list[str] = []

    def receiver(sender: str) -> None:
        calls.append(sender)

    receiver_id = blinker.base.make_id(receiver)
    sig.connect(receiver, sender="specific", weak=False)
    sig.connect_once(receiver, sender=blinker.ANY, weak=False)

    sig._disconnect_once_locked(receiver_id, blinker.base.ANY_ID)
    sig.send("other")
    sig.send("specific")

    assert calls == ["specific"]
    assert sig._by_receiver[receiver_id] == {blinker.base.make_id("specific")}
    assert not sig._once_receivers
