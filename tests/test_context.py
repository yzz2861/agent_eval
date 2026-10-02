from __future__ import annotations

import collections.abc as c
import gc
import typing as t
import weakref

import pytest

from blinker import Signal


def collect_acyclic_refs() -> None:
    gc.collect()


def test_temp_connection() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.send(1)
    with sig.connected_to(receiver):
        sig.send(2)
    sig.send(3)

    assert canary == [2]
    assert not sig.receivers


def test_temp_connection_for_sender() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=2):
        sig.send(1)
        sig.send(2)

    assert canary == [2]
    assert not sig.receivers


@pytest.mark.parametrize("sender", [Signal.ANY, 1])
def test_temp_connection_keeps_existing_connection(sender: t.Any) -> None:
    sig = Signal()
    canary = []

    def receiver(received_sender: t.Any) -> None:
        canary.append(received_sender)

    sig.connect(receiver, sender=sender, weak=False)

    with sig.connected_to(receiver, sender=2):
        sig.send(1)
        sig.send(2)

    sig.send(1)

    assert canary == [1, 2, 1]


def test_nested_temp_connections_keep_outer_sender() -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=1):
        with sig.connected_to(receiver, sender=2):
            sig.send(1)
            sig.send(2)

        sig.send(1)

    sig.send(1)

    assert canary == [1, 2, 1]
    assert not sig.receivers


def test_nested_temp_connections_for_same_sender() -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=1):
        with sig.connected_to(receiver, sender=1):
            sig.send(1)

        sig.send(1)

    assert canary == [1, 1]
    assert not sig.receivers


def test_temp_connection_keeps_explicit_disconnect() -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=False)

    with sig.connected_to(receiver, sender=2):
        sig.disconnect(receiver, sender=1)

    sig.send(1)
    sig.send(2)

    assert canary == []
    assert not sig.receivers


def test_temp_connection_keeps_connection_reconnected_inside_block() -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=2):
        sig.disconnect(receiver, sender=2)
        sig.connect(receiver, sender=2, weak=False)

    sig.send(2)

    assert canary == [2]


def test_temp_connection_keeps_strong_holder_with_other_temporary_sender() -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=1):
        sig.connect(receiver, sender=2, weak=True)
        assert sig.receivers[id(receiver)] is receiver

        sig.send(1)
        sig.send(2)

    assert isinstance(sig.receivers[id(receiver)], weakref.ref)
    sig.send(2)
    sig.send(1)
    assert canary == [1, 2, 2]


def test_temp_connection_keeps_explicit_connection_after_disconnect_all() -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=2):
        sig.disconnect(receiver)
        sig.connect(receiver, sender=3, weak=False)

    sig.send(2)
    sig.send(3)

    assert canary == [3]


@pytest.mark.parametrize("bound", [False, True])
def test_temp_connection_restores_weak_behavior(bound: bool) -> None:
    sig = Signal()
    canary = []

    class Receiver:
        def received(self, sender: t.Any) -> None:
            canary.append(sender)

    if bound:
        handler: Receiver | None = Receiver()
        receiver = handler.received
    else:
        def receiver(sender: t.Any) -> None:
            canary.append(sender)

    sig.connect(receiver, weak=True)

    with sig.connected_to(receiver, sender=2):
        sig.send(1)
        sig.send(2)

    sig.send(3)
    assert canary == [1, 2, 3]

    if bound:
        del handler
    del receiver
    collect_acyclic_refs()

    assert not sig.receivers


def test_temp_connection_does_not_restore_garbage_collected_sender() -> None:
    class Sender:
        pass

    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sender: Sender | None = Sender()
    sig.connect(receiver, sender=sender, weak=False)

    with sig.connected_to(receiver):
        sender_id = id(sender)
        sig.send(object())
        del sender
        collect_acyclic_refs()
        assert sender_id not in sig._by_sender

    assert len(canary) == 1
    assert not sig.receivers


async def test_temp_connection_visible_to_send_and_send_async() -> None:
    sig = Signal()

    def receiver(sender: t.Any) -> t.Any:
        return sender

    sig.connect(receiver, sender=1, weak=False)

    def wrap(func: c.Callable[..., t.Any]) -> c.Callable[..., t.Any]:
        def wrapped(*args: t.Any, **kwargs: t.Any) -> t.Any:
            return func(*args, **kwargs)

        async def async_wrapped(*args: t.Any, **kwargs: t.Any) -> t.Any:
            return wrapped(*args, **kwargs)

        return async_wrapped

    with sig.connected_to(receiver, sender=2):
        sync_receivers = {
            subscribed for sender in (1, 2) for subscribed, _ in sig.send(sender)
        }
        async_receivers = {
            subscribed
            for sender in (1, 2)
            for subscribed, _ in await sig.send_async(sender, _sync_wrapper=wrap)
        }

        assert async_receivers == sync_receivers == {receiver}

    assert sig.send(2) == []
    assert [subscribed for subscribed, _ in await sig.send_async(1, _sync_wrapper=wrap)]


class Failure(Exception):
    pass


class BaseFailure(BaseException):
    pass


@pytest.mark.parametrize("exc_type", [Failure, BaseFailure])
def test_temp_connection_failure(exc_type: type[BaseException]) -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with pytest.raises(exc_type):
        sig.send(1)
        with sig.connected_to(receiver):
            sig.send(2)
            raise exc_type
        sig.send(3)

    assert canary == [2]
    assert not sig.receivers


@pytest.mark.parametrize("exc_type", [Failure, BaseFailure])
def test_nested_temp_connection_failure_keeps_existing_connection(
    exc_type: type[BaseException],
) -> None:
    sig = Signal()
    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=False)

    with pytest.raises(exc_type):
        with sig.connected_to(receiver, sender=2):
            with sig.connected_to(receiver, sender=3):
                raise exc_type

    sig.send(1)
    sig.send(2)
    sig.send(3)

    assert canary == [1]
