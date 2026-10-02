from __future__ import annotations

import asyncio
import collections.abc as c
import gc
import typing as t
import weakref

import pytest

from blinker import ANY
from blinker import Signal
from blinker._utilities import make_id


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


def test_temp_connection_preserves_existing_senders() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=False)
    sig.connect(receiver, sender=2, weak=False)

    with sig.connected_to(receiver, sender=3):
        sig.send(3)

    sig.send(1)
    sig.send(2)
    sig.send(3)

    assert canary == [3, 1, 2]
    assert sig.receivers


def test_temp_connection_preserves_existing_any_connection() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, weak=False)

    with sig.connected_to(receiver, sender=1):
        sig.send(1)

    sig.send(2)
    sig.send(1)

    assert canary == [1, 2, 1]
    assert sig.receivers


@pytest.mark.parametrize(
    ("sender", "event_sender", "weak"),
    [(ANY, 2, True), (ANY, 2, False), (1, 1, True), (1, 1, False)],
)
def test_temp_connection_preserves_existing_connection_for_same_sender(
    sender: t.Any, event_sender: int, weak: bool
) -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=sender, weak=weak)
    receiver_id = make_id(receiver)

    with sig.connected_to(receiver, sender=sender):
        sig.send(event_sender)

    sig.send(event_sender)

    assert canary == [event_sender, event_sender]
    assert isinstance(sig.receivers[receiver_id], weakref.ref) is weak
    assert sig.receivers


def test_temp_any_connection_preserves_existing_sender() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=False)

    with sig.connected_to(receiver):
        sig.send(1)
        sig.send(2)

    sig.send(1)
    sig.send(2)

    assert canary == [1, 2, 1]
    assert sig.receivers


def test_nested_temp_connections_remove_only_inner_connection() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=1):
        with sig.connected_to(receiver, sender=2):
            sig.send(1)
            sig.send(2)
            sig.send(3)

        sig.send(1)
        sig.send(2)
        sig.send(3)

    sig.send(1)

    assert canary == [1, 2, 1]
    assert not sig.receivers


def test_nested_temp_connections_for_same_sender() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver):
        with sig.connected_to(receiver):
            sig.send(1)

        sig.send(2)

    sig.send(3)

    assert canary == [1, 2]
    assert not sig.receivers


def test_explicit_disconnect_inside_temp_connection_is_not_restored() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=False)

    with sig.connected_to(receiver, sender=2):
        sig.disconnect(receiver)
        sig.connect(receiver, sender=3, weak=False)
        sig.send(1)
        sig.send(2)
        sig.send(3)

    sig.send(1)
    sig.send(2)
    sig.send(3)

    assert canary == [3, 3]
    assert sig.receivers


def test_explicit_connect_for_another_sender_survives_temp_connection() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=1):
        sig.connect(receiver, sender=2, weak=False)
        sig.send(1)
        sig.send(2)

    sig.send(1)
    sig.send(2)

    assert canary == [1, 2, 2]
    assert sig.receivers


def test_explicit_reconnect_for_temp_sender_survives_temp_connection() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    with sig.connected_to(receiver, sender=1):
        sig.disconnect(receiver, sender=1)
        sig.connect(receiver, sender=1, weak=False)
        sig.send(1)

    sig.send(1)

    assert canary == [1, 1]
    assert sig.receivers


def test_explicit_disconnect_of_existing_same_sender_is_not_restored() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=False)

    with sig.connected_to(receiver, sender=1):
        sig.disconnect(receiver, sender=1)

    sig.send(1)

    assert canary == []
    assert not sig.receivers


def test_temp_connection_preserves_weak_receiver_behavior() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    sig.connect(receiver, sender=1, weak=True)
    receiver_id = make_id(receiver)

    with sig.connected_to(receiver, sender=2):
        sig.send(2)

    assert isinstance(sig.receivers[receiver_id], weakref.ref)
    sig.send(1)
    sig.send(2)
    assert canary == [2, 1]

    del receiver
    gc.collect()
    sig.send(1)
    assert canary == [2, 1]


def test_temp_connection_does_not_restore_cleaned_up_sender() -> None:
    sig = Signal()

    canary = []

    def receiver(sender: t.Any) -> None:
        canary.append(sender)

    class Sender:
        pass

    sender = Sender()
    sender_id = make_id(sender)
    sig.connect(receiver, sender=sender, weak=False)

    with sig.connected_to(receiver, sender=2):
        del sender
        gc.collect()

    assert sender_id not in sig._by_sender
    sig.send(2)
    assert canary == []


def test_send_and_send_async_observe_same_connections() -> None:
    sig = Signal()
    sync_events = []
    async_events = []

    def sync_receiver(sender: t.Any) -> None:
        sync_events.append(sender)

    async def async_receiver(sender: t.Any) -> None:
        async_events.append(sender)

    def run_async(func: c.Callable[..., t.Any]) -> c.Callable[..., None]:
        def wrapper(*args: t.Any, **kwargs: t.Any) -> None:
            asyncio.run(func(*args, **kwargs))

        return wrapper

    def run_sync(func: c.Callable[..., t.Any]) -> c.Callable[..., t.Any]:
        async def wrapper(*args: t.Any, **kwargs: t.Any) -> None:
            func(*args, **kwargs)

        return wrapper

    sig.connect(sync_receiver, sender=1, weak=False)

    with sig.connected_to(async_receiver, sender=1):
        sig.send(1, _async_wrapper=run_async)
        asyncio.run(sig.send_async(1, _sync_wrapper=run_sync))

    assert sync_events == [1, 1]
    assert async_events == [1, 1]

    asyncio.run(sig.send_async(1, _sync_wrapper=run_sync))
    assert sync_events == [1, 1, 1]
    assert async_events == [1, 1]


class BoundReceiver:
    def __init__(self, events: list[t.Any]) -> None:
        self.events = events

    def received(self, sender: t.Any) -> None:
        self.events.append(sender)


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
def test_temp_connection_failure_preserves_bound_method_connection(
    exc_type: type[BaseException],
) -> None:
    sig = Signal()
    events: list[t.Any] = []
    bound_receiver = BoundReceiver(events)

    sig.connect(bound_receiver.received, sender=1)

    with pytest.raises(exc_type):
        with sig.connected_to(bound_receiver.received, sender=2):
            sig.send(1)
            sig.send(2)
            raise exc_type

    sig.send(1)
    sig.send(2)

    assert events == [1, 2, 1]
    assert sig.receivers
