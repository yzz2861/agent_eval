from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from anyio import (
    BrokenResourceError,
    CancelScope,
    ClosedResourceError,
    EndOfStream,
    Event,
    WouldBlock,
    create_task_group,
    wait_all_tasks_blocked,
)
from anyio.streams.broadcast import (
    BroadcastOverflowError,
    BroadcastStream,
)

if TYPE_CHECKING:
    from anyio.streams.broadcast import BroadcastReceiveStream


def test_invalid_max_buffer_size() -> None:
    pytest.raises(ValueError, BroadcastStream, 1.0).match(
        "max_buffer_size must be either an integer or math.inf"
    )


def test_negative_max_buffer_size() -> None:
    pytest.raises(ValueError, BroadcastStream, -1).match(
        "max_buffer_size cannot be negative"
    )


def test_invalid_on_overflow() -> None:
    pytest.raises(ValueError, BroadcastStream, 0, on_overflow="drop").match(
        'on_overflow must be either "wait" or "close"'
    )


async def test_broadcast_to_all_subscribers() -> None:
    async with BroadcastStream[str](2) as stream:
        async with stream.subscribe() as sub_a, stream.subscribe() as sub_b:
            await stream.send("one")
            await stream.send("two")
            assert await sub_a.receive() == "one"
            assert await sub_a.receive() == "two"
            assert await sub_b.receive() == "one"
            assert await sub_b.receive() == "two"


async def test_items_published_before_subscription_are_not_received() -> None:
    async with BroadcastStream[str](2) as stream:
        await stream.send("before")  # no subscribers yet, so this is discarded
        async with stream.subscribe() as sub:
            await stream.send("after")
            assert await sub.receive() == "after"
            await stream.aclose()
            with pytest.raises(EndOfStream):
                await sub.receive()


async def test_send_waits_for_slow_subscriber() -> None:
    """With on_overflow="wait", a send blocks until every subscriber has room."""
    received_slow: list[str] = []
    proceed = Event()
    send_completed = Event()

    async def slow_consumer(slow: BroadcastReceiveStream[str]) -> None:
        await proceed.wait()
        received_slow.append(await slow.receive())

    async def sender(stream: BroadcastStream[str]) -> None:
        await stream.send("two")
        send_completed.set()

    async with BroadcastStream[str](1) as stream:
        fast = stream.subscribe()
        slow = stream.subscribe()
        async with create_task_group() as tg:
            tg.start_soon(slow_consumer, slow)
            await stream.send("one")  # fills both subscribers' buffers
            assert await fast.receive() == "one"
            tg.start_soon(sender, stream)
            await wait_all_tasks_blocked()
            assert not send_completed.is_set()
            proceed.set()  # let the slow subscriber free up its buffer
            await send_completed.wait()
            assert received_slow == ["one"]
            assert await fast.receive() == "two"
            assert await slow.receive() == "two"

        await fast.aclose()
        await slow.aclose()


async def test_close_policy_drops_lagging_subscriber() -> None:
    async with BroadcastStream[str](1, on_overflow="close") as stream:
        fast = stream.subscribe()
        slow = stream.subscribe()
        await stream.send("one")
        assert await fast.receive() == "one"
        # The slow subscriber's buffer is still full, so it gets dropped
        await stream.send("two")
        assert await fast.receive() == "two"
        with pytest.raises(BroadcastOverflowError):
            await slow.receive()

        # The error is persistent and identifiable as a broken resource
        with pytest.raises(BrokenResourceError):
            await slow.receive()

        # The publisher and the remaining subscribers are unaffected
        await stream.send("three")
        assert await fast.receive() == "three"
        await fast.aclose()
        await slow.aclose()


async def test_close_policy_drops_unready_subscriber_with_zero_buffer() -> None:
    async with BroadcastStream[str](0, on_overflow="close") as stream:
        sub = stream.subscribe()
        await stream.send("one")  # subscriber is not waiting, so it gets dropped
        with pytest.raises(BroadcastOverflowError):
            await sub.receive()

        await sub.aclose()


async def test_cancelled_send_is_not_delivered() -> None:
    """A cancelled send must not deliver the item to any subscriber."""
    send_started = Event()

    async def sender(stream: BroadcastStream[str], scope: CancelScope) -> None:
        with scope:
            send_started.set()
            await stream.send("two")

    async with BroadcastStream[str](1) as stream:
        sub_a = stream.subscribe()
        sub_b = stream.subscribe()
        await stream.send("one")  # fill both subscribers' buffers
        scope = CancelScope()
        async with create_task_group() as tg:
            tg.start_soon(sender, stream, scope)
            await send_started.wait()
            await wait_all_tasks_blocked()
            scope.cancel()

        assert scope.cancelled_caught
        for sub in (sub_a, sub_b):
            assert sub.receive_nowait() == "one"
            with pytest.raises(WouldBlock):
                sub.receive_nowait()

            await sub.aclose()


async def test_unsubscribe_unblocks_waiting_sender() -> None:
    send_completed = Event()

    async def sender(stream: BroadcastStream[str]) -> None:
        await stream.send("two")
        send_completed.set()

    async with BroadcastStream[str](1) as stream:
        slow = stream.subscribe()
        await stream.send("one")
        async with create_task_group() as tg:
            tg.start_soon(sender, stream)
            await wait_all_tasks_blocked()
            assert not send_completed.is_set()
            await slow.aclose()  # unsubscribing lifts the backpressure
            await send_completed.wait()


async def test_send_with_no_subscribers_is_a_noop() -> None:
    async with BroadcastStream[str](1) as stream:
        await stream.send("ignored")
        async with stream.subscribe() as sub:
            await stream.send("kept")
            assert await sub.receive() == "kept"


async def test_publisher_close() -> None:
    stream = BroadcastStream[str](2)
    sub = stream.subscribe()
    await stream.send("one")
    await stream.aclose()
    # Buffered items can still be received before the end of the stream
    assert await sub.receive() == "one"
    with pytest.raises(EndOfStream):
        await sub.receive()

    with pytest.raises(ClosedResourceError):
        await stream.send("two")

    with pytest.raises(ClosedResourceError):
        stream.subscribe()

    await sub.aclose()


async def test_new_subscriber_during_blocked_send() -> None:
    """A subscriber that subscribes before delivery completes gets the item."""
    send_completed = Event()

    async def sender(stream: BroadcastStream[str]) -> None:
        await stream.send("two")
        send_completed.set()

    async with BroadcastStream[str](1) as stream:
        first = stream.subscribe()
        await stream.send("one")  # fills the first subscriber's buffer
        async with create_task_group() as tg:
            tg.start_soon(sender, stream)
            await wait_all_tasks_blocked()
            assert not send_completed.is_set()
            # Subscribe while the send is still blocked
            second = stream.subscribe()
            assert await first.receive() == "one"
            await send_completed.wait()
            # The new subscriber receives the in-flight item, but not older ones
            assert second.receive_nowait() == "two"
            with pytest.raises(WouldBlock):
                second.receive_nowait()

            assert await first.receive() == "two"
            await second.aclose()

        await first.aclose()


async def test_zero_buffer_rendezvous() -> None:
    """With a 0-sized buffer, sends wait until every subscriber is receiving."""
    received: list[int] = []

    async def consumer(sub: BroadcastReceiveStream[int]) -> None:
        received.extend([item async for item in sub])

    async with BroadcastStream[int]() as stream:
        async with stream.subscribe() as sub:
            async with create_task_group() as tg:
                tg.start_soon(consumer, sub)
                await wait_all_tasks_blocked()
                for num in range(3):
                    await stream.send(num)

                await stream.aclose()

    assert received == [0, 1, 2]


async def test_close_policy_with_waiting_receiver() -> None:
    received: list[str] = []

    async def consumer(sub: BroadcastReceiveStream[str]) -> None:
        received.extend([item async for item in sub])

    async with BroadcastStream[str](0, on_overflow="close") as stream:
        async with stream.subscribe() as sub:
            async with create_task_group() as tg:
                tg.start_soon(consumer, sub)
                await wait_all_tasks_blocked()
                await stream.send("one")
                await stream.aclose()

    assert received == ["one"]


async def test_send_nowait() -> None:
    async with BroadcastStream[str](1) as stream:
        sub = stream.subscribe()
        stream.send_nowait("one")
        with pytest.raises(WouldBlock):
            stream.send_nowait("two")

        assert sub.receive_nowait() == "one"
        stream.send_nowait("two")
        assert sub.receive_nowait() == "two"
        await sub.aclose()

    with pytest.raises(ClosedResourceError):
        stream.send_nowait("three")


async def test_receive_nowait() -> None:
    async with BroadcastStream[str](1) as stream:
        sub = stream.subscribe()
        with pytest.raises(WouldBlock):
            sub.receive_nowait()

        stream.send_nowait("one")
        assert sub.receive_nowait() == "one"
        await stream.aclose()
        with pytest.raises(EndOfStream):
            sub.receive_nowait()

        await sub.aclose()


async def test_closed_receive_stream() -> None:
    async with BroadcastStream[str](1) as stream:
        sub = stream.subscribe()
        await sub.aclose()
        with pytest.raises(ClosedResourceError):
            await sub.receive()

        with pytest.raises(ClosedResourceError):
            sub.receive_nowait()
