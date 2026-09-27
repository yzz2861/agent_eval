from __future__ import annotations

import gc
import math
import sys
from typing import TYPE_CHECKING, NoReturn

import pytest

from anyio import (
    BrokenResourceError,
    CancelScope,
    ClosedResourceError,
    EndOfStream,
    WouldBlock,
    create_memory_object_stream,
    create_task_group,
    fail_after,
    wait_all_tasks_blocked,
)
from anyio.streams.memory import (
    MemoryObjectReceiveStream,
    MemoryObjectSendStream,
    _MemoryObjectItemReceiver,
)

from ..conftest import asyncio_params

if TYPE_CHECKING:
    from anyio.abc import ObjectReceiveStream, ObjectSendStream, TaskStatus

if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup


def test_invalid_max_buffer() -> None:
    pytest.raises(ValueError, create_memory_object_stream, 1.0).match(
        "max_buffer_size must be either an integer or math.inf"
    )


def test_negative_max_buffer() -> None:
    pytest.raises(ValueError, create_memory_object_stream, -1).match(
        "max_buffer_size cannot be negative"
    )


async def test_receive_then_send() -> None:
    async def receiver() -> None:
        received_objects.append(await receive.receive())
        received_objects.append(await receive.receive())

    send, receive = create_memory_object_stream[str](0)
    received_objects: list[str] = []
    async with create_task_group() as tg:
        tg.start_soon(receiver)
        await wait_all_tasks_blocked()
        await send.send("hello")
        await send.send("anyio")

    assert received_objects == ["hello", "anyio"]

    send.close()
    receive.close()


async def test_receive_then_send_nowait() -> None:
    async def receiver() -> None:
        received_objects.append(await receive.receive())

    send, receive = create_memory_object_stream[str](0)
    received_objects: list[str] = []
    async with create_task_group() as tg:
        tg.start_soon(receiver)
        tg.start_soon(receiver)
        await wait_all_tasks_blocked()
        send.send_nowait("hello")
        send.send_nowait("anyio")

    assert sorted(received_objects, reverse=True) == ["hello", "anyio"]

    send.close()
    receive.close()


async def test_send_then_receive_nowait() -> None:
    send, receive = create_memory_object_stream[str](0)
    async with create_task_group() as tg:
        tg.start_soon(send.send, "hello")
        await wait_all_tasks_blocked()
        assert receive.receive_nowait() == "hello"

    send.close()
    receive.close()


async def test_send_is_unblocked_after_receive_nowait() -> None:
    send, receive = create_memory_object_stream[str](1)
    send.send_nowait("hello")

    with fail_after(1):
        async with create_task_group() as tg:
            tg.start_soon(send.send, "anyio")
            await wait_all_tasks_blocked()
            assert receive.receive_nowait() == "hello"

    assert receive.receive_nowait() == "anyio"

    send.close()
    receive.close()


async def test_send_nowait_then_receive_nowait() -> None:
    send, receive = create_memory_object_stream[str](2)
    send.send_nowait("hello")
    send.send_nowait("anyio")
    assert receive.receive_nowait() == "hello"
    assert receive.receive_nowait() == "anyio"

    send.close()
    receive.close()


async def test_iterate() -> None:
    async def receiver() -> None:
        received_objects.extend([item async for item in receive])

    send, receive = create_memory_object_stream[str]()
    received_objects: list[str] = []
    async with create_task_group() as tg:
        tg.start_soon(receiver)
        await send.send("hello")
        await send.send("anyio")
        await send.aclose()

    assert received_objects == ["hello", "anyio"]

    send.close()
    receive.close()


async def test_receive_send_closed_send_stream() -> None:
    send, receive = create_memory_object_stream[None]()
    await send.aclose()
    with pytest.raises(EndOfStream):
        receive.receive_nowait()

    with pytest.raises(ClosedResourceError):
        await send.send(None)

    receive.close()


async def test_receive_send_closed_receive_stream() -> None:
    send, receive = create_memory_object_stream[None]()
    await receive.aclose()
    with pytest.raises(ClosedResourceError):
        receive.receive_nowait()

    with pytest.raises(BrokenResourceError):
        await send.send(None)

    send.close()


async def test_cancel_receive() -> None:
    send, receive = create_memory_object_stream[str]()
    async with create_task_group() as tg:
        tg.start_soon(receive.receive)
        await wait_all_tasks_blocked()
        tg.cancel_scope.cancel()

    with pytest.raises(WouldBlock):
        send.send_nowait("hello")

    send.close()
    receive.close()


async def test_cancel_send() -> None:
    send, receive = create_memory_object_stream[str]()
    async with create_task_group() as tg:
        tg.start_soon(send.send, "hello")
        await wait_all_tasks_blocked()
        tg.cancel_scope.cancel()

    with pytest.raises(WouldBlock):
        receive.receive_nowait()

    send.close()
    receive.close()


async def test_clone() -> None:
    send1, receive1 = create_memory_object_stream[str](1)
    send2 = send1.clone()
    receive2 = receive1.clone()
    await send1.aclose()
    await receive1.aclose()
    send2.send_nowait("hello")
    assert receive2.receive_nowait() == "hello"

    send1.close()
    receive1.close()
    send2.close()
    receive2.close()


async def test_clone_closed() -> None:
    send, receive = create_memory_object_stream[NoReturn](1)
    await send.aclose()
    await receive.aclose()
    pytest.raises(ClosedResourceError, send.clone)
    pytest.raises(ClosedResourceError, receive.clone)


async def test_close_send_while_receiving() -> None:
    send, receive = create_memory_object_stream[NoReturn](1)
    with pytest.raises(ExceptionGroup) as exc:
        async with create_task_group() as tg:
            tg.start_soon(receive.receive)
            await wait_all_tasks_blocked()
            await send.aclose()

    assert len(exc.value.exceptions) == 1
    assert isinstance(exc.value.exceptions[0], EndOfStream)

    send.close()
    receive.close()


async def test_close_receive_while_sending() -> None:
    # We send None here as a regression test for #731
    send, receive = create_memory_object_stream[None](0)
    with pytest.raises(ExceptionGroup) as exc:
        async with create_task_group() as tg:
            tg.start_soon(send.send, None)
            await wait_all_tasks_blocked()
            await receive.aclose()

    assert len(exc.value.exceptions) == 1
    assert isinstance(exc.value.exceptions[0], BrokenResourceError)

    send.close()
    receive.close()


async def test_receive_after_send_closed() -> None:
    send, receive = create_memory_object_stream[str](1)
    await send.send("hello")
    await send.aclose()
    assert await receive.receive() == "hello"

    send.close()
    receive.close()


async def test_receive_when_cancelled() -> None:
    """
    Test that calling receive() in a cancelled scope prevents it from going through with
    the operation.

    """
    send, receive = create_memory_object_stream[str]()
    async with create_task_group() as tg:
        tg.start_soon(send.send, "hello")
        await wait_all_tasks_blocked()
        tg.start_soon(send.send, "world")
        await wait_all_tasks_blocked()

        with CancelScope() as scope:
            scope.cancel()
            await receive.receive()

        assert await receive.receive() == "hello"
        assert await receive.receive() == "world"

    send.close()
    receive.close()


async def test_send_when_cancelled() -> None:
    """
    Test that calling send() in a cancelled scope prevents it from going through with
    the operation.

    """

    async def receiver() -> None:
        received.append(await receive.receive())

    received: list[str] = []
    send, receive = create_memory_object_stream[str]()
    async with create_task_group() as tg:
        tg.start_soon(receiver)
        with CancelScope() as scope:
            scope.cancel()
            await send.send("hello")

        await send.send("world")

    assert received == ["world"]

    send.close()
    receive.close()


async def test_cancel_during_receive() -> None:
    """
    Test that cancelling a pending receive() operation does not cause an item in the
    stream to be lost.

    """

    async def scoped_receiver(task_status: TaskStatus[CancelScope]) -> None:
        with CancelScope() as cancel_scope:
            task_status.started(cancel_scope)
            received.append(await receive.receive())

        assert cancel_scope.cancel_called

    received: list[str] = []
    send, receive = create_memory_object_stream[str]()
    with send, receive:
        async with create_task_group() as tg:
            receiver_scope = await tg.start(scoped_receiver)
            await wait_all_tasks_blocked()
            send.send_nowait("hello")
            receiver_scope.cancel()

    assert received == ["hello"]


async def test_cancel_during_receive_buffered() -> None:
    """
    Test that sending an item to a memory object stream when the receiver that is next
    in line has been cancelled will not result in the item being lost.
    """

    async def scoped_receiver(
        receive: MemoryObjectReceiveStream[str], task_status: TaskStatus[CancelScope]
    ) -> None:
        with CancelScope() as cancel_scope:
            task_status.started(cancel_scope)
            await receive.receive()

    send, receive = create_memory_object_stream[str](1)
    with send, receive:
        async with create_task_group() as tg:
            cancel_scope = await tg.start(scoped_receiver, receive)
            await wait_all_tasks_blocked()
            cancel_scope.cancel()
            send.send_nowait("item")

        # Since the item was not sent to the cancelled task, it should be available here
        assert receive.receive_nowait() == "item"


async def test_close_receive_after_send() -> None:
    async def send() -> None:
        async with send_stream:
            await send_stream.send("test")

    async def receive() -> None:
        async with receive_stream:
            assert await receive_stream.receive() == "test"

    send_stream, receive_stream = create_memory_object_stream[str]()
    async with create_task_group() as tg:
        tg.start_soon(send)
        tg.start_soon(receive)

    send_stream.close()
    receive_stream.close()


async def test_statistics() -> None:
    send_stream, receive_stream = create_memory_object_stream[None](1)
    streams: list[MemoryObjectReceiveStream[None] | MemoryObjectSendStream[None]] = [
        send_stream,
        receive_stream,
    ]
    for stream in streams:
        statistics = stream.statistics()
        assert statistics.max_buffer_size == 1
        assert statistics.current_buffer_used == 0
        assert statistics.open_send_streams == 1
        assert statistics.open_receive_streams == 1
        assert statistics.tasks_waiting_send == 0
        assert statistics.tasks_waiting_receive == 0

    for stream in streams:
        async with create_task_group() as tg:
            # Test tasks_waiting_send
            send_stream.send_nowait(None)
            assert stream.statistics().current_buffer_used == 1
            tg.start_soon(send_stream.send, None)
            await wait_all_tasks_blocked()
            assert stream.statistics().current_buffer_used == 1
            assert stream.statistics().tasks_waiting_send == 1
            receive_stream.receive_nowait()
            assert stream.statistics().current_buffer_used == 1
            assert stream.statistics().tasks_waiting_send == 0
            receive_stream.receive_nowait()
            assert stream.statistics().current_buffer_used == 0

            # Test tasks_waiting_receive
            tg.start_soon(receive_stream.receive)
            await wait_all_tasks_blocked()
            assert stream.statistics().tasks_waiting_receive == 1
            send_stream.send_nowait(None)
            assert stream.statistics().tasks_waiting_receive == 0

        async with create_task_group() as tg:
            # Test tasks_waiting_send
            send_stream.send_nowait(None)
            assert stream.statistics().tasks_waiting_send == 0
            for _ in range(3):
                tg.start_soon(send_stream.send, None)

            await wait_all_tasks_blocked()
            assert stream.statistics().tasks_waiting_send == 3
            for i in range(2, -1, -1):
                receive_stream.receive_nowait()
                assert stream.statistics().tasks_waiting_send == i

            receive_stream.receive_nowait()

        assert stream.statistics().current_buffer_used == 0
        assert stream.statistics().tasks_waiting_send == 0
        assert stream.statistics().tasks_waiting_receive == 0

    send_stream.close()
    receive_stream.close()


async def test_sync_close() -> None:
    send_stream, receive_stream = create_memory_object_stream[None](1)
    with send_stream, receive_stream:
        pass

    with pytest.raises(ClosedResourceError):
        send_stream.send_nowait(None)

    with pytest.raises(ClosedResourceError):
        receive_stream.receive_nowait()


async def test_type_variance() -> None:
    """
    This test does not do anything at run time, but since the test suite is also checked
    with a static type checker, it ensures that the memory object stream
    co/contravariance works as intended. If it doesn't, one or both of the following
    reassignments will trip the type checker.

    """
    send, receive = create_memory_object_stream[float]()
    receive1: MemoryObjectReceiveStream[complex] = receive  # noqa: F841
    receive2: ObjectReceiveStream[complex] = receive  # noqa: F841
    send1: MemoryObjectSendStream[int] = send  # noqa: F841
    send2: ObjectSendStream[int] = send  # noqa: F841

    send.close()
    receive.close()


async def test_deprecated_item_type_parameter() -> None:
    with pytest.warns(DeprecationWarning, match="item_type argument has been "):
        send, receive = create_memory_object_stream(item_type=int)  # type: ignore[var-annotated]

        send.close()
        receive.close()


async def test_not_closed_warning() -> None:
    send, receive = create_memory_object_stream[int]()

    with pytest.warns(
        ResourceWarning, match="Unclosed <MemoryObjectSendStream at [0-9a-f]+>"
    ):
        del send
        gc.collect()

    with pytest.warns(
        ResourceWarning, match="Unclosed <MemoryObjectReceiveStream at [0-9a-f]+>"
    ):
        del receive
        gc.collect()


@pytest.mark.parametrize("anyio_backend", asyncio_params)
async def test_send_to_natively_cancelled_receiver() -> None:
    """
    Test that if a task waiting on receive.receive() is cancelled and then another
    task sends an item, said item is not delivered to the task with a pending
    cancellation, but rather to the next one in line.

    """
    from asyncio import CancelledError, create_task

    send, receive = create_memory_object_stream[str](1)
    with send, receive:
        receive_task = create_task(receive.receive())
        await wait_all_tasks_blocked()  # ensure that the task is waiting to receive
        receive_task.cancel()
        send.send_nowait("hello")
        with pytest.raises(CancelledError):
            await receive_task

        assert receive.receive_nowait() == "hello"


async def test_memory_object_item_receiver_repr() -> None:
    """
    Test the repr of `MemoryObjectItemReceiver`.
    Since when `item` is not set, the default dataclass repr raises an AttributeError.
    """
    receiver = _MemoryObjectItemReceiver[str]()

    assert str(receiver) is not None
    receiver_repr = repr(receiver)
    assert "item=None" in receiver_repr

    assert str(receiver) is not None
    receiver.item = "test_item"
    receiver_repr = repr(receiver)
    assert "item='test_item'" in receiver_repr


def test_negative_max_buffer_weight() -> None:
    pytest.raises(
        ValueError, create_memory_object_stream, 1, None, max_buffer_weight=-1
    ).match("max_buffer_weight cannot be negative")


def test_nan_max_buffer_weight() -> None:
    pytest.raises(
        ValueError,
        create_memory_object_stream,
        1,
        None,
        max_buffer_weight=math.nan,
    ).match("max_buffer_weight cannot be NaN")


async def test_weight_budget_send_nowait() -> None:
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=10, item_weight=len
    )
    send.send_nowait("hello")  # weight 5
    send.send_nowait("hi")  # weight 2, total 7
    with pytest.raises(WouldBlock):
        send.send_nowait("four")  # 7 + 4 would exceed the budget of 10

    # The item count limit still applies when the weight budget would allow more
    send2, receive2 = create_memory_object_stream[str](
        1, max_buffer_weight=100, item_weight=len
    )
    send2.send_nowait("a")
    with pytest.raises(WouldBlock):
        send2.send_nowait("b")

    assert receive.receive_nowait() == "hello"
    assert receive.receive_nowait() == "hi"
    assert receive2.receive_nowait() == "a"
    send.close()
    receive.close()
    send2.close()
    receive2.close()


async def test_send_unblocked_after_weight_freed() -> None:
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=5, item_weight=len
    )
    send.send_nowait("aaaa")  # weight 4
    async with create_task_group() as tg:
        tg.start_soon(send.send, "bb")  # weight 2, 4 + 2 > 5 so it waits
        await wait_all_tasks_blocked()
        assert send.statistics().tasks_waiting_send == 1
        assert receive.receive_nowait() == "aaaa"

    assert receive.receive_nowait() == "bb"
    send.close()
    receive.close()


async def test_overweight_item_rejected() -> None:
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=5, item_weight=len
    )
    with pytest.raises(ValueError, match="exceeds the stream's maximum buffer weight"):
        send.send_nowait("xxxxxx")

    # The async send() must reject the item immediately instead of waiting forever
    with pytest.raises(ValueError, match="exceeds the stream's maximum buffer weight"):
        await send.send("xxxxxx")

    # Even a waiting receiver cannot accept an overweight item
    send2, receive2 = create_memory_object_stream[str](
        0, max_buffer_weight=5, item_weight=len
    )
    async with create_task_group() as tg:
        tg.start_soon(receive2.receive)
        await wait_all_tasks_blocked()
        with pytest.raises(ValueError, match="exceeds"):
            send2.send_nowait("xxxxxx")

        tg.cancel_scope.cancel()

    send.close()
    receive.close()
    send2.close()
    receive2.close()


async def test_invalid_item_weight() -> None:
    send, receive = create_memory_object_stream[str](
        1, max_buffer_weight=5, item_weight=lambda item: -1
    )
    with pytest.raises(ValueError, match="item weight cannot be negative"):
        send.send_nowait("x")

    send2, receive2 = create_memory_object_stream[str](
        1, max_buffer_weight=5, item_weight=lambda item: math.nan
    )
    with pytest.raises(ValueError, match="item weight cannot be NaN"):
        send2.send_nowait("x")

    send.close()
    receive.close()
    send2.close()
    receive2.close()


async def test_item_weight_computed_once() -> None:
    calls = 0

    def item_weight(item: list[int]) -> float:
        nonlocal calls
        calls += 1
        return len(item)

    send, receive = create_memory_object_stream[list[int]](
        3, max_buffer_weight=10, item_weight=item_weight
    )
    item = [1, 2, 3]
    send.send_nowait(item)
    await send.send([4, 5])
    assert calls == 2

    # Mutating the item afterwards must not change the accounted weight
    item.append(4)
    assert send.statistics().current_buffer_weight == 5
    assert receive.receive_nowait() is item
    assert send.statistics().current_buffer_weight == 2
    assert receive.receive_nowait() == [4, 5]
    assert send.statistics().current_buffer_weight == 0
    send.close()
    receive.close()


async def test_weight_budget_shared_with_clones() -> None:
    send1, receive = create_memory_object_stream[str](
        10, max_buffer_weight=5, item_weight=len
    )
    send2 = send1.clone()
    send1.send_nowait("aaa")  # weight 3
    send2.send_nowait("bb")  # weight 2, total 5
    with pytest.raises(WouldBlock):
        send1.send_nowait("c")

    with pytest.raises(WouldBlock):
        send2.send_nowait("c")

    assert receive.receive_nowait() == "aaa"
    send2.send_nowait("c")  # fits now that weight was freed
    assert receive.receive_nowait() == "bb"
    assert receive.receive_nowait() == "c"
    send1.close()
    send2.close()
    receive.close()


async def test_cancel_send_weighted() -> None:
    """Cancelling a waiting send must not leak any of the weight budget."""
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=3, item_weight=len
    )
    send.send_nowait("aa")  # weight 2
    async with create_task_group() as tg:
        tg.start_soon(send.send, "bb")  # 2 + 2 > 3 so it waits
        await wait_all_tasks_blocked()
        tg.cancel_scope.cancel()

    statistics = send.statistics()
    assert statistics.current_buffer_weight == 2
    assert statistics.tasks_waiting_send == 0
    assert receive.receive_nowait() == "aa"
    with pytest.raises(WouldBlock):
        receive.receive_nowait()

    send.close()
    receive.close()


async def test_close_receive_while_sending_weighted() -> None:
    """Closing the receive end while a send waits must not leak the weight budget."""
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=3, item_weight=len
    )
    send.send_nowait("aa")  # weight 2
    with pytest.raises(ExceptionGroup) as exc:
        async with create_task_group() as tg:
            tg.start_soon(send.send, "bbb")  # 2 + 3 > 3 so it waits
            await wait_all_tasks_blocked()
            await receive.aclose()

    assert len(exc.value.exceptions) == 1
    assert isinstance(exc.value.exceptions[0], BrokenResourceError)
    assert send.statistics().current_buffer_weight == 2
    assert send.statistics().tasks_waiting_send == 0
    send.close()


async def test_zero_buffer_weight_budget() -> None:
    """Direct hand-off to a receiver must work with a zero-sized buffer."""
    send, receive = create_memory_object_stream[str](
        0, max_buffer_weight=5, item_weight=len
    )
    async with create_task_group() as tg:
        tg.start_soon(send.send, "hello")
        await wait_all_tasks_blocked()
        assert receive.receive_nowait() == "hello"

    assert send.statistics().current_buffer_weight == 0

    # Direct delivery to a waiting receiver is not weighed against the budget
    async with create_task_group() as tg:
        tg.start_soon(receive.receive)
        await wait_all_tasks_blocked()
        send.send_nowait("hello")

    assert send.statistics().current_buffer_weight == 0
    send.close()
    receive.close()


async def test_item_weight_function_raises() -> None:
    def item_weight(item: str) -> float:
        if item == "bad":
            raise RuntimeError("cannot weigh the item")

        return len(item)

    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=10, item_weight=item_weight
    )
    send.send_nowait("ok")
    with pytest.raises(RuntimeError, match="cannot weigh the item"):
        send.send_nowait("bad")

    with pytest.raises(RuntimeError, match="cannot weigh the item"):
        await send.send("bad")

    # Nothing was queued and no weight was leaked, so the stream still works
    statistics = send.statistics()
    assert statistics.current_buffer_used == 1
    assert statistics.current_buffer_weight == 2
    send.send_nowait("fine")
    assert receive.receive_nowait() == "ok"
    assert receive.receive_nowait() == "fine"
    send.close()
    receive.close()


async def test_weight_statistics() -> None:
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=10, item_weight=len
    )
    statistics = send.statistics()
    assert statistics.max_buffer_weight == 10
    assert statistics.current_buffer_weight == 0

    send.send_nowait("hello")
    assert send.statistics().current_buffer_weight == 5
    assert receive.statistics().current_buffer_weight == 5

    async with create_task_group() as tg:
        tg.start_soon(send.send, "......")  # weight 6, 5 + 6 > 10 so it waits
        await wait_all_tasks_blocked()
        statistics = send.statistics()
        assert statistics.tasks_waiting_send == 1
        assert statistics.current_buffer_weight == 5
        assert receive.receive_nowait() == "hello"

    assert send.statistics().current_buffer_weight == 6
    assert receive.receive_nowait() == "......"
    assert send.statistics().current_buffer_weight == 0
    send.close()
    receive.close()


async def test_weight_statistics_defaults() -> None:
    send, receive = create_memory_object_stream[str](2)
    statistics = send.statistics()
    assert statistics.max_buffer_weight == math.inf
    assert statistics.current_buffer_weight == 0
    send.send_nowait("x")
    assert send.statistics().current_buffer_weight == 1
    send.close()
    receive.close()


async def test_weight_fairness_fifo() -> None:
    """
    Test that a big item waiting for buffer capacity is never overtaken by smaller
    items sent later, even when the smaller items would fit (strict FIFO).

    """
    send, receive = create_memory_object_stream[str](
        10, max_buffer_weight=10, item_weight=len
    )
    send.send_nowait("aaaa")  # weight 4
    send.send_nowait("bbbbbb")  # weight 6, total 10
    async with create_task_group() as tg:
        # Start the sends one at a time so that they queue up in this exact order
        for item in ("BIGBIG", "s1", "s2"):  # weights 6, 2 and 2
            tg.start_soon(send.send, item)
            await wait_all_tasks_blocked()

        assert send.statistics().tasks_waiting_send == 3

        # Freeing 4 units of weight is not enough for BIGBIG, and the smaller
        # items queued behind it must not overtake it
        assert receive.receive_nowait() == "aaaa"
        statistics = send.statistics()
        assert statistics.current_buffer_weight == 6
        assert statistics.tasks_waiting_send == 3

        # Once enough weight is freed, the waiting items are admitted in FIFO order
        assert receive.receive_nowait() == "bbbbbb"
        assert receive.receive_nowait() == "BIGBIG"
        assert receive.receive_nowait() == "s1"
        assert receive.receive_nowait() == "s2"

    send.close()
    receive.close()
