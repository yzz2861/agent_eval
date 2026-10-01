from __future__ import annotations

import json

import trio

from .. import _core
from ..testing import wait_all_tasks_blocked

record_wait_diagnostics = _core.record_wait_diagnostics
wait_graph_snapshot = _core.wait_graph_snapshot


def _current_task_id() -> int:
    return id(_core.current_task())


def _edges_for(
    snapshot: _core.WaitGraphSnapshot,
    task_id: int,
) -> list[_core.WaitEdge]:
    return [edge for edge in snapshot.edges if edge.task_id == task_id]


async def test_disabled_by_default() -> None:
    assert not _core.wait_diagnostics_enabled()
    lock = trio.Lock()
    async with lock:
        pass
    async with trio.open_nursery() as nursery:
        nursery.start_soon(lock.acquire)
        await wait_all_tasks_blocked()
        snapshot = wait_graph_snapshot()
        assert snapshot.edges == ()
        assert snapshot.definite_cycles == ()
        assert not snapshot.diagnostics_enabled
        nursery.cancel_scope.cancel()


async def test_lock_wait_edge_and_owner() -> None:
    lock = trio.Lock()
    holder_id: int | None = None
    waiter_id: int | None = None

    async def holder(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal holder_id
        holder_id = _current_task_id()
        await lock.acquire()
        task_status.started()
        await trio.sleep_forever()

    async def waiter(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal waiter_id
        waiter_id = _current_task_id()
        task_status.started()
        await lock.acquire()

    with record_wait_diagnostics():
        assert _core.wait_diagnostics_enabled()
        async with trio.open_nursery() as nursery:
            await nursery.start(holder)
            await nursery.start(waiter)
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            assert snapshot.diagnostics_enabled
            (edge,) = _edges_for(snapshot, waiter_id)
            assert edge.resource_kind == "lock"
            assert edge.operation == "acquire"
            assert edge.resource_id == id(lock)
            assert edge.owner_task_ids == (holder_id,)
            assert edge.owner_evidence_complete
            # A one-directional wait is not a cycle.
            assert snapshot.definite_cycles == ()
            nursery.cancel_scope.cancel()
        # Both tasks exited; nothing may be retained.
        assert _edges_for(wait_graph_snapshot(), waiter_id) == []
        assert _edges_for(wait_graph_snapshot(), holder_id) == []
    assert not _core.wait_diagnostics_enabled()


async def test_double_lock_cycle_is_definite_and_cancel_clears_it() -> None:
    lock1 = trio.Lock()
    lock2 = trio.Lock()
    both_holding = trio.Event()
    task_ids: dict[str, int] = {}

    async def looper(
        name: str,
        first: trio.Lock,
        second: trio.Lock,
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        task_ids[name] = _current_task_id()
        await first.acquire()
        task_status.started()
        await both_holding.wait()
        await second.acquire()

    with record_wait_diagnostics():
        async with trio.open_nursery() as nursery:
            await nursery.start(looper, "a", lock1, lock2)
            await nursery.start(looper, "b", lock2, lock1)
            both_holding.set()
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            assert snapshot.deadlocked_task_ids == frozenset(task_ids.values())
            (cycle,) = snapshot.definite_cycles
            assert set(cycle) == {task_ids["a"], task_ids["b"]}
            # Cancelling the tasks breaks the cycle and removes the edges.
            nursery.cancel_scope.cancel()
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            assert snapshot.definite_cycles == ()
            assert _edges_for(snapshot, task_ids["a"]) == []
            assert _edges_for(snapshot, task_ids["b"]) == []


async def test_capacity_limiter_edge_and_incomplete_evidence() -> None:
    limiter = trio.CapacityLimiter(1)
    holder_id: int | None = None
    waiter_id: int | None = None

    async def holder(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal holder_id
        holder_id = _current_task_id()
        await limiter.acquire()
        task_status.started()
        await trio.sleep_forever()

    async def waiter(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal waiter_id
        waiter_id = _current_task_id()
        task_status.started()
        await limiter.acquire()

    with record_wait_diagnostics():
        async with trio.open_nursery() as nursery:
            await nursery.start(holder)
            await nursery.start(waiter)
            await wait_all_tasks_blocked()
            (edge,) = _edges_for(wait_graph_snapshot(), waiter_id)
            assert edge.resource_kind == "capacity_limiter"
            assert edge.resource_id == id(limiter)
            assert edge.owner_task_ids == (holder_id,)
            assert edge.owner_evidence_complete
            nursery.cancel_scope.cancel()

        # A token borrowed on behalf of a non-task object means we cannot
        # name a task that would release it: evidence is incomplete, and
        # no definite cycle may be reported through such an edge.
        limiter2 = trio.CapacityLimiter(1)
        limiter2.acquire_on_behalf_of_nowait(object())
        async with trio.open_nursery() as nursery:
            nursery.start_soon(limiter2.acquire)
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            (edge,) = [
                e for e in snapshot.edges if e.resource_kind == "capacity_limiter"
            ]
            assert edge.owner_task_ids == ()
            assert not edge.owner_evidence_complete
            assert snapshot.definite_cycles == ()
            nursery.cancel_scope.cancel()


async def test_capacity_limiter_lock_cycle() -> None:
    limiter = trio.CapacityLimiter(1)
    lock = trio.Lock()
    both_holding = trio.Event()
    task_ids: dict[str, int] = {}

    async def holds_limiter(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        task_ids["limiter"] = _current_task_id()
        await limiter.acquire()
        task_status.started()
        await both_holding.wait()
        await lock.acquire()

    async def holds_lock(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        task_ids["lock"] = _current_task_id()
        await lock.acquire()
        task_status.started()
        await both_holding.wait()
        await limiter.acquire()

    with record_wait_diagnostics():
        async with trio.open_nursery() as nursery:
            await nursery.start(holds_limiter)
            await nursery.start(holds_lock)
            both_holding.set()
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            assert snapshot.deadlocked_task_ids == frozenset(task_ids.values())
            nursery.cancel_scope.cancel()


async def test_memory_channel_waits_are_not_deadlocks() -> None:
    send_channel, receive_channel = trio.open_memory_channel[str](0)
    receiver_id: int | None = None
    sender_id: int | None = None

    async def receiver(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal receiver_id
        receiver_id = _current_task_id()
        task_status.started()
        await receive_channel.receive()

    async def sender(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal sender_id
        sender_id = _current_task_id()
        task_status.started()
        await send_channel.send("hello")

    with record_wait_diagnostics():
        # A consumer blocked waiting for the next message is a normal
        # state, not a deadlock.
        async with trio.open_nursery() as nursery:
            await nursery.start(receiver)
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            (edge,) = _edges_for(snapshot, receiver_id)
            assert edge.resource_kind == "memory_receive_channel"
            assert edge.operation == "receive"
            assert edge.resource_id == id(receive_channel)
            assert edge.owner_task_ids == ()
            assert snapshot.definite_cycles == ()
            nursery.cancel_scope.cancel()

        # A sender blocked on a full (here: unbuffered) channel is not
        # a deadlock either.
        async with trio.open_nursery() as nursery:
            await nursery.start(sender)
            await wait_all_tasks_blocked()
            snapshot = wait_graph_snapshot()
            (edge,) = _edges_for(snapshot, sender_id)
            assert edge.resource_kind == "memory_send_channel"
            assert edge.operation == "send"
            assert edge.owner_task_ids == ()
            assert snapshot.definite_cycles == ()
            nursery.cancel_scope.cancel()


async def test_unrecognized_wait_type_is_preserved() -> None:
    event = trio.Event()
    waiter_id: int | None = None

    async def waiter(
        task_status: trio.TaskStatus[None] = trio.TASK_STATUS_IGNORED,
    ) -> None:
        nonlocal waiter_id
        waiter_id = _current_task_id()
        task_status.started()
        await event.wait()

    with record_wait_diagnostics():
        async with trio.open_nursery() as nursery:
            await nursery.start(waiter)
            await wait_all_tasks_blocked()
            (edge,) = _edges_for(wait_graph_snapshot(), waiter_id)
            assert edge.resource_kind == "unknown"
            assert edge.resource_id is None
            assert edge.owner_task_ids == ()
            nursery.cancel_scope.cancel()


async def test_edges_removed_when_wait_completes() -> None:
    send_channel, receive_channel = trio.open_memory_channel[str](0)
    receiver_id: int | None = None

    async def receiver() -> str:
        nonlocal receiver_id
        receiver_id = _current_task_id()
        return await receive_channel.receive()

    with record_wait_diagnostics():
        async with trio.open_nursery() as nursery:
            nursery.start_soon(receiver)
            await wait_all_tasks_blocked()
            assert _edges_for(wait_graph_snapshot(), receiver_id)
            await send_channel.send("hello")
            await wait_all_tasks_blocked()
            # The wait completed normally, so the edge is gone.
            assert _edges_for(wait_graph_snapshot(), receiver_id) == []


async def test_snapshot_is_structured_and_json_serializable() -> None:
    lock = trio.Lock()

    async def waiter() -> None:
        await lock.acquire()

    with record_wait_diagnostics():
        async with lock:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(waiter)
                await wait_all_tasks_blocked()
                snapshot = wait_graph_snapshot()
                nursery.cancel_scope.cancel()
        as_dict = snapshot.to_dict()
        json.dumps(as_dict)
        assert as_dict["diagnostics_enabled"]
        assert isinstance(as_dict["edges"], list)
        assert isinstance(as_dict["definite_cycles"], list)
        (edge_dict,) = [e for e in as_dict["edges"] if e["resource_kind"] == "lock"]
        assert edge_dict["operation"] == "acquire"
        assert isinstance(edge_dict["task_id"], int)
        assert isinstance(edge_dict["task_name"], str)


async def test_diagnostics_do_not_change_behavior() -> None:
    # With diagnostics enabled, primitives keep their usual semantics.
    with record_wait_diagnostics():
        lock = trio.Lock()
        order = []

        async def user(name: str) -> None:
            async with lock:
                order.append(name)

        async with trio.open_nursery() as nursery:
            for name in ("a", "b", "c"):
                nursery.start_soon(user, name)
        assert sorted(order) == ["a", "b", "c"]

        send_channel, receive_channel = trio.open_memory_channel[str](1)
        async with trio.open_nursery() as nursery:
            nursery.start_soon(send_channel.send, "x")
            assert await receive_channel.receive() == "x"

        limiter = trio.CapacityLimiter(1)
        async with limiter:
            pass
        assert limiter.borrowed_tokens == 0


async def test_nested_record_wait_diagnostics() -> None:
    assert not _core.wait_diagnostics_enabled()
    with record_wait_diagnostics():
        with record_wait_diagnostics():
            assert _core.wait_diagnostics_enabled()
        # Nested exit does not disable the outer context.
        assert _core.wait_diagnostics_enabled()
    assert not _core.wait_diagnostics_enabled()
