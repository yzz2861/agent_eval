from __future__ import annotations

import trio


async def test_lock_cycle_is_reported_as_certain() -> None:
    first_has_lock = trio.Event()
    second_has_lock = trio.Event()
    lock1 = trio.Lock()
    lock2 = trio.Lock()

    async def hold_first_wait_second() -> None:
        async with lock1:
            first_has_lock.set()
            await second_has_lock.wait()
            await lock2.acquire()

    async def hold_second_wait_first() -> None:
        async with lock2:
            second_has_lock.set()
            await lock1.acquire()

    with trio.CancelScope() as cancel_scope:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(hold_first_wait_second)
            await first_has_lock.wait()
            with trio.lowlevel.wait_diagnostics() as diagnostics:
                nursery.start_soon(hold_second_wait_first)
                await trio.testing.wait_all_tasks_blocked()
                snapshot = diagnostics.snapshot()

                lock_waits = [
                    wait for wait in snapshot.waits if wait.resource_kind == "lock"
                ]
                assert len(lock_waits) == 2
                assert len(snapshot.cycles) == 1
                cycle = snapshot.cycles[0]
                assert cycle.certain
                assert len(cycle.task_ids) == 2
                assert len(cycle.resource_ids) == 2
                assert {edge.operation for edge in cycle.edges} == {"acquire"}
                cancel_scope.cancel()


async def test_channel_receive_wait_is_not_a_deadlock_cycle() -> None:
    send_channel, receive_channel = trio.open_memory_channel[object](0)
    receive_started = trio.Event()

    async def receive_next() -> None:
        receive_started.set()
        await receive_channel.receive()

    with trio.lowlevel.wait_diagnostics() as diagnostics:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(receive_next)
            await receive_started.wait()
            await trio.testing.wait_all_tasks_blocked()
            snapshot = diagnostics.snapshot()

            wait = next(
                candidate
                for candidate in snapshot.waits
                if candidate.operation == "channel_receive"
            )
            assert wait.resource_kind == "memory_channel"
            resource = next(
                candidate
                for candidate in snapshot.resources
                if candidate.id == wait.resource_id
            )
            assert resource.buffer_used == 0
            assert snapshot.cycles == ()

            await send_channel.send(None)


async def test_capacity_limiter_reports_borrowers_without_cycle() -> None:
    limiter = trio.CapacityLimiter(1)
    holder_started = trio.Event()

    async def hold_capacity() -> None:
        async with limiter:
            holder_started.set()
            await trio.sleep_forever()

    async def wait_for_capacity() -> None:
        await limiter.acquire()

    with trio.CancelScope() as cancel_scope:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(hold_capacity)
            await holder_started.wait()
            with trio.lowlevel.wait_diagnostics() as diagnostics:
                nursery.start_soon(wait_for_capacity)
                await trio.testing.wait_all_tasks_blocked()
                snapshot = diagnostics.snapshot()

                wait = next(
                    candidate
                    for candidate in snapshot.waits
                    if candidate.operation == "acquire_capacity"
                )
                resource = next(
                    candidate
                    for candidate in snapshot.resources
                    if candidate.id == wait.resource_id
                )
                assert resource.kind == "capacity_limiter"
                assert resource.borrowed_tokens == 1
                assert resource.total_tokens == 1
                assert len(resource.borrower_ids) == 1
                assert resource.borrower_ids[0].kind == "task"
                assert snapshot.cycles == ()
                cancel_scope.cancel()


async def test_channel_send_wait_reports_full_buffer_without_cycle() -> None:
    send_channel, receive_channel = trio.open_memory_channel[object](1)
    send_started = trio.Event()
    await send_channel.send(1)

    async def send_next() -> None:
        send_started.set()
        await send_channel.send(2)

    with trio.lowlevel.wait_diagnostics() as diagnostics:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(send_next)
            await send_started.wait()
            await trio.testing.wait_all_tasks_blocked()
            snapshot = diagnostics.snapshot()

            wait = next(
                candidate
                for candidate in snapshot.waits
                if candidate.operation == "channel_send"
            )
            resource = next(
                candidate
                for candidate in snapshot.resources
                if candidate.id == wait.resource_id
            )
            assert wait.resource_kind == "memory_channel"
            assert resource.buffer_used == 1
            assert resource.max_buffer_size == 1
            assert snapshot.cycles == ()

            assert await receive_channel.receive() == 1


async def test_cancelled_wait_edge_is_removed() -> None:
    lock = trio.Lock()
    holder_started = trio.Event()
    current = trio.lowlevel.current_task()

    async def hold_lock() -> None:
        async with lock:
            holder_started.set()
            await trio.sleep_forever()

    with trio.CancelScope() as overall:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(hold_lock)
            await holder_started.wait()
            with trio.lowlevel.wait_diagnostics() as diagnostics:
                with trio.move_on_after(0.01):
                    await lock.acquire()
                snapshot = diagnostics.snapshot()

                assert all(wait.task_id != current.id for wait in snapshot.waits)
                assert snapshot.cycles == ()
                overall.cancel()


async def test_unrecognized_wait_is_retained_and_uses_stable_id() -> None:
    with trio.CancelScope() as cancel_scope:
        with trio.lowlevel.wait_diagnostics() as diagnostics:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(trio.sleep_forever)
                await trio.testing.wait_all_tasks_blocked()
                first = diagnostics.snapshot()
                second = diagnostics.snapshot()

                wait = next(
                    candidate
                    for candidate in first.waits
                    if candidate.task_id != trio.lowlevel.current_task().id
                )
                same_wait = next(
                    candidate
                    for candidate in second.waits
                    if candidate.task_id == wait.task_id
                )
                assert wait.resource_kind == "unknown"
                assert wait.operation == "unknown"
                assert wait == same_wait
                cancel_scope.cancel()


async def test_snapshots_use_task_ids() -> None:
    current = trio.lowlevel.current_task()
    with trio.lowlevel.wait_diagnostics() as diagnostics:
        snapshot = diagnostics.snapshot()
        assert next(task for task in snapshot.tasks if task.id == current.id)


async def test_finished_task_does_not_remain_in_diagnostics() -> None:
    finished = trio.Event()
    task_ids: list[int] = []

    async def finish() -> None:
        task_ids.append(trio.lowlevel.current_task().id)
        finished.set()

    with trio.lowlevel.wait_diagnostics() as diagnostics:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(finish)
            await finished.wait()
            await trio.testing.wait_all_tasks_blocked()
            snapshot = diagnostics.snapshot()

            finished_id = task_ids[0]
            assert not any(wait.task_id == finished_id for wait in snapshot.waits)
