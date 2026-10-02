from __future__ import annotations

import platform
from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
from logging import Logger
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock

import anyio
import pytest
from anyio import CancelScope
from pytest_mock.plugin import MockerFixture

from apscheduler import (
    CoalescePolicy,
    ConflictPolicy,
    DeserializationError,
    Event,
    Job,
    JobOutcome,
    JobResult,
    ResourceCapacityUpdated,
    Schedule,
    ScheduleAdded,
    ScheduleRemoved,
    ScheduleUpdated,
    Task,
    TaskAdded,
    TaskLookupError,
    TaskUpdated,
)
from apscheduler._structures import ScheduleResult
from apscheduler.abc import DataStore, EventBroker, Serializer
from apscheduler.datastores.base import BaseExternalDataStore
from apscheduler.datastores.memory import MemoryDataStore
from apscheduler.datastores.mongodb import MongoDBDataStore
from apscheduler.datastores.sqlalchemy import SQLAlchemyDataStore
from apscheduler.triggers.date import DateTrigger

if TYPE_CHECKING:
    from time_machine import TimeMachineFixture

pytestmark = pytest.mark.anyio


@pytest.fixture
async def datastore(
    raw_datastore: DataStore, local_broker: EventBroker, logger: Logger
) -> AsyncGenerator[DataStore, None]:
    async with AsyncExitStack() as exit_stack:
        await local_broker.start(exit_stack, logger)
        await raw_datastore.start(exit_stack, local_broker, logger)
        yield raw_datastore


@pytest.fixture
def schedules() -> list[Schedule]:
    trigger = DateTrigger(datetime(2020, 9, 13, tzinfo=timezone.utc))
    schedule1 = Schedule(
        id="s1", task_id="task1", job_executor="async", trigger=trigger
    )
    schedule1.next_fire_time = trigger.next()

    trigger = DateTrigger(datetime(2020, 9, 14, tzinfo=timezone.utc))
    schedule2 = Schedule(
        id="s2", task_id="task2", job_executor="async", trigger=trigger
    )
    schedule2.next_fire_time = trigger.next()

    trigger = DateTrigger(datetime(2020, 9, 15, tzinfo=timezone.utc))
    schedule3 = Schedule(
        id="s3", task_id="task1", job_executor="async", trigger=trigger
    )
    schedule3.next_fire_time = trigger.next()

    return [schedule1, schedule2, schedule3]


@asynccontextmanager
async def capture_events(
    datastore: DataStore,
    limit: int,
    event_types: set[type[Event]] | None = None,
) -> AsyncGenerator[list[Event], None]:
    def listener(event: Event) -> None:
        events.append(event)
        if len(events) == limit:
            limit_event.set()
            subscription.unsubscribe()

    events: list[Event] = []
    limit_event = anyio.Event()
    subscription = datastore._event_broker.subscribe(listener, event_types)
    yield events
    if limit:
        with anyio.fail_after(3):
            await limit_event.wait()


async def test_add_replace_task(datastore: DataStore) -> None:
    event_types = {TaskAdded, TaskUpdated}
    async with capture_events(datastore, 3, event_types) as events:
        await datastore.add_task(
            Task(id="test_task", func="builtins:print", job_executor="async")
        )
        await datastore.add_task(
            Task(id="test_task2", func="math:ceil", job_executor="async")
        )
        await datastore.add_task(
            Task(id="test_task", func="builtins:repr", job_executor="async")
        )

        tasks = await datastore.get_tasks()
        assert len(tasks) == 2
        assert tasks[0].id == "test_task"
        assert tasks[0].func == "builtins:repr"
        assert tasks[1].id == "test_task2"
        assert tasks[1].func == "math:ceil"

    received_event = events.pop(0)
    assert isinstance(received_event, TaskAdded)
    assert received_event.task_id == "test_task"

    received_event = events.pop(0)
    assert isinstance(received_event, TaskAdded)
    assert received_event.task_id == "test_task2"

    received_event = events.pop(0)
    assert isinstance(received_event, TaskUpdated)
    assert received_event.task_id == "test_task"

    assert not events


async def test_add_schedules(datastore: DataStore, schedules: list[Schedule]) -> None:
    async with capture_events(datastore, 3, {ScheduleAdded}) as events:
        for schedule in schedules:
            await datastore.add_schedule(schedule, ConflictPolicy.exception)

        assert await datastore.get_schedules() == schedules
        assert await datastore.get_schedules({"s1", "s2", "s3"}) == schedules
        assert await datastore.get_schedules({"s1"}) == [schedules[0]]
        assert await datastore.get_schedules({"s2"}) == [schedules[1]]
        assert await datastore.get_schedules({"s3"}) == [schedules[2]]

    for event, schedule in zip(events, schedules, strict=True):
        assert isinstance(event, ScheduleAdded)
        assert event.schedule_id == schedule.id
        assert event.task_id == schedule.task_id
        assert event.next_fire_time == schedule.next_fire_time


async def test_replace_schedules(
    datastore: DataStore, schedules: list[Schedule]
) -> None:
    async with capture_events(datastore, 1, {ScheduleUpdated}) as events:
        for schedule in schedules:
            await datastore.add_schedule(schedule, ConflictPolicy.exception)

        trigger = DateTrigger(datetime(2020, 9, 16, tzinfo=timezone.utc))
        next_fire_time = trigger.next()
        schedule = Schedule(
            id="s3",
            task_id="foo",
            trigger=trigger,
            args=(),
            kwargs={},
            job_executor="async",
            coalesce=CoalescePolicy.earliest,
            misfire_grace_time=None,
        )
        schedule.next_fire_time = next_fire_time
        await datastore.add_schedule(schedule, ConflictPolicy.replace)

        schedules = await datastore.get_schedules({schedule.id})
        assert schedules[0].task_id == "foo"
        assert schedules[0].next_fire_time == next_fire_time
        assert schedules[0].args == ()
        assert schedules[0].kwargs == {}
        assert schedules[0].coalesce is CoalescePolicy.earliest
        assert schedules[0].misfire_grace_time is None

    received_event = events.pop(0)
    assert isinstance(received_event, ScheduleUpdated)
    assert received_event.schedule_id == "s3"
    assert received_event.task_id == "foo"
    assert received_event.next_fire_time == datetime(2020, 9, 16, tzinfo=timezone.utc)
    assert not events


async def test_remove_schedules(
    datastore: DataStore, schedules: list[Schedule]
) -> None:
    async with capture_events(datastore, 2, {ScheduleRemoved}) as events:
        for schedule in schedules:
            await datastore.add_schedule(schedule, ConflictPolicy.exception)

        await datastore.remove_schedules(["s1", "s2"])
        assert await datastore.get_schedules() == [schedules[2]]

    received_event = events.pop(0)
    assert isinstance(received_event, ScheduleRemoved)
    assert received_event.schedule_id == "s1"

    received_event = events.pop(0)
    assert isinstance(received_event, ScheduleRemoved)
    assert received_event.schedule_id == "s2"

    assert not events


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_acquire_release_schedules(
    datastore: DataStore, schedules: list[Schedule], time_machine: TimeMachineFixture
) -> None:
    time_machine.move_to(datetime(2020, 9, 14, tzinfo=timezone.utc))

    event_types = {ScheduleRemoved, ScheduleUpdated}
    async with capture_events(datastore, 2, event_types) as events:
        for schedule in schedules:
            await datastore.add_schedule(schedule, ConflictPolicy.exception)

        # The first scheduler gets the first due schedule
        schedules1 = await datastore.acquire_schedules(
            "dummy-id1", timedelta(seconds=30), 1
        )
        assert len(schedules1) == 1
        assert schedules1[0].id == "s1"

        # The second scheduler gets the second due schedule
        schedules2 = await datastore.acquire_schedules(
            "dummy-id2",
            timedelta(seconds=30),
            1,
        )
        assert len(schedules2) == 1
        assert schedules2[0].id == "s2"

        # The third scheduler gets nothing
        schedules3 = await datastore.acquire_schedules(
            "dummy-id3",
            timedelta(seconds=30),
            1,
        )
        assert not schedules3

        # Update the schedules and check that the job store actually deletes the
        # first one and updates the second one
        results1: list[ScheduleResult] = []
        results2: list[ScheduleResult] = []
        results1.append(
            ScheduleResult(
                schedule_id=schedules1[0].id,
                task_id=schedules1[0].task_id,
                trigger=schedules1[0].trigger,
                last_fire_time=datetime(2020, 9, 14, tzinfo=timezone.utc),
                next_fire_time=None,
            )
        )
        results2.append(
            ScheduleResult(
                schedule_id=schedules2[0].id,
                task_id=schedules2[0].task_id,
                trigger=schedules1[0].trigger,
                last_fire_time=datetime(2020, 9, 14, tzinfo=timezone.utc),
                next_fire_time=datetime(2020, 9, 15, tzinfo=timezone.utc),
            )
        )

        # Release all the schedules
        await datastore.release_schedules("dummy-id1", results1)
        await datastore.release_schedules("dummy-id2", results2)

        # Check that the first schedule has its next fire time nullified
        schedules = await datastore.get_schedules()
        assert len(schedules) == 3
        schedules.sort(key=lambda s: s.id)
        assert schedules[0].id == "s1"
        assert schedules[0].last_fire_time == datetime(2020, 9, 14, tzinfo=timezone.utc)
        assert schedules[0].next_fire_time is None
        assert schedules[1].id == "s2"
        assert schedules[1].last_fire_time == datetime(2020, 9, 14, tzinfo=timezone.utc)
        assert schedules[1].next_fire_time == datetime(2020, 9, 15, tzinfo=timezone.utc)
        assert schedules[2].id == "s3"
        assert schedules[2].last_fire_time is None
        assert schedules[2].next_fire_time == datetime(2020, 9, 15, tzinfo=timezone.utc)

    # Check for the appropriate update and delete events
    received_event = events.pop(0)
    assert isinstance(received_event, ScheduleUpdated)
    assert received_event.schedule_id == "s1"
    assert received_event.next_fire_time is None

    received_event = events.pop(0)
    assert isinstance(received_event, ScheduleUpdated)
    assert received_event.schedule_id == "s2"
    assert received_event.next_fire_time == datetime(2020, 9, 15, tzinfo=timezone.utc)

    assert not events


async def test_release_schedule_two_identical_fire_times(datastore: DataStore) -> None:
    """Regression test for #616."""
    for i in range(1, 3):
        trigger = DateTrigger(datetime(2020, 9, 13, tzinfo=timezone.utc))
        schedule = Schedule(
            id=f"s{i}", task_id="task1", job_executor="async", trigger=trigger
        )
        schedule.next_fire_time = trigger.next()
        await datastore.add_schedule(schedule, ConflictPolicy.exception)

    schedules = await datastore.acquire_schedules(
        "foo",
        timedelta(seconds=30),
        3,
    )
    results = [
        ScheduleResult(
            schedule_id=schedules[0].id,
            task_id=schedules[0].task_id,
            trigger=schedules[0].trigger,
            last_fire_time=datetime(2020, 9, 10, tzinfo=timezone.utc),
            next_fire_time=None,
        ),
    ]
    await datastore.release_schedules("foo", results)

    remaining = await datastore.get_schedules({s.id for s in schedules})
    assert len(remaining) == 2
    remaining.sort(key=lambda s: s.id)
    assert remaining[0].id == schedules[0].id
    assert remaining[0].next_fire_time is None
    assert remaining[1].id == schedules[1].id
    assert remaining[1].next_fire_time


async def test_release_two_schedules_at_once(datastore: DataStore) -> None:
    """Regression test for #621."""
    for i in range(2):
        trigger = DateTrigger(datetime(2020, 9, 13, tzinfo=timezone.utc))
        schedule = Schedule(
            id=f"s{i}", task_id="task1", job_executor="async", trigger=trigger
        )
        schedule.next_fire_time = trigger.next()
        await datastore.add_schedule(schedule, ConflictPolicy.exception)

    schedules = await datastore.acquire_schedules("foo", timedelta(seconds=30), 3)
    results = [
        ScheduleResult(
            schedule_id=schedules[0].id,
            task_id=schedules[0].task_id,
            trigger=schedules[0].trigger,
            last_fire_time=datetime(2020, 9, 10, tzinfo=timezone.utc),
            next_fire_time=None,
        ),
    ]
    await datastore.release_schedules("foo", results)

    remaining = await datastore.get_schedules({s.id for s in schedules})
    assert len(remaining) == 2


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_acquire_schedules_lock_timeout(
    datastore: DataStore,
    schedules: list[Schedule],
    time_machine: TimeMachineFixture,
) -> None:
    """
    Test that a scheduler can acquire schedules that were acquired by another
    scheduler but not released within the lock timeout period.

    """
    time_machine.move_to(datetime.now(timezone.utc), tick=False)
    await datastore.add_schedule(schedules[0], ConflictPolicy.exception)

    # First, one scheduler acquires the first available schedule
    acquired1 = await datastore.acquire_schedules(
        "dummy-id1",
        timedelta(seconds=30),
        1,
    )
    assert len(acquired1) == 1
    assert acquired1[0].id == "s1"

    # Try to acquire the schedule just at the threshold (now == acquired_until).
    # This should not yield any schedules.
    time_machine.shift(30)
    acquired2 = await datastore.acquire_schedules(
        "dummy-id2",
        timedelta(seconds=30),
        1,
    )
    assert not acquired2

    # Right after that, the schedule should be available
    time_machine.shift(1)
    acquired3 = await datastore.acquire_schedules(
        "dummy-id2",
        timedelta(seconds=30),
        1,
    )
    assert len(acquired3) == 1
    assert acquired3[0].id == "s1"


async def test_acquire_multiple_workers(datastore: DataStore) -> None:
    await datastore.add_task(
        Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    )
    jobs = [Job(task_id="task1", executor="async") for _ in range(2)]
    for job in jobs:
        await datastore.add_job(job)

    # The first worker gets the first job in the queue
    jobs1 = await datastore.acquire_jobs("worker1", timedelta(seconds=30), 1)
    assert len(jobs1) == 1
    assert jobs1[0].id == jobs[0].id

    # The second worker gets the second job
    jobs2 = await datastore.acquire_jobs("worker2", timedelta(seconds=30), 1)
    assert len(jobs2) == 1
    assert jobs2[0].id == jobs[1].id

    # The third worker gets nothing
    jobs3 = await datastore.acquire_jobs("worker3", timedelta(seconds=30), 1)
    assert not jobs3


async def test_job_release_success(datastore: DataStore) -> None:
    await datastore.add_task(
        Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    )
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(minutes=1)
    )
    await datastore.add_job(job)

    acquired = await datastore.acquire_jobs("worker_id", timedelta(seconds=30), 2)
    assert len(acquired) == 1
    assert acquired[0].id == job.id

    await datastore.release_job(
        "worker_id",
        acquired[0],
        JobResult.from_job(
            acquired[0],
            JobOutcome.success,
            return_value="foo",
        ),
    )
    result = await datastore.get_job_result(acquired[0].id)
    assert result
    assert result.outcome is JobOutcome.success
    assert result.exception is None
    assert result.return_value == "foo"

    # Check that the job and its result are gone
    assert not await datastore.get_jobs({acquired[0].id})
    assert not await datastore.get_job_result(acquired[0].id)


async def test_job_release_failure(datastore: DataStore) -> None:
    await datastore.add_task(
        Task(id="task1", job_executor="async", func="contextlib:asynccontextmanager")
    )
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(minutes=1)
    )
    await datastore.add_job(job)

    acquired = await datastore.acquire_jobs("worker_id", timedelta(seconds=30), 2)
    assert len(acquired) == 1
    assert acquired[0].id == job.id

    await datastore.release_job(
        "worker_id",
        acquired[0],
        JobResult.from_job(
            acquired[0],
            JobOutcome.error,
            exception=ValueError("foo"),
        ),
    )
    result = await datastore.get_job_result(acquired[0].id)
    assert result
    assert result.outcome is JobOutcome.error
    assert isinstance(result.exception, ValueError)
    assert result.exception.args == ("foo",)
    assert result.return_value is None

    # Check that the job and its result are gone
    assert not await datastore.get_jobs({acquired[0].id})
    assert not await datastore.get_job_result(acquired[0].id)


async def test_job_release_missed_deadline(datastore: DataStore):
    await datastore.add_task(
        Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    )
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(minutes=1)
    )
    await datastore.add_job(job)

    acquired = await datastore.acquire_jobs("worker_id", timedelta(seconds=30), 2)
    assert len(acquired) == 1
    assert acquired[0].id == job.id

    await datastore.release_job(
        "worker_id",
        acquired[0],
        JobResult.from_job(
            acquired[0],
            JobOutcome.missed_start_deadline,
        ),
    )
    result = await datastore.get_job_result(acquired[0].id)
    assert result
    assert result.outcome is JobOutcome.missed_start_deadline
    assert result.exception is None
    assert result.return_value is None

    # Check that the job and its result are gone
    assert not await datastore.get_jobs({acquired[0].id})
    assert not await datastore.get_job_result(acquired[0].id)


async def test_job_release_cancelled(datastore: DataStore) -> None:
    await datastore.add_task(
        Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    )
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(minutes=1)
    )
    await datastore.add_job(job)

    acquired = await datastore.acquire_jobs("worker1", timedelta(seconds=30), 2)
    assert len(acquired) == 1
    assert acquired[0].id == job.id

    await datastore.release_job(
        "worker1",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.cancelled),
    )
    result = await datastore.get_job_result(acquired[0].id)
    assert result
    assert result.outcome is JobOutcome.cancelled
    assert result.exception is None
    assert result.return_value is None

    # Check that the job and its result are gone
    assert not await datastore.get_jobs({acquired[0].id})
    assert not await datastore.get_job_result(acquired[0].id)


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_acquire_jobs_lock_timeout(
    datastore: DataStore, time_machine: TimeMachineFixture
) -> None:
    """
    Test that a worker can acquire jobs that were acquired by another scheduler but
    not released within the lock timeout period.

    """
    await datastore.add_task(
        Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    )
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(minutes=1)
    )
    await datastore.add_job(job)

    # First, one worker acquires the first available job
    time_machine.move_to(datetime.now(timezone.utc), tick=False)
    acquired = await datastore.acquire_jobs("worker1", timedelta(seconds=30), 1)
    assert len(acquired) == 1
    assert acquired[0].id == job.id

    # Try to acquire the job just at the threshold (now == acquired_until).
    # This should not yield any jobs.
    time_machine.shift(30)
    assert not await datastore.acquire_jobs("worker2", timedelta(seconds=30), 1)

    # Right after that, the job should be available
    time_machine.shift(1)
    acquired = await datastore.acquire_jobs("worker2", timedelta(seconds=30), 1)
    assert len(acquired) == 1
    assert acquired[0].id == job.id


async def test_acquire_jobs_max_number_exceeded(datastore: DataStore) -> None:
    await datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            max_running_jobs=2,
        )
    )
    assert (await datastore.get_task("task1")).running_jobs == 0

    jobs = [
        Job(task_id="task1", executor="async"),
        Job(task_id="task1", executor="async"),
        Job(task_id="task1", executor="async"),
    ]
    for job in jobs:
        await datastore.add_job(job)

    # Check that only 2 jobs are returned from acquire_jobs() even though the limit
    # was 3
    acquired_jobs = await datastore.acquire_jobs("worker1", timedelta(seconds=30), 3)
    assert len(acquired_jobs) == 2
    assert [job.id for job in acquired_jobs] == [job.id for job in jobs[:2]]
    assert (await datastore.get_task("task1")).running_jobs == 2
    for job in acquired_jobs:
        assert job.acquired_by == "worker1"
        assert job.acquired_until

    # Check that no jobs are acquired now that the task is at capacity
    assert not await datastore.acquire_jobs("worker1", timedelta(seconds=30), 3)

    # Release one job, and the worker should be able to acquire the third job
    await datastore.release_job(
        "worker1",
        acquired_jobs[0],
        JobResult.from_job(
            acquired_jobs[0],
            JobOutcome.success,
            return_value=None,
        ),
    )
    assert (await datastore.get_task("task1")).running_jobs == 1
    remaining_jobs = await datastore.get_jobs()
    assert len(remaining_jobs) == 2

    acquired_jobs = await datastore.acquire_jobs("worker1", timedelta(seconds=30), 3)
    assert [job.id for job in acquired_jobs] == [jobs[2].id]
    assert (await datastore.get_task("task1")).running_jobs == 2


async def test_add_get_task(datastore: DataStore) -> None:
    with pytest.raises(TaskLookupError):
        await datastore.get_task("dummyid")

    await datastore.add_task(
        Task(id="dummyid", func="contextlib:asynccontextmanager", job_executor="async")
    )
    task = await datastore.get_task("dummyid")
    assert task.id == "dummyid"
    assert task.func == "contextlib:asynccontextmanager"


async def test_cancel_start(
    raw_datastore: DataStore, local_broker: EventBroker, logger: Logger
) -> None:
    with CancelScope() as scope:
        scope.cancel()
        async with AsyncExitStack() as exit_stack:
            await raw_datastore.start(exit_stack, local_broker, logger)


async def test_cancel_stop(
    raw_datastore: DataStore, local_broker: EventBroker, logger: Logger
) -> None:
    with CancelScope() as scope:
        async with AsyncExitStack() as exit_stack:
            await raw_datastore.start(exit_stack, local_broker, logger)
            scope.cancel()


async def test_next_schedule_run_time(datastore: DataStore, schedules: list[Schedule]):
    next_schedule_run_time = await datastore.get_next_schedule_run_time()
    assert next_schedule_run_time is None

    for schedule in schedules:
        await datastore.add_schedule(schedule, ConflictPolicy.exception)

    next_schedule_run_time = await datastore.get_next_schedule_run_time()
    assert next_schedule_run_time == datetime(2020, 9, 13, tzinfo=timezone.utc)


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_cleanup_expired_schedule_leases(
    datastore: DataStore, schedules: list[Schedule], time_machine: TimeMachineFixture
) -> None:
    """
    Test that clean-up releases schedules whose leases have expired, and notifies
    schedulers about it.

    """
    time_machine.move_to(datetime(2020, 9, 14, tzinfo=timezone.utc))
    await datastore.add_schedule(schedules[0], ConflictPolicy.exception)

    # Acquire the schedule with a scheduler that then dies without releasing it
    acquired = await datastore.acquire_schedules("scheduler1", timedelta(seconds=30), 1)
    assert len(acquired) == 1

    # The lease has not expired yet, so clean-up must leave the schedule alone
    time_machine.shift(20)
    await datastore.cleanup()
    assert not await datastore.acquire_schedules("scheduler2", timedelta(seconds=30), 1)

    # The lease has expired now, so clean-up releases the schedule
    time_machine.shift(20)
    async with capture_events(datastore, 1, {ScheduleUpdated}) as events:
        await datastore.cleanup()

    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ScheduleUpdated)
    assert event.schedule_id == schedules[0].id
    assert event.task_id == schedules[0].task_id
    assert event.next_fire_time == schedules[0].next_fire_time

    acquired = await datastore.acquire_schedules("scheduler2", timedelta(seconds=30), 1)
    assert [schedule.id for schedule in acquired] == [schedules[0].id]


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_extend_acquired_schedule_leases(
    datastore: DataStore, time_machine: TimeMachineFixture, schedules: list[Schedule]
) -> None:
    """
    Test that the leases on acquired schedules are updated to prevent other schedulers
    from acquiring them.

    """
    time_machine.move_to(datetime(2020, 9, 14, tzinfo=timezone.utc))

    # Add a schedule to the data store
    await datastore.add_schedule(schedules[0], ConflictPolicy.exception)

    # Acquire the schedule
    schedules = await datastore.acquire_schedules(
        "scheduler_id",
        timedelta(seconds=30),
        1,
    )
    assert len(schedules) == 1

    # Move 20 seconds forward, then call extend_acquired_schedule_leases(). This should
    # set the acquired_until timestamp to 30 seconds from the new current time.
    time_machine.shift(20)
    await datastore.extend_acquired_schedule_leases(
        "scheduler_id", {schedules[0].id}, timedelta(seconds=30)
    )

    # The schedule was acquired by scheduler_id so scheduler2_id should not be able to
    # acquire it, as it's still within the original lock expiration delay
    assert not await datastore.acquire_schedules(
        "scheduler2_id",
        timedelta(seconds=30),
        1,
    )

    # Move 20 more seconds forward (beyond the initial lock expiration delay), then try
    # to have the second scheduler acquire the schedule again. This should also fail.
    time_machine.shift(20)
    assert not await datastore.acquire_schedules(
        "scheduler2_id",
        timedelta(seconds=30),
        1,
    )

    # Move 20 more seconds forward - this time the schedule should be available
    time_machine.shift(20)
    schedules = await datastore.acquire_schedules(
        "scheduler2_id",
        timedelta(seconds=30),
        1,
    )
    assert len(schedules) == 1


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_extend_acquired_job_leases(
    datastore: DataStore, time_machine: TimeMachineFixture
) -> None:
    """
    Test that the leases on acquired jobs are updated to prevent them from being cleaned
    up as if they had been abandoned.

    """
    time_machine.move_to(datetime(2020, 9, 14, tzinfo=timezone.utc))

    # Add a task to the data store
    task = Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    await datastore.add_task(task)

    # Add a job to the data store
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(seconds=30)
    )
    await datastore.add_job(job)

    # Acquire the job
    jobs = await datastore.acquire_jobs("scheduler_id", timedelta(seconds=30), 1)
    assert len(jobs) == 1

    # Move 20 seconds forward, then call extend_acquired_job_leases(). This should set
    # the acquired_until timestamp to 30 seconds from the new current time.
    time_machine.shift(20)
    await datastore.extend_acquired_job_leases(
        "scheduler_id", {job.id}, timedelta(seconds=30)
    )

    # The job was acquired by scheduler_id so scheduler2_id should not be able to
    # acquire it
    assert not await datastore.acquire_jobs("scheduler2_id", timedelta(seconds=30), 1)

    # Move 20 more seconds forward (beyond the initial lock expiration delay), then make
    # sure that the job is still within the data store.
    time_machine.shift(20)
    await datastore.cleanup()
    jobs = await datastore.get_jobs({job.id})
    assert len(jobs) == 1

    # Move 20 more seconds forward - this time the job's lease will have expired
    time_machine.shift(20)
    await datastore.cleanup()
    assert not await datastore.get_jobs({job.id})

    # Check that a result was recorded, with the "abandoned" outcome
    result = await datastore.get_job_result(job.id)
    assert result
    assert result.outcome is JobOutcome.abandoned


async def test_acquire_jobs_deserialization_failure(
    datastore: DataStore, mocker: MockerFixture
) -> None:
    if not isinstance(datastore, BaseExternalDataStore):
        pytest.skip("Only applicable to external data stores")

    # Add a task to the data store
    task = Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    await datastore.add_task(task)

    # Add a job to the data store
    job = Job(
        task_id="task1", executor="async", result_expiration_time=timedelta(seconds=30)
    )
    await datastore.add_job(job)

    # Make the serializer fail deserialization
    assert isinstance(datastore, BaseExternalDataStore)
    datastore.serializer = Mock(Serializer)
    datastore.serializer.deserialize.configure_mock(side_effect=DeserializationError)

    # This should not yield any jobs
    assert await datastore.acquire_jobs("scheduler_id", timedelta(seconds=30), 1) == []


async def test_reap_abandoned_jobs(
    datastore: DataStore, local_broker: EventBroker, logger: Logger
) -> None:
    # Add a task, schedule and job and acquire the latter two
    task = Task(id="task1", func="contextlib:asynccontextmanager", job_executor="async")
    await datastore.add_task(task)

    job = Job(
        task_id="task1",
        executor="async",
        result_expiration_time=timedelta(seconds=30),
    )
    await datastore.add_job(job)
    await datastore.reap_abandoned_jobs("testscheduler")
    jobs = await datastore.acquire_jobs("testscheduler", timedelta(seconds=30), 1)
    assert len(jobs) == 1

    await datastore.reap_abandoned_jobs("testscheduler")
    assert not await datastore.get_jobs()
    abandoned_job_result = await datastore.get_job_result(jobs[0].id)
    assert abandoned_job_result.outcome is JobOutcome.abandoned

    task = await datastore.get_task("task1")
    assert task.running_jobs == 0


@pytest.fixture
def resource_datastore(datastore: DataStore) -> DataStore:
    if not datastore.supports_resource_quotas:
        pytest.skip(f"{datastore.__class__.__name__} does not support resource quotas")

    return datastore


async def test_resource_capacity_management(resource_datastore: DataStore) -> None:
    async with capture_events(
        resource_datastore, 3, {ResourceCapacityUpdated}
    ) as events:
        await resource_datastore.set_resource_capacity("cpu", 4)
        await resource_datastore.set_resource_capacity("gpu", 1)
        await resource_datastore.set_resource_capacity("cpu", 8)

    assert [event.capacity for event in events] == [4, 1, 8]
    assert await resource_datastore.get_resource_capacities() == {
        "cpu": 8,
        "gpu": 1,
    }

    async with capture_events(
        resource_datastore, 1, {ResourceCapacityUpdated}
    ) as events:
        await resource_datastore.remove_resource_capacity("gpu")

    assert events[0].capacity is None
    assert await resource_datastore.get_resource_capacities() == {"cpu": 8}

    # Removing a nonexistent resource is a no-op
    await resource_datastore.remove_resource_capacity("gpu")
    assert await resource_datastore.get_resource_capacities() == {"cpu": 8}


@pytest.mark.parametrize(
    "name, capacity",
    [("", 1), (None, 1), ("cpu", -1), ("cpu", 1.5), ("cpu", True)],
    ids=["empty-name", "none-name", "negative", "non-integer", "bool"],
)
async def test_resource_capacity_validation(
    resource_datastore: DataStore, name: str, capacity: int
) -> None:
    with pytest.raises(ValueError):
        await resource_datastore.set_resource_capacity(name, capacity)


async def test_acquire_jobs_resource_quota(resource_datastore: DataStore) -> None:
    await resource_datastore.set_resource_capacity("cpu", 4)
    await resource_datastore.set_resource_capacity("gpu", 1)
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"cpu": 2, "gpu": 1},
        )
    )
    jobs = [Job(task_id="task1", executor="async") for _ in range(2)]
    for job in jobs:
        await resource_datastore.add_job(job)

    assert (await resource_datastore.get_task("task1")).resources == {
        "cpu": 2,
        "gpu": 1,
    }

    # The first job gets the full resource combination; the second one must wait
    # because there is not enough "gpu" left for it
    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 2
    )
    assert [job.id for job in acquired] == [jobs[0].id]
    assert await resource_datastore.get_resource_usage() == {"cpu": 2, "gpu": 1}

    # The second job must not be acquired, and no partial allocation may be made
    assert not await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 2
    )
    assert await resource_datastore.get_resource_usage() == {"cpu": 2, "gpu": 1}
    remaining_jobs = await resource_datastore.get_jobs()
    assert len(remaining_jobs) == 2
    unacquired_jobs = [job for job in remaining_jobs if job.acquired_by is None]
    assert [job.id for job in unacquired_jobs] == [jobs[1].id]

    # Releasing the first job frees its resources for the second job
    await resource_datastore.release_job(
        "worker1",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )
    assert await resource_datastore.get_resource_usage() == {}

    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 2
    )
    assert [job.id for job in acquired] == [jobs[1].id]
    assert await resource_datastore.get_resource_usage() == {"cpu": 2, "gpu": 1}


async def test_acquire_jobs_resource_quota_unconfigured_resource(
    resource_datastore: DataStore,
) -> None:
    # A resource with no configured capacity is treated as having a capacity of 0
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"tpu": 1},
        )
    )
    job = Job(task_id="task1", executor="async")
    await resource_datastore.add_job(job)

    assert not await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 1
    )
    assert await resource_datastore.get_resource_usage() == {}

    # Once the capacity is configured, the job can be acquired
    await resource_datastore.set_resource_capacity("tpu", 1)
    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 1
    )
    assert [job.id for job in acquired] == [job.id]
    assert await resource_datastore.get_resource_usage() == {"tpu": 1}


async def test_acquire_jobs_resource_quota_shared_between_schedulers(
    resource_datastore: DataStore,
) -> None:
    await resource_datastore.set_resource_capacity("cpu", 2)
    await resource_datastore.set_resource_capacity("gpu", 2)
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"cpu": 1, "gpu": 1},
        )
    )
    jobs = [Job(task_id="task1", executor="async") for _ in range(4)]
    for job in jobs:
        await resource_datastore.add_job(job)

    # The first worker acquires 2 jobs, exhausting the shared capacity
    acquired1 = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 4
    )
    assert len(acquired1) == 2
    assert await resource_datastore.get_resource_usage() == {"cpu": 2, "gpu": 2}

    # The second worker shares the same bookkeeping, so it cannot acquire any jobs
    assert not await resource_datastore.acquire_jobs(
        "worker2", timedelta(seconds=30), 4
    )

    # When the first worker releases a job, the second worker can acquire exactly one
    await resource_datastore.release_job(
        "worker1",
        acquired1[0],
        JobResult.from_job(acquired1[0], JobOutcome.success),
    )
    acquired2 = await resource_datastore.acquire_jobs(
        "worker2", timedelta(seconds=30), 4
    )
    assert len(acquired2) == 1
    assert await resource_datastore.get_resource_usage() == {"cpu": 2, "gpu": 2}


async def test_resource_capacity_shrink(resource_datastore: DataStore) -> None:
    await resource_datastore.set_resource_capacity("cpu", 2)
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"cpu": 1},
        )
    )
    jobs = [Job(task_id="task1", executor="async") for _ in range(3)]
    for job in jobs:
        await resource_datastore.add_job(job)

    acquired = await resource_datastore.acquire_jobs("worker", timedelta(seconds=30), 2)
    assert len(acquired) == 2

    # Shrinking the capacity below the current usage must not affect the running
    # jobs, but no new jobs can be acquired while the usage exceeds the capacity
    await resource_datastore.set_resource_capacity("cpu", 1)
    assert not await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 2
    )
    assert await resource_datastore.get_resource_usage() == {"cpu": 2}

    # Releasing one job is not enough to get below the shrunken capacity
    await resource_datastore.release_job(
        "worker1",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )
    assert not await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 2
    )

    # Once the usage drops below the capacity, new jobs can be acquired again
    await resource_datastore.release_job(
        "worker1",
        acquired[1],
        JobResult.from_job(acquired[1], JobOutcome.success),
    )
    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 2
    )
    assert [job.id for job in acquired] == [jobs[2].id]


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_resource_reclaim_on_lease_expiry(
    resource_datastore: DataStore, time_machine: TimeMachineFixture
) -> None:
    await resource_datastore.set_resource_capacity("cpu", 2)
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"cpu": 2},
        )
    )
    job = Job(task_id="task1", executor="async")
    await resource_datastore.add_job(job)

    time_machine.move_to(datetime.now(timezone.utc), tick=False)
    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 1
    )
    assert len(acquired) == 1
    assert await resource_datastore.get_resource_usage() == {"cpu": 2}

    # The worker dies; once the lease expires, clean-up reclaims the resources
    time_machine.shift(31)
    await resource_datastore.cleanup()
    assert await resource_datastore.get_resource_usage() == {}
    assert not await resource_datastore.get_jobs()


@pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="time-machine is not available",
)
async def test_resource_reclaim_on_reacquisition(
    resource_datastore: DataStore, time_machine: TimeMachineFixture
) -> None:
    await resource_datastore.set_resource_capacity("cpu", 2)
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"cpu": 2},
        )
    )
    job = Job(task_id="task1", executor="async")
    await resource_datastore.add_job(job)

    time_machine.move_to(datetime.now(timezone.utc), tick=False)
    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 1
    )
    assert len(acquired) == 1
    assert await resource_datastore.get_resource_usage() == {"cpu": 2}

    # The worker dies; another worker re-acquires the job after the lease expires.
    # The stale allocation must be replaced, not added to.
    time_machine.shift(31)
    acquired = await resource_datastore.acquire_jobs(
        "worker2", timedelta(seconds=30), 1
    )
    assert len(acquired) == 1
    assert await resource_datastore.get_resource_usage() == {"cpu": 2}


async def test_reap_abandoned_jobs_releases_resources(
    resource_datastore: DataStore,
) -> None:
    await resource_datastore.set_resource_capacity("cpu", 2)
    await resource_datastore.add_task(
        Task(
            id="task1",
            func="contextlib:asynccontextmanager",
            job_executor="async",
            resources={"cpu": 2},
        )
    )
    job = Job(task_id="task1", executor="async")
    await resource_datastore.add_job(job)

    acquired = await resource_datastore.acquire_jobs(
        "worker1", timedelta(seconds=30), 1
    )
    assert len(acquired) == 1
    assert await resource_datastore.get_resource_usage() == {"cpu": 2}

    await resource_datastore.reap_abandoned_jobs("worker1")
    assert await resource_datastore.get_resource_usage() == {}


async def test_resource_quotas_capability_declaration() -> None:
    assert MemoryDataStore.supports_resource_quotas
    assert SQLAlchemyDataStore.supports_resource_quotas
    assert not MongoDBDataStore.supports_resource_quotas

    # The default implementations must raise NotImplementedError
    mongodb_store = object.__new__(MongoDBDataStore)
    with pytest.raises(NotImplementedError):
        await mongodb_store.set_resource_capacity("cpu", 1)

    with pytest.raises(NotImplementedError):
        await mongodb_store.remove_resource_capacity("cpu")

    with pytest.raises(NotImplementedError):
        await mongodb_store.get_resource_capacities()

    with pytest.raises(NotImplementedError):
        await mongodb_store.get_resource_usage()


class TestRepr:
    async def test_memory(self, memory_store: MemoryDataStore) -> None:
        assert repr(memory_store) == "MemoryDataStore()"

    async def test_sqlite(self, tmp_path: Path) -> None:
        from sqlalchemy import create_engine

        expected_path = str(tmp_path).replace("\\", "\\\\")
        engine = create_engine(f"sqlite:///{tmp_path}")
        data_store = SQLAlchemyDataStore(engine)
        assert repr(data_store) == (
            f"SQLAlchemyDataStore(url='sqlite:///{expected_path}')"
        )

    async def test_psycopg(self) -> None:
        from sqlalchemy.ext.asyncio import create_async_engine

        pytest.importorskip("psycopg", reason="psycopg not available")
        engine = create_async_engine(
            "postgresql+psycopg://postgres:secret@localhost/testdb"
        )
        data_store = SQLAlchemyDataStore(engine, schema="myschema")
        assert repr(data_store) == (
            "SQLAlchemyDataStore(url='postgresql+psycopg://postgres:***@localhost/"
            "testdb', schema='myschema')"
        )

    async def test_mongodb(self) -> None:
        from pymongo.asynchronous.mongo_client import AsyncMongoClient

        async with AsyncMongoClient() as client:
            data_store = MongoDBDataStore(client)
            assert repr(data_store) == "MongoDBDataStore(host=[('localhost', 27017)])"
