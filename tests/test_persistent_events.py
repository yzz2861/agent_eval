from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AsyncExitStack
from datetime import datetime, timedelta, timezone
from logging import getLogger
from pathlib import Path
from unittest.mock import patch

import anyio
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from apscheduler import (
    ConflictPolicy,
    Job,
    JobAcquired,
    JobOutcome,
    JobResult,
    JobReleased,
    PersistentEventHistoryExpiredError,
    Schedule,
    ScheduleResult,
    ScheduleUpdated,
    Task,
)
from apscheduler.datastores.sqlalchemy import PersistentEvent, SQLAlchemyDataStore
from apscheduler.eventbrokers.local import LocalEventBroker
from apscheduler.triggers.date import DateTrigger

pytestmark = pytest.mark.anyio


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    db_path = Path(__file__).parent.parent / ".tmp" / "persistent-events-test.db"
    db_path.parent.mkdir(exist_ok=True)
    db_path.unlink(missing_ok=True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        yield engine
    finally:
        await engine.dispose()


async def start_store(
    engine: AsyncEngine,
    *,
    retention: timedelta | None = None,
) -> tuple[SQLAlchemyDataStore, LocalEventBroker, AsyncExitStack]:
    store = SQLAlchemyDataStore(
        engine,
        persistent_events=True,
        persistent_event_retention=retention,
    )
    broker = LocalEventBroker()
    exit_stack = AsyncExitStack()
    await broker.start(exit_stack, getLogger(__name__))
    await store.start(exit_stack, broker, getLogger(__name__))
    return store, broker, exit_stack


def listener_for(
    events: list[PersistentEvent], count: int
) -> tuple[object, anyio.Event]:
    done = anyio.Event()

    def listener(event: PersistentEvent) -> None:
        events.append(event)
        if len(events) == count:
            done.set()

    return listener, done


async def test_persistent_subscription_replays_and_tracks_cursor(
    engine: AsyncEngine,
) -> None:
    events: list[PersistentEvent] = []
    store, broker, exit_stack = await start_store(engine)
    try:
        await store.add_task(
            Task(id="task", func="builtins:print", job_executor="async")
        )
        trigger = DateTrigger(datetime.now(timezone.utc))
        schedule = Schedule(
            id="schedule", task_id="task", trigger=trigger, job_executor="async"
        )
        schedule.next_fire_time = trigger.next()
        await store.add_schedule(schedule, ConflictPolicy.exception)

        listener, done = listener_for(events, 2)
        subscription = await store.subscribe_persistent_events(
            listener,
            subscription_id="ops-ui",
            start_from=0,
        )
        with anyio.fail_after(3):
            await done.wait()
        await subscription.aclose()
        assert [event.id for event in events] == [1, 2]

        acquired = await store.acquire_schedules("scheduler", timedelta(minutes=1), 1)
        result = ScheduleResult(
            schedule_id=acquired[0].id,
            task_id=acquired[0].task_id,
            trigger=acquired[0].trigger,
            last_fire_time=acquired[0].next_fire_time,
            next_fire_time=None,
        )
        await store.release_schedules("scheduler", [result])
    finally:
        await exit_stack.aclose()

    store, broker, exit_stack = await start_store(engine)
    try:
        events_after_restart: list[PersistentEvent] = []
        listener, done = listener_for(events_after_restart, 1)
        await store.subscribe_persistent_events(
            listener,
            {ScheduleUpdated},
            subscription_id="ops-ui",
        )

        with anyio.fail_after(3):
            await done.wait()
        assert isinstance(events_after_restart[0].event, ScheduleUpdated)
        assert events_after_restart[0].id > events[-1].id
    finally:
        await exit_stack.aclose()


async def test_event_survives_notification_interruption(
    engine: AsyncEngine,
) -> None:
    store, broker, exit_stack = await start_store(engine)
    try:
        await store.add_task(
            Task(id="task", func="builtins:print", job_executor="async")
        )
        job = Job(task_id="task", executor="async")

        original_publish = broker.publish

        async def interrupted_publish(event):
            if isinstance(event, (JobAcquired, JobReleased)):
                raise RuntimeError("connection lost")
            return await original_publish(event)

        with patch.object(broker, "publish", side_effect=interrupted_publish):
            await store.add_job(job)
            with pytest.raises(RuntimeError, match="connection lost"):
                await store.acquire_jobs("scheduler", timedelta(minutes=1), 1)
            job.acquired_by = "scheduler"
            result = JobResult.from_job(job, JobOutcome.success, return_value=None)
            with pytest.raises(RuntimeError, match="connection lost"):
                await store.release_job("scheduler", job, result)

        events: list[PersistentEvent] = []
        listener, done = listener_for(events, 2)
        subscription = await store.subscribe_persistent_events(
            listener,
            {JobAcquired, JobReleased},
            subscription_id="ops-ui",
            start_from=0,
        )
        with anyio.fail_after(3):
            await done.wait()

        assert isinstance(events[0].event, JobAcquired)
        assert isinstance(events[1].event, JobReleased)
        assert events[0].event.job_id == job.id
        assert events[1].event.job_id == job.id
        await subscription.aclose()
    finally:
        await exit_stack.aclose()


async def test_subscribers_advance_independently(engine: AsyncEngine) -> None:
    store, broker, exit_stack = await start_store(engine)
    try:
        first_events: list[PersistentEvent] = []
        first_listener, first_done = listener_for(first_events, 1)
        await store.subscribe_persistent_events(
            first_listener,
            subscription_id="first",
            start_from=0,
        )

        await store.add_task(
            Task(id="task", func="builtins:print", job_executor="async")
        )
        with anyio.fail_after(3):
            await first_done.wait()

        second_events: list[PersistentEvent] = []
        second_listener, second_done = listener_for(second_events, 1)
        await store.subscribe_persistent_events(
            second_listener,
            subscription_id="second",
            start_from=0,
        )
        with anyio.fail_after(3):
            await second_done.wait()

        assert first_events[0].id == second_events[0].id == 1
    finally:
        await exit_stack.aclose()


async def test_failed_callback_retries_same_event(engine: AsyncEngine) -> None:
    store, broker, exit_stack = await start_store(engine)
    try:
        attempts = 0
        delivered: list[PersistentEvent] = []
        done = anyio.Event()

        def listener(event: PersistentEvent) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("temporary callback failure")
            delivered.append(event)
            done.set()

        subscription = await store.subscribe_persistent_events(
            listener,
            subscription_id="ops-ui",
            start_from=0,
        )
        await store.add_task(
            Task(id="task", func="builtins:print", job_executor="async")
        )
        with anyio.fail_after(3):
            await done.wait()

        assert attempts == 2
        assert len(delivered) == 1
        assert delivered[0].id == 1
        await subscription.aclose()
    finally:
        await exit_stack.aclose()


async def test_retention_requires_resynchronization(engine: AsyncEngine) -> None:
    store, broker, exit_stack = await start_store(engine, retention=timedelta(0))
    try:
        await store.add_task(
            Task(id="task", func="builtins:print", job_executor="async")
        )
        retention_events: list[PersistentEvent] = []
        listener, done = listener_for(retention_events, 1)
        subscription = await store.subscribe_persistent_events(
            listener,
            subscription_id="ops-ui",
            start_from=0,
        )
        with anyio.fail_after(3):
            await done.wait()
        await subscription.aclose()
        await store.cleanup()

        with pytest.raises(PersistentEventHistoryExpiredError):
            await store.subscribe_persistent_events(
                lambda event: None,
                subscription_id="ops-ui",
                start_from=0,
            )
        with pytest.raises(PersistentEventHistoryExpiredError):
            await store.resynchronize_persistent_subscription(
                "ops-ui", start_from=1
            )
    finally:
        await exit_stack.aclose()
