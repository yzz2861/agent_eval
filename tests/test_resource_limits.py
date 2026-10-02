from __future__ import annotations

from contextlib import AsyncExitStack
from datetime import timedelta
from logging import getLogger
from pathlib import Path
from typing import cast

import anyio
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apscheduler import AsyncScheduler, Job, JobOutcome, JobResult, Task
from apscheduler.abc import DataStore
from apscheduler.datastores.memory import MemoryDataStore
from apscheduler.datastores.sqlalchemy import SQLAlchemyDataStore
from apscheduler.eventbrokers.local import LocalEventBroker


pytestmark = pytest.mark.anyio


@pytest.fixture
async def memory_resource_store():
    store = MemoryDataStore(resource_limits={"cpu": 2, "gpu": 1})
    async with AsyncExitStack() as exit_stack:
        broker = LocalEventBroker()
        await broker.start(exit_stack, getLogger(__name__ + ".memory.broker"))
        await store.start(exit_stack, broker, getLogger(__name__ + ".memory"))
        yield store


@pytest.fixture
async def sqlite_resource_store():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    store = SQLAlchemyDataStore(engine, resource_limits={"cpu": 2, "gpu": 1})
    async with AsyncExitStack() as exit_stack:
        broker = LocalEventBroker()
        await broker.start(exit_stack, getLogger(__name__ + ".sqlite.broker"))
        await store.start(exit_stack, broker, getLogger(__name__ + ".sqlite"))
        yield store
    await engine.dispose()


@pytest.fixture(params=["memory", "sqlite"])
async def resource_store(request) -> DataStore:
    limits = {"cpu": 2, "gpu": 1}
    if request.param == "memory":
        store: DataStore = MemoryDataStore(resource_limits=limits)
    else:
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        store = SQLAlchemyDataStore(engine, resource_limits=limits)

    async with AsyncExitStack() as exit_stack:
        broker = LocalEventBroker()
        await broker.start(exit_stack, getLogger(__name__ + ".broker"))
        await store.start(exit_stack, broker, getLogger(__name__))
        yield store

    if request.param == "sqlite":
        await engine.dispose()



async def _add_task(store: DataStore) -> None:
    await store.add_task(Task(id="task", func=None, job_executor="async"))


def _job(resources: dict[str, int]) -> Job:
    return Job(task_id="task", executor="async", required_resources=resources)


async def test_resource_requirements_are_atomic(resource_store: DataStore) -> None:
    await _add_task(resource_store)
    first = _job({"cpu": 2, "gpu": 1})
    second = _job({"cpu": 2, "gpu": 1})
    await resource_store.add_job(first)
    await resource_store.add_job(second)

    acquired = await resource_store.acquire_jobs("worker", timedelta(seconds=30), 2)
    assert [job.id for job in acquired] == [first.id]
    assert not await resource_store.acquire_jobs("other", timedelta(seconds=30), 2)

    await resource_store.release_job(
        "worker",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )
    acquired = await resource_store.acquire_jobs("other", timedelta(seconds=30), 2)
    assert [job.id for job in acquired] == [second.id]
    await resource_store.release_job(
        "other",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )


async def test_incomplete_resource_combination_waits(resource_store: DataStore) -> None:
    await _add_task(resource_store)
    combo = _job({"cpu": 1, "gpu": 1})
    cpu_only = _job({"cpu": 1})
    await resource_store.add_job(combo)
    await resource_store.add_job(cpu_only)
    await resource_store.set_resource_limits({"cpu": 2, "gpu": 0})

    acquired = await resource_store.acquire_jobs("worker", timedelta(seconds=30), 2)
    assert [job.id for job in acquired] == [cpu_only.id]
    assert await resource_store.get_jobs({combo.id})
    await resource_store.release_job(
        "worker",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )


async def test_shrinking_resource_capacity(resource_store: DataStore) -> None:
    await _add_task(resource_store)
    job = _job({"cpu": 2})
    await resource_store.add_job(job)

    acquired = await resource_store.acquire_jobs("worker", timedelta(seconds=30), 1)
    assert len(acquired) == 1

    await resource_store.set_resource_limits({"cpu": 1, "gpu": 1})
    pending = _job({"cpu": 1})
    await resource_store.add_job(pending)
    assert not await resource_store.acquire_jobs("other", timedelta(seconds=30), 1)

    await resource_store.release_job(
        "worker",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )
    acquired = await resource_store.acquire_jobs("other", timedelta(seconds=30), 1)
    assert [job.id for job in acquired] == [pending.id]
    await resource_store.release_job(
        "other",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )


async def test_expired_lease_releases_resource_usage(resource_store: DataStore) -> None:
    await _add_task(resource_store)
    abandoned = _job({"cpu": 2, "gpu": 1})
    replacement = _job({"cpu": 2, "gpu": 1})
    await resource_store.add_job(abandoned)
    await resource_store.add_job(replacement)

    acquired = await resource_store.acquire_jobs("lost", timedelta(microseconds=1), 1)
    assert [job.id for job in acquired] == [abandoned.id]
    await anyio.sleep(0.002)
    acquired = await resource_store.acquire_jobs("other", timedelta(seconds=30), 1)
    assert [job.id for job in acquired] == [abandoned.id]
    assert (await resource_store.get_task("task")).running_jobs == 1
    assert await resource_store.get_jobs({replacement.id})

    await resource_store.release_job(
        "other",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )
    acquired = await resource_store.acquire_jobs("other", timedelta(seconds=30), 1)
    assert [job.id for job in acquired] == [replacement.id]
    await resource_store.release_job(
        "other",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )


async def test_resource_limits_api(resource_store: DataStore) -> None:
    assert await resource_store.get_resource_limits() == {"cpu": 2, "gpu": 1}
    await resource_store.set_resource_limits({"cpu": 3})
    assert await resource_store.get_resource_limits() == {"cpu": 3}


async def test_sqlite_resource_acquisition_is_serialized() -> None:
    db_path = Path.cwd() / "resource-concurrency-test.db"
    db_path.unlink(missing_ok=True)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    sqlite_resource_store = SQLAlchemyDataStore(
        engine, resource_limits={"cpu": 2, "gpu": 1}
    )
    async with AsyncExitStack() as exit_stack:
        broker = LocalEventBroker()
        await broker.start(exit_stack, getLogger(__name__ + ".concurrency.broker"))
        await sqlite_resource_store.start(
            exit_stack, broker, getLogger(__name__ + ".concurrency")
        )
        await _add_task(sqlite_resource_store)
        for _ in range(2):
            await sqlite_resource_store.add_job(_job({"cpu": 2, "gpu": 1}))

        results = await anyio.gather(
            sqlite_resource_store.acquire_jobs("worker1", timedelta(seconds=30), 1),
            sqlite_resource_store.acquire_jobs("worker2", timedelta(seconds=30), 1),
        )
        assert [len(result) for result in results].count(1) == 1
        assert (await sqlite_resource_store.get_task("task")).running_jobs == 1
    await engine.dispose()
    for suffix in ("", "-wal", "-shm"):
        Path(f"{db_path}{suffix}").unlink(missing_ok=True)


async def test_late_release_from_lost_executor_is_ignored(
    resource_store: DataStore,
) -> None:
    await _add_task(resource_store)
    job = _job({"cpu": 1})
    await resource_store.add_job(job)

    acquired = await resource_store.acquire_jobs("lost", timedelta(microseconds=1), 1)
    assert [job.id for job in acquired] == [job.id]
    stale_job = acquired[0]
    await anyio.sleep(0.002)

    acquired = await resource_store.acquire_jobs(
        "replacement", timedelta(seconds=30), 1
    )
    assert [job.id for job in acquired] == [job.id]

    await resource_store.release_job(
        "lost",
        stale_job,
        JobResult.from_job(stale_job, JobOutcome.success),
    )
    stored = await resource_store.get_jobs({job.id})
    assert stored
    assert stored[0].acquired_by == "replacement"
    assert (await resource_store.get_task("task")).running_jobs == 1


async def test_cleanup_releases_expired_resource_lease(resource_store: DataStore) -> None:
    await _add_task(resource_store)
    abandoned = _job({"cpu": 2, "gpu": 1})
    replacement = _job({"cpu": 2, "gpu": 1})
    await resource_store.add_job(abandoned)
    await resource_store.add_job(replacement)

    acquired = await resource_store.acquire_jobs("lost", timedelta(microseconds=1), 1)
    assert [job.id for job in acquired] == [abandoned.id]
    await anyio.sleep(0.002)
    await resource_store.cleanup()

    assert not await resource_store.get_jobs({abandoned.id})
    acquired = await resource_store.acquire_jobs("other", timedelta(seconds=30), 1)
    assert [job.id for job in acquired] == [replacement.id]
    assert (await resource_store.get_task("task")).running_jobs == 1
    await resource_store.release_job(
        "other",
        acquired[0],
        JobResult.from_job(acquired[0], JobOutcome.success),
    )


async def test_task_resources_are_applied_to_direct_jobs() -> None:
    async def noop() -> None:
        return None

    data_store = MemoryDataStore(resource_limits={"cpu": 2})
    async with AsyncScheduler(data_store=data_store) as scheduler:
        await scheduler.configure_task(
            "resourceful", func=noop, required_resources={"cpu": 2}
        )
        job_id = await scheduler.add_job("resourceful")
        stored_job = (await data_store.get_jobs({job_id}))[0]
        assert stored_job.required_resources == {"cpu": 2}
