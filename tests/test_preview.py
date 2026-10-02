from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest
from anyio import fail_after

from apscheduler import (
    AsyncScheduler,
    CoalescePolicy,
    FireTimeDecision,
    FireTimePreview,
    JobAdded,
    Schedule,
    Scheduler,
    SchedulerRole,
    ScheduleUpdated,
)
from apscheduler._preview import preview_schedule
from apscheduler.abc import DataStore, Trigger
from apscheduler.triggers.combining import OrTrigger
from apscheduler.triggers.interval import IntervalTrigger

pytestmark = pytest.mark.anyio


async def dummy_job() -> None:
    pass


def make_schedule(trigger: Trigger, **kwargs) -> Schedule:
    schedule = Schedule(
        id="sched1", task_id="task1", trigger=trigger, job_executor="async", **kwargs
    )
    schedule.next_fire_time = trigger.next()
    return schedule


class TestPreviewFunction:
    @pytest.mark.parametrize(
        "coalesce, expected_decisions",
        [
            pytest.param(
                CoalescePolicy.all,
                [FireTimeDecision.create_job] * 4,
                id="all",
            ),
            pytest.param(
                CoalescePolicy.earliest,
                [FireTimeDecision.create_job] + [FireTimeDecision.coalesced] * 3,
                id="earliest",
            ),
            pytest.param(
                CoalescePolicy.latest,
                [FireTimeDecision.coalesced] * 3 + [FireTimeDecision.create_job],
                id="latest",
            ),
        ],
    )
    def test_coalesce_policy(
        self, coalesce: CoalescePolicy, expected_decisions: list[FireTimeDecision]
    ) -> None:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=3, seconds=5)
        trigger = IntervalTrigger(minutes=1, start_time=start_time)
        schedule = make_schedule(trigger, coalesce=coalesce)

        preview = preview_schedule(schedule, now=now, max_results=4)

        assert preview.schedule_id == "sched1"
        assert preview.task_id == "task1"
        assert preview.now == now
        assert not preview.paused
        assert preview.note is None
        assert [entry.decision for entry in preview.fire_times] == expected_decisions
        for index, entry in enumerate(preview.fire_times):
            assert entry.fire_time == start_time + timedelta(minutes=index)
            assert entry.reason
            if entry.decision is FireTimeDecision.coalesced:
                assert coalesce.name in entry.reason

        # The first fire time beyond the preview is reported separately
        assert preview.next_fire_time == start_time + timedelta(minutes=4)

    def test_future_fire_times(self) -> None:
        now = datetime.now(timezone.utc)
        start_time = now + timedelta(minutes=1)
        trigger = IntervalTrigger(minutes=1, start_time=start_time)
        schedule = make_schedule(trigger)

        preview = preview_schedule(schedule, now=now, max_results=3)

        assert len(preview.fire_times) == 3
        for index, entry in enumerate(preview.fire_times):
            assert entry.decision is FireTimeDecision.create_job
            assert entry.fire_time == start_time + timedelta(minutes=index)
            assert "becomes due" in entry.reason

        assert preview.next_fire_time == start_time + timedelta(minutes=3)

    def test_until_limits_horizon(self) -> None:
        now = datetime.now(timezone.utc)
        start_time = now + timedelta(minutes=1)
        trigger = IntervalTrigger(minutes=1, start_time=start_time)
        schedule = make_schedule(trigger)

        until = now + timedelta(minutes=2, seconds=30)
        preview = preview_schedule(schedule, now=now, until=until, max_results=10)

        assert preview.until == until
        assert len(preview.fire_times) == 2
        assert preview.next_fire_time == start_time + timedelta(minutes=2)

    def test_max_results_limits_entries(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger)

        preview = preview_schedule(schedule, now=now, max_results=2)

        assert len(preview.fire_times) == 2
        assert preview.next_fire_time == now + timedelta(minutes=2)

    def test_misfire_grace_time(self) -> None:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=3, seconds=5)
        trigger = IntervalTrigger(minutes=1, start_time=start_time)
        schedule = make_schedule(
            trigger,
            coalesce=CoalescePolicy.all,
            misfire_grace_time=timedelta(seconds=30),
        )

        preview = preview_schedule(schedule, now=now, max_results=5)

        # The first three fire times are too old to still be runnable, the fourth
        # one is still within its grace period and the fifth one is in the future
        expected = [FireTimeDecision.missed] * 3 + [FireTimeDecision.create_job] * 2
        assert [entry.decision for entry in preview.fire_times] == expected
        for entry in preview.fire_times:
            assert entry.start_deadline == entry.fire_time + timedelta(seconds=30)
            if entry.decision is FireTimeDecision.missed:
                assert "misfire grace time" in entry.reason

    def test_no_misfire_grace_time(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now - timedelta(minutes=1))
        schedule = make_schedule(trigger, coalesce=CoalescePolicy.all)

        preview = preview_schedule(schedule, now=now, max_results=3)

        assert all(entry.start_deadline is None for entry in preview.fire_times)
        assert all(
            entry.decision is FireTimeDecision.create_job
            for entry in preview.fire_times
        )

    def test_paused_schedule(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger, paused=True)

        preview = preview_schedule(schedule, now=now)

        assert preview.paused
        assert preview.fire_times == []
        assert preview.note and "paused" in preview.note
        assert preview.next_fire_time == schedule.next_fire_time

    def test_exhausted_trigger(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger)
        schedule.next_fire_time = None

        preview = preview_schedule(schedule, now=now)

        assert preview.fire_times == []
        assert preview.note and "exhausted" in preview.note
        assert preview.next_fire_time is None

    def test_jitter_range_reported_without_seed(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger, max_jitter=timedelta(seconds=5))

        preview = preview_schedule(schedule, now=now, max_results=2)

        for entry in preview.fire_times:
            assert entry.jitter is None
            assert entry.jitter_range == (timedelta(0), timedelta(seconds=5))

    def test_jitter_range_capped_by_next_fire_time(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(seconds=10, start_time=now)
        schedule = make_schedule(trigger, max_jitter=timedelta(seconds=60))

        preview = preview_schedule(schedule, now=now, max_results=2)

        for entry in preview.fire_times:
            assert entry.jitter_range == (
                timedelta(0),
                timedelta(seconds=10) - timedelta(microseconds=1),
            )

    def test_jitter_seed_is_deterministic(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger, max_jitter=timedelta(seconds=30))

        preview1 = preview_schedule(schedule, now=now, max_results=3, jitter_seed=123)
        preview2 = preview_schedule(schedule, now=now, max_results=3, jitter_seed=123)
        preview3 = preview_schedule(schedule, now=now, max_results=3, jitter_seed=456)

        assert preview1.fire_times == preview2.fire_times
        jitters1 = [entry.jitter for entry in preview1.fire_times]
        jitters3 = [entry.jitter for entry in preview3.fire_times]
        assert jitters1 != jitters3
        for entry in preview1.fire_times:
            assert entry.jitter is not None
            assert entry.jitter_range is not None
            assert entry.jitter_range[0] <= entry.jitter <= entry.jitter_range[1]

    def test_preview_does_not_consume_global_random_state(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger, max_jitter=timedelta(seconds=30))

        random.seed(1234)
        expected = random.random()
        random.seed(1234)
        preview_schedule(schedule, now=now, max_results=5, jitter_seed=99)
        assert random.random() == expected

    def test_preview_does_not_consume_trigger_state(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        trigger = OrTrigger(
            [
                IntervalTrigger(seconds=10, start_time=now),
                IntervalTrigger(seconds=15, start_time=now),
            ]
        )
        reference = OrTrigger(
            [
                IntervalTrigger(seconds=10, start_time=now),
                IntervalTrigger(seconds=15, start_time=now),
            ]
        )
        schedule = make_schedule(trigger)
        reference.next()  # align with the next_fire_time consumed by make_schedule

        preview_schedule(schedule, now=now, max_results=10)

        # The original trigger (including the combining trigger's internal caches)
        # must produce the same sequence as if no preview had happened
        for _ in range(6):
            assert trigger.next() == reference.next()

    def test_preview_is_repeatable(self) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now - timedelta(minutes=2))
        schedule = make_schedule(trigger)

        preview1 = preview_schedule(schedule, now=now, max_results=5)
        preview2 = preview_schedule(schedule, now=now, max_results=5)

        assert preview1 == preview2

    @pytest.mark.parametrize(
        "kwargs, exc_match",
        [
            pytest.param(
                {"now": datetime(2026, 1, 1)},
                "'now' must be a timezone-aware datetime",
                id="naive-now",
            ),
            pytest.param(
                {"until": datetime(2026, 1, 1)},
                "'until' must be a timezone-aware datetime",
                id="naive-until",
            ),
            pytest.param(
                {"until": datetime(2025, 1, 1, tzinfo=timezone.utc)},
                "'until' must not be earlier than 'now'",
                id="until-before-now",
            ),
            pytest.param(
                {"max_results": 0},
                "'max_results' must be at least 1",
                id="bad-max-results",
            ),
        ],
    )
    def test_argument_validation(self, kwargs: dict, exc_match: str) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        trigger = IntervalTrigger(minutes=1, start_time=now)
        schedule = make_schedule(trigger)
        kwargs.setdefault("now", now)

        with pytest.raises(ValueError, match=exc_match):
            preview_schedule(schedule, **kwargs)


class TestAsyncSchedulerPreview:
    async def test_preview_matches_real_run(self, raw_datastore: DataStore) -> None:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=3, seconds=5)
        trigger = IntervalTrigger(minutes=1, start_time=start_time)
        async with AsyncScheduler(
            data_store=raw_datastore,
            role=SchedulerRole.scheduler,
            cleanup_interval=None,
        ) as scheduler:
            await scheduler.add_schedule(
                dummy_job, trigger, id="foo", coalesce=CoalescePolicy.latest
            )

            # Repeated previews must not alter the schedule or the following real
            # processing
            previews = [
                await scheduler.preview_schedule("foo", now=now, max_results=5)
                for _ in range(3)
            ]
            assert previews[0].fire_times == previews[1].fire_times
            assert previews[1].fire_times == previews[2].fire_times
            preview = previews[0]

            # No jobs must have been created by the previews
            assert await scheduler.get_jobs() == []

            await scheduler.start_in_background()
            with fail_after(5):
                event = await scheduler.get_next_event(JobAdded)
                assert event.schedule_id == "foo"
                updated_event = await scheduler.get_next_event(ScheduleUpdated)
                assert updated_event.schedule_id == "foo"

            # The real run must have created exactly the jobs the preview predicted
            preview_due_jobs = [
                entry
                for entry in preview.fire_times
                if entry.decision is FireTimeDecision.create_job
                and entry.fire_time <= preview.now
            ]
            assert len(preview_due_jobs) == 1
            jobs = await scheduler.get_jobs()
            assert len(jobs) == 1
            assert jobs[0].scheduled_fire_time == preview_due_jobs[0].fire_time

            # The schedule must have been advanced exactly to the first fire time
            # the preview reported beyond the observation time
            schedule = await scheduler.get_schedule("foo")
            future_entries = [
                entry for entry in preview.fire_times if entry.fire_time > preview.now
            ]
            assert schedule.next_fire_time == future_entries[0].fire_time

    async def test_preview_future_sequence_matches_real_run(
        self, raw_datastore: DataStore
    ) -> None:
        now = datetime.now(timezone.utc)
        trigger = IntervalTrigger(
            seconds=1, start_time=now + timedelta(milliseconds=500)
        )
        async with AsyncScheduler(
            data_store=raw_datastore,
            role=SchedulerRole.scheduler,
            cleanup_interval=None,
        ) as scheduler:
            await scheduler.add_schedule(dummy_job, trigger, id="foo")

            # Previewing several times must not change the outcome
            for _ in range(3):
                preview = await scheduler.preview_schedule("foo", max_results=2)

            assert len(preview.fire_times) == 2
            expected_fire_times = [entry.fire_time for entry in preview.fire_times]

            await scheduler.start_in_background()
            with fail_after(10):
                for _ in range(2):
                    await scheduler.get_next_event(JobAdded)

            jobs = await scheduler.get_jobs()
            actual_fire_times = sorted(job.scheduled_fire_time for job in jobs)
            assert actual_fire_times == expected_fire_times

    async def test_preview_unknown_schedule(self, raw_datastore: DataStore) -> None:
        from apscheduler import ScheduleLookupError

        async with AsyncScheduler(data_store=raw_datastore) as scheduler:
            with pytest.raises(ScheduleLookupError):
                await scheduler.preview_schedule("foo")


def test_sync_scheduler_preview() -> None:
    now = datetime.now(timezone.utc)
    trigger = IntervalTrigger(minutes=1, start_time=now)
    with Scheduler() as scheduler:
        scheduler.add_schedule(dummy_job, trigger, id="foo")
        preview = scheduler.preview_schedule("foo", max_results=3)

    assert preview.schedule_id == "foo"
    assert len(preview.fire_times) == 3
    assert all(
        entry.decision is FireTimeDecision.create_job for entry in preview.fire_times
    )
    assert isinstance(preview.fire_times[0], FireTimePreview)
