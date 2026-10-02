from __future__ import annotations

import copy
import random
from datetime import datetime, timedelta, timezone

from ._enums import CoalescePolicy, FireTimeDecision
from ._structures import FireTimePreview, Schedule, SchedulePreview
from .abc import Trigger

_microsecond_delta = timedelta(microseconds=1)
_zero_timedelta = timedelta()


def _clone_trigger(trigger: Trigger) -> Trigger:
    """
    Create an isolated copy of a trigger, including any internal caches.

    The copy is made through the trigger's own __getstate__/__setstate__ machinery,
    so internal state such as the next-fire-time caches of combining triggers is
    carried over, while sharing no mutable state with the original.
    """
    return copy.deepcopy(trigger)


def _jitter_range(
    schedule: Schedule, fire_time: datetime, following_fire_time: datetime | None
) -> tuple[timedelta, timedelta] | None:
    """
    Compute the possible jitter range for a fire time, mirroring the jitter capping
    logic of the schedule processing loop of the scheduler.
    """
    if not schedule.max_jitter:
        return None

    max_jitter = schedule.max_jitter.total_seconds()
    if following_fire_time is not None:
        # Jitter must never be so high that it would cause a fire time to equal or
        # exceed the next fire time
        max_jitter = min(
            max_jitter,
            (following_fire_time - fire_time - _microsecond_delta).total_seconds(),
        )

    return _zero_timedelta, timedelta(seconds=max(max_jitter, 0.0))


def preview_schedule(
    schedule: Schedule,
    *,
    now: datetime | None = None,
    until: datetime | None = None,
    max_results: int = 10,
    jitter_seed: int | None = None,
) -> SchedulePreview:
    """
    Preview the jobs a schedule would generate, without changing any state.

    The preview simulates the schedule processing loop of the scheduler against an
    isolated copy of the trigger of the schedule, honoring the coalesce policy,
    misfire grace time, paused flag and jitter bounds of the schedule. It never
    writes jobs to the data store, never updates the schedule and never touches the
    global random state.

    :param schedule: the schedule to preview
    :param now: the observation time (defaults to the current time); fire times at or
        before this time are considered due
    :param until: the end of the preview horizon; fire times after this time are not
        included in the preview (``None`` to only limit the preview by
        ``max_results``)
    :param max_results: maximum number of fire times to include in the preview
    :param jitter_seed: seed for the random number generator used to compute concrete
        jitter values; if ``None``, no concrete jitter is computed and only the
        possible jitter range is reported
    :return: the computed preview

    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        raise ValueError("'now' must be a timezone-aware datetime")

    if until is not None:
        if until.tzinfo is None:
            raise ValueError("'until' must be a timezone-aware datetime")
        if until < now:
            raise ValueError("'until' must not be earlier than 'now'")

    if max_results < 1:
        raise ValueError("'max_results' must be at least 1")

    if schedule.paused:
        return SchedulePreview(
            schedule_id=schedule.id,
            task_id=schedule.task_id,
            now=now,
            until=until,
            paused=True,
            note="schedule is paused - no jobs will be created until it is unpaused",
            fire_times=[],
            next_fire_time=schedule.next_fire_time,
        )

    if schedule.next_fire_time is None:
        return SchedulePreview(
            schedule_id=schedule.id,
            task_id=schedule.task_id,
            now=now,
            until=until,
            paused=False,
            note="trigger is exhausted - no further fire times",
            fire_times=[],
            next_fire_time=None,
        )

    # Use a dedicated random generator so that previewing never consumes the random
    # state of the process (or of a concurrently running scheduler)
    rng = random.Random(jitter_seed) if jitter_seed is not None else None

    # Work on an isolated copy of the trigger so that iterating it here does not
    # consume the state of the trigger used by the running scheduler
    trigger = _clone_trigger(schedule.trigger)

    fire_times: list[FireTimePreview] = []

    def make_entry(
        fire_time: datetime,
        following_fire_time: datetime | None,
        *,
        due: bool,
    ) -> FireTimePreview:
        jitter_range = _jitter_range(schedule, fire_time, following_fire_time)
        jitter: timedelta | None = None
        if jitter_range is not None and rng is not None:
            jitter = timedelta(
                seconds=rng.uniform(
                    jitter_range[0].total_seconds(), jitter_range[1].total_seconds()
                )
            )

        effective_fire_time = fire_time + (jitter or _zero_timedelta)
        start_deadline: datetime | None = None
        if schedule.misfire_grace_time is not None:
            start_deadline = effective_fire_time + schedule.misfire_grace_time

        if start_deadline is not None and start_deadline < now:
            decision = FireTimeDecision.missed
            reason = (
                f"misfire grace time ({schedule.misfire_grace_time}) would expire at "
                f"{start_deadline} which is before the observation time ({now}); the "
                f"job would be released with the missed_start_deadline outcome"
            )
        elif due:
            decision = FireTimeDecision.create_job
            reason = (
                f"fire time is due at the observation time ({now}); a job would be "
                f"created immediately"
            )
        else:
            decision = FireTimeDecision.create_job
            reason = "a job would be created when this fire time becomes due"

        return FireTimePreview(
            fire_time=fire_time,
            decision=decision,
            reason=reason,
            jitter=jitter,
            jitter_range=jitter_range,
            start_deadline=start_deadline,
        )

    # Collect the backlog of due fire times, mirroring the schedule processing loop
    # of the scheduler
    due_fire_times: list[datetime] = []
    upcoming: datetime | None = schedule.next_fire_time
    if upcoming is not None and upcoming <= now:
        due_fire_times.append(upcoming)
        while True:
            fire_time = trigger.next()
            if fire_time is None or fire_time > now:
                upcoming = fire_time
                break

            due_fire_times.append(fire_time)

    # Apply the coalesce policy to the backlog
    kept_indices: list[int]
    if schedule.coalesce is CoalescePolicy.all:
        kept_indices = list(range(len(due_fire_times)))
    elif schedule.coalesce is CoalescePolicy.latest:
        kept_indices = [len(due_fire_times) - 1] if due_fire_times else []
    else:  # CoalescePolicy.earliest
        kept_indices = [0] if due_fire_times else []

    kept_set = set(kept_indices)
    kept_fire_times = [due_fire_times[i] for i in kept_indices]
    for index, fire_time in enumerate(due_fire_times):
        if len(fire_times) >= max_results:
            break

        if index in kept_set:
            kept_index = kept_indices.index(index)
            if kept_index + 1 < len(kept_fire_times):
                following = kept_fire_times[kept_index + 1]
            else:
                following = upcoming

            fire_times.append(make_entry(fire_time, following, due=True))
        else:
            if schedule.coalesce is CoalescePolicy.earliest:
                kept_fire_time = due_fire_times[kept_indices[0]]
            else:
                kept_fire_time = due_fire_times[kept_indices[-1]]

            fire_times.append(
                FireTimePreview(
                    fire_time=fire_time,
                    decision=FireTimeDecision.coalesced,
                    reason=(
                        f"coalesce policy {schedule.coalesce.name!r} merges this fire "
                        f"time into the fire time at {kept_fire_time}; no job would "
                        f"be created for it"
                    ),
                )
            )

    # Preview future fire times up to the horizon
    while upcoming is not None and len(fire_times) < max_results:
        if until is not None and upcoming > until:
            break

        fire_time = upcoming
        upcoming = trigger.next()
        fire_times.append(make_entry(fire_time, upcoming, due=False))

    return SchedulePreview(
        schedule_id=schedule.id,
        task_id=schedule.task_id,
        now=now,
        until=until,
        paused=False,
        note=None,
        fire_times=fire_times,
        next_fire_time=upcoming,
    )
