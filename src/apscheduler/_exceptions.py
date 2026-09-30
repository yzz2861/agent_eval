from __future__ import annotations

from uuid import UUID


class TaskLookupError(LookupError):
    """Raised by a data store when it cannot find the requested task."""

    def __init__(self, task_id: str):
        super().__init__(f"No task by the id of {task_id!r} was found")


class ScheduleLookupError(LookupError):
    """Raised by a scheduler when it cannot find the requested schedule."""

    def __init__(self, schedule_id: str):
        super().__init__(f"No schedule by the id of {schedule_id!r} was found")


class JobLookupError(LookupError):
    """Raised when the job store cannot find a job for update or removal."""

    def __init__(self, job_id: UUID):
        super().__init__(f"No job by the id of {job_id} was found")


class CallableLookupError(LookupError):
    """Raised when the target callable for a job could not be found."""


class JobResultNotReady(Exception):
    """
    Raised by :meth:`~Scheduler.get_job_result` if the job result is
    not ready.
    """

    def __init__(self, job_id: UUID):
        super().__init__(f"No job by the id of {job_id} was found")


class JobCancelled(Exception):
    """
    Raised by :meth:`~Scheduler.get_job_result` if the job was
    cancelled.
    """


class JobDeadlineMissed(Exception):
    """
    Raised by :meth:`~Scheduler.get_job_result` if the job failed to
    start within the allotted time.
    """


class ConflictingIdError(KeyError):
    """
    Raised when trying to add a schedule to a store that already contains a schedule by
    that ID, and the conflict policy of ``exception`` is used.
    """

    def __init__(self, schedule_id):
        super().__init__(
            f"This data store already contains a schedule with the identifier "
            f"{schedule_id!r}"
        )


class EventLogPrunedError(Exception):
    """
    Raised when resuming a persistent event subscription whose acknowledged cursor
    points to events that have since been pruned from the persistent event log by the
    retention policy.

    The subscriber must resynchronize (for example by re-subscribing with an explicit
    ``start_from`` value) instead of silently continuing from the latest event.
    """

    def __init__(self, subscription_id: str):
        super().__init__(
            f"The persistent event subscription {subscription_id!r} cannot be "
            f"resumed because its acknowledged position has been pruned from the "
            f"event log; resynchronize the subscriber and subscribe again with an "
            f"explicit start_from value"
        )


class SerializationError(Exception):
    """Raised when a serializer fails to serialize the given object."""


class DeserializationError(Exception):
    """Raised when a serializer fails to deserialize the given object."""


class MaxIterationsReached(Exception):
    """
    Raised when a trigger has reached its maximum number of allowed computation
    iterations when trying to calculate the next fire time.
    """
