from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Literal, TypeAlias

import attrs

from .._util import final
from ._run_context import GLOBAL_RUN_CONTEXT

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ._run import Task


WaitResourceKind: TypeAlias = Literal[
    "lock", "capacity_limiter", "memory_channel", "unknown"
]
WaitOperation: TypeAlias = Literal[
    "acquire",
    "acquire_capacity",
    "channel_send",
    "channel_receive",
    "unknown",
]
BorrowerKind: TypeAlias = Literal["task", "object"]


@final
@attrs.frozen
class WaitTaskSnapshot:
    """A task and the resource it is currently waiting for, if any."""

    id: int
    name: str
    waiting_for: WaitSnapshot | None


@final
@attrs.frozen
class BorrowerSnapshot:
    """An entity currently borrowing capacity from a CapacityLimiter."""

    kind: BorrowerKind
    id: int | str


@final
@attrs.frozen
class WaitResourceSnapshot:
    """A resource that one or more tasks are currently waiting on."""

    kind: WaitResourceKind
    id: str
    owner_task_id: int | None = None
    borrower_ids: tuple[BorrowerSnapshot, ...] = ()
    borrowed_tokens: int | None = None
    total_tokens: int | float | None = None
    buffer_used: int | None = None
    max_buffer_size: int | float | None = None
    open_send_channels: int | None = None
    open_receive_channels: int | None = None


@final
@attrs.frozen
class WaitSnapshot:
    """The operation and resource associated with one blocked task."""

    operation: WaitOperation
    resource: WaitResourceSnapshot


@final
@attrs.frozen
class WaitEdgeSnapshot:
    """A directed wait edge from a task to a resource."""

    task_id: int
    operation: WaitOperation
    resource_id: str
    resource_kind: WaitResourceKind


@final
@attrs.frozen
class WaitCycleSnapshot:
    """A cycle found in the current wait graph."""

    task_ids: tuple[int, ...]
    resource_ids: tuple[str, ...]
    edges: tuple[WaitEdgeSnapshot, ...]
    certain: bool
    explanation: str | None


@final
@attrs.frozen
class WaitDiagnosticsSnapshot:
    """An immutable point-in-time view of task wait relationships."""

    tasks: tuple[WaitTaskSnapshot, ...]
    resources: tuple[WaitResourceSnapshot, ...]
    waits: tuple[WaitEdgeSnapshot, ...]
    cycles: tuple[WaitCycleSnapshot, ...]


@final
@attrs.frozen
class LockWait:
    resource: object
    operation: Literal["acquire"] = "acquire"


@final
@attrs.frozen
class CapacityLimiterWait:
    resource: object
    operation: Literal["acquire_capacity"] = "acquire_capacity"


@final
@attrs.frozen
class MemoryChannelWait:
    resource: object
    operation: Literal["channel_send", "channel_receive"]


@final
@attrs.frozen
class UnknownWait:
    operation: Literal["unknown"] = "unknown"


WaitInfo: TypeAlias = LockWait | CapacityLimiterWait | MemoryChannelWait | UnknownWait


@final
@attrs.define(eq=False)
class WaitDiagnostics:
    """Active wait relationship diagnostics for one Trio run."""

    waits: dict[Task, WaitInfo] = attrs.Factory(dict)
    unknown_sequence: int = attrs.field(default=0, init=False)
    unknown_resources: dict[Task, str] = attrs.Factory(dict)
    depth: int = attrs.field(default=0, init=False)

    def add_wait(self, task: Task, wait_info: WaitInfo | None) -> WaitInfo:
        info = wait_info if wait_info is not None else UnknownWait()
        self.waits[task] = info
        if isinstance(info, UnknownWait):
            self.unknown_sequence += 1
            self.unknown_resources[task] = f"unknown:{self.unknown_sequence}"
        else:
            self.unknown_resources.pop(task, None)
        return info

    def remove_wait(self, task: Task) -> None:
        self.waits.pop(task, None)
        self.unknown_resources.pop(task, None)

    def snapshot(self) -> WaitDiagnosticsSnapshot:
        """Return the current wait graph for the active Trio run."""
        try:
            runner = GLOBAL_RUN_CONTEXT.runner
            live_tasks = set(runner.tasks)
        except AttributeError:
            live_tasks = set()

        waits_by_task: dict[Task, WaitSnapshot] = {}
        resources: dict[str, WaitResourceSnapshot] = {}
        for task, info in self.waits.items():
            resource = self._resource_snapshot(task, info, resources, live_tasks)
            waits_by_task[task] = WaitSnapshot(
                operation=info.operation,
                resource=resource,
            )

        task_snapshots = tuple(
            WaitTaskSnapshot(
                id=task.id,
                name=task.name,
                waiting_for=waits_by_task.get(task),
            )
            for task in sorted(live_tasks, key=lambda candidate: candidate.id)
        )
        wait_edges = tuple(
            WaitEdgeSnapshot(
                task_id=task.id,
                operation=wait.operation,
                resource_id=wait.resource.id,
                resource_kind=wait.resource.kind,
            )
            for task, wait in sorted(
                waits_by_task.items(),
                key=lambda item: item[0].id,
            )
        )
        return WaitDiagnosticsSnapshot(
            tasks=task_snapshots,
            resources=tuple(resources.values()),
            waits=wait_edges,
            cycles=self._lock_cycles(waits_by_task),
        )

    def _resource_snapshot(
        self,
        task: Task,
        info: WaitInfo,
        resources: dict[str, WaitResourceSnapshot],
        live_tasks: set[Task],
    ) -> WaitResourceSnapshot:
        if isinstance(info, UnknownWait):
            return WaitResourceSnapshot(
                kind="unknown",
                id=self.unknown_resources[task],
            )

        resource = info.resource
        resource_id = self._resource_id(info, resource)
        existing = resources.get(resource_id)
        if existing is not None:
            return existing

        if isinstance(info, LockWait):
            owner = getattr(resource, "_owner", None)
            snapshot = WaitResourceSnapshot(
                kind="lock",
                id=resource_id,
                owner_task_id=owner.id if owner in live_tasks else None,
            )
        elif isinstance(info, CapacityLimiterWait):
            borrowers = tuple(
                (
                    BorrowerSnapshot(kind="task", id=borrower.id)
                    if borrower in live_tasks
                    else BorrowerSnapshot(kind="object", id=f"object:{id(borrower):x}")
                )
                for borrower in getattr(resource, "_borrowers", set())
            )
            snapshot = WaitResourceSnapshot(
                kind="capacity_limiter",
                id=resource_id,
                borrower_ids=borrowers,
                borrowed_tokens=len(borrowers),
                total_tokens=getattr(resource, "total_tokens", None),
            )
        else:
            state = getattr(resource, "_state", resource)
            snapshot = WaitResourceSnapshot(
                kind="memory_channel",
                id=resource_id,
                buffer_used=len(getattr(state, "data", ())),
                max_buffer_size=getattr(state, "max_buffer_size", None),
                open_send_channels=getattr(state, "open_send_channels", None),
                open_receive_channels=getattr(state, "open_receive_channels", None),
            )

        resources[resource_id] = snapshot
        return snapshot

    @staticmethod
    def _resource_id(info: WaitInfo, resource: object) -> str:
        if isinstance(info, LockWait):
            kind = "lock"
        elif isinstance(info, CapacityLimiterWait):
            kind = "capacity-limiter"
        else:
            kind = "memory-channel"
        return f"{kind}:{id(resource):x}"

    @staticmethod
    def _lock_cycles(
        waits_by_task: dict[Task, WaitSnapshot],
    ) -> tuple[WaitCycleSnapshot, ...]:
        lock_owner: dict[Task, Task] = {}
        edges_by_task: dict[Task, WaitEdgeSnapshot] = {}
        for waiter, wait in waits_by_task.items():
            if wait.resource.kind != "lock" or wait.resource.owner_task_id is None:
                continue
            owner = next(
                (
                    candidate
                    for candidate in waits_by_task
                    if candidate.id == wait.resource.owner_task_id
                ),
                None,
            )
            if owner is None:
                continue
            lock_owner[waiter] = owner
            edges_by_task[waiter] = WaitEdgeSnapshot(
                task_id=waiter.id,
                operation=wait.operation,
                resource_id=wait.resource.id,
                resource_kind="lock",
            )

        cycles: list[WaitCycleSnapshot] = []
        visited: set[Task] = set()
        for start in lock_owner:
            if start in visited:
                continue
            path: list[Task] = []
            positions: dict[Task, int] = {}
            current = start
            while current not in visited:
                if current in positions:
                    cycle_tasks = path[positions[current] :]
                    cycle_edges = [edges_by_task[task] for task in cycle_tasks]
                    cycles.append(
                        WaitCycleSnapshot(
                            task_ids=tuple(task.id for task in cycle_tasks),
                            resource_ids=tuple(
                                edge.resource_id for edge in cycle_edges
                            ),
                            edges=tuple(cycle_edges),
                            certain=True,
                            explanation=(
                                "each task is waiting for a lock held by the next "
                                "task in the cycle"
                            ),
                        ),
                    )
                    break
                positions[current] = len(path)
                path.append(current)
                next_task = lock_owner.get(current)
                if next_task is None:
                    break
                current = next_task
            visited.update(path)

        return tuple(sorted(cycles, key=lambda cycle: cycle.task_ids))


def current_wait_diagnostics() -> WaitDiagnostics | None:
    try:
        diagnostics: WaitDiagnostics | None = (
            GLOBAL_RUN_CONTEXT.runner._wait_diagnostics
        )
    except AttributeError:
        return None
    return diagnostics


@contextmanager
def wait_diagnostics() -> Iterator[WaitDiagnostics]:
    """Enable opt-in collection of task wait relationships for this run.

    Entering or leaving this context does not checkpoint. While it is active,
    supported blocking calls attach explicit resource evidence and unsupported
    blocking calls are retained as unknown waits. The resulting snapshots do not
    inspect coroutine stack frames or local variables.
    """
    try:
        runner = GLOBAL_RUN_CONTEXT.runner
    except AttributeError as error:
        raise RuntimeError(
            "wait_diagnostics() must be used inside a Trio run",
        ) from error

    diagnostics = getattr(runner, "_wait_diagnostics", None)
    created = diagnostics is None
    if created:
        diagnostics = WaitDiagnostics()
        runner._wait_diagnostics = diagnostics
    diagnostics.depth += 1
    try:
        yield diagnostics
    finally:
        diagnostics.depth -= 1
        if diagnostics.depth == 0:
            diagnostics.waits.clear()
            diagnostics.unknown_resources.clear()
            diagnostics.unknown_sequence = 0
            runner._wait_diagnostics = None
