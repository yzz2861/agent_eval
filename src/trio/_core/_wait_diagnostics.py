"""Opt-in diagnostics for "who is waiting on what, and who holds it".

This module implements a lightweight wait-graph collector. When enabled
(via :func:`trio.lowlevel.record_wait_diagnostics`), Trio's blocking
primitives record a *wait edge* for each blocked task: which resource the
task is waiting on, and (when knowable) which task(s) currently hold the
lock or capacity token it needs. A structured snapshot of the current
edges is available through :func:`trio.lowlevel.wait_graph_snapshot`.

Design notes:

* Collection is strictly opt-in. When disabled, the hooks in the
  primitives cost a single check against a module-level flag and record
  nothing, and scheduling behavior is identical either way: the hooks
  only perform synchronous dict inserts/removals and never add
  checkpoints or interact with the scheduler.
* Edges are removed as soon as the wait ends -- whether by being
  rescheduled, cancelled, or by the surrounding operation failing -- so
  the collector never retains references to tasks that have exited.
* Tasks and resources are identified by ``id()``, which is stable for
  the lifetime of an edge because the edge itself keeps the objects
  alive. Snapshots contain only plain data (ints/strings/tuples), never
  object references.
* We only record information that the primitives themselves know
  directly. In particular, we never inspect stack-frame locals to guess
  which user objects might be involved in a wait.
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

import attrs

from .._util import final

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from ._run import Task

# Kinds of resources that appear in WaitEdge.resource_kind. Any blocking
# operation that we do not specifically recognize is recorded as "unknown"
# rather than being dropped.
LOCK = "lock"
CAPACITY_LIMITER = "capacity_limiter"
MEMORY_SEND_CHANNEL = "memory_send_channel"
MEMORY_RECEIVE_CHANNEL = "memory_receive_channel"
UNKNOWN = "unknown"


@final
@attrs.frozen
class WaitEdge:
    """A single "task is blocked waiting on a resource" relation.

    Part of a `WaitGraphSnapshot`; see
    :func:`trio.lowlevel.wait_graph_snapshot`.

    Currently the following fields are defined:

    * ``task_id``: ``id()`` of the waiting :class:`trio.lowlevel.Task`.
      Stable for as long as the task is alive.
    * ``task_name``: the waiting task's name, captured when the snapshot
      was taken.
    * ``resource_id``: ``id()`` of the object being waited on (the lock,
      limiter, or channel endpoint), or None if the wait type is not
      recognized and no specific resource could be identified.
    * ``resource_kind``: one of ``"lock"``, ``"capacity_limiter"``,
      ``"memory_send_channel"``, ``"memory_receive_channel"``, or
      ``"unknown"`` for blocking operations Trio does not specifically
      recognize.
    * ``operation``: what the task was trying to do, e.g. ``"acquire"``,
      ``"send"``, ``"receive"``, or ``"wait"``.
    * ``owner_task_ids``: ids of the tasks currently holding the lock or
      capacity token that the waiting task needs. Empty when the holders
      are unknown or are not tasks -- in particular, channel waits never
      have owners, because a blocked ``send``/``receive`` is waiting for
      some future counterpart operation, not for a specific current
      holder.
    * ``owner_evidence_complete``: True if every holder of the needed
      resource is accounted for in ``owner_task_ids``. False if some
      holders are unknown or are not tasks (for example, a
      `~trio.CapacityLimiter` token borrowed on behalf of an arbitrary
      object). Cycles are only reported as definite when every edge in
      them has complete owner evidence.

    """

    task_id: int
    task_name: str
    resource_id: int | None
    resource_kind: str
    operation: str
    owner_task_ids: tuple[int, ...]
    owner_evidence_complete: bool


@final
@attrs.frozen
class WaitGraphSnapshot:
    """A point-in-time structured view of Trio's wait relations.

    Returned by :func:`trio.lowlevel.wait_graph_snapshot`.

    Currently the following fields are defined:

    * ``edges``: the currently-recorded `WaitEdge` objects, one per
      blocked task whose wait began while diagnostics were enabled.
    * ``definite_cycles``: cycles of task ids where each task is blocked
      on a resource held by the next task in the cycle, and every edge in
      the cycle has complete owner evidence. Only such fully-evidenced
      lock/token cycles are reported as definite deadlocks; waits whose
      blockers cannot be identified (such as channel waits) never produce
      a definite cycle.
    * ``diagnostics_enabled``: whether collection was enabled when this
      snapshot was taken.

    """

    edges: tuple[WaitEdge, ...]
    definite_cycles: tuple[tuple[int, ...], ...]
    diagnostics_enabled: bool

    @property
    def deadlocked_task_ids(self) -> frozenset[int]:
        """The set of task ids participating in at least one definite cycle."""
        return frozenset(task_id for cycle in self.definite_cycles for task_id in cycle)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this snapshot."""
        return {
            "diagnostics_enabled": self.diagnostics_enabled,
            "edges": [
                {
                    "task_id": edge.task_id,
                    "task_name": edge.task_name,
                    "resource_id": edge.resource_id,
                    "resource_kind": edge.resource_kind,
                    "operation": edge.operation,
                    "owner_task_ids": list(edge.owner_task_ids),
                    "owner_evidence_complete": edge.owner_evidence_complete,
                }
                for edge in self.edges
            ],
            "definite_cycles": [list(cycle) for cycle in self.definite_cycles],
        }


@attrs.define(slots=False)
class _LiveEdge:
    # Strong references are fine here: an edge exists only while the task
    # is actually blocked, and is removed before the task can exit.
    task: Task
    resource: object | None
    kind: str
    operation: str
    # Callable returning the current holder(s) of the resource: None, a
    # single object, or an iterable of objects. Evaluated lazily at
    # snapshot time, because ownership changes as locks are handed off.
    owner_fn: Callable[[], object] | None


_enabled = False
# {id(task): _LiveEdge} -- a task can be blocked in at most one wait.
_edges: dict[int, _LiveEdge] = {}


def wait_diagnostics_enabled() -> bool:
    """Return True if wait-relation diagnostics are currently being collected.

    See :func:`trio.lowlevel.record_wait_diagnostics`.
    """
    return _enabled


@contextmanager
def record_wait_diagnostics() -> Iterator[None]:
    """Context manager that enables collection of wait-relation diagnostics.

    While active, Trio records a wait edge for every task that blocks in
    a recognized primitive (`trio.Lock`, `trio.CapacityLimiter`, memory
    channels) or in any other reschedulable wait (recorded with resource
    kind ``"unknown"``). Use :func:`trio.lowlevel.wait_graph_snapshot` to
    inspect the current edges.

    Enabling diagnostics does not change scheduling behavior, and edges
    are discarded as soon as the corresponding wait ends. Waits that
    started before collection was enabled are not visible.

    May be nested; collection stops when the outermost invocation exits.
    """
    global _enabled
    already_enabled = _enabled
    _enabled = True
    try:
        yield
    finally:
        if not already_enabled:
            _enabled = False
            _edges.clear()


def begin_wait(
    task: Task,
    resource: object,
    kind: str,
    operation: str,
    owner_fn: Callable[[], object] | None = None,
) -> int | None:
    """Record that ``task`` is now blocked on ``resource``.

    Returns a token for `end_wait`, or None if diagnostics are disabled.
    """
    if not _enabled:
        return None
    key = id(task)
    _edges[key] = _LiveEdge(task, resource, kind, operation, owner_fn)
    return key


def begin_generic_wait() -> int | None:
    """Record an "unknown" wait for the current task, if not recorded yet.

    Used by the low-level reschedulable-wait trap so that blocking
    operations Trio does not specifically recognize still show up in
    snapshots. If a higher-level primitive already recorded a more
    specific edge for this task, that edge is kept.
    """
    if not _enabled:
        return None
    from ._run import current_task  # late import to avoid a circular import

    task = current_task()
    key = id(task)
    if key in _edges:
        return None
    _edges[key] = _LiveEdge(task, None, UNKNOWN, "wait", None)
    return key


def end_wait(token: int | None) -> None:
    """Remove the wait edge associated with ``token``, if still present."""
    if token is not None:
        _edges.pop(token, None)


def _resolve_owners(edge: _LiveEdge) -> tuple[tuple[int, ...], bool]:
    """Snapshot the current owners for ``edge`` as (task ids, complete?)."""
    if edge.owner_fn is None:
        # No ownership concept (channels, unrecognized waits): the task is
        # waiting for some future event, not for a specific current holder.
        return (), True
    from ._run import Task  # late import to avoid a circular import

    raw = edge.owner_fn()
    if raw is None:
        holders: tuple[object, ...] = ()
    elif isinstance(raw, Task):
        holders = (raw,)
    elif isinstance(raw, Iterable):
        holders = tuple(raw)
    else:
        holders = (raw,)
    owner_ids: list[int] = []
    complete = True
    for holder in holders:
        if isinstance(holder, Task):
            owner_ids.append(id(holder))
        else:
            # A token held by a non-task object: we cannot point at a task
            # that would have to release it, so the evidence is incomplete.
            complete = False
    return tuple(owner_ids), complete


def _find_definite_cycles(
    edges: tuple[WaitEdge, ...],
) -> tuple[tuple[int, ...], ...]:
    # Build a task -> task graph using only edges with complete owner
    # evidence. Self-loops are dropped: they occur transiently when a lock
    # or token is handed off to a waiter that has not been rescheduled yet.
    adjacency: dict[int, set[int]] = {}
    for edge in edges:
        if not edge.owner_evidence_complete:
            continue
        targets = adjacency.setdefault(edge.task_id, set())
        for owner_id in edge.owner_task_ids:
            if owner_id != edge.task_id:
                targets.add(owner_id)

    cycles: set[tuple[int, ...]] = set()

    def dfs(start: int, node: int, path: list[int], seen: set[int]) -> None:
        for nxt in adjacency.get(node, ()):
            if nxt == start:
                # Canonical rotation (smallest id first) for deduplication.
                smallest = path.index(min(path))
                cycles.add(tuple(path[smallest:] + path[:smallest]))
            elif nxt not in seen and nxt > start:
                # Only enumerate cycles from their smallest member.
                seen.add(nxt)
                path.append(nxt)
                dfs(start, nxt, path, seen)
                path.pop()
                seen.discard(nxt)

    for start in adjacency:
        dfs(start, start, [start], {start})
    return tuple(sorted(cycles))


def wait_graph_snapshot() -> WaitGraphSnapshot:
    """Return a structured snapshot of who is currently waiting on what.

    Each blocked task that began its wait while diagnostics were enabled
    contributes one `WaitEdge`, describing the resource it is waiting on
    and -- when knowable -- the task(s) holding the lock or capacity token
    it needs. Cycles of tasks mutually waiting on each other's locks or
    tokens are reported in ``definite_cycles``, but only when every edge
    in the cycle has complete owner evidence; in particular, a task
    blocked on a memory channel is never reported as deadlocked, because
    its counterpart may simply not have run yet.

    Returns an empty snapshot when diagnostics are disabled; see
    :func:`trio.lowlevel.record_wait_diagnostics`.
    """
    edges: list[WaitEdge] = []
    for live in list(_edges.values()):
        owner_ids, complete = _resolve_owners(live)
        edges.append(
            WaitEdge(
                task_id=id(live.task),
                task_name=live.task.name,
                resource_id=None if live.resource is None else id(live.resource),
                resource_kind=live.kind,
                operation=live.operation,
                owner_task_ids=owner_ids,
                owner_evidence_complete=complete,
            )
        )
    result_edges = tuple(edges)
    return WaitGraphSnapshot(
        edges=result_edges,
        definite_cycles=_find_definite_cycles(result_edges),
        diagnostics_enabled=_enabled,
    )
