from __future__ import annotations

import enum
from collections.abc import Callable, Iterable, Sequence
from typing import Any, NamedTuple, ParamSpec

import anyio

from starlette._utils import is_async_callable
from starlette.concurrency import run_in_threadpool

P = ParamSpec("P")


class BackgroundTask:
    def __init__(self, func: Callable[P, Any], *args: P.args, **kwargs: P.kwargs) -> None:
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.is_async = is_async_callable(func)

    async def __call__(self) -> None:
        if self.is_async:
            await self.func(*self.args, **self.kwargs)
        else:
            await run_in_threadpool(self.func, *self.args, **self.kwargs)


class BackgroundTasks(BackgroundTask):
    def __init__(self, tasks: Sequence[BackgroundTask] | None = None):
        self.tasks = list(tasks) if tasks else []

    def add_task(self, func: Callable[P, Any], *args: P.args, **kwargs: P.kwargs) -> None:
        task = BackgroundTask(func, *args, **kwargs)
        self.tasks.append(task)

    async def __call__(self) -> None:
        for task in self.tasks:
            await task()


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class TaskResult(NamedTuple):
    task_id: str
    status: TaskStatus
    error: BaseException | None = None


class BackgroundTaskGraphError(Exception):
    """Raised when one or more tasks in a ``BackgroundTaskGraph`` fail."""

    def __init__(self, results: dict[str, TaskResult]) -> None:
        self.results = results
        self.errors = {
            task_id: result.error for task_id, result in results.items() if result.status is TaskStatus.FAILED
        }
        detail = ", ".join(f"{task_id}: {error!r}" for task_id, error in self.errors.items())
        super().__init__(f"{len(self.errors)} background task(s) failed: {detail}")


class _GraphNode(NamedTuple):
    task: BackgroundTask
    dependencies: tuple[str, ...]


class BackgroundTaskGraph(BackgroundTask):
    """
    A background task container that runs tasks according to their dependencies.

    Tasks are identified by a stable ``task_id`` and only run once all of their
    dependencies have succeeded. Independent branches run concurrently (up to
    ``max_concurrency`` tasks at a time). If a task fails, its descendants are
    marked as ``TaskStatus.SKIPPED`` while unrelated branches still run to
    completion.
    """

    def __init__(self, *, max_concurrency: int | None = None) -> None:
        if max_concurrency is not None and max_concurrency < 1:
            raise ValueError("max_concurrency must be a positive integer or None")
        self.max_concurrency = max_concurrency
        self._nodes: dict[str, _GraphNode] = {}
        self._results: dict[str, TaskResult] = {}

    def add_task(
        self,
        task_id: str,
        func: Callable[..., Any],
        *args: Any,
        dependencies: Iterable[str] = (),
        **kwargs: Any,
    ) -> None:
        if task_id in self._nodes:
            raise ValueError(f"Duplicate task identifier: {task_id!r}")
        dependencies = tuple(dependencies)
        if task_id in dependencies:
            raise ValueError(f"Task {task_id!r} cannot depend on itself")
        unknown = [dependency for dependency in dependencies if dependency not in self._nodes]
        if unknown:
            raise ValueError(f"Unknown dependencies for task {task_id!r}: {', '.join(unknown)}")
        task = BackgroundTask(func, *args, **kwargs)
        self._nodes[task_id] = _GraphNode(task=task, dependencies=dependencies)

    @property
    def results(self) -> dict[str, TaskResult]:
        return {
            task_id: self._results.get(task_id, TaskResult(task_id=task_id, status=TaskStatus.PENDING))
            for task_id in self._nodes
        }

    def status(self, task_id: str) -> TaskStatus:
        if task_id not in self._nodes:
            raise KeyError(task_id)
        return self.results[task_id].status

    async def __call__(self) -> None:
        results: dict[str, TaskResult] = {}
        settled = {task_id: anyio.Event() for task_id in self._nodes}
        semaphore = anyio.Semaphore(self.max_concurrency) if self.max_concurrency is not None else None

        async def run_node(task_id: str, node: _GraphNode) -> None:
            try:
                for dependency in node.dependencies:
                    await settled[dependency].wait()
                if any(results[dependency].status is not TaskStatus.SUCCEEDED for dependency in node.dependencies):
                    results[task_id] = TaskResult(task_id=task_id, status=TaskStatus.SKIPPED)
                    return
                try:
                    if semaphore is None:
                        await node.task()
                    else:
                        async with semaphore:
                            await node.task()
                except Exception as exc:
                    results[task_id] = TaskResult(task_id=task_id, status=TaskStatus.FAILED, error=exc)
                else:
                    results[task_id] = TaskResult(task_id=task_id, status=TaskStatus.SUCCEEDED)
            finally:
                settled[task_id].set()

        async with anyio.create_task_group() as task_group:
            for task_id, node in self._nodes.items():
                task_group.start_soon(run_node, task_id, node)
        self._results = results
        failed = [result for result in results.values() if result.status is TaskStatus.FAILED]
        if failed:
            raise BackgroundTaskGraphError(results) from failed[0].error
