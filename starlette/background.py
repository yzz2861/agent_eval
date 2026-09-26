from __future__ import annotations

import enum
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, ParamSpec

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


class TaskStatus(enum.Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class BackgroundTaskResult:
    task_id: str
    status: TaskStatus = TaskStatus.PENDING
    exception: Exception | None = None


@dataclass
class _GraphNode:
    task: BackgroundTask
    depends_on: tuple[str, ...] = field(default_factory=tuple)


class BackgroundTaskGraph(BackgroundTask):
    """
    A collection of background tasks organized as a dependency graph.

    Tasks run concurrently once all of their dependencies have succeeded,
    optionally bounded by max_concurrency. If a task fails, its descendants
    are marked as TaskStatus.SKIPPED, while unrelated branches keep running.
    The outcome of every task is available through the results property
    once the graph has been awaited.
    """

    def __init__(self, *, max_concurrency: int | None = None) -> None:
        if max_concurrency is not None and max_concurrency < 1:
            raise ValueError("'max_concurrency' must be a positive integer or None.")
        self.max_concurrency = max_concurrency
        self.nodes: dict[str, _GraphNode] = {}
        self._results: dict[str, BackgroundTaskResult] = {}

    def add_task(
        self,
        task_id: str,
        func: Callable[P, Any],
        *args: P.args,
        depends_on: Sequence[str] = (),
        **kwargs: P.kwargs,
    ) -> None:
        if isinstance(depends_on, str):
            depends_on = (depends_on,)
        if task_id in self.nodes:
            raise ValueError(f"Duplicate task id {task_id!r}.")
        missing = [dependency for dependency in depends_on if dependency not in self.nodes]
        if missing:
            raise ValueError(f"Task {task_id!r} depends on unknown task(s): {', '.join(missing)}.")
        self.nodes[task_id] = _GraphNode(task=BackgroundTask(func, *args, **kwargs), depends_on=tuple(depends_on))
        self._results[task_id] = BackgroundTaskResult(task_id=task_id)

    @property
    def results(self) -> dict[str, BackgroundTaskResult]:
        return dict(self._results)

    async def __call__(self) -> None:
        self._results = {task_id: BackgroundTaskResult(task_id=task_id) for task_id in self.nodes}
        events = {task_id: anyio.Event() for task_id in self.nodes}
        limiter = anyio.Semaphore(self.max_concurrency) if self.max_concurrency is not None else None
        async with anyio.create_task_group() as task_group:
            for task_id in self.nodes:
                task_group.start_soon(self._run_task, task_id, events, limiter)

    async def _run_task(
        self,
        task_id: str,
        events: dict[str, anyio.Event],
        limiter: anyio.Semaphore | None,
    ) -> None:
        node = self.nodes[task_id]
        for dependency in node.depends_on:
            await events[dependency].wait()
        result = self._results[task_id]
        if all(self._results[dependency].status is TaskStatus.SUCCESS for dependency in node.depends_on):
            if limiter is None:
                await self._execute(node.task, result)
            else:
                async with limiter:
                    await self._execute(node.task, result)
        else:
            result.status = TaskStatus.SKIPPED
        events[task_id].set()

    @staticmethod
    async def _execute(task: BackgroundTask, result: BackgroundTaskResult) -> None:
        try:
            await task()
        except Exception as exc:
            result.status = TaskStatus.FAILED
            result.exception = exc
        else:
            result.status = TaskStatus.SUCCESS
