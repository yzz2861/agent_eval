import threading

import anyio
import pytest

from starlette.background import (
    BackgroundTask,
    BackgroundTaskGraph,
    BackgroundTaskGraphError,
    BackgroundTasks,
    TaskStatus,
)
from starlette.responses import Response
from starlette.types import Receive, Scope, Send
from tests.types import TestClientFactory


def test_async_task(test_client_factory: TestClientFactory) -> None:
    TASK_COMPLETE = False

    async def async_task() -> None:
        nonlocal TASK_COMPLETE
        TASK_COMPLETE = True

    task = BackgroundTask(async_task)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("task initiated", media_type="text/plain", background=task)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "task initiated"
    assert TASK_COMPLETE


def test_sync_task(test_client_factory: TestClientFactory) -> None:
    TASK_COMPLETE = False

    def sync_task() -> None:
        nonlocal TASK_COMPLETE
        TASK_COMPLETE = True

    task = BackgroundTask(sync_task)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("task initiated", media_type="text/plain", background=task)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "task initiated"
    assert TASK_COMPLETE


def test_multiple_tasks(test_client_factory: TestClientFactory) -> None:
    TASK_COUNTER = 0

    def increment(amount: int) -> None:
        nonlocal TASK_COUNTER
        TASK_COUNTER += amount

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        tasks = BackgroundTasks()
        tasks.add_task(increment, amount=1)
        tasks.add_task(increment, amount=2)
        tasks.add_task(increment, amount=3)
        response = Response("tasks initiated", media_type="text/plain", background=tasks)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert TASK_COUNTER == 1 + 2 + 3


def test_multi_tasks_failure_avoids_next_execution(
    test_client_factory: TestClientFactory,
) -> None:
    TASK_COUNTER = 0

    def increment() -> None:
        nonlocal TASK_COUNTER
        TASK_COUNTER += 1
        if TASK_COUNTER == 1:  # pragma: no branch
            raise Exception("task failed")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        tasks = BackgroundTasks()
        tasks.add_task(increment)
        tasks.add_task(increment)
        response = Response("tasks initiated", media_type="text/plain", background=tasks)
        await response(scope, receive, send)

    client = test_client_factory(app)
    with pytest.raises(Exception):
        client.get("/")
    assert TASK_COUNTER == 1


def test_graph_runs_tasks_in_dependency_order(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []

    def upload() -> None:
        events.append("upload")

    def write_index() -> None:
        events.append("index")

    def notify() -> None:
        events.append("notify")

    graph = BackgroundTaskGraph()
    graph.add_task("upload", upload)
    graph.add_task("index", write_index, dependencies=["upload"])
    graph.add_task("notify", notify, dependencies=["upload"])

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert events[0] == "upload"
    assert sorted(events[1:]) == ["index", "notify"]
    assert graph.status("upload") is TaskStatus.SUCCEEDED
    assert graph.status("index") is TaskStatus.SUCCEEDED
    assert graph.status("notify") is TaskStatus.SUCCEEDED


def test_graph_failure_skips_descendants_but_completes_independent_branches(
    test_client_factory: TestClientFactory,
) -> None:
    events: list[str] = []
    upload_error = RuntimeError("upload failed")

    def upload() -> None:
        events.append("upload")
        raise upload_error

    def write_index() -> None:  # pragma: no cover - skipped
        events.append("index")

    def notify() -> None:  # pragma: no cover - skipped
        events.append("notify")

    def cleanup() -> None:
        events.append("cleanup")

    graph = BackgroundTaskGraph()
    graph.add_task("upload", upload)
    graph.add_task("index", write_index, dependencies=["upload"])
    graph.add_task("notify", notify, dependencies=["index"])
    graph.add_task("cleanup", cleanup)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    with pytest.raises(BackgroundTaskGraphError) as exc_info:
        client.get("/")
    assert sorted(events) == ["cleanup", "upload"]
    assert exc_info.value.__cause__ is upload_error
    assert exc_info.value.errors == {"upload": upload_error}
    assert graph.status("upload") is TaskStatus.FAILED
    assert graph.status("index") is TaskStatus.SKIPPED
    assert graph.status("notify") is TaskStatus.SKIPPED
    assert graph.status("cleanup") is TaskStatus.SUCCEEDED
    assert graph.results["upload"].error is upload_error


def test_graph_async_tasks_run_concurrently(test_client_factory: TestClientFactory) -> None:
    running = 0
    max_running = 0

    async def task() -> None:
        nonlocal running, max_running
        running += 1
        max_running = max(max_running, running)
        await anyio.sleep(0.01)
        running -= 1

    graph = BackgroundTaskGraph()
    for task_id in ("a", "b", "c"):
        graph.add_task(task_id, task)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert max_running == 3


def test_graph_max_concurrency_limit(test_client_factory: TestClientFactory) -> None:
    running = 0
    max_running = 0

    async def task() -> None:
        nonlocal running, max_running
        running += 1
        max_running = max(max_running, running)
        await anyio.sleep(0.01)
        running -= 1

    graph = BackgroundTaskGraph(max_concurrency=1)
    for task_id in ("a", "b", "c"):
        graph.add_task(task_id, task)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert max_running == 1
    assert all(result.status is TaskStatus.SUCCEEDED for result in graph.results.values())


def test_graph_sync_tasks_run_in_threadpool(test_client_factory: TestClientFactory) -> None:
    loop_thread_id = None
    sync_thread_id = None

    async def async_task() -> None:
        nonlocal loop_thread_id
        loop_thread_id = threading.get_ident()

    def sync_task() -> None:
        nonlocal sync_thread_id
        sync_thread_id = threading.get_ident()

    graph = BackgroundTaskGraph()
    graph.add_task("async", async_task)
    graph.add_task("sync", sync_task)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert sync_thread_id is not None
    assert sync_thread_id != loop_thread_id


def test_graph_results_pending_before_run() -> None:
    graph = BackgroundTaskGraph()
    graph.add_task("upload", lambda: None)
    assert graph.status("upload") is TaskStatus.PENDING
    assert graph.results["upload"] == ("upload", TaskStatus.PENDING, None)
    with pytest.raises(KeyError):
        graph.status("unknown")


def test_graph_rejects_duplicate_task_id() -> None:
    graph = BackgroundTaskGraph()
    graph.add_task("upload", lambda: None)
    with pytest.raises(ValueError, match="Duplicate task identifier"):
        graph.add_task("upload", lambda: None)


def test_graph_rejects_unknown_dependency() -> None:
    graph = BackgroundTaskGraph()
    with pytest.raises(ValueError, match="Unknown dependencies"):
        graph.add_task("index", lambda: None, dependencies=["upload"])


def test_graph_rejects_self_dependency() -> None:
    graph = BackgroundTaskGraph()
    with pytest.raises(ValueError, match="cannot depend on itself"):
        graph.add_task("upload", lambda: None, dependencies=["upload"])


def test_graph_rejects_invalid_max_concurrency() -> None:
    with pytest.raises(ValueError, match="max_concurrency"):
        BackgroundTaskGraph(max_concurrency=0)
