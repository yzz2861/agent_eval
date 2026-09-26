import threading

import anyio
import pytest

from starlette.background import BackgroundTask, BackgroundTaskGraph, BackgroundTasks, TaskStatus
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


def test_graph_runs_dependencies_in_order(
    test_client_factory: TestClientFactory,
) -> None:
    calls: list[str] = []

    async def upload() -> None:
        calls.append("upload")

    def write_index() -> None:
        calls.append("index")

    def notify() -> None:
        calls.append("notify")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        graph = BackgroundTaskGraph()
        graph.add_task("upload", upload)
        graph.add_task("index", write_index, depends_on=["upload"])
        graph.add_task("notify", notify, depends_on=["upload"])
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert calls[0] == "upload"
    assert sorted(calls[1:]) == ["index", "notify"]


def test_graph_failure_skips_dependents_but_not_other_branches(
    test_client_factory: TestClientFactory,
) -> None:
    calls: list[str] = []
    boom = ValueError("upload failed")
    graph = BackgroundTaskGraph()

    async def upload() -> None:
        calls.append("upload")
        raise boom

    def write_index() -> None:
        calls.append("index")

    def notify() -> None:
        calls.append("notify")

    async def cleanup() -> None:
        calls.append("cleanup")

    graph.add_task("upload", upload)
    graph.add_task("index", write_index, depends_on=["upload"])
    graph.add_task("notify", notify, depends_on=["upload"])
    graph.add_task("cleanup", cleanup)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "tasks initiated"
    assert sorted(calls) == ["cleanup", "upload"]

    results = graph.results
    assert results["upload"].status is TaskStatus.FAILED
    assert results["upload"].exception is boom
    assert results["index"].status is TaskStatus.SKIPPED
    assert results["index"].exception is None
    assert results["notify"].status is TaskStatus.SKIPPED
    assert results["cleanup"].status is TaskStatus.SUCCESS


def test_graph_skip_is_transitive(test_client_factory: TestClientFactory) -> None:
    graph = BackgroundTaskGraph()

    def fail() -> None:
        raise RuntimeError("root failure")

    graph.add_task("a", fail)
    graph.add_task("b", lambda: None, depends_on=["a"])
    graph.add_task("c", lambda: None, depends_on=["b"])

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    client.get("/")
    results = graph.results
    assert results["a"].status is TaskStatus.FAILED
    assert results["b"].status is TaskStatus.SKIPPED
    assert results["c"].status is TaskStatus.SKIPPED


def test_graph_runs_independent_tasks_concurrently(
    test_client_factory: TestClientFactory,
) -> None:
    running = 0
    max_running = 0

    async def job() -> None:
        nonlocal running, max_running
        running += 1
        max_running = max(max_running, running)
        await anyio.sleep(0.01)
        running -= 1

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        graph = BackgroundTaskGraph()
        for name in ("a", "b", "c"):
            graph.add_task(name, job)
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    client.get("/")
    assert max_running == 3


def test_graph_limits_concurrency(test_client_factory: TestClientFactory) -> None:
    running = 0
    max_running = 0

    async def job() -> None:
        nonlocal running, max_running
        running += 1
        max_running = max(max_running, running)
        await anyio.sleep(0.01)
        running -= 1

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        graph = BackgroundTaskGraph(max_concurrency=1)
        for name in ("a", "b", "c"):
            graph.add_task(name, job)
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    client.get("/")
    assert max_running == 1


def test_graph_sync_task_runs_in_threadpool(
    test_client_factory: TestClientFactory,
) -> None:
    loop_thread: int | None = None
    sync_thread: int | None = None

    async def async_task() -> None:
        nonlocal loop_thread
        loop_thread = threading.get_ident()

    def sync_task() -> None:
        nonlocal sync_thread
        sync_thread = threading.get_ident()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        graph = BackgroundTaskGraph()
        graph.add_task("async", async_task)
        graph.add_task("sync", sync_task)
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    client.get("/")
    assert loop_thread is not None
    assert sync_thread is not None
    assert sync_thread != loop_thread


def test_graph_async_task_not_blocked_by_sync_task(
    test_client_factory: TestClientFactory,
) -> None:
    proceed = threading.Event()
    done: list[str] = []

    def sync_task() -> None:
        assert proceed.wait(timeout=5)
        done.append("sync")

    async def async_task() -> None:
        await anyio.sleep(0.01)
        done.append("async")
        proceed.set()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        graph = BackgroundTaskGraph()
        graph.add_task("sync", sync_task)
        graph.add_task("async", async_task)
        response = Response("tasks initiated", media_type="text/plain", background=graph)
        await response(scope, receive, send)

    client = test_client_factory(app)
    client.get("/")
    assert done == ["async", "sync"]


def test_graph_rejects_duplicate_task_id() -> None:
    graph = BackgroundTaskGraph()
    graph.add_task("a", lambda: None)
    with pytest.raises(ValueError, match="Duplicate task id 'a'"):
        graph.add_task("a", lambda: None)


def test_graph_rejects_missing_dependency() -> None:
    graph = BackgroundTaskGraph()
    with pytest.raises(ValueError, match="unknown task"):
        graph.add_task("a", lambda: None, depends_on=["b"])


def test_graph_rejects_cycles_before_response() -> None:
    graph = BackgroundTaskGraph()
    graph.add_task("a", lambda: None)
    graph.add_task("b", lambda: None, depends_on="a")
    # Closing a cycle requires reusing an existing id...
    with pytest.raises(ValueError, match="Duplicate task id"):
        graph.add_task("a", lambda: None, depends_on="b")
    # ...or depending on a task that does not exist yet, including itself.
    with pytest.raises(ValueError, match="unknown task"):
        graph.add_task("c", lambda: None, depends_on="c")


def test_graph_rejects_invalid_max_concurrency() -> None:
    with pytest.raises(ValueError, match="max_concurrency"):
        BackgroundTaskGraph(max_concurrency=0)
