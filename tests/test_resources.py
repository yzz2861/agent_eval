from __future__ import annotations

import asyncio
from typing import Any

import pytest

from quart import Quart
from quart import resources
from quart.resources import CircularResourceError
from quart.resources import RequestResources
from quart.resources import ResourceClosedError


class FakeConnection:
    """In-memory stand-in recording its lifecycle into a shared log."""

    def __init__(self, name: str, events: list) -> None:
        self.name = name
        self.events = events
        self.closed = False

    async def close(self) -> None:
        self.closed = True
        self.events.append("close:" + self.name)


def _factory(name: str, events: list):
    async def factory(registry: RequestResources) -> FakeConnection:
        events.append("open:" + name)
        return FakeConnection(name, events)

    return factory


def _cleanup(name: str, events: list):
    async def cleanup(value: FakeConnection) -> None:
        await value.close()

    return cleanup


async def test_get_creates_once_and_shares_between_coroutines() -> None:
    registry = RequestResources()
    calls = 0

    async def factory(registry: RequestResources) -> object:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return object()

    registry.register("db", factory)
    first, second = await asyncio.gather(registry.get("db"), registry.get("db"))
    assert first is second
    assert calls == 1


async def test_waiter_cancellation_does_not_cancel_initialisation() -> None:
    registry = RequestResources()
    started = asyncio.Event()
    finish = asyncio.Event()

    async def factory(registry: RequestResources) -> str:
        started.set()
        await finish.wait()
        return "value"

    registry.register("db", factory)
    waiter = asyncio.ensure_future(registry.get("db"))
    cancelled = asyncio.ensure_future(registry.get("db"))
    await started.wait()
    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    finish.set()
    assert await waiter == "value"
    assert await registry.get("db") == "value"


async def test_initiator_cancellation_still_completes_creation() -> None:
    registry = RequestResources()
    started = asyncio.Event()
    finish = asyncio.Event()

    async def factory(registry: RequestResources) -> str:
        started.set()
        await finish.wait()
        return "value"

    registry.register("db", factory)
    initiator = asyncio.ensure_future(registry.get("db"))
    await started.wait()
    initiator.cancel()
    with pytest.raises(asyncio.CancelledError):
        await initiator
    finish.set()
    # The creation outlived its cancelled initiator.
    assert await registry.get("db") == "value"


async def test_dependencies_close_in_reverse_creation_order() -> None:
    events: list = []
    app = Quart(__name__)

    async with app.test_request_context("/") as ctx:

        async def repo_factory(registry: RequestResources) -> FakeConnection:
            db = await registry.get("db")
            assert not db.closed
            events.append("open:repo")
            return FakeConnection("repo", events)

        ctx.resources.register("db", _factory("db", events), _cleanup("db", events))
        ctx.resources.register("repo", repo_factory, _cleanup("repo", events))
        repo = await ctx.resources.get("repo")
        events.append("use:repo")
        assert not repo.closed

    assert events == ["open:db", "open:repo", "use:repo", "close:repo", "close:db"]


async def test_circular_dependency_reports_full_chain() -> None:
    registry = RequestResources()

    async def factory_a(registry: RequestResources) -> Any:
        return await registry.get("b")

    async def factory_b(registry: RequestResources) -> Any:
        return await registry.get("c")

    async def factory_c(registry: RequestResources) -> Any:
        return await registry.get("a")

    registry.register("a", factory_a)
    registry.register("b", factory_b)
    registry.register("c", factory_c)
    with pytest.raises(CircularResourceError) as exc_info:
        await registry.get("a")
    assert exc_info.value.chain == ("a", "b", "c", "a")
    assert "a -> b -> c -> a" in str(exc_info.value)


async def test_failed_creation_rolls_back_opened_resources() -> None:
    events: list = []
    registry = RequestResources()

    async def factory_b(registry: RequestResources) -> FakeConnection:
        await registry.get("a")
        events.append("open:b")
        return FakeConnection("b", events)

    async def factory_c(registry: RequestResources) -> None:
        await registry.get("b")
        raise RuntimeError("boom")

    registry.register("a", _factory("a", events), _cleanup("a", events))
    registry.register("b", factory_b, _cleanup("b", events))
    registry.register("c", factory_c, _cleanup("c", events))
    with pytest.raises(RuntimeError, match="boom"):
        await registry.get("c")
    # Everything opened by the failed resolution is released in reverse.
    assert events == ["open:a", "open:b", "close:b", "close:a"]
    # A failed resolution can be retried from scratch.
    await registry.get("a")
    assert events[-1] == "open:a"
    await registry.aclose()
    assert events[-1] == "close:a"


async def test_aclose_releases_once_and_seals_the_registry() -> None:
    events: list = []
    registry = RequestResources()
    registry.register("db", _factory("db", events), _cleanup("db", events))
    with pytest.raises(KeyError):
        await registry.get("missing")
    await registry.get("db")
    await registry.aclose()
    await registry.aclose()
    assert events == ["open:db", "close:db"]
    with pytest.raises(ResourceClosedError):
        await registry.get("db")
    with pytest.raises(ResourceClosedError):
        registry.register("other", _factory("other", events))


async def test_aclose_waits_for_inflight_creation() -> None:
    events: list = []
    registry = RequestResources()
    finish = asyncio.Event()

    async def factory(registry: RequestResources) -> FakeConnection:
        events.append("open:db")
        await finish.wait()
        return FakeConnection("db", events)

    registry.register("db", factory, _cleanup("db", events))
    getter = asyncio.ensure_future(registry.get("db"))
    await asyncio.sleep(0)
    closer = asyncio.ensure_future(registry.aclose())
    await asyncio.sleep(0)
    finish.set()
    await getter
    await closer
    assert events == ["open:db", "close:db"]


async def test_cleanup_errors_are_collected() -> None:
    events: list = []
    registry = RequestResources()

    async def cleanup_a(value: FakeConnection) -> None:
        events.append("close:a")
        raise ValueError("a")

    async def cleanup_b(value: FakeConnection) -> None:
        events.append("close:b")
        raise ValueError("b")

    registry.register("a", _factory("a", events), cleanup_a)
    registry.register("b", _factory("b", events), cleanup_b)
    await registry.get("a")
    await registry.get("b")
    with pytest.raises(ExceptionGroup) as exc_info:
        await registry.aclose()
    assert len(exc_info.value.exceptions) == 2
    assert events == ["open:a", "open:b", "close:b", "close:a"]


async def test_resources_closed_once_after_request() -> None:
    events: list = []
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        resources.register("db", _factory("db", events), _cleanup("db", events))
        db = await resources.get("db")
        events.append("view:closed=" + str(db.closed))
        return "ok"

    response = await app.test_client().get("/")
    assert response.status_code == 200
    assert events == ["open:db", "view:closed=False", "close:db"]


async def test_streaming_response_keeps_resources_until_body_done() -> None:
    events: list = []
    app = Quart(__name__)

    @app.route("/")
    async def index():
        resources.register("db", _factory("db", events), _cleanup("db", events))
        db = await resources.get("db")

        async def stream():
            events.append("stream:closed=" + str(db.closed))
            yield b"chunk"
            events.append("stream:closed=" + str(db.closed))
            yield b"done"

        return stream()

    response = await app.test_client().get("/")
    assert response.status_code == 200
    assert events == [
        "open:db",
        "stream:closed=False",
        "stream:closed=False",
        "close:db",
    ]


async def test_client_disconnect_releases_streaming_resources() -> None:
    events: list = []
    app = Quart(__name__)
    started = asyncio.Event()

    @app.route("/")
    async def index():
        resources.register("db", _factory("db", events), _cleanup("db", events))
        await resources.get("db")

        async def stream():
            yield b"chunk"
            started.set()
            await asyncio.sleep(60)
            yield b"never"

        return stream()

    client = app.test_client()
    async with client.request("/") as connection:
        await connection.receive()
        await asyncio.wait_for(started.wait(), timeout=1)
        await connection.disconnect()
    assert events == ["open:db", "close:db"]


async def test_exception_in_view_releases_resources() -> None:
    events: list = []
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        resources.register("db", _factory("db", events), _cleanup("db", events))
        await resources.get("db")
        raise RuntimeError("boom")

    response = await app.test_client().get("/")
    assert response.status_code == 500
    assert events == ["open:db", "close:db"]


async def test_streaming_error_releases_resources() -> None:
    events: list = []
    app = Quart(__name__)

    @app.route("/")
    async def index():
        resources.register("db", _factory("db", events), _cleanup("db", events))
        await resources.get("db")

        async def stream():
            yield b"chunk"
            raise RuntimeError("boom")

        return stream()

    try:
        async with app.test_client().request("/") as connection:
            await connection.receive()
    except BaseExceptionGroup as error:
        assert any(
            isinstance(exception, RuntimeError) for exception in error.exceptions
        )
    else:
        raise AssertionError("The stream error should propagate")
    assert events == ["open:db", "close:db"]
