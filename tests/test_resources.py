from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import pytest

from quart import Quart
from quart import ResourceDependencyError
from quart import ResourceError
from quart import ResourceNotFoundError
from quart import resources
from quart import websocket


class FakeResource:
    """In-memory resource stand-in recording its lifecycle."""

    def __init__(self, name: str, events: list[str]) -> None:
        self.name = name
        self.events = events
        self.closed = False

    async def use(self) -> None:
        assert not self.closed, f"resource {self.name} used after close"
        self.events.append(f"use:{self.name}")

    async def close(self) -> None:
        assert not self.closed, f"resource {self.name} closed twice"
        self.closed = True
        self.events.append(f"close:{self.name}")


def _factory(
    name: str,
    events: list[str],
    *,
    depends: tuple[str, ...] = (),
    fail: bool = False,
    calls: list[str] | None = None,
):
    async def factory(registry) -> FakeResource:
        if calls is not None:
            calls.append(name)
        events.append(f"create:{name}")
        resource = FakeResource(name, events)
        for dependency in depends:
            await registry.get(dependency)
        if fail:
            events.append(f"fail:{name}")
            raise RuntimeError(f"boom:{name}")
        return resource

    return factory


async def _cleanup(resource: FakeResource) -> None:
    await resource.close()


async def test_lazy_creation_and_sharing() -> None:
    app = Quart(__name__)
    events: list[str] = []
    calls: list[str] = []
    app.register_resource("db", _factory("db", events, calls=calls), cleanup=_cleanup)

    async with app.test_request_context("/"):
        assert events == []
        first = await resources.get("db")
        assert events == ["create:db"]
        second = await resources.get("db")
        assert second is first
        assert calls == ["db"]


async def test_concurrent_get_initializes_once() -> None:
    app = Quart(__name__)
    events: list[str] = []
    calls: list[str] = []

    async def factory(registry) -> FakeResource:
        calls.append("db")
        await asyncio.sleep(0.01)
        return FakeResource("db", events)

    app.register_resource("db", factory, cleanup=_cleanup)

    async with app.test_request_context("/"):
        first, second = await asyncio.gather(resources.get("db"), resources.get("db"))
        assert first is second
        assert calls == ["db"]


async def test_waiter_cancellation_does_not_cancel_initialization() -> None:
    app = Quart(__name__)
    events: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def factory(registry) -> FakeResource:
        started.set()
        await release.wait()
        return FakeResource("db", events)

    app.register_resource("db", factory, cleanup=_cleanup)

    async with app.test_request_context("/"):
        creator = asyncio.ensure_future(resources.get("db"))
        await started.wait()
        waiter = asyncio.ensure_future(resources.get("db"))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        resource = await creator
        assert not resource.closed
        assert await resources.get("db") is resource


async def test_dependencies_close_in_reverse_order() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("a", _factory("a", events), cleanup=_cleanup)
    app.register_resource("b", _factory("b", events, depends=("a",)), cleanup=_cleanup)
    app.register_resource("c", _factory("c", events, depends=("b",)), cleanup=_cleanup)

    async with app.test_request_context("/"):
        await resources.get("c")
        assert events == ["create:c", "create:b", "create:a"]
    assert events == [
        "create:c",
        "create:b",
        "create:a",
        "close:c",
        "close:b",
        "close:a",
    ]


async def test_circular_dependency_shows_full_chain() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("a", _factory("a", events, depends=("b",)))
    app.register_resource("b", _factory("b", events, depends=("a",)))

    async with app.test_request_context("/"):
        with pytest.raises(ResourceDependencyError) as exc_info:
            await resources.get("a")
    assert exc_info.value.chain == ["a", "b", "a"]
    assert "'a' -> 'b' -> 'a'" in str(exc_info.value)


async def test_failed_creation_rolls_back_opened_resources() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("a", _factory("a", events), cleanup=_cleanup)
    app.register_resource(
        "b", _factory("b", events, depends=("a",), fail=True), cleanup=_cleanup
    )

    async with app.test_request_context("/"):
        with pytest.raises(RuntimeError, match="boom:b"):
            await resources.get("b")
        assert events == ["create:b", "create:a", "fail:b", "close:a"]
        # The registry itself is still usable after the failure.
        resource = await resources.get("a")
        assert not resource.closed


async def test_unknown_resource() -> None:
    app = Quart(__name__)

    async with app.test_request_context("/"):
        with pytest.raises(ResourceNotFoundError):
            await resources.get("missing")


async def test_get_after_close_raises() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    async with app.test_request_context("/") as ctx:
        await resources.get("db")
        await ctx.resources.close()
        with pytest.raises(ResourceError):
            await resources.get("db")


async def test_close_is_idempotent() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    async with app.test_request_context("/") as ctx:
        await resources.get("db")
        await ctx.resources.close()
        await ctx.resources.close()
    assert events == ["create:db", "close:db"]


async def test_async_generator_factory() -> None:
    app = Quart(__name__)
    events: list[str] = []

    @app.register_resource("db")
    async def create_db(registry) -> AsyncGenerator[FakeResource]:
        events.append("create:db")
        resource = FakeResource("db", events)
        yield resource
        await resource.close()

    async with app.test_request_context("/"):
        resource = await resources.get("db")
        await resource.use()
    assert events == ["create:db", "use:db", "close:db"]


async def test_request_lifecycle_closes_resources() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    @app.route("/")
    async def index() -> str:
        db = await resources.get("db")
        await db.use()
        return "ok"

    response = await app.test_client().get("/")
    assert response.status_code == 200
    assert events == ["create:db", "use:db", "close:db"]


async def test_streaming_response_keeps_resources_open_until_sent() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    @app.route("/")
    async def index():
        db = await resources.get("db")

        async def _gen() -> AsyncGenerator[str]:
            yield "first"
            # The resource must still be open whilst streaming.
            await db.use()
            assert "close:db" not in events
            yield "second"

        return _gen()

    response = await app.test_client().get("/")
    assert response.status_code == 200
    assert await response.data == b"firstsecond"
    assert events == ["create:db", "use:db", "close:db"]


async def test_client_disconnect_releases_resources() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    @app.route("/")
    async def index():
        db = await resources.get("db")
        await db.use()

        async def _gen() -> AsyncGenerator[str]:
            yield "data"
            await asyncio.Event().wait()  # Stream forever
            yield "never"

        return _gen()

    test_client = app.test_client()
    async with test_client.request("/", method="GET") as connection:
        assert await connection.receive() == b"data"
        await connection.disconnect()

    assert events == ["create:db", "use:db", "close:db"]


async def test_view_exception_releases_resources() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    @app.route("/")
    async def index() -> str:
        db = await resources.get("db")
        await db.use()
        raise RuntimeError("boom")

    response = await app.test_client().get("/")
    assert response.status_code == 500
    assert events == ["create:db", "use:db", "close:db"]


async def test_websocket_closes_resources() -> None:
    app = Quart(__name__)
    events: list[str] = []
    app.register_resource("db", _factory("db", events), cleanup=_cleanup)

    @app.websocket("/")
    async def ws() -> None:
        db = await resources.get("db")
        await db.use()
        await websocket.send("ready")
        await websocket.receive()

    test_client = app.test_client()
    async with test_client.websocket("/") as connection:
        assert await connection.receive() == "ready"
        await connection.send("ping")

    assert events == ["create:db", "use:db", "close:db"]


async def test_request_level_registration() -> None:
    app = Quart(__name__)
    events: list[str] = []

    @app.route("/")
    async def index() -> str:
        resources.register("db", _factory("db", events), cleanup=_cleanup)
        db = await resources.get("db")
        await db.use()
        return "ok"

    response = await app.test_client().get("/")
    assert response.status_code == 200
    assert events == ["create:db", "use:db", "close:db"]
