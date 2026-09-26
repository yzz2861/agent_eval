from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import pytest

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import BaseRoute, Mount, Route
from starlette.types import Receive, Scope, Send
from tests.types import TestClientFactory

Events = list[str]


def make_lifespan(
    name: str,
    events: Events,
    entered: set[str],
    fail_on_startup: bool = False,
) -> Any:
    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[dict[str, str]]:
        events.append(f"{name}:enter")
        entered.add(name)
        try:
            if fail_on_startup:
                raise RuntimeError(f"{name} failed to start")
            yield {"conn": f"{name}-conn"}
        finally:
            entered.discard(name)
            events.append(f"{name}:exit")

    return lifespan


def make_app(
    name: str,
    events: Events,
    entered: set[str],
    *,
    routes: Sequence[BaseRoute] = (),
    fail_on_startup: bool = False,
) -> Starlette:
    async def endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"app": name, "conn": request.state["conn"]})

    return Starlette(
        routes=[Route("/", endpoint), *routes],
        lifespan=make_lifespan(name, events, entered, fail_on_startup),
    )


def test_composed_lifespan_startup_and_shutdown_order(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()
    child_a = make_app("a", events, entered)
    child_b = make_app("b", events, entered)
    parent = make_app(
        "parent",
        events,
        entered,
        routes=[
            Mount("/a", app=child_a, compose_lifespan=True),
            Mount("/b", app=child_b, compose_lifespan=True),
        ],
    )

    with test_client_factory(parent) as client:
        assert events == ["parent:enter", "a:enter", "b:enter"]
        assert entered == {"parent", "a", "b"}
        assert client.get("/").json() == {"app": "parent", "conn": "parent-conn"}

    assert events == ["parent:enter", "a:enter", "b:enter", "b:exit", "a:exit", "parent:exit"]
    assert not entered


def test_composed_lifespan_state_isolation(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()
    child_a = make_app("a", events, entered)
    child_b = make_app("b", events, entered)
    parent = make_app(
        "parent",
        events,
        entered,
        routes=[
            Mount("/a", app=child_a, compose_lifespan=True),
            Mount("/b", app=child_b, compose_lifespan=True),
        ],
    )

    with test_client_factory(parent) as client:
        # Every application yields a "conn" key, and each one only sees its own.
        assert client.get("/").json()["conn"] == "parent-conn"
        assert client.get("/a/").json()["conn"] == "a-conn"
        assert client.get("/b/").json()["conn"] == "b-conn"
        # The parent's state is not polluted by the mounted applications.
        assert client.get("/").json()["conn"] == "parent-conn"

    assert not entered


def test_composed_lifespan_nested_mounts(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()
    grandchild = make_app("grandchild", events, entered)
    child = make_app("child", events, entered, routes=[Mount("/gc", app=grandchild, compose_lifespan=True)])
    parent = make_app("parent", events, entered, routes=[Mount("/child", app=child, compose_lifespan=True)])

    with test_client_factory(parent) as client:
        assert events == ["parent:enter", "child:enter", "grandchild:enter"]
        assert client.get("/child/").json()["conn"] == "child-conn"
        assert client.get("/child/gc/").json()["conn"] == "grandchild-conn"

    assert events == [
        "parent:enter",
        "child:enter",
        "grandchild:enter",
        "grandchild:exit",
        "child:exit",
        "parent:exit",
    ]
    assert not entered


def test_composed_lifespan_rollback_on_child_failure(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()
    child_ok = make_app("ok", events, entered)
    child_bad = make_app("bad", events, entered, fail_on_startup=True)
    parent = make_app(
        "parent",
        events,
        entered,
        routes=[
            Mount("/ok", app=child_ok, compose_lifespan=True),
            Mount("/bad", app=child_bad, compose_lifespan=True),
        ],
    )

    with pytest.raises(RuntimeError, match="bad failed to start"):
        with test_client_factory(parent):
            pass  # pragma: no cover

    # Everything that started was shut down again, in reverse order.
    assert events == ["parent:enter", "ok:enter", "bad:enter", "bad:exit", "ok:exit", "parent:exit"]
    assert not entered


def test_composed_lifespan_shared_sub_app_runs_once(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()
    child = make_app("child", events, entered)
    parent = Starlette(
        routes=[
            Mount("/one", app=child, compose_lifespan=True),
            Mount("/two", app=child, compose_lifespan=True),
        ]
    )

    with test_client_factory(parent) as client:
        assert events == ["child:enter"]
        assert client.get("/one/").json() == {"app": "child", "conn": "child-conn"}
        assert client.get("/two/").json() == {"app": "child", "conn": "child-conn"}

    assert events == ["child:enter", "child:exit"]
    assert not entered


def test_composed_lifespan_cycle_detected_before_startup(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()
    child = make_app("child", events, entered)
    parent = make_app("parent", events, entered, routes=[Mount("/child", app=child, compose_lifespan=True)])
    child.routes.append(Mount("/parent", app=parent, compose_lifespan=True))

    with pytest.raises(RuntimeError, match="Cyclic lifespan composition detected"):
        with test_client_factory(parent):
            pass  # pragma: no cover

    # The cycle is reported before any lifespan runs.
    assert events == []
    assert not entered


def test_composed_lifespan_plain_asgi_callable(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()

    async def plain_asgi_app(scope: Scope, receive: Receive, send: Send) -> None:
        assert scope["type"] == "http"
        response = PlainTextResponse("plain-ok")
        await response(scope, receive, send)

    parent = make_app(
        "parent",
        events,
        entered,
        routes=[Mount("/plain", app=plain_asgi_app, compose_lifespan=True)],
    )

    with test_client_factory(parent) as client:
        assert events == ["parent:enter"]
        response = client.get("/plain")
        assert response.status_code == 200
        assert response.text == "plain-ok"

    assert events == ["parent:enter", "parent:exit"]
    assert not entered


def test_mounted_app_lifespan_not_composed_by_default(test_client_factory: TestClientFactory) -> None:
    events: Events = []
    entered: set[str] = set()

    async def endpoint(request: Request) -> PlainTextResponse:
        return PlainTextResponse("child-ok")

    child = Starlette(routes=[Route("/", endpoint)], lifespan=make_lifespan("child", events, entered))
    parent = Starlette(routes=[Mount("/child", app=child)])

    with test_client_factory(parent) as client:
        # Without 'compose_lifespan', the mounted application's lifespan
        # never runs, matching the behavior of existing projects.
        assert events == []
        response = client.get("/child/")
        assert response.status_code == 200
        assert response.text == "child-ok"

    assert events == []
    assert not entered
