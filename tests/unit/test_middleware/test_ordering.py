from __future__ import annotations

import pytest

from litestar import Litestar, Router, get
from litestar.controller import Controller
from litestar.exceptions import ImproperlyConfiguredException
from litestar.middleware.base import ASGIMiddleware, DefineMiddleware
from litestar.middleware.constraints import MiddlewareConstraints, check_middleware_constraints
from litestar.middleware.ordering import (
    DuplicateMiddlewareNameError,
    MiddlewareCycleError,
    MiddlewareExecutionOrder,
    MiddlewareLayerError,
    MissingMiddlewareError,
    get_middleware_execution_order,
    resolve_middleware_order,
)
from litestar.testing import TestClient
from litestar.types import ASGIApp, Receive, Scope, Send


def create_middleware(
    name: str | None = None,
    constraints: MiddlewareConstraints | None = None,
    log: list | None = None,
) -> ASGIMiddleware:
    if log is not None:

        async def handle(self: ASGIMiddleware, scope: Scope, receive: Receive, send: Send, next_app: ASGIApp) -> None:
            log.append(("enter", name))
            await next_app(scope, receive, send)
            log.append(("exit", name))

    else:

        async def handle(self: ASGIMiddleware, scope: Scope, receive: Receive, send: Send, next_app: ASGIApp) -> None:
            await next_app(scope, receive, send)

    cls = type(f"Middleware_{name}", (ASGIMiddleware,), {"name": name, "constraints": constraints, "handle": handle})
    return cls()


def names(middleware: tuple) -> list:
    return [m.name for m in middleware]


def test_resolve_without_constraints_keeps_order() -> None:
    middleware = [create_middleware() for _ in range(3)]
    layered = [("application", middleware[0]), ("router", middleware[1]), ("route handler", middleware[2])]

    assert resolve_middleware_order(layered) == tuple(middleware)


def test_resolve_named_without_constraints_keeps_order() -> None:
    middleware = [create_middleware(name) for name in ("a", "b", "c")]
    layered = [("route handler", m) for m in middleware]

    assert resolve_middleware_order(layered) == tuple(middleware)


def test_resolve_after_constraint() -> None:
    first = create_middleware("first")
    second = create_middleware("second", MiddlewareConstraints(after=("first",)))
    third = create_middleware("third")
    layered = [("route handler", m) for m in (second, first, third)]

    assert resolve_middleware_order(layered) == (first, second, third)


def test_resolve_before_constraint() -> None:
    first = create_middleware("first")
    second = create_middleware("second", MiddlewareConstraints(before=("first",)))
    layered = [("route handler", m) for m in (first, second)]

    assert resolve_middleware_order(layered) == (second, first)


def test_resolve_unconstrained_keep_relative_order() -> None:
    a = create_middleware("a")
    b = create_middleware("b", MiddlewareConstraints(before=("a",)))
    c = create_middleware("c")
    d = create_middleware("d")
    layered = [("route handler", m) for m in (a, b, c, d)]

    assert resolve_middleware_order(layered) == (b, a, c, d)


def test_resolve_transitive_constraints() -> None:
    a = create_middleware("a", MiddlewareConstraints(after=("b",)))
    b = create_middleware("b", MiddlewareConstraints(after=("c",)))
    c = create_middleware("c")
    layered = [("route handler", m) for m in (a, b, c)]

    assert resolve_middleware_order(layered) == (c, b, a)


def test_resolve_cross_layer_satisfied_constraint() -> None:
    app_mw = create_middleware("app_mw")
    handler_mw = create_middleware("handler_mw", MiddlewareConstraints(after=("app_mw",)))
    layered = [("application", app_mw), ("route handler", handler_mw)]

    assert resolve_middleware_order(layered) == (app_mw, handler_mw)


def test_resolve_duplicate_names() -> None:
    one = create_middleware("dup")
    two = create_middleware("dup")
    layered = [("application", one), ("route handler", two)]

    with pytest.raises(DuplicateMiddlewareNameError) as exc_info:
        resolve_middleware_order(layered)

    message = str(exc_info.value)
    assert "'dup'" in message
    assert "application" in message
    assert "route handler" in message


def test_resolve_missing_dependency() -> None:
    middleware = create_middleware("a", MiddlewareConstraints(after=("missing",)))
    layered = [("route handler", middleware)]

    with pytest.raises(MissingMiddlewareError) as exc_info:
        resolve_middleware_order(layered)

    message = str(exc_info.value)
    assert "'missing'" in message
    assert "'missing' -> 'a'" in message


def test_resolve_missing_dependency_before() -> None:
    middleware = create_middleware("a", MiddlewareConstraints(before=("missing",)))
    layered = [("route handler", middleware)]

    with pytest.raises(MissingMiddlewareError) as exc_info:
        resolve_middleware_order(layered)

    assert "'a' -> 'missing'" in str(exc_info.value)


def test_resolve_cycle() -> None:
    a = create_middleware("a", MiddlewareConstraints(before=("b",)))
    b = create_middleware("b", MiddlewareConstraints(before=("a",)))
    layered = [("route handler", a), ("route handler", b)]

    with pytest.raises(MiddlewareCycleError) as exc_info:
        resolve_middleware_order(layered)

    message = str(exc_info.value)
    assert "'a' -> 'b' -> 'a'" in message or "'b' -> 'a' -> 'b'" in message


def test_resolve_layer_violation() -> None:
    app_mw = create_middleware("app_mw")
    handler_mw = create_middleware("handler_mw", MiddlewareConstraints(before=("app_mw",)))
    layered = [("application", app_mw), ("route handler", handler_mw)]

    with pytest.raises(MiddlewareLayerError) as exc_info:
        resolve_middleware_order(layered)

    message = str(exc_info.value)
    assert "'handler_mw' -> 'app_mw'" in message
    assert "application" in message
    assert isinstance(exc_info.value, ImproperlyConfiguredException)


def test_name_based_constraints_ignored_by_type_based_check() -> None:
    # name references are resolved by the ordering resolver; the type-based
    # constraint validation should ignore them
    middleware = create_middleware("a", MiddlewareConstraints(before=("b",), after=("c",)))
    check_middleware_constraints((middleware,))


def test_apply_name_helpers() -> None:
    constraints = MiddlewareConstraints().apply_before_name("b").apply_after_name("c")
    assert constraints.before == ("b",)
    assert constraints.after == ("c",)


def test_get_middleware_execution_order_display_names() -> None:
    def factory(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
            await app(scope, receive, send)

        return wrapped

    named = create_middleware("named")
    defined = DefineMiddleware(factory)
    order = get_middleware_execution_order([named, defined, factory])

    assert order.enter[0] == "named"
    assert order.enter[1].endswith("factory")
    assert order.enter[2].endswith("factory")
    assert order.exit == tuple(reversed(order.enter))


def create_app(
    *, handler_middleware: list, app_middleware: list | None = None, router_middleware: list | None = None
) -> Litestar:
    @get("/", middleware=handler_middleware, sync_to_thread=False)
    def handler() -> dict:
        return {}

    router = Router(path="/", route_handlers=[handler], middleware=router_middleware or [])
    return Litestar(route_handlers=[router], middleware=app_middleware or [])


def test_app_resolves_order_across_layers() -> None:
    app_mw = create_middleware("app_mw")
    router_mw = create_middleware("router_mw")
    h1 = create_middleware("h1")
    h2 = create_middleware("h2", MiddlewareConstraints(before=("h1",)))

    app = create_app(
        app_middleware=[app_mw],
        router_middleware=[router_mw],
        handler_middleware=[h1, h2],
    )

    route_handler = app.routes[0].route_handlers[0]
    assert names(route_handler.middleware) == ["app_mw", "router_mw", "h2", "h1"]


def test_app_controller_layer() -> None:
    controller_mw = create_middleware("controller_mw")
    h1 = create_middleware("h1")
    h2 = create_middleware("h2", MiddlewareConstraints(before=("h1",)))

    class MyController(Controller):
        path = "/"
        middleware = [controller_mw]

        @get("/", middleware=[h1, h2], sync_to_thread=False)
        def handler(self) -> dict:
            return {}

    app = Litestar(route_handlers=[MyController])
    route_handler = app.routes[0].route_handlers[0]
    assert names(route_handler.middleware) == ["controller_mw", "h2", "h1"]


def test_app_controller_layer_label_in_error() -> None:
    controller_mw = create_middleware("controller_mw")
    handler_mw = create_middleware("handler_mw", MiddlewareConstraints(before=("controller_mw",)))

    class MyController(Controller):
        path = "/"
        middleware = [controller_mw]

        @get("/", middleware=[handler_mw], sync_to_thread=False)
        def handler(self) -> dict:
            return {}

    with pytest.raises(MiddlewareLayerError) as exc_info:
        Litestar(route_handlers=[MyController])

    assert "controller 'MyController'" in str(exc_info.value)


def test_app_layer_violation_raises() -> None:
    app_mw = create_middleware("app_mw")
    handler_mw = create_middleware("handler_mw", MiddlewareConstraints(before=("app_mw",)))

    with pytest.raises(MiddlewareLayerError):
        create_app(app_middleware=[app_mw], handler_middleware=[handler_mw])


def test_app_duplicate_names_raise() -> None:
    with pytest.raises(DuplicateMiddlewareNameError):
        create_app(
            app_middleware=[create_middleware("dup")],
            handler_middleware=[create_middleware("dup")],
        )


def test_app_missing_dependency_raises() -> None:
    handler_mw = create_middleware("handler_mw", MiddlewareConstraints(after=("missing",)))

    with pytest.raises(MissingMiddlewareError):
        create_app(handler_middleware=[handler_mw])


def test_app_cycle_raises() -> None:
    a = create_middleware("a", MiddlewareConstraints(before=("b",)))
    b = create_middleware("b", MiddlewareConstraints(before=("a",)))

    with pytest.raises(MiddlewareCycleError):
        create_app(handler_middleware=[a, b])


def test_app_legacy_middleware_unchanged() -> None:
    def factory(app: ASGIApp) -> ASGIApp:
        async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
            await app(scope, receive, send)

        return wrapped

    defined = DefineMiddleware(factory)
    plain = create_middleware()

    app = create_app(handler_middleware=[defined, factory, plain])
    route_handler = app.routes[0].route_handlers[0]
    assert route_handler.middleware == (defined, factory, plain)


def test_execution_order_view_matches_runtime() -> None:
    log: list = []
    app_mw = create_middleware("app_mw", log=log)
    router_mw = create_middleware("router_mw", log=log)
    h1 = create_middleware("h1", log=log)
    h2 = create_middleware("h2", MiddlewareConstraints(before=("h1",)), log=log)

    app = create_app(
        app_middleware=[app_mw],
        router_middleware=[router_mw],
        handler_middleware=[h1, h2],
    )

    route_handler = app.routes[0].route_handlers[0]
    order = route_handler.middleware_execution_order

    assert isinstance(order, MiddlewareExecutionOrder)
    assert order.enter == ("app_mw", "router_mw", "h2", "h1")
    assert order.exit == ("h1", "h2", "router_mw", "app_mw")

    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200

    entered = tuple(entry for direction, entry in log if direction == "enter")
    exited = tuple(entry for direction, entry in log if direction == "exit")
    assert entered == order.enter
    assert exited == order.exit


def test_app_level_execution_order_view() -> None:
    app_mw = create_middleware("app_mw")
    h1 = create_middleware("h1")

    app = create_app(app_middleware=[app_mw], handler_middleware=[h1])

    orders = app.get_middleware_execution_order()
    route_handler = app.routes[0].route_handlers[0]
    assert route_handler.middleware_execution_order in orders.values()
    assert orders[route_handler.name or str(route_handler)].enter == ("app_mw", "h1")
