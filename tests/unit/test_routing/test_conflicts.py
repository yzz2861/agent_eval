from __future__ import annotations

from datetime import date
from typing import Any
from uuid import UUID

import pytest

from litestar import Litestar, Router, asgi, get, post, websocket
from litestar.connection import WebSocket
from litestar.exceptions import ImproperlyConfiguredException
from litestar.params import FromPath
from litestar.routing import ConflictKind, RouteConflict, check_route_conflicts


def _app(*handlers: Any) -> Litestar:
    return Litestar(route_handlers=list(handlers), openapi_config=None)


def _http_findings(report: Any) -> list[RouteConflict]:
    """Filter out synthetic auto-OPTIONS declarations, leaving one finding per user declaration pair."""
    return [f for f in report if f.witness.method != "OPTIONS"]


def test_static_route_takes_priority_over_parameter() -> None:
    @get("/users/me")
    async def user_me() -> dict:
        return {}

    @get("/users/{user_id:str}")
    async def user_by_id(user_id: FromPath[str]) -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(user_me, user_by_id)))[0]
    assert finding.kind is ConflictKind.STATIC_PRIORITY
    assert not finding.blocks_startup
    assert finding.witness.path == "/users/me"
    assert finding.witness.resolved_handler == "user_me"
    app = _app(user_me, user_by_id)
    assert app.asgi_router.handle_routing(path="/users/someone", method="GET")[1].handler_name == "user_by_id"


def test_literal_outside_int_parameter_range_is_disjoint() -> None:
    @get("/users/{user_id:int}")
    async def user_int(user_id: FromPath[int]) -> dict:
        return {}

    @get("/users/archive")
    async def user_archive() -> dict:
        return {}

    assert _http_findings(check_route_conflicts(_app(user_int, user_archive))) == []


def test_path_normalization_is_respected() -> None:
    @get("/users/me/")
    async def user_me() -> dict:
        return {}

    @get("/users/{user_id:str}")
    async def user_by_id(user_id: FromPath[str]) -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(user_me, user_by_id)))[0]
    assert finding.kind is ConflictKind.STATIC_PRIORITY
    assert finding.witness.path == "/users/me"


def test_shared_literal_prefix_is_not_a_conflict() -> None:
    @get("/items/{item_id:int}")
    async def items(item_id: FromPath[int]) -> dict:
        return {}

    @get("/orders/{order_id:int}")
    async def orders(order_id: FromPath[int]) -> dict:
        return {}

    assert _http_findings(check_route_conflicts(_app(items, orders))) == []


def test_different_methods_do_not_conflict() -> None:
    @get("/things/{thing_id:int}")
    async def get_thing(thing_id: FromPath[int]) -> dict:
        return {}

    @post("/things/{thing_id:int}")
    async def create_thing(thing_id: FromPath[int]) -> dict:
        return {}

    assert _http_findings(check_route_conflicts(_app(get_thing, create_thing))) == []


def test_int_and_str_parameters_overlap_at_same_node() -> None:
    @get("/users/{user_id:int}")
    async def user_int(user_id: FromPath[int]) -> dict:
        return {}

    @get("/users/{user_id:str}")
    async def user_str(user_id: FromPath[str]) -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(user_int, user_str)))[0]
    assert finding.kind is ConflictKind.OVERLAPPING
    assert finding.witness.method == "GET"
    assert finding.witness.path == "/users/1"
    assert finding.witness.resolved_handler == "user_str"
    app = _app(user_int, user_str)
    assert app.asgi_router.handle_routing(path="/users/1", method="GET")[1].handler_name == "user_str"


def test_int_and_uuid_parameters_share_node_but_ranges_are_disjoint() -> None:
    @get("/users/{user_id:uuid}")
    async def user_uuid(user_id: FromPath[UUID]) -> dict:
        return {}

    @get("/users/{user_id:int}")
    async def user_int(user_id: FromPath[int]) -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(user_uuid, user_int)))[0]
    assert finding.kind is ConflictKind.OVERLAPPING
    assert finding.witness.path == "/users/00000000-0000-0000-0000-000000000001"
    assert finding.witness.resolved_handler is None


def test_path_parameter_greedily_shadows_parameter_route_below() -> None:
    @get("/{a:str}/{b:int}")
    async def nested(a: FromPath[str], b: FromPath[int]) -> dict:
        return {}

    @get("/{p:path}")
    async def catch_all(p: FromPath[str]) -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(nested, catch_all)))[0]
    assert finding.kind is ConflictKind.SHADOWED
    assert finding.witness.path == "/value/1"
    assert finding.witness.resolved_handler == "catch_all"


def test_literal_sibling_of_path_parameter_keeps_static_priority() -> None:
    @get("/files/{p:path}")
    async def files_path(p: FromPath[str]) -> dict:
        return {}

    @get("/files/download")
    async def files_download() -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(files_path, files_download)))[0]
    assert finding.kind is ConflictKind.STATIC_PRIORITY
    assert finding.witness.path == "/files/download"
    assert finding.witness.resolved_handler == "files_download"


def test_equivalent_templates_from_different_routers_are_shadowed() -> None:
    @get("/{value:int}")
    async def first(value: FromPath[int]) -> dict:
        return {}

    @get("/{other:int}")
    async def second(other: FromPath[int]) -> dict:
        return {}

    finding = _http_findings(
        check_route_conflicts(
            _app(Router(path="/x", route_handlers=[first]), Router(path="/x", route_handlers=[second]))
        )
    )[0]
    assert finding.kind is ConflictKind.SHADOWED
    assert finding.witness.path == "/x/1"
    assert finding.witness.resolved_handler == "second"


def test_unknown_converter_is_reported_as_unknown_not_guessed() -> None:
    @get("/reports/{day:date}")
    async def report_day(day: FromPath[date]) -> dict:
        return {}

    @get("/reports/{day:str}")
    async def report_any(day: FromPath[str]) -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(report_day, report_any)))[0]
    assert finding.kind is ConflictKind.UNKNOWN
    assert not finding.blocks_startup
    assert "custom converter" in finding.reason
    assert finding.witness.resolved_handler == "report_any"


def test_literal_against_unknown_converter_is_unknown() -> None:
    @get("/reports/{day:date}")
    async def report_day(day: FromPath[date]) -> dict:
        return {}

    @get("/reports/today")
    async def report_today() -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(report_day, report_today)))[0]
    assert finding.kind is ConflictKind.UNKNOWN
    assert finding.witness.resolved_handler == "report_today"


def test_mount_with_nested_static_handler_is_static_priority() -> None:
    @asgi("/mounted", is_mount=True)
    async def mounted_app(scope: Any, receive: Any, send: Any) -> None:
        return None

    @get("/mounted/items")
    async def mounted_items() -> dict:
        return {}

    finding = _http_findings(check_route_conflicts(_app(mounted_app, mounted_items)))[0]
    assert finding.kind is ConflictKind.STATIC_PRIORITY
    assert finding.witness.method == "GET"
    assert finding.witness.path == "/mounted/items"
    assert finding.witness.resolved_handler == "mounted_items"


def test_nested_mount_is_shadowed_by_outer_mount() -> None:
    @asgi("/a", is_mount=True)
    async def outer_mount(scope: Any, receive: Any, send: Any) -> None:
        return None

    @asgi("/a/b", is_mount=True)
    async def inner_mount(scope: Any, receive: Any, send: Any) -> None:
        return None

    finding = check_route_conflicts(_app(outer_mount, inner_mount)).findings[0]
    assert finding.kind is ConflictKind.SHADOWED
    assert finding.witness.path == "/a/b"
    assert finding.witness.resolved_handler == "outer_mount"


def test_http_and_websocket_same_path_do_not_conflict() -> None:
    @get("/shared")
    async def http_handler() -> dict:
        return {}

    @websocket("/shared")
    async def ws_handler(socket: WebSocket) -> None:
        return None

    assert _http_findings(check_route_conflicts(_app(http_handler, ws_handler))) == []


def test_witnesses_can_be_reverified_on_live_router() -> None:
    @get("/a/{x:int}")
    async def int_route(x: FromPath[int]) -> dict:
        return {}

    @get("/a/{x:str}")
    async def str_route(x: FromPath[str]) -> dict:
        return {}

    app = _app(int_route, str_route)
    report = check_route_conflicts(app)
    assert report.verify(app) == ()
    assert all(finding.reason for finding in report)


def test_strict_mode_blocks_startup_for_hard_conflicts() -> None:
    @get("/a/{x:int}")
    async def int_route(x: FromPath[int]) -> dict:
        return {}

    @get("/a/{x:str}")
    async def str_route(x: FromPath[str]) -> dict:
        return {}

    with pytest.raises(ImproperlyConfiguredException, match="Conflicting route declarations"):
        Litestar(route_handlers=[int_route, str_route], openapi_config=None, strict_route_conflicts=True)


def test_strict_mode_allows_unknown_and_static_priority() -> None:
    @get("/reports/{day:date}")
    async def report_day(day: FromPath[date]) -> dict:
        return {}

    @get("/reports/today")
    async def report_today() -> dict:
        return {}

    app = Litestar(route_handlers=[report_day, report_today], openapi_config=None, strict_route_conflicts=True)
    assert app.route_conflicts.unknown
    assert app.route_conflicts.is_clean
