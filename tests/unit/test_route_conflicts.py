from __future__ import annotations

import logging
from uuid import UUID

import pytest

from litestar import Litestar, WebSocket, get, post, websocket
from litestar.exceptions import ImproperlyConfiguredException
from litestar.handlers import asgi
from litestar.route_conflicts import ConflictKind, check_route_conflicts
from litestar.routes.base import param_type_map, parsers_map
from litestar.testing import TestClient
from litestar.types import Receive, Scope, Send


def test_static_route_priority_is_not_reported() -> None:
    @get("/users/me", sync_to_thread=False)
    def me() -> str:
        return "me"

    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    report = check_route_conflicts(Litestar([me, by_id], openapi_config=None))
    assert report.ok
    assert not report
    assert report.render().startswith("route conflict report: 0 conflict(s)")


def test_shadowed_parameter_routes() -> None:
    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    @get("/users/{name:str}", sync_to_thread=False)
    def by_name() -> str:
        return "name"

    app = Litestar([by_id, by_name], openapi_config=None)
    report = check_route_conflicts(app)

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.kind is ConflictKind.SHADOWED
    assert conflict.methods == ("GET",)
    assert conflict.declarations[0].path == "/users/{uid:int}"
    assert conflict.declarations[1].path == "/users/{name:str}"
    # the witness is accepted by both declarations and is routed to the later one
    assert conflict.witness_method == "GET"
    assert conflict.witness_path == "/users/1"
    assert conflict.resolved_to is not None
    assert conflict.resolved_to.handler_names == ("by_name",)

    with TestClient(app) as client:
        assert client.get("/users/1").text == "name"


def test_parameter_overlap_with_different_shapes() -> None:
    @get("/a/{x:str}", sync_to_thread=False)
    def a_x() -> str:
        return "a_x"

    @get("/{y:str}/b", sync_to_thread=False)
    def y_b() -> str:
        return "y_b"

    app = Litestar([a_x, y_b], openapi_config=None)
    report = check_route_conflicts(app)

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.kind is ConflictKind.PARAM_OVERLAP
    assert conflict.witness_method == "GET"
    assert conflict.witness_path == "/a/b"
    assert conflict.resolved_to is not None
    assert conflict.resolved_to.handler_names == ("a_x",)

    with TestClient(app) as client:
        assert client.get("/a/b").text == "a_x"
        assert client.get("/other/b").text == "y_b"


def test_int_and_uuid_ranges_overlap() -> None:
    @get("/{a:int}/edit", sync_to_thread=False)
    def int_edit() -> str:
        return "int"

    @get("/{b:uuid}/{c:str}", sync_to_thread=False)
    def uuid_any() -> str:
        return "uuid"

    report = check_route_conflicts(Litestar([int_edit, uuid_any], openapi_config=None))

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.kind is ConflictKind.PARAM_OVERLAP
    assert conflict.witness_path is not None
    first_segment = conflict.witness_path.split("/")[1]
    # the witness segment is accepted both as 'int' and as 'uuid'
    int(first_segment)
    UUID(first_segment)


def test_path_parameter_overlap() -> None:
    @get("/{p:path}", sync_to_thread=False)
    def catch_all() -> str:
        return "path"

    @get("/files/{name:str}", sync_to_thread=False)
    def files() -> str:
        return "files"

    report = check_route_conflicts(Litestar([catch_all, files], openapi_config=None))

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.kind is ConflictKind.PARAM_OVERLAP
    assert conflict.witness_path is not None
    assert conflict.witness_path.startswith("/files/")


def test_disjoint_methods_are_not_reported() -> None:
    @get("/a/{x:int}", sync_to_thread=False)
    def get_a() -> str:
        return "get"

    @post("/a/{y:str}", sync_to_thread=False)
    def post_a() -> str:
        return "post"

    report = check_route_conflicts(Litestar([get_a, post_a], openapi_config=None))
    assert report.ok


def test_only_shared_methods_are_reported() -> None:
    @get("/a/{x:int}", sync_to_thread=False)
    def get_a() -> str:
        return "get"

    @post("/a/{x:int}", sync_to_thread=False)
    def post_a() -> str:
        return "post_a"

    @post("/a/{y:str}", sync_to_thread=False)
    def post_b() -> str:
        return "post_b"

    report = check_route_conflicts(Litestar([get_a, post_a, post_b], openapi_config=None))

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.methods == ("POST",)
    assert conflict.witness_method == "POST"


def test_unknown_for_non_analyzable_converters(monkeypatch: pytest.MonkeyPatch) -> None:
    class Slug(str):
        pass

    monkeypatch.setitem(param_type_map, "slug", Slug)
    monkeypatch.setitem(parsers_map, Slug, Slug)

    @get("/{p:path}", sync_to_thread=False)
    def catch_all() -> str:
        return "path"

    @get("/a/{s:slug}", sync_to_thread=False)
    def a_slug() -> str:
        return "slug"

    # strict mode must not prevent startup for undecidable pairs
    app = Litestar([catch_all, a_slug], openapi_config=None, route_conflict_check="strict")
    report = check_route_conflicts(app)

    assert report.ok
    assert len(report.unknowns) == 1
    unknown = report.unknowns[0]
    assert unknown.kind is ConflictKind.UNKNOWN
    assert "Slug" in unknown.reason


def test_float_converter_is_treated_as_unknown() -> None:
    @get("/{p:path}", sync_to_thread=False)
    def catch_all() -> str:
        return "path"

    @get("/a/{x:float}", sync_to_thread=False)
    def a_float() -> str:
        return "float"

    report = check_route_conflicts(Litestar([catch_all, a_float], openapi_config=None))

    assert report.ok
    assert len(report.unknowns) == 1
    assert report.unknowns[0].kind is ConflictKind.UNKNOWN


def test_shadowing_is_certain_even_for_unknown_converters(monkeypatch: pytest.MonkeyPatch) -> None:
    class Slug(str):
        pass

    monkeypatch.setitem(param_type_map, "slug", Slug)
    monkeypatch.setitem(parsers_map, Slug, Slug)

    @get("/a/{x:slug}", sync_to_thread=False)
    def a_x() -> str:
        return "x"

    @get("/a/{y:slug}", sync_to_thread=False)
    def a_y() -> str:
        return "y"

    report = check_route_conflicts(Litestar([a_x, a_y], openapi_config=None))

    assert len(report.conflicts) == 1
    assert report.conflicts[0].kind is ConflictKind.SHADOWED


def test_mount_routes_do_not_conflict_with_handlers_below() -> None:
    @asgi("/static", is_mount=True)
    async def static_app(scope: Scope, receive: Receive, send: Send) -> None:
        pass

    @asgi("/static/admin", is_mount=True)
    async def admin_app(scope: Scope, receive: Receive, send: Send) -> None:
        pass

    @get("/{name:str}", sync_to_thread=False)
    def name() -> str:
        return "name"

    report = check_route_conflicts(Litestar([static_app, admin_app, name], openapi_config=None))
    assert report.ok


def test_duplicate_mount_paths_are_shadowed() -> None:
    @asgi("/static", is_mount=True)
    async def static_one(scope: Scope, receive: Receive, send: Send) -> None:
        pass

    @asgi("/static", is_mount=True)
    async def static_two(scope: Scope, receive: Receive, send: Send) -> None:
        pass

    report = check_route_conflicts(Litestar([static_one, static_two], openapi_config=None))

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.kind is ConflictKind.SHADOWED
    assert conflict.declarations[0].is_mount
    assert conflict.resolved_to is not None
    assert conflict.resolved_to.handler_names == ("static_two",)


def test_duplicate_websocket_paths_are_shadowed() -> None:
    @websocket("/ws")
    async def ws_one(socket: WebSocket) -> None:
        pass

    @websocket("/ws")
    async def ws_two(socket: WebSocket) -> None:
        pass

    report = check_route_conflicts(Litestar([ws_one, ws_two], openapi_config=None))

    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert conflict.kind is ConflictKind.SHADOWED
    assert conflict.methods == ("websocket",)
    assert conflict.witness_path == "/ws"


def test_overlap_preempted_by_static_route_is_unknown() -> None:
    @get("/a/b", sync_to_thread=False)
    def static_ab() -> str:
        return "static"

    @get("/a/{x:str}", sync_to_thread=False)
    def a_x() -> str:
        return "a_x"

    @get("/{y:str}/b", sync_to_thread=False)
    def y_b() -> str:
        return "y_b"

    report = check_route_conflicts(Litestar([static_ab, a_x, y_b], openapi_config=None))

    # the only path shared by the two parameterized routes is claimed by the static route
    assert report.ok
    assert len(report.unknowns) == 1
    assert report.unknowns[0].kind is ConflictKind.UNKNOWN


def test_strict_mode_prevents_startup() -> None:
    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    @get("/users/{name:str}", sync_to_thread=False)
    def by_name() -> str:
        return "name"

    with pytest.raises(ImproperlyConfiguredException, match="shadowed"):
        Litestar([by_id, by_name], openapi_config=None, route_conflict_check="strict")


def test_warn_mode_logs_and_continues(caplog: pytest.LogCaptureFixture) -> None:
    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    @get("/users/{name:str}", sync_to_thread=False)
    def by_name() -> str:
        return "name"

    with caplog.at_level(logging.WARNING, logger="litestar.route_conflicts"):
        app = Litestar([by_id, by_name], openapi_config=None, route_conflict_check="warn")

    assert app.route_conflict_report is not None
    assert not app.route_conflict_report.ok
    assert any("shadowed" in record.message for record in caplog.records)


def test_check_is_off_by_default() -> None:
    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    @get("/users/{name:str}", sync_to_thread=False)
    def by_name() -> str:
        return "name"

    app = Litestar([by_id, by_name], openapi_config=None)
    assert app.route_conflict_report is None


def test_app_check_route_conflicts_method() -> None:
    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    @get("/users/{name:str}", sync_to_thread=False)
    def by_name() -> str:
        return "name"

    app = Litestar([by_id, by_name], openapi_config=None)

    report = app.check_route_conflicts()
    assert not report.ok
    with pytest.raises(ImproperlyConfiguredException):
        app.check_route_conflicts(strict=True)


def test_conflict_render_includes_declarations_reason_and_witness() -> None:
    @get("/users/{uid:int}", sync_to_thread=False)
    def by_id() -> str:
        return "id"

    @get("/users/{name:str}", sync_to_thread=False)
    def by_name() -> str:
        return "name"

    report = check_route_conflicts(Litestar([by_id, by_name], openapi_config=None))
    rendered = report.render()

    assert "/users/{uid:int}" in rendered
    assert "/users/{name:str}" in rendered
    assert "reason:" in rendered
    assert "witness: GET /users/1" in rendered
