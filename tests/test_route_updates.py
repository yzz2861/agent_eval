import asyncio
import gc
import json as stdlib_json
import re
import weakref

import pytest

from sanic_routing.patterns import ParamInfo

from sanic import Blueprint, Sanic
from sanic.exceptions import SanicException
from sanic.request import Request
from sanic.response import json, text


pytestmark = pytest.mark.asyncio


async def test_route_update_is_atomic(app: Sanic):
    @app.get("/old", name="old")
    async def old_handler(request):
        return text("old")

    app.router.finalize()
    app.finalize_middleware()
    router_before = app.router

    def invalid_builder(candidate):
        @candidate.get("/new")
        async def new_handler(request):
            return text("new")

        @candidate.get("/<__invalid__:str>")
        async def invalid_handler(request):
            return text("invalid")

    with pytest.raises(SanicException, match="Invalid route"):
        await app.update_routes(invalid_builder)

    assert app.router is router_before
    _, response = await app.asgi_client.get("/old")
    assert response.status_code == 200
    _, response = await app.asgi_client.get("/new")
    assert response.status_code == 404


async def test_route_update_replaces_blueprint_prefix_and_middleware(
    app: Sanic,
):
    bp_one = Blueprint("plugin", url_prefix="/plugin")

    @bp_one.get("/", name="root")
    async def root_one(request):
        return text("one")

    @bp_one.on_response
    async def version_one(request, response):
        response.headers["X-Version"] = "1"

    app.blueprint(bp_one)
    app.router.finalize()
    app.finalize_middleware()

    bp_two = Blueprint("plugin", url_prefix="/plugin")

    @bp_two.get("/", name="root")
    async def root_two(request):
        return text("two")

    @bp_two.on_response
    async def version_two(request, response):
        response.headers["X-Version"] = "2"

    await app.update_routes(bp_two)

    request, response = await app.asgi_client.get("/plugin")
    assert response.status_code == 200
    assert response.text == "two"
    assert response.headers["X-Version"] == "2"
    assert request.route.name == f"{app.name}.plugin.root"


async def test_route_update_applies_host_method_and_converter(app: Sanic):
    @app.get("/match", host="old.example", name="match")
    async def old_match(request):
        return text("old")

    app.router.finalize()
    app.finalize_middleware()

    def code_converter(value):
        if not re.fullmatch(r"[A-Z]{3}", value):
            raise ValueError(value)
        return value

    def builder(candidate):
        candidate.router.register_pattern(
            "code", code_converter, r"[A-Z]{3}", ParamInfo
        )

        @candidate.get("/match", host="new.example")
        async def host_match(request):
            return text("host")

        @candidate.post("/method")
        async def post_match(request):
            return text("post")

        @candidate.get("/codes/<code:code>", name="code")
        async def code_route(request, code):
            return json({"code": code})

    await app.update_routes(builder)

    _, response = await app.asgi_client.get(
        "/match", headers={"host": "new.example"}
    )
    assert (response.status_code, response.text) == (200, "host")
    _, response = await app.asgi_client.get(
        "/match", headers={"host": "old.example"}
    )
    assert response.status_code == 404
    _, response = await app.asgi_client.post("/method")
    assert (response.status_code, response.text) == (200, "post")
    _, response = await app.asgi_client.get("/codes/ABC")
    assert (response.status_code, response.json) == (200, {"code": "ABC"})
    _, response = await app.asgi_client.get("/codes/AB")
    assert response.status_code == 404


async def test_route_update_keeps_named_middleware_for_replaced_route(
    app: Sanic,
):
    @app.get("/one", name="one")
    async def one_handler(request):
        return text("one")

    async def add_custom_header(request, response):
        response.headers["X-Custom"] = "retained"

    app.register_named_middleware(
        add_custom_header,
        route_names=[f"{app.name}.one"],
        attach_to="response",
    )
    app.router.finalize()
    app.finalize_middleware()

    def builder(candidate):
        @candidate.get("/two", name="one")
        async def two_handler(request):
            return text("two")

    await app.update_routes(builder)
    _, response = await app.asgi_client.get("/two")
    assert response.status_code == 200
    assert response.text == "two"
    assert response.headers["X-Custom"] == "retained"


async def test_inflight_request_keeps_old_router(app: Sanic):
    entered = asyncio.Event()
    release = asyncio.Event()

    @app.get("/old", name="old")
    async def old_handler(request):
        entered.set()
        await release.wait()
        return json({"url": request.app.url_for("old")})

    app.router.finalize()
    app.finalize_middleware()
    old_router = app.router
    old_router_reference = weakref.ref(old_router)

    pinned_request = Request(b"/old", {}, "1.1", "GET", None, app)
    pinned_request._router = old_router
    request_ref = [pinned_request]

    async def run_old_request():
        current_token = Request._current.set(request_ref[0])
        try:
            return await old_handler(request_ref[0])
        finally:
            Request._current.reset(current_token)

    old_request_task = asyncio.create_task(run_old_request())
    await entered.wait()

    def builder(candidate):
        @candidate.get("/new", name="new")
        async def new_handler(request):
            return text("new")

    await app.update_routes(builder)
    assert app.router is not old_router
    assert app.url_for("new") == "/new"

    release.set()
    old_response = await old_request_task
    assert old_response.status == 200
    assert stdlib_json.loads(old_response.body)["url"].endswith("/old")

    _, new_response = await app.asgi_client.get("/new")
    assert new_response.text == "new"
    _, removed_response = await app.asgi_client.get("/old")
    assert removed_response.status_code == 404

    gc.collect()
    assert old_router_reference() is old_router
    del old_router
    del pinned_request
    request_ref.clear()
    del old_request_task
    gc.collect()
    gc.collect()
    assert old_router_reference() is None


async def test_route_updates_are_serialized(app: Sanic):
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    order = []

    async def first_builder(candidate):
        order.append(1)
        first_started.set()
        await release_first.wait()

        @candidate.get("/first")
        async def first_handler(request):
            return text("first")

    def second_builder(candidate):
        order.append(2)

        @candidate.get("/second")
        async def second_handler(request):
            return text("second")

    first_update = asyncio.create_task(app.update_routes(first_builder))
    await first_started.wait()
    second_update = asyncio.create_task(app.update_routes(second_builder))
    await asyncio.sleep(0)
    assert order == [1]

    release_first.set()
    await first_update
    await second_update

    assert order == [1, 2]
    _, response = await app.asgi_client.get("/second")
    assert response.status_code == 200


async def test_route_update_replaces_static_routes(app: Sanic, tmp_path):
    static_file = tmp_path / "plugin.txt"
    static_file.write_text("static")

    def builder(candidate):
        candidate.static(
            "/assets",
            tmp_path,
            name="plugin_assets",
        )

    await app.update_routes(builder)

    _, response = await app.asgi_client.get("/assets/plugin.txt")
    assert response.status_code == 200
    assert response.text == "static"
