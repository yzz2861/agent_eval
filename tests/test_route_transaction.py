import asyncio
import gc
import weakref

import pytest

from sanic import Blueprint
from sanic.exceptions import RouteUpdateError, URLBuildError
from sanic.request import Request
from sanic.response import text
from sanic.router import Router


def make_handler(content, name=None):
    async def handler(request):
        return text(content)

    if name:
        handler.__name__ = name
    return handler


@pytest.mark.asyncio
async def test_transaction_add_route(app):
    @app.get("/existing", name="existing")
    async def existing(request):
        return text("existing")

    _, response = await app.asgi_client.get("/existing")
    assert response.status == 200

    _, response = await app.asgi_client.get("/added")
    assert response.status == 404

    transaction = app.route_transaction()
    transaction.add(make_handler("added"), "/added", name="added")
    new_router = await transaction.commit()

    assert new_router is app.router
    assert isinstance(new_router, Router)

    _, response = await app.asgi_client.get("/added")
    assert response.status == 200
    assert response.text == "added"

    # Previously existing routes keep working
    _, response = await app.asgi_client.get("/existing")
    assert response.status == 200
    assert response.text == "existing"


@pytest.mark.asyncio
async def test_transaction_remove_route(app):
    @app.get("/keep", name="keep")
    async def keep(request):
        return text("keep")

    @app.get("/drop", name="drop")
    async def drop(request):
        return text("drop")

    _, response = await app.asgi_client.get("/drop")
    assert response.status == 200

    async with app.route_transaction() as transaction:
        transaction.remove("drop")

    _, response = await app.asgi_client.get("/drop")
    assert response.status == 404

    _, response = await app.asgi_client.get("/keep")
    assert response.status == 200


@pytest.mark.asyncio
async def test_transaction_replace_route(app):
    @app.get("/thing", name="thing")
    async def thing(request):
        return text("old")

    _, response = await app.asgi_client.get("/thing")
    assert response.text == "old"

    async with app.route_transaction() as transaction:
        transaction.replace(make_handler("new"), "/thing", name="thing")

    _, response = await app.asgi_client.get("/thing")
    assert response.status == 200
    assert response.text == "new"

    # The named URL still resolves, now against the replacement
    assert app.url_for("thing") == "/thing"


@pytest.mark.asyncio
async def test_transaction_replace_with_new_path(app):
    @app.get("/v1-widget", name="widget")
    async def widget(request):
        return text("widget")

    async with app.route_transaction() as transaction:
        transaction.replace(
            make_handler("widget-v2"), "/v2-widget", name="widget"
        )

    _, response = await app.asgi_client.get("/v1-widget")
    assert response.status == 404

    _, response = await app.asgi_client.get("/v2-widget")
    assert response.status == 200
    assert app.url_for("widget") == "/v2-widget"


@pytest.mark.asyncio
async def test_transaction_invalid_route_keeps_old_version(app):
    @app.get("/stable", name="stable")
    async def stable(request):
        return text("stable")

    old_router = app.router

    transaction = app.route_transaction()
    transaction.add(make_handler("ok"), "/ok", name="ok")
    # An invalid method makes the whole transaction fail
    transaction.add(make_handler("bad"), "/bad", methods=["BOGUS"], name="bad")

    with pytest.raises(Exception):
        await transaction.commit()

    # Old version is still active and fully functional
    assert app.router is old_router
    _, response = await app.asgi_client.get("/stable")
    assert response.status == 200
    assert response.text == "stable"

    # None of the staged routes leaked into the active version
    _, response = await app.asgi_client.get("/ok")
    assert response.status == 404
    _, response = await app.asgi_client.get("/bad")
    assert response.status == 404


@pytest.mark.asyncio
async def test_transaction_duplicate_name_keeps_old_version(app):
    @app.get("/one", name="dup")
    async def one(request):
        return text("one")

    old_router = app.router

    transaction = app.route_transaction()
    transaction.add(make_handler("two"), "/two", name="dup")

    with pytest.raises(Exception):
        await transaction.commit()

    assert app.router is old_router
    _, response = await app.asgi_client.get("/one")
    assert response.status == 200
    _, response = await app.asgi_client.get("/two")
    assert response.status == 404


@pytest.mark.asyncio
async def test_transaction_remove_missing_route_fails(app):
    @app.get("/here", name="here")
    async def here(request):
        return text("here")

    old_router = app.router

    transaction = app.route_transaction()
    transaction.remove("not_there")

    with pytest.raises(RouteUpdateError):
        await transaction.commit()

    assert app.router is old_router
    _, response = await app.asgi_client.get("/here")
    assert response.status == 200


@pytest.mark.asyncio
async def test_transaction_context_manager_discards_on_error(app):
    @app.get("/base", name="base")
    async def base(request):
        return text("base")

    old_router = app.router

    with pytest.raises(RuntimeError):
        async with app.route_transaction() as transaction:
            transaction.add(make_handler("nope"), "/nope", name="nope")
            raise RuntimeError("abort")

    assert app.router is old_router
    _, response = await app.asgi_client.get("/nope")
    assert response.status == 404


@pytest.mark.asyncio
async def test_transaction_cannot_be_reused(app):
    @app.get("/a", name="a")
    async def a(request):
        return text("a")

    transaction = app.route_transaction()
    transaction.add(make_handler("b"), "/b", name="b")
    await transaction.commit()

    with pytest.raises(RouteUpdateError):
        transaction.add(make_handler("c"), "/c", name="c")

    with pytest.raises(RouteUpdateError):
        await transaction.commit()

    discarded = app.route_transaction()
    discarded.discard()
    with pytest.raises(RouteUpdateError):
        await discarded.commit()


@pytest.mark.asyncio
async def test_inflight_request_keeps_old_router_version(app):
    started = asyncio.Event()
    resume = asyncio.Event()
    seen = {}

    @app.get("/old", name="old_endpoint")
    async def old(request):
        return text("old")

    @app.get("/slow", name="slow")
    async def slow(request):
        started.set()
        await resume.wait()
        # The swap has happened by now, but this request entered before
        # it, so it must still see the old version.
        seen["request_url_for"] = request.url_for("old_endpoint")
        seen["app_url_for"] = app.url_for("old_endpoint")
        return text("slow-done")

    request_task = asyncio.create_task(app.asgi_client.get("/slow"))
    await started.wait()

    async with app.route_transaction() as transaction:
        transaction.remove("old_endpoint")
        transaction.add(make_handler("new"), "/new", name="new_endpoint")

    resume.set()
    _, response = await request_task

    assert response.status == 200
    assert response.text == "slow-done"
    # url_for inside the in-flight request resolved against the old version
    assert seen["request_url_for"].endswith("/old")
    assert seen["app_url_for"].endswith("/old")

    # New requests only see the new version
    _, response = await app.asgi_client.get("/new")
    assert response.status == 200
    _, response = await app.asgi_client.get("/old")
    assert response.status == 404

    with pytest.raises(URLBuildError):
        app.url_for("old_endpoint")
    assert app.url_for("new_endpoint") == "/new"


@pytest.mark.asyncio
async def test_inflight_request_does_not_see_new_names(app):
    started = asyncio.Event()
    resume = asyncio.Event()
    seen = {}

    @app.get("/slow", name="slow")
    async def slow(request):
        started.set()
        await resume.wait()
        try:
            request.url_for("added_later")
            seen["error"] = None
        except URLBuildError:
            seen["error"] = "URLBuildError"
        return text("done")

    request_task = asyncio.create_task(app.asgi_client.get("/slow"))
    await started.wait()

    async with app.route_transaction() as transaction:
        transaction.add(make_handler("added"), "/added", name="added_later")

    resume.set()
    _, response = await request_task

    assert response.status == 200
    # The new route name did not leak into the in-flight request
    assert seen["error"] == "URLBuildError"

    _, response = await app.asgi_client.get("/added")
    assert response.status == 200


@pytest.mark.asyncio
async def test_transaction_preserves_hosts_methods_and_blueprints(app):
    blueprint = Blueprint("plugin", url_prefix="/plugin")

    @blueprint.get("/item/<item_id:int>", name="item")
    async def item(request, item_id):
        return text(f"item {item_id}")

    app.blueprint(blueprint)

    @app.route("/multi", methods=["GET", "POST"], name="multi")
    async def multi(request):
        return text(request.method)

    @app.get("/hosted", host="example.com", name="hosted")
    async def hosted(request):
        return text("hosted")

    _, response = await app.asgi_client.get("/plugin/item/3")
    assert response.text == "item 3"

    async with app.route_transaction() as transaction:
        transaction.add(make_handler("extra"), "/extra", name="extra")

    # Blueprint prefixed routes still resolve
    _, response = await app.asgi_client.get("/plugin/item/7")
    assert response.status == 200
    assert response.text == "item 7"
    assert app.url_for("plugin.item", item_id=7) == "/plugin/item/7"

    # Methods are preserved
    _, response = await app.asgi_client.post("/multi")
    assert response.status == 200
    assert response.text == "POST"

    # Host-bound routes still resolve with the right host
    _, response = await app.asgi_client.get(
        "/hosted", headers={"host": "example.com"}
    )
    assert response.status == 200
    assert response.text == "hosted"
    assert app.url_for("hosted", _external=True) == "http://example.com/hosted"

    # And the new route works too
    _, response = await app.asgi_client.get("/extra")
    assert response.status == 200


@pytest.mark.asyncio
async def test_transaction_add_with_host_and_methods(app):
    @app.get("/root", name="root")
    async def root(request):
        return text("root")

    async with app.route_transaction() as transaction:
        transaction.add(
            make_handler("hosted-new"),
            "/hosted-new",
            methods=["GET", "POST"],
            host="new.example.com",
            name="hosted_new",
        )

    _, response = await app.asgi_client.post(
        "/hosted-new", headers={"host": "new.example.com"}
    )
    assert response.status == 200
    assert response.text == "hosted-new"

    _, response = await app.asgi_client.get("/hosted-new")
    assert response.status == 404


@pytest.mark.asyncio
async def test_concurrent_transactions_are_serialized(app):
    @app.get("/start", name="start")
    async def start(request):
        return text("start")

    first = app.route_transaction()
    first.add(make_handler("one"), "/one", name="one")
    second = app.route_transaction()
    second.add(make_handler("two"), "/two", name="two")

    await asyncio.gather(first.commit(), second.commit())

    # Both transactions were applied, in order, on top of each other
    _, response = await app.asgi_client.get("/one")
    assert response.status == 200
    _, response = await app.asgi_client.get("/two")
    assert response.status == 200
    _, response = await app.asgi_client.get("/start")
    assert response.status == 200


@pytest.mark.asyncio
async def test_transaction_added_route_runs_middleware(app):
    @app.on_request
    async def mark(request):
        request.ctx.marked = True

    @app.get("/before", name="before")
    async def before(request):
        return text(str(getattr(request.ctx, "marked", False)))

    async def after_handler(request):
        return text(str(getattr(request.ctx, "marked", False)))

    async with app.route_transaction() as transaction:
        transaction.add(after_handler, "/after", name="after")

    _, response = await app.asgi_client.get("/after")
    assert response.status == 200
    assert response.text == "True"

    _, response = await app.asgi_client.get("/before")
    assert response.status == 200
    assert response.text == "True"


@pytest.mark.asyncio
async def test_transaction_preserves_static_routes(app, static_file_directory):
    app.static(
        "/static",
        static_file_directory,
        name="static_files",
    )

    _, response = await app.asgi_client.get("/static/test.file")
    assert response.status == 200

    async with app.route_transaction() as transaction:
        transaction.add(make_handler("extra"), "/extra", name="extra")

    _, response = await app.asgi_client.get("/static/test.file")
    assert response.status == 200

    url = app.url_for("static_files", filename="test.file")
    assert url == "/static/test.file"

    _, response = await app.asgi_client.get("/extra")
    assert response.status == 200


@pytest.mark.asyncio
async def test_superseded_router_version_can_be_reclaimed(app):
    @app.get("/recycle", name="recycle")
    async def recycle(request):
        return text("recycle")

    sanic_request, response = await app.asgi_client.get("/recycle")
    assert response.status == 200

    old_router = app.router
    reference = weakref.ref(old_router)

    async with app.route_transaction() as transaction:
        transaction.add(make_handler("next"), "/next", name="next")

    assert app.router is not old_router

    # Release the references the test harness keeps to the last request
    # (which is pinned to the superseded router version)
    app._asgi_app = None
    app.asgi_client.last_request = None
    Request._current.set(None)
    del old_router, response, sanic_request
    gc.collect()

    assert reference() is None
