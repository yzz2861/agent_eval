from __future__ import annotations

import asyncio
from typing import cast
from unittest.mock import Mock

import pytest
from hypercorn.typing import HTTPScope
from werkzeug.datastructures import Headers
from werkzeug.exceptions import BadRequest

from quart.app import Quart
from quart.ctx import after_this_request
from quart.ctx import AppContext
from quart.ctx import copy_current_app_context
from quart.ctx import copy_current_request_context
from quart.ctx import copy_current_websocket_context
from quart.ctx import has_app_context
from quart.ctx import has_request_context
from quart.ctx import RequestContextSnapshot
from quart.ctx import snapshot_request_context
from quart.ctx import SnapshotCopyError
from quart.globals import _cv_app
from quart.globals import current_app
from quart.globals import g
from quart.globals import request
from quart.globals import session
from quart.globals import websocket
from quart.routing import QuartRule
from quart.sessions import SecureCookieSession
from quart.testing import make_test_headers_path_and_query_string
from quart.testing import no_op_push
from quart.wrappers import Request


async def test_request_context_match(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    url_adapter = Mock()
    rule = QuartRule("/", methods={"GET"}, endpoint="index")
    url_adapter.match.return_value = (rule, {"arg": "value"})
    app.create_url_adapter = lambda *_: url_adapter  # type: ignore
    request = Request(
        "GET",
        "http",
        "/",
        b"",
        Headers([("host", "quart.com")]),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    async with AppContext(app, request=request):
        assert request.url_rule == rule
        assert request.view_args == {"arg": "value"}


async def test_bad_request_if_websocket_route(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    url_adapter = Mock()
    url_adapter.match.side_effect = BadRequest()
    app.create_url_adapter = lambda *_: url_adapter  # type: ignore
    request = Request(
        "GET",
        "http",
        "/",
        b"",
        Headers([("host", "quart.com")]),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    async with AppContext(app, request=request):
        assert isinstance(request.routing_exception, BadRequest)


async def test_after_this_request(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    async with AppContext(
        Quart(__name__),
        request=Request(
            "GET",
            "http",
            path,
            query_string,
            headers,
            "",
            "1.1",
            http_scope,
            send_push_promise=no_op_push,
        ),
    ) as context:
        after_this_request(lambda: "hello")  # type: ignore
        assert context._after_request_functions[0]() == "hello"  # type: ignore


async def test_has_request_context(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request = Request(
        "GET",
        "http",
        path,
        query_string,
        headers,
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    async with AppContext(Quart(__name__), request=request):
        assert has_request_context() is True
        assert has_app_context() is True
    assert has_request_context() is False
    assert has_app_context() is False


async def test_has_app_context() -> None:
    async with AppContext(Quart(__name__)):
        assert has_app_context() is True
    assert has_app_context() is False


async def test_copy_current_app_context() -> None:
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        current_app.foo = "bar"  # type: ignore

        @copy_current_app_context
        async def within_context() -> None:
            assert current_app.foo == "bar"  # type: ignore

        await asyncio.ensure_future(within_context())
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200


def test_copy_current_app_context_error() -> None:
    with pytest.raises(RuntimeError):
        copy_current_app_context(lambda: None)()


async def test_copy_current_request_context() -> None:
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        @copy_current_request_context
        async def within_context() -> None:
            assert request.path == "/"

        await asyncio.ensure_future(within_context())
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200


def test_copy_current_request_context_error() -> None:
    with pytest.raises(RuntimeError):
        copy_current_request_context(lambda: None)()


async def test_works_without_copy_current_request_context() -> None:
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        async def within_context() -> None:
            assert request.path == "/"

        await asyncio.ensure_future(within_context())
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200


async def test_copy_current_websocket_context() -> None:
    app = Quart(__name__)

    @app.websocket("/")
    async def index() -> None:
        @copy_current_websocket_context
        async def within_context() -> str:
            return websocket.path

        data = await asyncio.ensure_future(within_context())
        await websocket.send(data.encode())

    test_client = app.test_client()
    async with test_client.websocket("/") as test_websocket:
        data = await test_websocket.receive()
    assert cast(bytes, data) == b"/"


def test_copy_current_websocket_context_error() -> None:
    with pytest.raises(RuntimeError):
        copy_current_websocket_context(lambda: None)()


async def test_snapshot_request_context() -> None:
    app = Quart(__name__)
    snapshots: list[RequestContextSnapshot] = []

    @app.route("/")
    async def index() -> str:
        g.user_id = 7
        g.other = "not-snapshotted"
        snapshots.append(
            snapshot_request_context(
                request_fields=["method", "path"], g_fields=["user_id"]
            )
        )
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200

    # The request has finished, the snapshot can be entered in a new task.
    async def audit() -> tuple[str, str, int]:
        async with snapshots[0]:
            assert has_request_context() is True
            assert has_app_context() is True
            assert current_app._get_current_object() is app
            return request.method, request.path, g.user_id

    assert await asyncio.ensure_future(audit()) == ("GET", "/", 7)
    assert has_request_context() is False
    assert has_app_context() is False


async def test_snapshot_request_context_fixed_at_creation() -> None:
    app = Quart(__name__)
    snapshots: list[RequestContextSnapshot] = []

    @app.route("/")
    async def index() -> str:
        g.items = [1, 2]
        snapshots.append(
            snapshot_request_context(request_fields=["method"], g_fields=["items"])
        )
        g.items.append(3)
        request.method = "POST"
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200

    async with snapshots[0]:
        assert request.method == "GET"
        assert g.items == [1, 2]


async def test_snapshot_request_context_uncopyable_field() -> None:
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        g.session_copy = SecureCookieSession()
        with pytest.raises(SnapshotCopyError, match="session_copy"):
            snapshot_request_context(g_fields=["session_copy"])

        with pytest.raises(SnapshotCopyError, match="body"):
            snapshot_request_context(request_fields=["body"])

        class Uncopyable:
            def __deepcopy__(self, memo: dict) -> Uncopyable:
                raise RuntimeError("cannot be copied")

        g.uncopyable = Uncopyable()
        with pytest.raises(SnapshotCopyError, match="uncopyable"):
            snapshot_request_context(g_fields=["uncopyable"])
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200


async def test_snapshot_request_context_missing_field() -> None:
    app = Quart(__name__)

    @app.route("/")
    async def index() -> str:
        with pytest.raises(AttributeError):
            snapshot_request_context(request_fields=["not_a_field"])
        with pytest.raises(AttributeError):
            snapshot_request_context(g_fields=["not_a_field"])
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200


async def test_snapshot_request_context_read_only() -> None:
    app = Quart(__name__)
    snapshot = RequestContextSnapshot(app, {"method": "GET"}, {"user_id": 1})

    async with snapshot:
        assert request.method == "GET"
        assert g.user_id == 1
        assert g.get("user_id") == 1
        assert "user_id" in g
        with pytest.raises(AttributeError):
            request.method = "POST"
        with pytest.raises(AttributeError):
            g.user_id = 2
        with pytest.raises(AttributeError):
            _ = request.path  # not included in the snapshot
        with pytest.raises(TypeError):
            g.pop("user_id")


async def test_snapshot_request_context_no_session() -> None:
    app = Quart(__name__)
    snapshot = RequestContextSnapshot(app, {}, {})

    async with snapshot:
        with pytest.raises(RuntimeError):
            session.get("key")


async def test_snapshot_request_context_no_teardown() -> None:
    app = Quart(__name__)
    teardowns = 0
    snapshots: list[RequestContextSnapshot] = []

    @app.teardown_request
    async def teardown(_: BaseException | None) -> None:
        nonlocal teardowns
        teardowns += 1

    @app.route("/")
    async def index() -> str:
        snapshots.append(snapshot_request_context(request_fields=["method"]))
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200
    assert teardowns == 1

    # Entering and exiting the snapshot must not run the request's
    # teardown functions again.
    async with snapshots[0]:
        pass
    assert teardowns == 1


async def test_snapshot_request_context_nested() -> None:
    app = Quart(__name__)
    first = RequestContextSnapshot(app, {"path": "/first"}, {"marker": "first"})
    second = RequestContextSnapshot(app, {"path": "/second"}, {"marker": "second"})

    async with AppContext(app) as outer:
        async with first:
            assert request.path == "/first"
            async with second:
                assert request.path == "/second"
                assert g.marker == "second"
            assert request.path == "/first"
            assert g.marker == "first"
        assert _cv_app.get() is outer
    assert not has_app_context()


async def test_snapshot_request_context_restored_on_cancel() -> None:
    app = Quart(__name__)
    snapshot = RequestContextSnapshot(app, {"path": "/"}, {})

    async with AppContext(app) as outer:
        task = asyncio.current_task()

        async def cancel() -> None:
            await asyncio.sleep(0.01)
            task.cancel()

        asyncio.ensure_future(cancel())
        with pytest.raises(asyncio.CancelledError):
            async with snapshot:
                await asyncio.sleep(10)
        assert _cv_app.get() is outer


async def test_snapshot_request_context_concurrent_requests(
    http_scope: HTTPScope,
) -> None:
    app = Quart(__name__)
    results: dict[str, tuple[str, str]] = {}

    async def handle(path: str, marker: str) -> None:
        headers, req_path, query_string = make_test_headers_path_and_query_string(
            app, path
        )
        req = Request(
            "GET",
            "http",
            req_path,
            query_string,
            headers,
            "",
            "1.1",
            http_scope,
            send_push_promise=no_op_push,
        )
        async with AppContext(app, request=req):
            g.marker = marker
            snapshot = snapshot_request_context(
                request_fields=["path"], g_fields=["marker"]
            )
            g.marker = f"{marker}-changed"
            await asyncio.sleep(0)
        # The request has finished, audit later via the snapshot.
        await asyncio.sleep(0)
        async with snapshot:
            results[marker] = (request.path, g.marker)

    await asyncio.gather(handle("/a", "one"), handle("/b", "two"))
    assert results == {"one": ("/a", "one"), "two": ("/b", "two")}


async def test_snapshot_request_context_copy() -> None:
    app = Quart(__name__)
    snapshot = RequestContextSnapshot(app, {"method": "GET"}, {"user_id": 1})

    async with snapshot.copy():
        assert request.method == "GET"
        assert g.user_id == 1


def test_snapshot_request_context_error() -> None:
    with pytest.raises(RuntimeError):
        snapshot_request_context(request_fields=["method"])


async def test_snapshot_request_context_app_context_only() -> None:
    async with AppContext(Quart(__name__)):
        with pytest.raises(RuntimeError):
            snapshot_request_context(request_fields=["method"])
