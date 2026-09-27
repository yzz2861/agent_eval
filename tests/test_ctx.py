from __future__ import annotations

import asyncio
import gc
import weakref
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
from quart.ctx import snapshot_current_request_context
from quart.globals import current_app
from quart.globals import g
from quart.globals import request
from quart.globals import session
from quart.globals import websocket
from quart.routing import QuartRule
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


async def test_snapshot_current_request_context() -> None:
    app = Quart(__name__)
    snapshots = []

    @app.route("/")
    async def index() -> str:
        g.user = "alice"
        g.state = {"count": 1}
        snapshots.append(
            snapshot_current_request_context(
                request_fields=("method", "path"), g_fields=("user", "state")
            )
        )
        g.state["count"] = 2  # Must not affect the snapshot
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200

    snapshot = snapshots[0]
    async with snapshot:
        assert request.method == "GET"
        assert request.path == "/"
        assert g.user == "alice"
        assert g.state == {"count": 1}
    assert has_request_context() is False


async def test_snapshot_current_request_context_defaults(
    http_scope: HTTPScope,
) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request_ = Request(
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
    async with AppContext(app, request=request_):
        snapshot = snapshot_current_request_context()

    async with snapshot:
        assert request.method == "GET"
        assert request.scheme == "http"
        assert request.path == "/"
        assert request.http_version == "1.1"
        assert list(request.headers) == list(headers)


def test_snapshot_current_request_context_error() -> None:
    with pytest.raises(RuntimeError):
        snapshot_current_request_context()


@pytest.mark.parametrize(
    "field",
    ["body", "data", "files", "form", "json", "stream", "values", "scope"],
)
async def test_snapshot_forbidden_request_fields(
    http_scope: HTTPScope, field: str
) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request_ = Request(
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
    async with AppContext(app, request=request_):
        with pytest.raises(ValueError, match=field):
            snapshot_current_request_context(request_fields=(field,))


async def test_snapshot_unknown_fields(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request_ = Request(
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
    async with AppContext(app, request=request_):
        with pytest.raises(ValueError, match="unknown"):
            snapshot_current_request_context(request_fields=("unknown",))
        with pytest.raises(ValueError, match="missing"):
            snapshot_current_request_context(g_fields=("missing",))


async def test_snapshot_uncopyable_g_field(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request_ = Request(
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
    async with AppContext(app, request=request_):
        g.generator = (item for item in range(3))
        with pytest.raises(ValueError, match="g.generator"):
            snapshot_current_request_context(g_fields=("generator",))


async def test_snapshot_is_read_only(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request_ = Request(
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
    async with AppContext(app, request=request_):
        g.value = 1
        snapshot = snapshot_current_request_context(
            request_fields=("path",), g_fields=("value",)
        )

    async with snapshot:
        with pytest.raises(AttributeError):
            request.path = "/other"  # type: ignore
        with pytest.raises(AttributeError):
            g.value = 2
        assert request.path == "/"
        assert g.value == 1


async def test_snapshot_has_no_session(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    headers, path, query_string = make_test_headers_path_and_query_string(app, "/")
    request_ = Request(
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
    async with AppContext(app, request=request_):
        snapshot = snapshot_current_request_context()

    async with snapshot:
        with pytest.raises(RuntimeError):
            session._get_current_object()


async def test_snapshot_nested_restores_outer(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    request_ = Request(
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
    async with AppContext(app, request=request_):
        g.value = "outer"
        snapshot = snapshot_current_request_context(
            request_fields=(), g_fields=("value",)
        )
        g.value = "changed"
        async with snapshot:
            assert g.value == "outer"
            assert has_request_context() is True
        assert g.value == "changed"
        assert request._get_current_object() is request_


async def test_snapshot_restores_on_cancellation(http_scope: HTTPScope) -> None:
    app = Quart(__name__)
    request_ = Request(
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
    async with AppContext(app, request=request_):
        g.value = "outer"
        snapshot = snapshot_current_request_context(
            request_fields=(), g_fields=("value",)
        )
        g.value = "changed"
        entered = asyncio.Event()

        async def audit() -> None:
            async with snapshot:
                assert g.value == "outer"
                entered.set()
                await asyncio.sleep(60)

        task = asyncio.ensure_future(audit())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert g.value == "changed"
        assert has_request_context() is True


async def test_snapshot_does_not_run_request_teardown() -> None:
    app = Quart(__name__)
    snapshots = []
    teardowns = []

    @app.teardown_request
    async def teardown(_: BaseException | None) -> None:
        teardowns.append(True)

    @app.route("/")
    async def index() -> str:
        snapshots.append(snapshot_current_request_context())
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200
    assert len(teardowns) == 1

    async with snapshots[0]:
        pass
    assert len(teardowns) == 1


async def test_snapshot_concurrent_requests() -> None:
    app = Quart(__name__)
    audits: list[tuple[str, str]] = []
    audit_tasks = []
    gate = asyncio.Event()

    @app.route("/<name>")
    async def index(name: str) -> str:
        g.name = name
        snapshot = snapshot_current_request_context(
            request_fields=("path",), g_fields=("name",)
        )

        async def audit() -> None:
            await gate.wait()  # Outlives the request
            async with snapshot:
                audits.append((request.path, g.name))

        audit_tasks.append(asyncio.ensure_future(audit()))
        await asyncio.sleep(0.01)  # Ensure the requests overlap
        return name

    test_client = app.test_client()
    responses = await asyncio.gather(test_client.get("/a"), test_client.get("/b"))
    assert {response.status_code for response in responses} == {200}
    gate.set()
    await asyncio.gather(*audit_tasks)
    assert sorted(audits) == [("/a", "a"), ("/b", "b")]


async def test_snapshot_does_not_keep_request_alive() -> None:
    app = Quart(__name__)
    snapshots = []
    requests = []

    @app.route("/")
    async def index() -> str:
        requests.append(weakref.ref(request._get_current_object()))
        snapshots.append(snapshot_current_request_context())
        return ""

    test_client = app.test_client()
    response = await test_client.get("/")
    assert response.status_code == 200
    gc.collect()
    assert requests[0]() is None
