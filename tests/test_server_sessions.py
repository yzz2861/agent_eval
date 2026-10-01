from __future__ import annotations

import asyncio
from datetime import datetime
from datetime import timedelta
from datetime import UTC
from http.cookies import SimpleCookie

import pytest
from werkzeug.wrappers import Response as WerkzeugResponse

from quart import Quart
from quart import session
from quart.server_sessions import ServerSideSession
from quart.server_sessions import ServerSideSessionError
from quart.server_sessions import ServerSideSessionInterface
from quart.server_sessions import ServerSideSessionStore
from quart.server_sessions import SessionConflictError
from quart.server_sessions import SessionNotFoundError
from quart.server_sessions import SqliteSessionStore
from quart.testing import QuartClient

COOKIE_NAME = "session"


class _TestSessionInterface(ServerSideSessionInterface):
    async def handle_commit_error(
        self,
        app: Quart,
        response: WerkzeugResponse,
        error: ServerSideSessionError,
    ) -> None:
        if isinstance(error, SessionConflictError):
            response.status_code = 409
            response.data = f"conflict: {','.join(error.conflicts)}"
        elif isinstance(error, SessionNotFoundError):
            response.status_code = 410
            response.data = "session gone"


def _cookie_value(response: WerkzeugResponse, name: str = COOKIE_NAME) -> str | None:
    header = response.headers.getlist("Set-Cookie")
    for value in header:
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(value)
        if name in cookie:
            morsel = cookie[name]
            if morsel.value == "":
                return None
            return morsel.value
    return None


def _shared_cookie(client: QuartClient, sid: str) -> None:
    client.set_cookie("localhost", COOKIE_NAME, sid)


@pytest.fixture()
async def app_store() -> tuple[Quart, ServerSideSessionStore]:
    store = SqliteSessionStore()
    app = Quart(__name__)
    app.secret_key = "secret"
    app.session_interface = _TestSessionInterface(store)
    app.config["SESSION_COOKIE_NAME"] = COOKIE_NAME

    @app.route("/init/")
    async def init_session():
        session["a"] = "init"
        session["b"] = 2
        return "ok"

    @app.route("/set-a/")
    async def set_a():
        session["a"] = "from-a"
        await app.config["barrier"].wait()
        return "ok"

    @app.route("/set-b/")
    async def set_b():
        session["b"] = 20
        await app.config["barrier"].wait()
        return "ok"

    @app.route("/set-a-too/")
    async def set_a_too():
        session["a"] = "other-value"
        await app.config["barrier"].wait()
        return "ok"

    @app.route("/read/")
    async def read_session():
        _ = session["a"]
        return "ok"

    @app.route("/clear-a/")
    async def clear_a():
        del session["a"]
        await app.config["barrier"].wait()
        return "ok"

    @app.route("/logout/")
    async def logout():
        session.clear()
        await app.config["barrier"].wait()
        return "ok"

    @app.route("/set-a-late/")
    async def set_a_late():
        session["a"] = "late-value"
        app.config["late_entered"].set()
        await app.config["allow_late"].wait()
        return "ok"

    @app.route("/add-c/")
    async def add_c():
        session["c"] = "new"
        await app.config["barrier"].wait()
        return "ok"

    @app.route("/login/")
    async def login():
        session.clear()
        session["user"] = "bob"
        session.rotate()
        return "ok"

    @app.route("/inspect/")
    async def inspect_session():
        return {
            "a": session.get("a"),
            "b": session.get("b"),
            "user": session.get("user"),
        }

    yield app, store
    await store.close()


async def test_concurrent_changes_to_different_fields_merge(app_store) -> None:
    app, store = app_store
    app.config["barrier"] = asyncio.Event()

    async with app.test_app() as test_app:
        client1 = test_app.test_client()
        client2 = test_app.test_client()

        init_response = await client1.get("/init/")
        sid = _cookie_value(init_response)
        assert sid is not None
        _shared_cookie(client2, sid)

        task1 = asyncio.ensure_future(client1.get("/set-a/"))
        task2 = asyncio.ensure_future(client2.get("/set-b/"))
        await asyncio.sleep(0.05)
        app.config["barrier"].set()
        response1, response2 = await asyncio.gather(task1, task2)

        assert response1.status_code == 200
        assert response2.status_code == 200

        stored = await store.load(sid)
        assert stored is not None
        assert stored.data == {"a": "from-a", "b": 20}
        assert stored.version == 3

        inspect = await client1.get("/inspect/")
        assert await inspect.get_json() == {
            "a": "from-a",
            "b": 20,
            "user": None,
        }


async def test_concurrent_changes_to_same_field_conflict(app_store) -> None:
    app, store = app_store
    app.config["barrier"] = asyncio.Event()

    async with app.test_app() as test_app:
        client1 = test_app.test_client()
        client2 = test_app.test_client()

        init_response = await client1.get("/init/")
        sid = _cookie_value(init_response)
        _shared_cookie(client2, sid)

        task1 = asyncio.ensure_future(client1.get("/set-a/"))
        task2 = asyncio.ensure_future(client2.get("/set-a-too/"))
        await asyncio.sleep(0.05)
        app.config["barrier"].set()
        response1, response2 = await asyncio.gather(task1, task2)

        statuses = sorted((response1.status_code, response2.status_code))
        assert statuses == [200, 409]

        failed = response2 if response2.status_code == 409 else response1
        assert b"a" in await failed.get_data()

        stored = await store.load(sid)
        assert stored is not None
        assert set(stored.data) == {"a", "b"}
        assert stored.data["b"] == 2
        assert stored.version == 2


async def test_unmodified_read_does_not_write(app_store) -> None:
    app, store = app_store
    app.config["barrier"] = asyncio.Event()

    async with app.test_app() as test_app:
        client = test_app.test_client()
        init_response = await client.get("/init/")
        sid = _cookie_value(init_response)

        stored = await store.load(sid)
        assert stored is not None
        version = stored.version

        read_response = await client.get("/read/")
        assert read_response.status_code == 200
        assert _cookie_value(read_response) is None

        stored = await store.load(sid)
        assert stored is not None
        assert stored.version == version
        assert stored.data == {"a": "init", "b": 2}


async def test_field_deletion_merges_with_other_change(app_store) -> None:
    app, store = app_store
    app.config["barrier"] = asyncio.Event()

    async with app.test_app() as test_app:
        client1 = test_app.test_client()
        client2 = test_app.test_client()

        init_response = await client1.get("/init/")
        sid = _cookie_value(init_response)
        _shared_cookie(client2, sid)

        task1 = asyncio.ensure_future(client1.get("/clear-a/"))
        task2 = asyncio.ensure_future(client2.get("/set-b/"))
        await asyncio.sleep(0.05)
        app.config["barrier"].set()
        response1, response2 = await asyncio.gather(task1, task2)
        assert response1.status_code == 200
        assert response2.status_code == 200

        stored = await store.load(sid)
        assert stored is not None
        assert stored.data == {"b": 20}


async def test_logout_conflicts_with_concurrent_independent_field(app_store) -> None:
    app, store = app_store
    app.config["barrier"] = asyncio.Event()

    async with app.test_app() as test_app:
        client1 = test_app.test_client()
        client2 = test_app.test_client()

        init_response = await client1.get("/init/")
        sid = _cookie_value(init_response)
        _shared_cookie(client2, sid)

        logout_task = asyncio.ensure_future(client1.get("/logout/"))
        add_task = asyncio.ensure_future(client2.get("/add-c/"))
        await asyncio.sleep(0.05)
        app.config["barrier"].set()
        responses = await asyncio.gather(logout_task, add_task)
        statuses = sorted(response.status_code for response in responses)
        assert statuses in ([200, 409], [200, 410])

        add_response = responses[1]
        stored = await store.load(sid)
        if add_response.status_code == 409:
            # The add committed first: the conflicting clear is rejected.
            assert stored is not None
            assert stored.data == {"a": "init", "b": 2, "c": "new"}
        else:
            # The clear committed first: the late add must not resurrect
            # the deleted row.
            assert stored is None


async def test_logout_before_late_request_does_not_resurrect(app_store) -> None:
    app, store = app_store
    barrier = asyncio.Event()
    barrier.set()
    app.config["barrier"] = barrier
    app.config["late_entered"] = asyncio.Event()
    app.config["allow_late"] = asyncio.Event()

    async with app.test_app() as test_app:
        client1 = test_app.test_client()
        client2 = test_app.test_client()

        init_response = await client1.get("/init/")
        sid = _cookie_value(init_response)
        _shared_cookie(client2, sid)

        # The late request opens the session, then blocks before returning.
        late_task = asyncio.ensure_future(client1.get("/set-a-late/"))
        await app.config["late_entered"].wait()

        # Logout completes and deletes the row while that request is in flight.
        logout_response = await client2.get("/logout/")
        assert logout_response.status_code == 200
        assert await store.load(sid) is None

        app.config["allow_late"].set()
        late_response = await late_task
        assert late_response.status_code == 410
        assert await store.load(sid) is None

        inspect = await client1.get("/inspect/")
        assert await inspect.get_json() == {
            "a": None,
            "b": None,
            "user": None,
        }


async def test_login_rotates_session_identifier(app_store) -> None:
    app, store = app_store
    app.config["barrier"] = asyncio.Event()

    async with app.test_app() as test_app:
        client = test_app.test_client()
        init_response = await client.get("/init/")
        old_sid = _cookie_value(init_response)

        login_response = await client.get("/login/")
        new_sid = _cookie_value(login_response)
        assert new_sid is not None
        assert new_sid != old_sid
        assert await store.load(old_sid) is None

        stored = await store.load(new_sid)
        assert stored is not None
        assert stored.data == {"user": "bob"}
        assert stored.version == 2


async def test_expired_session_is_not_resurrected() -> None:
    store = SqliteSessionStore()
    app = Quart(__name__)
    app.secret_key = "secret"
    app.session_interface = _TestSessionInterface(store)

    app.config["expired_entered"] = asyncio.Event()
    app.config["allow_expired_late"] = asyncio.Event()

    @app.route("/write/")
    async def write():
        session["x"] = 1
        return "ok"

    @app.route("/late-expired/")
    async def late_expired():
        session["x"] = 2
        app.config["expired_entered"].set()
        await app.config["allow_expired_late"].wait()
        return "ok"

    async with app.test_app() as test_app:
        client = test_app.test_client()
        response = await client.get("/write/")
        sid = _cookie_value(response)
        assert sid is not None

        late_task = asyncio.ensure_future(client.get("/late-expired/"))
        await app.config["expired_entered"].wait()

        # Expire the row while the late request is still in flight.
        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        store.connection.execute(
            "UPDATE quart_sessions SET expires_at = ? WHERE sid = ?",
            (past, sid),
        )
        store.connection.commit()

        app.config["allow_expired_late"].set()
        late_response = await late_task
        assert late_response.status_code == 410
        assert await store.load(sid) is None
        assert _cookie_value(late_response) is None
        count = store.connection.execute(
            "SELECT COUNT(*) FROM quart_sessions"
        ).fetchone()[0]
        assert count == 0
    await store.close()


async def test_open_session_without_cookie() -> None:
    store = SqliteSessionStore()
    interface = ServerSideSessionInterface(store)
    app = Quart(__name__)
    session_object = await interface.open_session(app, _RequestStub())
    assert isinstance(session_object, ServerSideSession)
    assert session_object.sid is None
    assert session_object.base_snapshot == {}
    await store.close()


class _RequestStub:
    cookies: dict[str, str] = {}
