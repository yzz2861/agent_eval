from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import datetime
from datetime import timedelta
from datetime import UTC
from http.cookies import SimpleCookie
from pathlib import Path

from hypercorn.typing import HTTPScope
import pytest
from werkzeug.datastructures import Headers

from quart.app import Quart
from quart.globals import session
from quart.sessions import SecureCookieSession
from quart.sessions import SecureCookieSessionInterface
from quart.sessions import ServerSideSessionInterface
from quart.sessions import SessionConflict
from quart.sessions import SQLiteSessionStore
from quart.testing import no_op_push
from quart.testing import QuartClient
from quart.wrappers import Request
from quart.wrappers import Response


async def test_secure_cookie_session_interface_open_session(
    http_scope: HTTPScope,
) -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    response = Response("")
    await interface.save_session(app, session, response)
    request = Request(
        "GET",
        "http",
        "/",
        b"",
        Headers(),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    request.headers["Cookie"] = response.headers["Set-Cookie"]
    new_session = await interface.open_session(app, request)
    assert new_session == session


async def test_secure_cookie_session_interface_save_session() -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    response = Response("")
    await interface.save_session(app, session, response)
    cookies: SimpleCookie = SimpleCookie()
    cookies.load(response.headers["Set-Cookie"])
    cookie = cookies[app.config["SESSION_COOKIE_NAME"]]
    assert cookie["path"] == interface.get_cookie_path(app)
    assert cookie["httponly"] == "" if not interface.get_cookie_httponly(app) else True
    assert cookie["secure"] == "" if not interface.get_cookie_secure(app) else True
    assert cookie["samesite"] == (interface.get_cookie_samesite(app) or "")
    assert cookie["domain"] == (interface.get_cookie_domain(app) or "")
    assert cookie["expires"] == (interface.get_expiration_time(app, session) or "")
    assert response.headers["Vary"] == "Cookie"


async def _save_session(session: SecureCookieSession) -> Response:
    interface = SecureCookieSessionInterface()
    app = Quart(__name__)
    app.secret_key = "secret"
    response = Response("")
    await interface.save_session(app, session, response)
    return response


async def test_secure_cookie_session_interface_save_session_no_modification() -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    session.modified = False
    response = await _save_session(session)
    assert response.headers.get("Set-Cookie") is None


async def test_secure_cookie_session_interface_save_session_no_access() -> None:
    session = SecureCookieSession()
    session["something"] = "else"
    session.accessed = False
    session.modified = False
    response = await _save_session(session)
    assert response.headers.get("Set-Cookie") is None
    assert response.headers.get("Vary") is None


@pytest.fixture(name="server_side_app")
async def _server_side_app(
    tmp_path: Path,
) -> AsyncGenerator[tuple[Quart, SQLiteSessionStore, str]]:
    database_path = tmp_path / "sessions.db"
    store = SQLiteSessionStore(database_path)
    app = Quart(__name__)
    app.session_interface = ServerSideSessionInterface(store)
    cookie_name = app.config["SESSION_COOKIE_NAME"]

    field_a_ready = asyncio.Event()
    field_b_ready = asyncio.Event()
    release_field_a = asyncio.Event()
    release_field_b = asyncio.Event()
    nested_a_ready = asyncio.Event()
    nested_b_ready = asyncio.Event()
    release_nested_a = asyncio.Event()
    release_nested_b = asyncio.Event()
    rotation_ready = asyncio.Event()
    rotation_field_ready = asyncio.Event()
    release_rotation = asyncio.Event()
    release_rotation_field = asyncio.Event()
    late_request_started = asyncio.Event()
    release_late_request = asyncio.Event()
    app.field_a_ready = field_a_ready
    app.field_b_ready = field_b_ready
    app.release_field_a = release_field_a
    app.release_field_b = release_field_b
    app.nested_a_ready = nested_a_ready
    app.nested_b_ready = nested_b_ready
    app.release_nested_a = release_nested_a
    app.release_nested_b = release_nested_b
    app.rotation_ready = rotation_ready
    app.rotation_field_ready = rotation_field_ready
    app.release_rotation = release_rotation
    app.release_rotation_field = release_rotation_field
    app.release_late_request = release_late_request

    @app.route("/a")
    async def change_a() -> str:
        session["a"] = "from-a"
        field_a_ready.set()
        await release_field_a.wait()
        return "a"

    @app.route("/b")
    async def change_b() -> str:
        session["b"] = "from-b"
        field_b_ready.set()
        await release_field_b.wait()
        return "b"

    @app.route("/nested-a")
    async def nested_a() -> str:
        session["document"]["a"] = "from-a"
        nested_a_ready.set()
        await release_nested_a.wait()
        return "nested-a"

    @app.route("/nested-b")
    async def nested_b() -> str:
        session["document"]["b"] = "from-b"
        nested_b_ready.set()
        await release_nested_b.wait()
        return "nested-b"

    @app.route("/rotate")
    async def rotate() -> str:
        session.rotate()
        rotation_ready.set()
        await release_rotation.wait()
        return "rotate"

    @app.route("/rotate-field")
    async def rotate_field() -> str:
        session["rotation_field"] = True
        rotation_field_ready.set()
        await release_rotation_field.wait()
        return "rotate-field"

    @app.route("/late")
    async def late() -> str:
        session["late"] = True
        late_request_started.set()
        await release_late_request.wait()
        return "late"

    @app.route("/logout", methods=["DELETE"])
    async def logout() -> str:
        session.clear()
        return "logout"

    @app.route("/read")
    async def read() -> str:
        return str(session.get("user"))

    try:
        yield app, store, cookie_name
    finally:
        store.close()


async def _seed_session(
    client: QuartClient, data: dict[str, object]
) -> None:
    async with client.session_transaction() as server_session:
        server_session.update(data)


def _cookie_value(client: QuartClient) -> str:
    return next(iter(client.cookie_jar)).value


async def test_server_side_session_merges_distinct_fields(
    server_side_app: tuple[Quart, SQLiteSessionStore, str],
) -> None:
    app, store, cookie_name = server_side_app
    seeder = app.test_client()
    await _seed_session(seeder, {"user": "bill", "a": "old", "b": "old"})
    sid = _cookie_value(seeder)

    client_one = app.test_client()
    client_two = app.test_client()
    client_one.set_cookie("localhost", cookie_name, sid)
    client_two.set_cookie("localhost", cookie_name, sid)

    request_one = asyncio.ensure_future(client_one.get("/a"))
    request_two = asyncio.ensure_future(client_two.get("/b"))
    await asyncio.gather(app.field_a_ready.wait(), app.field_b_ready.wait())
    app.release_field_a.set()
    response_one = await request_one
    app.release_field_b.set()
    response_two = await request_two

    assert response_one.status_code == 200
    assert response_two.status_code == 200
    record = await store.load(sid)
    assert record is not None
    assert record.data == {
        "user": "bill",
        "a": "from-a",
        "b": "from-b",
    }
    assert record.version == 3
    assert record.field_versions == {"user": 1, "a": 2, "b": 3}
    assert _cookie_value(client_one) == sid
    assert _cookie_value(client_two) == sid


async def test_server_side_session_conflicts_on_same_top_level_field(
    server_side_app: tuple[Quart, SQLiteSessionStore, str],
) -> None:
    app, store, cookie_name = server_side_app
    seeder = app.test_client()
    await _seed_session(seeder, {"document": {}})
    sid = _cookie_value(seeder)

    client_one = app.test_client()
    client_two = app.test_client()
    client_one.set_cookie("localhost", cookie_name, sid)
    client_two.set_cookie("localhost", cookie_name, sid)

    request_one = asyncio.ensure_future(client_one.get("/nested-a"))
    request_two = asyncio.ensure_future(client_two.get("/nested-b"))
    await asyncio.gather(app.nested_a_ready.wait(), app.nested_b_ready.wait())
    app.release_nested_a.set()
    response_one = await request_one
    app.release_nested_b.set()
    response_two = await request_two

    assert {response_one.status_code, response_two.status_code} == {200, 409}
    loser = (
        response_one
        if response_one.status_code == 409
        else response_two
    )
    assert loser.headers.get("Set-Cookie") is None
    record = await store.load(sid)
    assert record is not None
    assert record.field_versions == {"document": 2}


async def test_logout_before_late_request_returns_prevents_revival(
    server_side_app: tuple[Quart, SQLiteSessionStore, str],
) -> None:
    app, store, cookie_name = server_side_app
    seeder = app.test_client()
    await _seed_session(seeder, {"user": "bill"})
    sid = _cookie_value(seeder)

    client_one = app.test_client()
    client_two = app.test_client()
    client_one.set_cookie("localhost", cookie_name, sid)
    client_two.set_cookie("localhost", cookie_name, sid)

    late_request = asyncio.ensure_future(client_one.get("/late"))
    await asyncio.sleep(0)
    logout_response = await client_two.delete("/logout")
    assert logout_response.status_code == 200
    assert await store.load(sid) is None

    app.release_late_request.set()
    late_response = await late_request

    assert late_response.status_code == 409
    assert await store.load(sid) is None


async def test_rotation_uses_same_version_rules(
    server_side_app: tuple[Quart, SQLiteSessionStore, str],
) -> None:
    app, store, cookie_name = server_side_app
    seeder = app.test_client()
    await _seed_session(seeder, {"user": "bill"})
    old_sid = _cookie_value(seeder)

    client_one = app.test_client()
    client_two = app.test_client()
    client_one.set_cookie("localhost", cookie_name, old_sid)
    client_two.set_cookie("localhost", cookie_name, old_sid)

    rotation_request = asyncio.ensure_future(client_one.get("/rotate"))
    field_request = asyncio.ensure_future(client_two.get("/rotate-field"))
    await asyncio.gather(app.rotation_ready.wait(), app.rotation_field_ready.wait())
    app.release_rotation.set()
    rotation_response = await rotation_request
    app.release_rotation_field.set()
    field_response = await field_request

    assert {rotation_response.status_code, field_response.status_code} == {200, 409}
    assert await store.load(old_sid) is None
    rows = store._connection.execute("SELECT sid, version FROM sessions").fetchall()
    assert len(rows) == 1
    assert rows[0]["version"] == 2
    assert rows[0]["sid"] != old_sid


async def test_expired_session_and_unmodified_read_do_not_revive_or_refresh(
    server_side_app: tuple[Quart, SQLiteSessionStore, str],
) -> None:
    app, store, cookie_name = server_side_app
    result = await store.commit(
        None,
        None,
        {},
        {"user": "bill"},
        set(),
        expires=datetime.now(UTC) - timedelta(seconds=1),
        rotate=False,
        delete=False,
    )
    sid = result.sid

    client = app.test_client()
    client.set_cookie("localhost", cookie_name, sid)
    response = await client.get("/read")

    assert response.status_code == 200
    assert response.headers.get("Set-Cookie") is None
    assert await store.load(sid) is None


async def test_missing_loaded_sid_cannot_create_session(
    tmp_path: Path,
) -> None:
    store = SQLiteSessionStore(tmp_path / "sessions.db")
    try:
        with pytest.raises(SessionConflict):
            await store.commit(
                "stale-sid",
                1,
                {"user": "bill"},
                {"late": True},
                set(),
                expires=datetime.now(UTC) + timedelta(minutes=1),
                rotate=False,
                delete=False,
                sid_was_loaded=True,
            )

        rows = store._connection.execute("SELECT sid FROM sessions").fetchall()
        assert rows == []
    finally:
        store.close()


async def test_sqlite_store_merges_deletion_and_reports_conflict(
    tmp_path: Path,
) -> None:
    store = SQLiteSessionStore(tmp_path / "sessions.db")
    try:
        initial = await store.commit(
            None,
            None,
            {},
            {"a": 1, "b": 2},
            set(),
            expires=datetime.now(UTC) + timedelta(minutes=1),
            rotate=False,
            delete=False,
        )
        await store.commit(
            initial.sid,
            initial.version,
            {"a": 1, "b": 1},
            {"b": "winning-change"},
            set(),
            expires=datetime.now(UTC) + timedelta(minutes=1),
            rotate=False,
            delete=False,
        )
        with pytest.raises(SessionConflict):
            await store.commit(
                initial.sid,
                initial.version,
                {"a": 1, "b": 1},
                {"b": "changed-after-merge"},
                set(),
                expires=datetime.now(UTC) + timedelta(minutes=1),
                rotate=False,
                delete=False,
            )
        merged = await store.commit(
            initial.sid,
            2,
            {"a": 1, "b": 2},
            {},
            {"a"},
            expires=datetime.now(UTC) + timedelta(minutes=1),
            rotate=False,
            delete=False,
        )

        record = await store.load(initial.sid)
        assert record is not None
        assert record.data == {"b": "winning-change"}
        assert record.version == merged.version

        initial = await store.commit(
            None,
            None,
            {},
            {"a": 1, "b": 2, "c": 3},
            set(),
            expires=datetime.now(UTC) + timedelta(minutes=1),
            rotate=False,
            delete=False,
        )
        await store.commit(
            initial.sid,
            initial.version,
            {"a": 1, "b": 1, "c": 1},
            {"d": 4},
            set(),
            expires=datetime.now(UTC) + timedelta(minutes=1),
            rotate=False,
            delete=False,
        )
        logout = await store.commit(
            initial.sid,
            initial.version,
            {"a": 1, "b": 1, "c": 1},
            {},
            {"a", "b", "c"},
            expires=datetime.now(UTC) + timedelta(minutes=1),
            rotate=False,
            delete=True,
        )
        record = await store.load(initial.sid)
        assert record is not None
        assert record.data == {"d": 4}
        assert not logout.deleted
    finally:
        store.close()
