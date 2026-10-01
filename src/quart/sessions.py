from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import UTC
import secrets
from typing import TYPE_CHECKING
from typing import Any
from typing import Protocol

from flask.sessions import NullSession as NullSession  # noqa: F401
from flask.sessions import SecureCookieSession as SecureCookieSession  # noqa: F401
from flask.sessions import (  # noqa: F401
    session_json_serializer as session_json_serializer,
)
from flask.sessions import SessionMixin as SessionMixin  # noqa: F401
from itsdangerous import BadSignature
from itsdangerous import URLSafeTimedSerializer
from werkzeug.wrappers import Response as WerkzeugResponse

from .wrappers import BaseRequestWebsocket
from .wrappers import Response

if TYPE_CHECKING:
    from .app import Quart  # noqa


class SessionConflict(Exception):
    """Raised when a session field was changed by a concurrent request."""

    def __init__(self, fields: set[str]) -> None:
        super().__init__(f"Concurrent session modifications to {sorted(fields)}")
        self.fields = fields


@dataclass(frozen=True, slots=True)
class SessionRecord:
    sid: str
    version: int
    data: dict[str, Any]
    field_versions: dict[str, int]


@dataclass(frozen=True, slots=True)
class SessionCommitResult:
    sid: str
    version: int
    deleted: bool = False


class SessionStore(Protocol):
    async def load(self, sid: str) -> SessionRecord | None: ...

    async def commit(
        self,
        sid: str | None,
        base_version: int | None,
        base_field_versions: Mapping[str, int],
        changes: Mapping[str, Any],
        deletions: set[str],
        *,
        expires: datetime | None,
        rotate: bool,
        delete: bool,
        sid_was_loaded: bool = False,
    ) -> SessionCommitResult: ...


class ServerSideSession(SecureCookieSession):
    """A session snapshot with optimistic-concurrency metadata."""

    def __init__(
        self,
        data: Mapping[str, Any] | None = None,
        *,
        sid: str | None = None,
        version: int | None = None,
        field_versions: Mapping[str, int] | None = None,
        original: Mapping[str, Any] | None = None,
        store: SessionStore | None = None,
        loaded: bool = False,
    ) -> None:
        super().__init__(copy.deepcopy(dict(data or {})))
        self.sid = sid
        self.version = version
        self.field_versions = dict(field_versions or {})
        self.original = copy.deepcopy(
            dict(original if original is not None else data or {})
        )
        self.store = store
        self.loaded = loaded
        self.rotate_sid = False
        self.modified = False
        self.accessed = False

    def rotate(self) -> None:
        """Request a new opaque session identifier on save."""
        self.rotate_sid = True
        self.modified = True


class SessionInterface:
    """Base class for session interfaces.

    Attributes:
        null_session_class: Storage class for null (no storage)
            sessions.
        pickle_based: Indicates if pickling is used for the session.
    """

    null_session_class = NullSession
    pickle_based = False

    async def make_null_session(self, app: Quart) -> NullSession:
        """Create a Null session object.

        This is used in replacement of an actual session if sessions
        are not configured or active.
        """
        return self.null_session_class()

    def is_null_session(self, instance: object) -> bool:
        """Returns True is the instance is a null session."""
        return isinstance(instance, self.null_session_class)

    def get_cookie_name(self, app: Quart) -> str:
        """Helper method to return the Cookie Name for the App."""
        return app.config["SESSION_COOKIE_NAME"]

    def get_cookie_domain(self, app: Quart) -> str | None:
        """Helper method to return the Cookie Domain for the App."""
        rv = app.config["SESSION_COOKIE_DOMAIN"]
        return rv if rv else None

    def get_cookie_partitioned(self, app: Quart) -> bool:
        """Helper method to return the Cookie partitioned setting for the App."""
        return app.config["SESSION_COOKIE_PARTITIONED"]

    def get_cookie_path(self, app: Quart) -> str:
        """Helper method to return the Cookie path for the App."""
        return app.config["SESSION_COOKIE_PATH"] or app.config["APPLICATION_ROOT"]

    def get_cookie_httponly(self, app: Quart) -> bool:
        """Helper method to return if the Cookie should be HTTPOnly for the App."""
        return app.config["SESSION_COOKIE_HTTPONLY"]

    def get_cookie_secure(self, app: Quart) -> bool:
        """Helper method to return if the Cookie should be Secure for the App."""
        return app.config["SESSION_COOKIE_SECURE"]

    def get_cookie_samesite(self, app: Quart) -> str:
        """Helper method to return the Cookie Samesite configuration for the App."""
        return app.config["SESSION_COOKIE_SAMESITE"]

    def get_expiration_time(self, app: Quart, session: SessionMixin) -> datetime | None:
        """Helper method to return the Session expiration time.

        If the session is not 'permanent' it will expire as and when
        the browser stops accessing the app.
        """
        if session.permanent:
            return datetime.now(UTC) + app.permanent_session_lifetime
        else:
            return None

    def should_set_cookie(self, app: Quart, session: SessionMixin) -> bool:
        """Helper method to return if the Set Cookie header should be present.

        This triggers if the session is marked as modified or the app
        is configured to always refresh the cookie.
        """
        if session.modified:
            return True
        save_each = app.config["SESSION_REFRESH_EACH_REQUEST"]
        return save_each and session.permanent

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> SessionMixin | None:
        """Open an existing session from the request or create one.

        Returns:
            The Session object or None if no session can be created,
            in which case the :attr:`null_session_class` is expected
            to be used.
        """
        raise NotImplementedError()

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        """Save the session argument to the response.

        Arguments:
            response: Can be None if the session is being saved after
                a websocket connection closes.

        Returns:
            The modified response, with the session stored.

        """
        raise NotImplementedError()


class SecureCookieSessionInterface(SessionInterface):
    """A Session interface that uses cookies as storage.

    This will store the data on the cookie in plain text, but with a
    signature to prevent modification.
    """

    digest_method = staticmethod(hashlib.sha1)
    key_derivation = "hmac"
    salt = "cookie-session"
    serializer = session_json_serializer
    session_class = SecureCookieSession

    def get_signing_serializer(self, app: Quart) -> URLSafeTimedSerializer | None:
        """Return a serializer for the session that also signs data.

        This will return None if the app is not configured for secrets.
        """
        if not app.secret_key:
            return None

        keys: list[str | bytes] = []

        if fallbacks := app.config["SECRET_KEY_FALLBACKS"]:
            keys.extend(fallbacks)

        keys.append(app.secret_key)  # itsdangerous expects current key at top
        options = {
            "key_derivation": self.key_derivation,
            "digest_method": self.digest_method,
        }
        return URLSafeTimedSerializer(
            keys,  # type: ignore[arg-type]
            salt=self.salt,
            serializer=self.serializer,
            signer_kwargs=options,
        )

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> SecureCookieSession | None:
        """Open a secure cookie based session.

        This will return None if a signing serializer is not available,
        usually if the config SECRET_KEY is not set.
        """
        signer = self.get_signing_serializer(app)
        if signer is None:
            return None

        cookie = request.cookies.get(self.get_cookie_name(app))
        if cookie is None:
            return self.session_class()
        max_age = int(app.permanent_session_lifetime.total_seconds())
        try:
            data = signer.loads(cookie, max_age=max_age)
            return self.session_class(data)
        except BadSignature:
            return self.session_class()

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        """Saves the session to the response in a secure cookie."""
        if response is None:
            if session.modified:
                app.logger.exception(
                    "Secure Cookie Session modified during websocket handling. "
                    "These modifications will be lost as a cookie cannot be set."
                )
            return

        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        partitioned = self.get_cookie_partitioned(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        # Add a "Vary: Cookie" header if the session was accessed at all.
        if session.accessed:
            response.vary.add("Cookie")

        # If the session is modified to be empty, remove the cookie.
        # If the session is empty, return without setting the cookie.
        if not session:
            if session.modified:
                response.delete_cookie(
                    name,
                    domain=domain,
                    partitioned=partitioned,
                    path=path,
                    secure=secure,
                    samesite=samesite,
                    httponly=httponly,
                )
                response.vary.add("Cookie")

            return

        if not self.should_set_cookie(app, session):
            return

        expires = self.get_expiration_time(app, session)
        val = self.get_signing_serializer(app).dumps(dict(session))
        response.set_cookie(
            name,
            val,
            expires=expires,
            httponly=httponly,
            domain=domain,
            partitioned=partitioned,
            path=path,
            secure=secure,
            samesite=samesite,
        )
        response.vary.add("Cookie")


class ServerSideSessionInterface(SessionInterface):
    """Store session data server side and put only an ID in the cookie."""

    session_class = ServerSideSession

    def __init__(self, store: SessionStore) -> None:
        self.store = store

    def new_session(self) -> ServerSideSession:
        return self.session_class(store=self.store)

    def _get_expiration_datetime(
        self, app: Quart, session: SessionMixin
    ) -> datetime:
        lifetime = app.permanent_session_lifetime
        if not isinstance(lifetime, timedelta):
            lifetime = timedelta(seconds=lifetime)
        return datetime.now(UTC) + lifetime

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> ServerSideSession:
        cookie = request.cookies.get(self.get_cookie_name(app))
        if cookie is None:
            return self.new_session()

        record = await self.store.load(cookie)
        if record is None:
            return self.new_session()

        return self.session_class(
            record.data,
            sid=record.sid,
            version=record.version,
            field_versions=record.field_versions,
            original=record.data,
            store=self.store,
            loaded=True,
        )

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        if not isinstance(session, self.session_class):
            raise TypeError("ServerSideSessionInterface requires a ServerSideSession")

        if response is None:
            return

        name = self.get_cookie_name(app)
        if session.accessed:
            response.vary.add("Cookie")

        changes: dict[str, Any] = {}
        for key, value in session.items():
            if key not in session.original or session.original[key] != value:
                changes[key] = copy.deepcopy(value)
        deletions = {
            key
            for key in session.original
            if key not in session
        }

        if not changes and not deletions and not session.rotate_sid:
            return

        delete = not session
        expires = self._get_expiration_datetime(app, session)
        try:
            result = await self.store.commit(
                session.sid,
                session.version,
                session.field_versions,
                changes,
                deletions,
                expires=expires,
                rotate=session.rotate_sid,
                delete=delete,
                sid_was_loaded=session.loaded,
            )
        except SessionConflict:
            response.status_code = 409
            return

        if result.deleted:
            response.delete_cookie(
                name,
                domain=self.get_cookie_domain(app),
                partitioned=self.get_cookie_partitioned(app),
                path=self.get_cookie_path(app),
                secure=self.get_cookie_secure(app),
                samesite=self.get_cookie_samesite(app),
                httponly=self.get_cookie_httponly(app),
            )
            return

        response.set_cookie(
            name,
            result.sid,
            expires=self.get_expiration_time(app, session),
            httponly=self.get_cookie_httponly(app),
            domain=self.get_cookie_domain(app),
            partitioned=self.get_cookie_partitioned(app),
            path=self.get_cookie_path(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
        )


class SQLiteSessionStore:
    """A SQLite reference implementation of the server-side session store."""

    def __init__(self, path: str | os.PathLike[str] = "sessions.db") -> None:
        self._path = os.fspath(path)
        self._connection = sqlite3.connect(
            self._path, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = asyncio.Lock()
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    sid TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    field_versions TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

    async def load(self, sid: str) -> SessionRecord | None:
        async with self._lock:
            return await asyncio.to_thread(self._load, sid)

    async def commit(
        self,
        sid: str | None,
        base_version: int | None,
        base_field_versions: Mapping[str, int],
        changes: Mapping[str, Any],
        deletions: set[str],
        *,
        expires: datetime | None,
        rotate: bool,
        delete: bool,
        sid_was_loaded: bool = False,
    ) -> SessionCommitResult:
        async with self._lock:
            return await asyncio.to_thread(
                self._commit,
                sid,
                base_version,
                dict(base_field_versions),
                dict(changes),
                set(deletions),
                expires,
                rotate,
                delete,
                sid_was_loaded,
            )

    def close(self) -> None:
        self._connection.close()

    async def __aenter__(self) -> SQLiteSessionStore:
        return self

    async def __aexit__(self, *args: object) -> None:
        self.close()

    def _load(self, sid: str) -> SessionRecord | None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT sid, version, data, field_versions, expires_at "
                "FROM sessions WHERE sid = ?",
                (sid,),
            ).fetchone()
            if row is None:
                pass
            elif self._parse_datetime(row["expires_at"]) <= datetime.now(UTC):
                self._connection.execute(
                    "DELETE FROM sessions WHERE sid = ?", (sid,)
                )
                row = None
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

        if row is None:
            return None
        return SessionRecord(
            sid=row["sid"],
            version=row["version"],
            data=session_json_serializer.loads(row["data"]),
            field_versions=json.loads(row["field_versions"]),
        )

    def _commit(
        self,
        sid: str | None,
        base_version: int | None,
        base_field_versions: dict[str, int],
        changes: dict[str, Any],
        deletions: set[str],
        expires: datetime | None,
        rotate: bool,
        delete: bool,
        sid_was_loaded: bool = False,
    ) -> SessionCommitResult:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = None
            if sid is not None:
                row = self._connection.execute(
                    "SELECT sid, version, data, field_versions, expires_at "
                    "FROM sessions WHERE sid = ?",
                    (sid,),
                ).fetchone()
                if row is not None and self._parse_datetime(
                    row["expires_at"]
                ) <= datetime.now(UTC):
                    self._connection.execute(
                        "DELETE FROM sessions WHERE sid = ?", (sid,)
                    )
                    row = None

            if row is None:
                result = self._commit_missing(
                    sid,
                    base_version,
                    changes,
                    deletions,
                    expires,
                    delete,
                    sid_was_loaded,
                )
            else:
                result = self._update_existing(
                    row,
                    sid,
                    base_version,
                    base_field_versions,
                    changes,
                    deletions,
                    expires,
                    rotate,
                )
            self._connection.execute("COMMIT")
            return result
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def _commit_missing(
        self,
        sid: str | None,
        base_version: int | None,
        changes: dict[str, Any],
        deletions: set[str],
        expires: datetime | None,
        delete: bool,
        sid_was_loaded: bool,
    ) -> SessionCommitResult:
        if sid_was_loaded and not delete:
            raise SessionConflict(set(changes) | deletions)
        if delete or not changes:
            return SessionCommitResult(sid or "", 0, True)
        if expires is None:
            raise ValueError("A non-empty session requires an expiration datetime")

        new_sid = secrets.token_urlsafe(32)
        version = 1
        field_versions = dict.fromkeys(changes, version)
        self._insert(new_sid, version, changes, field_versions, expires)
        return SessionCommitResult(new_sid, version)

    def _update_existing(
        self,
        row: sqlite3.Row,
        sid: str | None,
        base_version: int | None,
        base_field_versions: dict[str, int],
        changes: dict[str, Any],
        deletions: set[str],
        expires: datetime | None,
        rotate: bool,
    ) -> SessionCommitResult:
        current_field_versions: dict[str, int] = json.loads(row["field_versions"])
        conflicts = self._conflicts(
            base_field_versions,
            current_field_versions,
            set(changes) | deletions,
        )
        if row["version"] != base_version and not changes and not deletions and rotate:
            conflicts = set(current_field_versions)
        if conflicts:
            raise SessionConflict(conflicts)
        if expires is None:
            raise ValueError("A non-empty session requires an expiration datetime")

        data = session_json_serializer.loads(row["data"])
        data.update(changes)
        for key in deletions:
            data.pop(key, None)

        if not data:
            self._connection.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
            return SessionCommitResult(sid or "", row["version"] + 1, True)

        new_version = row["version"] + 1
        field_versions = current_field_versions
        field_versions.update(dict.fromkeys(changes, new_version))
        for key in deletions:
            field_versions.pop(key, None)

        new_sid = secrets.token_urlsafe(32) if rotate else sid
        if rotate:
            self._connection.execute("DELETE FROM sessions WHERE sid = ?", (sid,))
            self._insert(new_sid, new_version, data, field_versions, expires)
        else:
            self._update(sid, new_version, data, field_versions, expires)
        return SessionCommitResult(new_sid, new_version)

    @staticmethod
    def _conflicts(
        base_field_versions: Mapping[str, int],
        current_field_versions: Mapping[str, int],
        fields: set[str] | None = None,
    ) -> set[str]:
        keys = fields if fields is not None else set(base_field_versions) | set(
            current_field_versions
        )
        return {
            key
            for key in keys
            if base_field_versions.get(key, 0) != current_field_versions.get(key, 0)
        }

    def _insert(
        self,
        sid: str | None,
        version: int,
        data: Mapping[str, Any],
        field_versions: Mapping[str, int],
        expires: datetime,
    ) -> None:
        self._connection.execute(
            "INSERT INTO sessions (sid, version, data, field_versions, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                sid,
                version,
                session_json_serializer.dumps(dict(data)),
                json.dumps(dict(field_versions), separators=(",", ":")),
                expires.astimezone(UTC).isoformat(),
            ),
        )

    def _update(
        self,
        sid: str | None,
        version: int,
        data: Mapping[str, Any],
        field_versions: Mapping[str, int],
        expires: datetime,
    ) -> None:
        self._connection.execute(
            "UPDATE sessions SET version = ?, data = ?, field_versions = ?, "
            "expires_at = ? WHERE sid = ?",
            (
                version,
                session_json_serializer.dumps(dict(data)),
                json.dumps(dict(field_versions), separators=(",", ":")),
                expires.astimezone(UTC).isoformat(),
                sid,
            ),
        )

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
