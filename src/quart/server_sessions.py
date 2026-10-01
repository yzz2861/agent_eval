from __future__ import annotations

import asyncio
import secrets
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from datetime import timedelta
from datetime import UTC
from typing import Any
from typing import TYPE_CHECKING

from flask.sessions import session_json_serializer
from werkzeug.wrappers import Response as WerkzeugResponse

from .sessions import SecureCookieSession
from .sessions import SessionInterface
from .sessions import SessionMixin
from .wrappers import BaseRequestWebsocket
from .wrappers import Response

if TYPE_CHECKING:
    from .app import Quart


DELETED_FIELDS = "__quart_deleted_fields__"
CLEAR_FIELDS = "__quart_clear_fields__"


class ServerSideSessionError(Exception):
    """Base class for server side session errors."""


class SessionNotFoundError(ServerSideSessionError):
    """Raised when a request commits against a session that no longer exists.

    This happens if the session expired or was deleted (for example by a
    logout) between the request opening and the request ending. The late
    request is not allowed to recreate the session.
    """


class SessionConflictError(ServerSideSessionError):
    """Raised when two concurrent requests change the same top level field.

    Attributes:
        sid: The opaque session identifier.
        version: The stored version the request expected.
        conflicts: The top level field names that changed concurrently.
    """

    def __init__(self, sid: str, version: int, conflicts: tuple[str, ...]) -> None:
        self.sid = sid
        self.version = version
        self.conflicts = conflicts
        names = ", ".join(conflicts)
        super().__init__(f"Conflicting concurrent changes to session field(s): {names}")


def _canonical(value: Any) -> Any:
    """Return a JSON round tripped representation of *value*.

    Values are compared via this representation so that semantically equal
    nested values do not produce spurious field changes. Nested values are
    otherwise treated as opaque: any difference inside a top level field
    counts as a change of that whole field.
    """
    return session_json_serializer.loads(session_json_serializer.dumps(value))


def field_changes(
    base: Mapping[str, Any], current: Mapping[str, Any]
) -> dict[str, Any]:
    """Return the top level field changes between *base* and *current*.

    A field present in *current* with a different value is stored with the
    new value. A field missing from *current* is recorded under
    :data:`DELETED_FIELDS`, so deletions (including a full
    ``session.clear()``) count as changes and are detected as conflicts.
    Nested values are compared as whole top level fields.
    """
    changes: dict[str, Any] = {}
    deleted: set[str] = set(base) - set(current)
    for key in set(current) - set(base):
        changes[key] = _canonical(current[key])
    for key in set(base) & set(current):
        if _canonical(base[key]) != _canonical(current[key]):
            changes[key] = _canonical(current[key])
    if deleted:
        changes[DELETED_FIELDS] = deleted
    if not current:
        # A full clear conflicts with any concurrent field level change,
        # including fields the clearer never knew about.
        changes[CLEAR_FIELDS] = True
    return changes


def apply_changes(data: dict[str, Any], changes: Mapping[str, Any]) -> None:
    """Apply *changes* (including field deletions) to *data* in place."""
    for key, value in changes.items():
        if key == DELETED_FIELDS:
            for deleted in value:
                data.pop(deleted, None)
        elif key == CLEAR_FIELDS:
            continue
        else:
            data[key] = value


class ServerSideSession(SecureCookieSession):
    """Session that stores its data server side.

    The cookie only carries an opaque identifier (:attr:`sid`). The session
    keeps a :attr:`base_snapshot` of the data read when the request opened,
    which is used to compute the field level changes at commit time.
    """

    def __init__(
        self,
        initial: Mapping[str, Any] | None = None,
        *,
        sid: str | None = None,
        version: int = 0,
        base_snapshot: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(initial)
        self.sid = sid
        self.version = version
        snapshot = base_snapshot if base_snapshot is not None else initial
        self.base_snapshot = _canonical(snapshot if snapshot is not None else {})
        self._rotate = False

    def rotate(self) -> None:
        """Mark the session for identifier rotation at commit time.

        Call this on login (privilege level change) so the session moves to
        a new opaque identifier under the same version rules.
        """
        self._rotate = True

    @property
    def rotation_requested(self) -> bool:
        """True if :meth:`rotate` was called during the request."""
        return self._rotate


class StoredSession:
    """A session row read from a store."""

    __slots__ = ("data", "version")

    def __init__(self, data: dict[str, Any], version: int) -> None:
        self.data = data
        self.version = version


class CommitResult:
    """The result of a successful versioned commit.

    :attr:`data` is None if the commit left the session empty and the row
    was deleted.
    """

    __slots__ = ("sid", "version", "data")

    def __init__(self, sid: str, version: int, data: dict[str, Any] | None) -> None:
        self.sid = sid
        self.version = version
        self.data = data


class ServerSideSessionStore:
    """Base class for server side session stores.

    Stores apply the same version rules to every operation: expiration,
    identifier rotation, empty session deletion and field level merge.
    """

    async def initialize(self) -> None:
        """Prepare the store (create tables, connections, ...)."""

    async def load(self, sid: str) -> StoredSession | None:
        """Return the stored session, or None if it is missing or expired."""
        raise NotImplementedError()

    async def create(
        self, data: Mapping[str, Any], expires_at: datetime | None
    ) -> CommitResult:
        """Create a brand new session under a new opaque identifier."""
        raise NotImplementedError()

    async def commit(
        self,
        sid: str,
        base_version: int,
        base_data: Mapping[str, Any],
        changes: Mapping[str, Any],
        expires_at: datetime | None,
    ) -> CommitResult:
        """Commit field changes against the read version.

        Different top level fields are merged. A change to a field that was
        already changed since *base_version* raises
        :class:`SessionConflictError`. A missing or expired session raises
        :class:`SessionNotFoundError`. If the merged session is empty the
        row is deleted and :attr:`CommitResult.data` is None.
        """
        raise NotImplementedError()

    async def rotate(
        self,
        sid: str,
        base_version: int,
        base_data: Mapping[str, Any],
        changes: Mapping[str, Any],
        expires_at: datetime | None,
    ) -> CommitResult:
        """Commit *changes* and move the row onto a new opaque identifier.

        The old row is deleted; an empty session is not recreated.
        """
        raise NotImplementedError()

    async def delete_expired(self) -> None:
        """Delete sessions that have expired."""

    async def close(self) -> None:
        """Release any resources held by the store."""


class ServerSideSessionInterface(SessionInterface):
    """A session interface storing data in a pluggable server side store.

    Only an opaque session identifier is carried in the cookie. At the end
    of a request the fields that changed since the session opened are
    committed against the version that was read. Concurrent requests that
    change different top level fields merge; changes to the same field
    raise :class:`SessionConflictError`.
    """

    session_class = ServerSideSession

    def __init__(self, store: ServerSideSessionStore) -> None:
        self.store = store

    def get_expiration_time(self, app: Quart, session: SessionMixin) -> datetime | None:
        if session.permanent:
            return datetime.now(UTC) + app.permanent_session_lifetime
        return None

    async def open_session(
        self, app: Quart, request: BaseRequestWebsocket
    ) -> ServerSideSession:
        sid = request.cookies.get(self.get_cookie_name(app))
        if sid is None:
            return self.session_class()
        stored = await self.store.load(sid)
        if stored is None:
            return self.session_class()
        return self.session_class(
            stored.data,
            sid=sid,
            version=stored.version,
            base_snapshot=stored.data,
        )

    async def save_session(
        self,
        app: Quart,
        session: SessionMixin,
        response: Response | WerkzeugResponse | None,
    ) -> None:
        if response is None:
            if isinstance(session, ServerSideSession) and (
                session.modified or session.rotation_requested
            ):
                app.logger.exception(
                    "Server side Session modified during websocket handling. "
                    "These modifications will be lost as a cookie cannot be set."
                )
            return

        if session.accessed:
            response.vary.add("Cookie")

        if not isinstance(session, ServerSideSession):
            return
        server_session = session
        changes = field_changes(server_session.base_snapshot, server_session)
        modified = bool(changes)
        rotation = server_session.rotation_requested

        if not modified and not rotation:
            # A pure read must not overwrite the stored data or its expiry.
            return

        expires = self.get_expiration_time(app, server_session)

        try:
            if server_session.sid is None:
                if not server_session:
                    self._delete_cookie(app, response)
                    return
                result = await self.store.create(dict(server_session), expires)
            elif rotation:
                result = await self.store.rotate(
                    server_session.sid,
                    server_session.version,
                    server_session.base_snapshot,
                    changes,
                    expires,
                )
            else:
                result = await self.store.commit(
                    server_session.sid,
                    server_session.version,
                    server_session.base_snapshot,
                    changes,
                    expires,
                )

            if result.data is None:
                self._delete_cookie(app, response)
            else:
                self._write_cookie(app, response, result.sid, expires)
        except ServerSideSessionError as error:
            await self.handle_commit_error(app, response, error)

    async def handle_commit_error(
        self,
        app: Quart,
        response: Response | WerkzeugResponse,
        error: ServerSideSessionError,
    ) -> None:
        """Handle a commit time conflict or missing session.

        The default re-raises *error* so that the failure is reported
        explicitly. Override this (for example in a subclass) to turn the
        error into a response, such as ``409 Conflict`` or ``410 Gone``.
        No session cookie is written when this is called.
        """
        raise error

    def _write_cookie(
        self,
        app: Quart,
        response: Response | WerkzeugResponse,
        sid: str,
        expires: datetime | None,
    ) -> None:
        response.set_cookie(
            self.get_cookie_name(app),
            sid,
            expires=expires,
            httponly=self.get_cookie_httponly(app),
            domain=self.get_cookie_domain(app),
            partitioned=self.get_cookie_partitioned(app),
            path=self.get_cookie_path(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
        )
        response.vary.add("Cookie")

    def _delete_cookie(self, app: Quart, response: Response | WerkzeugResponse) -> None:
        response.delete_cookie(
            self.get_cookie_name(app),
            domain=self.get_cookie_domain(app),
            partitioned=self.get_cookie_partitioned(app),
            path=self.get_cookie_path(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
            httponly=self.get_cookie_httponly(app),
        )
        response.vary.add("Cookie")


class _SidCollisionError(Exception):
    """Internal signal used to retry identifier rotation."""


class SqliteSessionStore(ServerSideSessionStore):
    """A runnable reference store backed by SQLite.

    A single connection guarded by a lock makes the read/merge/write
    version rules atomic even with concurrent requests.

    Arguments:
        path: Database file path, or ``":memory:"`` for an in memory store.
        ttl: Stored row lifetime for non permanent sessions. Without a row
            expiry the server could not evict sessions referenced only by a
            browser session cookie. Ignored for permanent sessions.
    """

    def __init__(
        self,
        path: str = ":memory:",
        ttl: timedelta | None = timedelta(days=31),
    ) -> None:
        self.path = path
        self.ttl = ttl
        self._connection: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        if self._connection is not None:
            return
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS quart_sessions (
                sid TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                data TEXT NOT NULL,
                expires_at TEXT
            )
            """
        )
        connection.commit()
        self._connection = connection

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("The session store has not been initialized.")
        return self._connection

    @staticmethod
    def _format_expiry(expires_at: datetime | None) -> str | None:
        if expires_at is None:
            return None
        return expires_at.astimezone(UTC).isoformat()

    @staticmethod
    def _expired(row_expiry: str | None) -> bool:
        if row_expiry is None:
            return False
        return datetime.fromisoformat(row_expiry) <= datetime.now(UTC)

    async def load(self, sid: str) -> StoredSession | None:
        await self.initialize()
        async with self._lock:
            row = self.connection.execute(
                "SELECT version, data, expires_at FROM quart_sessions WHERE sid = ?",
                (sid,),
            ).fetchone()
            if row is None:
                return None
            version, encoded, row_expiry = row
            if self._expired(row_expiry):
                with self.connection:
                    self.connection.execute(
                        "DELETE FROM quart_sessions WHERE sid = ?", (sid,)
                    )
                return None
            data = session_json_serializer.loads(encoded)
            return StoredSession(data, version)

    async def create(
        self, data: Mapping[str, Any], expires_at: datetime | None
    ) -> CommitResult:
        await self.initialize()
        encoded = session_json_serializer.dumps(dict(data))
        expiry = self._format_expiry(self._effective_expiry(expires_at))
        async with self._lock:
            for _ in range(5):
                sid = secrets.token_urlsafe(32)
                try:
                    with self.connection:
                        self.connection.execute(
                            "INSERT INTO quart_sessions "
                            "(sid, version, data, expires_at) "
                            "VALUES (?, 1, ?, ?)",
                            (sid, encoded, expiry),
                        )
                except sqlite3.IntegrityError:
                    continue
                return CommitResult(sid, 1, dict(data))
        raise RuntimeError("Unable to allocate a unique session identifier.")

    async def commit(
        self,
        sid: str,
        base_version: int,
        base_data: Mapping[str, Any],
        changes: Mapping[str, Any],
        expires_at: datetime | None,
    ) -> CommitResult:
        await self.initialize()
        async with self._lock:
            return self._commit_locked(
                sid,
                base_version,
                base_data,
                changes,
                expires_at,
                new_sid=None,
            )

    async def rotate(
        self,
        sid: str,
        base_version: int,
        base_data: Mapping[str, Any],
        changes: Mapping[str, Any],
        expires_at: datetime | None,
    ) -> CommitResult:
        await self.initialize()
        async with self._lock:
            for _ in range(5):
                new_sid = secrets.token_urlsafe(32)
                try:
                    return self._commit_locked(
                        sid,
                        base_version,
                        base_data,
                        changes,
                        expires_at,
                        new_sid=new_sid,
                    )
                except _SidCollisionError:
                    continue
        raise RuntimeError("Unable to allocate a unique session identifier.")

    def _commit_locked(
        self,
        sid: str,
        base_version: int,
        base_data: Mapping[str, Any],
        changes: Mapping[str, Any],
        expires_at: datetime | None,
        new_sid: str | None,
    ) -> CommitResult:
        row = self.connection.execute(
            "SELECT version, data, expires_at FROM quart_sessions WHERE sid = ?",
            (sid,),
        ).fetchone()
        if row is None or self._expired(row[2]):
            raise SessionNotFoundError(sid)
        version, encoded, _ = row
        current = session_json_serializer.loads(encoded)
        if version != base_version:
            if changes.get(CLEAR_FIELDS) and current:
                raise SessionConflictError(sid, version, ("<all fields>",))
            conflicts = _conflicting_fields(_canonical(base_data), current, changes)
            if conflicts:
                raise SessionConflictError(sid, version, tuple(conflicts))

        apply_changes(current, changes)
        expiry = self._format_expiry(self._effective_expiry(expires_at))
        new_version = version + 1

        with self.connection:
            if not current:
                self.connection.execute(
                    "DELETE FROM quart_sessions WHERE sid = ?", (sid,)
                )
                return CommitResult(new_sid or sid, new_version, None)
            new_encoded = session_json_serializer.dumps(current)
            if new_sid is None:
                self.connection.execute(
                    "UPDATE quart_sessions SET version = ?, data = ?, "
                    "expires_at = ? WHERE sid = ?",
                    (new_version, new_encoded, expiry, sid),
                )
                return CommitResult(sid, new_version, current)
            self.connection.execute("DELETE FROM quart_sessions WHERE sid = ?", (sid,))
            try:
                self.connection.execute(
                    "INSERT INTO quart_sessions "
                    "(sid, version, data, expires_at) VALUES (?, ?, ?, ?)",
                    (new_sid, new_version, new_encoded, expiry),
                )
            except sqlite3.IntegrityError as error:
                raise _SidCollisionError from error
            return CommitResult(new_sid, new_version, current)

    async def delete_expired(self) -> None:
        await self.initialize()
        now = datetime.now(UTC).isoformat()
        async with self._lock:
            with self.connection:
                self.connection.execute(
                    "DELETE FROM quart_sessions "
                    "WHERE expires_at IS NOT NULL AND expires_at <= ?",
                    (now,),
                )

    async def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _effective_expiry(self, expires_at: datetime | None) -> datetime | None:
        if expires_at is not None:
            return expires_at
        if self.ttl is None:
            return None
        return datetime.now(UTC) + self.ttl


def _conflicting_fields(
    base_data: Mapping[str, Any],
    stored_data: Mapping[str, Any],
    changes: Mapping[str, Any],
) -> list[str]:
    deleted = set(changes.get(DELETED_FIELDS, ()))
    result: list[str] = []
    for key in set(changes) - {DELETED_FIELDS, CLEAR_FIELDS}:
        if _value_for(base_data, key) != _value_for(stored_data, key):
            result.append(key)
    for key in deleted:
        if _value_for(base_data, key) != _value_for(stored_data, key):
            result.append(key)
    return sorted(result)


_MISSING: object = object()


def _value_for(data: Mapping[str, Any], key: str) -> object:
    if key not in data:
        return _MISSING
    return _canonical(data[key])
