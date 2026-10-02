"""SQLite-backed storage for the idempotency-key middleware."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
import enum
import json
import os
import sqlite3
import threading
import time
from typing import NamedTuple


class IdempotencyStatus(str, enum.Enum):
    """Lifecycle states of a stored idempotent request."""

    PROCESSING = 'processing'
    COMPLETED = 'completed'
    UNKNOWN = 'unknown'


class IdempotencyRecord(NamedTuple):
    """A stored idempotency record as returned by the store."""

    scope: str
    route: str
    key: str
    status: IdempotencyStatus
    fingerprint: bytes
    owner: str | None
    lease_expires_at: float | None
    status_code: int | None
    headers: list[list[str]] | None
    body: bytes | None
    created_at: float
    completed_at: float | None
    expires_at: float | None


class AcquisitionResult(NamedTuple):
    """Outcome of attempting to claim an idempotency key."""

    state: str
    record: IdempotencyRecord | None
    owner: str | None


class FingerprintMismatch(Exception):
    """Raised when a key is reused with a different request fingerprint."""


STATE_CREATED = 'created'
STATE_REPLAY = 'replay'
STATE_PROCESSING = 'processing'
STATE_UNKNOWN = 'unknown'


class SQLiteIdempotencyStore:
    """Shared SQLite storage for idempotency-key records.

    The store is safe to share between multiple WSGI application instances in
    the same process, as well as between multiple OS processes. It uses a
    single SQLite database file and serializes writes with 'BEGIN IMMEDIATE'
    transactions. Readers do not block on the writer.

    Each stored key progresses through three states:

    * 'processing' -- the owning request is executing the responder;
    * 'completed' -- the response has been committed and may be replayed;
    * 'unknown' -- the owner disappeared before committing, and the key is
      blocked until an administrator releases it.

    Processing rows are leased to their owner. A processing row whose lease
    has expired is treated as 'unknown' rather than handed over to another
    request, because the store cannot tell a slow-but-alive owner apart from
    one that crashed after performing side effects. The middleware renews the
    lease in a background thread while the responder runs.

    Note:
        The store coordinates request deduplication only. It does not
        participate in the responder's business-database transactions. A
        completed record means the response bytes were committed here, not
        that the business transaction committed atomically with them. The
        responder is responsible for committing (or making idempotent) its
        own side effects before it returns.

    Args:
        path (str): Filesystem path of the SQLite database file. The special
            value ':memory:' creates a private in-memory database that can
            not be shared between processes (useful for tests).
        lease_seconds (float): Initial owner lease duration. The owning
            request renews the lease periodically while the responder runs
            (default 30.0).
        ttl_seconds (float | None): Lifetime of completed records. Expired
            completed rows are treated as absent and may be purged. None
            keeps them indefinitely (default 86400.0).
        busy_timeout_ms (int): SQLite busy timeout while another process
            holds the database write lock (default 5000).
        now (callable | None): Override the wall clock used for leases and
            expiry. Intended for tests (default time.time).

    """

    def __init__(
        self,
        path: str,
        *,
        lease_seconds: float = 30.0,
        ttl_seconds: float | None = 86400.0,
        busy_timeout_ms: int = 5000,
        now: Callable[[], float] | None = None,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError('lease_seconds must be positive')
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError('ttl_seconds must be positive or None')

        self._path = path
        self._lease_seconds = float(lease_seconds)
        self._ttl_seconds = ttl_seconds
        self._busy_timeout_ms = busy_timeout_ms
        self._now = now or time.time
        self._local = threading.local()
        ident = f'{os.getpid()}-{id(self)}-{os.urandom(4).hex()}'
        self._owner_instance = ident
        self._owner_seq = 0
        self._owner_lock = threading.Lock()

        if path != ':memory:':
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)

        with self._connect() as connection:
            self._initialize(connection)

    @property
    def lease_seconds(self) -> float:
        """Initial lease granted to a new owner, in seconds."""
        return self._lease_seconds

    def _connect(self) -> sqlite3.Connection:
        connection = getattr(self._local, 'connection', None)
        if connection is None:
            connection = sqlite3.connect(
                self._path,
                timeout=self._busy_timeout_ms / 1000.0,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA busy_timeout = %d' % self._busy_timeout_ms)
            if self._path != ':memory:':
                connection.execute('PRAGMA journal_mode = WAL')
            connection.execute('PRAGMA synchronous = NORMAL')
            self._local.connection = connection
        return connection

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS idempotency_records (
                scope TEXT NOT NULL,
                route TEXT NOT NULL,
                key TEXT NOT NULL,
                fingerprint BLOB NOT NULL,
                status TEXT NOT NULL,
                owner TEXT,
                lease_expires_at REAL,
                status_code INTEGER,
                headers_json TEXT,
                body BLOB,
                created_at REAL NOT NULL,
                completed_at REAL,
                expires_at REAL,
                PRIMARY KEY (scope, route, key)
            );
            """
        )
        connection.execute(
            'CREATE INDEX IF NOT EXISTS ix_idempotency_expires_at '
            'ON idempotency_records (expires_at)'
        )

    def _new_owner(self) -> str:
        with self._owner_lock:
            self._owner_seq += 1
            seq = self._owner_seq
        return f'{self._owner_instance}:{seq}'

    @classmethod
    def _row_to_record(cls, row: sqlite3.Row) -> IdempotencyRecord:
        headers_json = row['headers_json']
        headers = json.loads(headers_json) if headers_json is not None else None
        body = row['body']
        return IdempotencyRecord(
            scope=row['scope'],
            route=row['route'],
            key=row['key'],
            status=IdempotencyStatus(row['status']),
            fingerprint=bytes(row['fingerprint']),
            owner=row['owner'],
            lease_expires_at=row['lease_expires_at'],
            status_code=row['status_code'],
            headers=headers,
            body=bytes(body) if body is not None else None,
            created_at=row['created_at'],
            completed_at=row['completed_at'],
            expires_at=row['expires_at'],
        )

    def _immediate(self) -> sqlite3.Connection:
        """Begin an immediate write transaction, retrying on lock."""
        connection = self._connect()
        attempts = 0
        while True:
            try:
                connection.execute('BEGIN IMMEDIATE')
                return connection
            except sqlite3.OperationalError as ex:
                locked = str(ex).lower() == 'database is locked'
                if not locked or attempts >= 100:
                    raise
                attempts += 1
                time.sleep(0.05)

    @contextmanager
    def _transaction(self):
        """Yield a connection inside an immediate write transaction."""
        connection = self._immediate()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @staticmethod
    def _select(
        connection: sqlite3.Connection, scope: str, route: str, key: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            'SELECT rowid, * FROM idempotency_records '
            'WHERE scope = ? AND route = ? AND key = ?',
            (scope, route, key),
        ).fetchone()

    def acquire(
        self,
        scope: str,
        route: str,
        key: str,
        fingerprint: bytes,
    ) -> AcquisitionResult:
        """Atomically claim a key or report the state of an existing claim.

        Args:
            scope (str): User/security scope of the request.
            route (str): URI template of the matched route.
            key (str): Idempotency-Key value.
            fingerprint (bytes): Hash identifying the request payload.

        Returns:
            AcquisitionResult: A fresh claim (state 'created'), a replayable
            completed record (state 'replay'), an in-flight record (state
            'processing'), or a blocked record (state 'unknown').

        Raises:
            FingerprintMismatch: The key exists with a different fingerprint.

        """
        connection = self._immediate()
        try:
            row = self._select(connection, scope, route, key)
            now = self._now()

            if row is not None:
                if bytes(row['fingerprint']) != fingerprint:
                    raise FingerprintMismatch(key)

                status = row['status']

                if status == IdempotencyStatus.COMPLETED.value:
                    expires_at = row['expires_at']
                    if expires_at is None or expires_at > now:
                        connection.commit()
                        return AcquisitionResult(
                            STATE_REPLAY, self._row_to_record(row), None
                        )

                if status == IdempotencyStatus.PROCESSING.value:
                    lease = row['lease_expires_at']
                    if lease is not None and lease > now:
                        connection.commit()
                        return AcquisitionResult(
                            STATE_PROCESSING,
                            self._row_to_record(row),
                            None,
                        )
                    connection.execute(
                        'UPDATE idempotency_records '
                        "SET status = 'unknown', owner = NULL, "
                        'lease_expires_at = NULL WHERE rowid = ?',
                        (row['rowid'],),
                    )
                    row = self._select(connection, scope, route, key)
                    connection.commit()
                    assert row is not None
                    return AcquisitionResult(
                        STATE_UNKNOWN, self._row_to_record(row), None
                    )

                if status == IdempotencyStatus.UNKNOWN.value:
                    connection.commit()
                    return AcquisitionResult(
                        STATE_UNKNOWN, self._row_to_record(row), None
                    )

                # An expired completed record is replaced in the same claim.
                connection.execute(
                    'DELETE FROM idempotency_records WHERE rowid = ?',
                    (row['rowid'],),
                )

            owner = self._new_owner()
            lease_expires_at = now + self._lease_seconds
            connection.execute(
                'INSERT INTO idempotency_records '
                '(scope, route, key, fingerprint, status, owner, '
                'lease_expires_at, created_at) '
                "VALUES (?, ?, ?, ?, 'processing', ?, ?, ?)",
                (
                    scope,
                    route,
                    key,
                    fingerprint,
                    owner,
                    lease_expires_at,
                    now,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

        row = self._select(self._connect(), scope, route, key)
        assert row is not None
        return AcquisitionResult(STATE_CREATED, self._row_to_record(row), owner)

    def renew_lease(
        self,
        scope: str,
        route: str,
        key: str,
        owner: str,
        lease_seconds: float | None = None,
    ) -> bool:
        """Extend the owner lease while the responder is still running.

        Args:
            scope (str): User/security scope of the request.
            route (str): URI template of the matched route.
            key (str): Idempotency-Key value.
            owner (str): Owner token returned by acquire().
            lease_seconds: Override the extension interval, or None for the
                store default.

        Returns:
            bool: True if the lease was renewed; False if the owner no
            longer owns a processing row.

        """
        if lease_seconds is None:
            duration = self._lease_seconds
        else:
            duration = lease_seconds
        with self._transaction() as connection:
            cursor = connection.execute(
                'UPDATE idempotency_records SET lease_expires_at = ? '
                'WHERE scope = ? AND route = ? AND key = ? AND owner = ? '
                "AND status = 'processing'",
                (self._now() + duration, scope, route, key, owner),
            )
        return cursor.rowcount == 1

    def complete(
        self,
        scope: str,
        route: str,
        key: str,
        owner: str,
        status_code: int,
        headers: list[tuple[str, str]],
        body: bytes,
        ttl_seconds: float | None = None,
    ) -> bool:
        """Commit the recorded response for a claimed request.

        The update is conditional on the owner still holding a processing
        row. If the lease was lost in the meantime (the row was released or
        flipped to unknown), the response is discarded instead of silently
        overwriting the resolved state.

        Args:
            scope (str): User/security scope of the request.
            route (str): URI template of the matched route.
            key (str): Idempotency-Key value.
            owner (str): Owner token returned by acquire().
            status_code (int): HTTP status code to replay.
            headers (list): Response headers to replay as name/value pairs.
            body (bytes): Raw response body to replay.
            ttl_seconds: Per-record lifetime override, or None for default.

        Returns:
            bool: True if the result was committed; False if this owner no
            longer owns the claim.

        """
        if ttl_seconds is None:
            ttl = self._ttl_seconds
        else:
            ttl = ttl_seconds
        now = self._now()
        with self._transaction() as connection:
            cursor = connection.execute(
                'UPDATE idempotency_records '
                "SET status = 'completed', owner = NULL, "
                'lease_expires_at = NULL, status_code = ?, headers_json = ?, '
                'body = ?, completed_at = ?, expires_at = ? '
                'WHERE scope = ? AND route = ? AND key = ? AND owner = ? '
                "AND status = 'processing'",
                (
                    status_code,
                    json.dumps(headers),
                    body,
                    now,
                    now + ttl if ttl is not None else None,
                    scope,
                    route,
                    key,
                    owner,
                ),
            )
        return cursor.rowcount == 1

    def mark_unknown(self, scope: str, route: str, key: str, owner: str) -> bool:
        """Mark a claim unknown when the owner aborts before committing.

        Args:
            scope (str): User/security scope of the request.
            route (str): URI template of the matched route.
            key (str): Idempotency-Key value.
            owner (str): Owner token returned by acquire().

        Returns:
            bool: True if the row was flipped to unknown by this owner.

        """
        with self._transaction() as connection:
            cursor = connection.execute(
                'UPDATE idempotency_records '
                "SET status = 'unknown', owner = NULL, lease_expires_at = NULL "
                'WHERE scope = ? AND route = ? AND key = ? AND owner = ? '
                "AND status = 'processing'",
                (scope, route, key, owner),
            )
        return cursor.rowcount == 1

    def get(self, scope: str, route: str, key: str) -> IdempotencyRecord | None:
        """Return a record without changing it, or None if it is absent.

        Completed records past their expiry are reported as absent.
        """
        connection = self._connect()
        row = self._select(connection, scope, route, key)
        if row is None:
            return None
        if (
            row['status'] == IdempotencyStatus.COMPLETED.value
            and row['expires_at'] is not None
            and row['expires_at'] <= self._now()
        ):
            return None
        return self._row_to_record(row)

    def release(
        self,
        scope: str,
        route: str,
        key: str,
        *,
        allow_completed: bool = False,
    ) -> bool:
        """Administratively release an unknown (or processing) key.

        This is the manual confirmation hook used after an operator verifies
        whether the request's side effects occurred. It never re-runs the
        responder; the released key simply becomes available for a fresh
        claim on the next request.

        Args:
            scope (str): User/security scope of the request.
            route (str): URI template of the matched route.
            key (str): Idempotency-Key value.
            allow_completed (bool): Also permit deleting a completed record
                before its TTL elapses (default False).

        Returns:
            bool: True if a record was deleted.

        """
        with self._transaction() as connection:
            if allow_completed:
                cursor = connection.execute(
                    'DELETE FROM idempotency_records '
                    'WHERE scope = ? AND route = ? AND key = ?',
                    (scope, route, key),
                )
            else:
                cursor = connection.execute(
                    'DELETE FROM idempotency_records '
                    'WHERE scope = ? AND route = ? AND key = ? '
                    "AND status != 'completed'",
                    (scope, route, key),
                )
        return cursor.rowcount == 1

    def purge_expired(self) -> int:
        """Delete completed records whose TTL has elapsed.

        Returns:
            int: Number of records removed.

        """
        with self._transaction() as connection:
            cursor = connection.execute(
                'DELETE FROM idempotency_records '
                "WHERE status = 'completed' AND expires_at IS NOT NULL "
                'AND expires_at <= ?',
                (self._now(),),
            )
            removed = cursor.rowcount
        return removed

    def close(self) -> None:
        """Close this thread's database connection, if open."""
        connection = getattr(self._local, 'connection', None)
        if connection is not None:
            connection.close()
            self._local.connection = None
