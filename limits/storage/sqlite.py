from __future__ import annotations

import os
import sqlite3
import threading
import time
import urllib.parse
from contextlib import contextmanager
from math import floor
from typing import TYPE_CHECKING, Any

from limits.errors import LockTimeoutError

from .base import MovingWindowSupport, SlidingWindowCounterSupport, Storage

if TYPE_CHECKING:
    from collections.abc import Iterator


class _Denied(Exception):
    pass


def _sqlite_path(uri: str) -> str:
    parsed = urllib.parse.urlparse(uri)
    if not parsed.netloc and parsed.path in ("", "/"):
        return ":memory:"
    if parsed.path == "/:memory:":
        return ":memory:"
    if parsed.netloc:
        return f"{parsed.netloc}{parsed.path}"
    return parsed.path[1:] if parsed.path.startswith("//") else parsed.path


class SQLiteStorage(Storage, MovingWindowSupport, SlidingWindowCounterSupport):
    """Rate limit storage backed by the standard-library :mod:`sqlite3`."""

    STORAGE_SCHEME = ["sqlite"]

    def __init__(
        self,
        uri: str | None = None,
        wrap_exceptions: bool = False,
        *,
        timeout: float = 5.0,
        cleanup_batch_size: int = 1000,
        journal_mode: str = "wal",
        synchronous: str = "normal",
        **options: Any,
    ) -> None:
        super().__init__(uri, wrap_exceptions=wrap_exceptions, **options)
        self.path = _sqlite_path(uri or "sqlite://")
        self.timeout = timeout
        self.cleanup_batch_size = cleanup_batch_size
        self.journal_mode = journal_mode
        self.synchronous = synchronous
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._pid: int | None = None
        self._time = time.time
        self.connection

    @property
    def base_exceptions(self) -> type[Exception] | tuple[type[Exception], ...]:
        return sqlite3.Error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout,
            check_same_thread=False,
            isolation_level=None,
        )
        connection.execute(f"PRAGMA busy_timeout = {int(self.timeout * 1000)}")
        if self.path != ":memory:":
            connection.execute(f"PRAGMA journal_mode = {self.journal_mode}")
        connection.execute(f"PRAGMA synchronous = {self.synchronous}")
        return connection

    @property
    def connection(self) -> sqlite3.Connection:
        pid = os.getpid()
        if self._connection is not None and self._pid != pid:
            with self._lock:
                if self._connection is not None and self._pid != pid:
                    self._connection.close()
                    self._connection = None
        if self._connection is None:
            with self._lock:
                if self._connection is None:
                    connection = self._connect()
                    self._initialize(connection)
                    self._connection = connection
                    self._pid = pid
        return self._connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS counters (
                    key TEXT PRIMARY KEY,
                    count INTEGER NOT NULL CHECK (count >= 0),
                    expires_at REAL NOT NULL
                )"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS counters_expires_at_idx
                ON counters(expires_at)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    key TEXT NOT NULL,
                    at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS events_key_at_idx
                ON events(key, at, expires_at)"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS events_expires_at_idx ON events(expires_at)"
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS sliding_states (
                    key TEXT PRIMARY KEY,
                    window_index INTEGER NOT NULL,
                    previous_count INTEGER NOT NULL CHECK (previous_count >= 0),
                    current_count INTEGER NOT NULL CHECK (current_count >= 0),
                    previous_expires_at REAL NOT NULL DEFAULT 0,
                    expires_at REAL NOT NULL
                )"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS sliding_expires_at_idx
                ON sliding_states(expires_at)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS sliding_window_idx
                ON sliding_states(key, window_index)"""
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _locked(self, exc: sqlite3.OperationalError) -> bool:
        code = getattr(exc, "sqlite_errorcode", None)
        if isinstance(code, int):
            return code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
        message = str(exc).lower()
        return "database is locked" in message or "database table is locked" in message

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connection
        with self._lock:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                if self._locked(exc):
                    raise LockTimeoutError(str(exc)) from exc
                raise
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _purge_expired(self, connection: sqlite3.Connection, now: float) -> None:
        tables = ("counters", "events", "sliding_states")
        for table in tables:
            connection.execute(
                f"""DELETE FROM {table} WHERE rowid IN (
                    SELECT rowid FROM {table}
                    WHERE expires_at <= ? ORDER BY expires_at LIMIT ?
                )""",
                (now, self.cleanup_batch_size),
            )

    def incr(self, key: str, expiry: int | float, amount: int = 1) -> int:
        now = self._time()
        with self._transaction() as connection:
            self._purge_expired(connection, now)
            connection.execute(
                "DELETE FROM counters WHERE key = ? AND expires_at <= ?", (key, now)
            )
            connection.execute(
                """INSERT INTO counters(key, count, expires_at) VALUES(?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    count = counters.count + excluded.count,
                    expires_at = excluded.expires_at""",
                (key, amount, now + expiry),
            )
            count = connection.execute(
                "SELECT count FROM counters WHERE key = ?", (key,)
            ).fetchone()[0]
        return int(count)

    def get(self, key: str) -> int:
        now = self._time()
        row = self.connection.execute(
            "SELECT count FROM counters WHERE key = ? AND expires_at > ?", (key, now)
        ).fetchone()
        return int(row[0]) if row else 0

    def get_expiry(self, key: str) -> float:
        now = self._time()
        row = self.connection.execute(
            "SELECT expires_at FROM counters WHERE key = ? AND expires_at > ?",
            (key, now),
        ).fetchone()
        return float(row[0]) if row else now

    def clear(self, key: str) -> None:
        with self._transaction() as connection:
            connection.execute("DELETE FROM counters WHERE key = ?", (key,))
            connection.execute("DELETE FROM events WHERE key = ?", (key,))
            connection.execute(
                "DELETE FROM sliding_states WHERE key = ?",
                (self._sliding_key(key),),
            )

    def acquire_entry(
        self, key: str, limit: int, expiry: int, amount: int = 1
    ) -> bool:
        if amount > limit:
            return False
        now = self._time()
        with self._transaction() as connection:
            self._purge_expired(connection, now)
            count = connection.execute(
                """SELECT count(*) FROM events
                WHERE key = ? AND at > ? AND expires_at > ?""",
                (key, now - expiry, now),
            ).fetchone()[0]
            if int(count) + amount > limit:
                return False
            while amount:
                batch = min(5000, amount)
                connection.execute(
                    """WITH RECURSIVE seq(value) AS (
                        SELECT 1 UNION ALL
                        SELECT value + 1 FROM seq WHERE value < ?
                    ) INSERT INTO events(key, at, expires_at)
                    SELECT ?, ?, ? FROM seq""",
                    (batch, key, now, now + expiry),
                )
                amount -= batch
            return True

    def get_moving_window(self, key: str, limit: int, expiry: int) -> tuple[float, int]:
        now = self._time()
        row = self.connection.execute(
            """SELECT min(at), count(*) FROM events
            WHERE key = ? AND at > ? AND expires_at > ?""",
            (key, now - expiry, now),
        ).fetchone()
        return (float(row[0]), int(row[1])) if row and row[1] else (now, 0)

    def _sliding_key(self, key: str) -> str:
        return f"\x00sliding\x00{key}"

    def _sliding_state(
        self, connection: sqlite3.Connection, state_key: str, expiry: int, now: float
    ) -> tuple[int, int, bool, float]:
        current_index = int(now // expiry)
        row = connection.execute(
            """SELECT window_index, previous_count, current_count,
                   previous_expires_at, expires_at
            FROM sliding_states WHERE key = ?""",
            (state_key,),
        ).fetchone()
        if row is None:
            return 0, 0, False, 0.0
        index, previous, current, previous_expires_at, expires_at = row
        if index == current_index:
            return (
                int(previous),
                int(current),
                False,
                max(0.0, float(previous_expires_at) - now),
            )
        boundary = current_index * expiry
        if index == current_index - 1 and now == boundary:
            return (
                int(current),
                0,
                False,
                max(0.0, float(expires_at) - now),
            )
        if index == current_index - 1 and now > boundary and int(current):
            previous_ttl = max(0.0, float(previous_expires_at or expires_at) - now)
            connection.execute(
                """UPDATE sliding_states SET
                    window_index = window_index + 1,
                    previous_count = current_count,
                    current_count = 0,
                    previous_expires_at = ?,
                    expires_at = ?
                WHERE key = ?""",
                (
                    (current_index + 1) * expiry,
                    (current_index + 2) * expiry,
                    state_key,
                ),
            )
            return (
                int(current),
                0,
                True,
                previous_ttl,
            )
        connection.execute("DELETE FROM sliding_states WHERE key = ?", (state_key,))
        return 0, 0, False, 0.0

    def acquire_sliding_window_entry(
        self, key: str, limit: int, expiry: int, amount: int = 1
    ) -> bool:
        if amount > limit:
            return False
        now = self._time()
        state_key = self._sliding_key(key)
        current_index = int(now // expiry)
        try:
            with self._transaction() as connection:
                self._purge_expired(connection, now)
                previous, current, shifted, actual_previous_ttl = self._sliding_state(
                    connection, state_key, expiry, now
                )
                if actual_previous_ttl == 0.0:
                    actual_previous_ttl = max(
                        0.0, (current_index + 1) * expiry - now
                    )
                weighted = floor(previous * actual_previous_ttl / expiry) + current
                if weighted + amount > limit:
                    raise _Denied
                connection.execute(
                    """INSERT INTO sliding_states(
                        key, window_index, previous_count, current_count,
                        previous_expires_at, expires_at
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        previous_count = CASE
                            WHEN sliding_states.window_index < excluded.window_index
                            THEN sliding_states.current_count
                            ELSE sliding_states.previous_count
                        END,
                        current_count = CASE
                            WHEN sliding_states.window_index < excluded.window_index
                            THEN excluded.current_count
                            ELSE sliding_states.current_count + excluded.current_count
                        END,
                        window_index = excluded.window_index,
                        previous_expires_at = CASE
                            WHEN sliding_states.window_index < excluded.window_index
                            THEN CASE
                                WHEN sliding_states.current_count > 0
                                THEN sliding_states.expires_at
                                ELSE sliding_states.previous_expires_at
                            END
                            ELSE sliding_states.previous_expires_at
                        END,
                        expires_at = CASE
                            WHEN sliding_states.window_index < excluded.window_index
                            THEN excluded.expires_at
                            ELSE sliding_states.expires_at
                        END""",
                    (
                        state_key,
                        current_index,
                        previous,
                        amount,
                        (current_index + 1) * expiry,
                        (current_index + 2) * expiry,
                    ),
                )
                return True
        except _Denied:
            return False

    def get_sliding_window(
        self, key: str, expiry: int
    ) -> tuple[int, float, int, float]:
        now = self._time()
        state_key = self._sliding_key(key)
        current_index = int(now // expiry)
        with self._transaction() as connection:
            self._purge_expired(connection, now)
            previous, current, _, actual_previous_ttl = self._sliding_state(
                connection, state_key, expiry, now
            )
            if actual_previous_ttl == 0.0:
                actual_previous_ttl = max(
                    0.0,
                    (current_index + 1) * expiry - now,
                )
        current_ttl = max(0.0, (current_index + 1) * expiry - now)
        return previous, actual_previous_ttl if previous else 0.0, current, current_ttl

    def clear_sliding_window(self, key: str, expiry: int) -> None:
        with self._transaction() as connection:
            connection.execute(
                "DELETE FROM sliding_states WHERE key = ?",
                (self._sliding_key(key),),
            )

    def check(self) -> bool:
        try:
            self.connection.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def reset(self) -> int | None:
        total = self.connection.execute(
            """SELECT (
                (SELECT count(*) FROM counters) +
                (SELECT count(DISTINCT key) FROM events) +
                (SELECT count(*) FROM sliding_states)
            )"""
        ).fetchone()[0]
        for table in ("counters", "events", "sliding_states"):
            while True:
                with self._transaction() as connection:
                    deleted = connection.execute(
                        f"""DELETE FROM {table} WHERE rowid IN (
                            SELECT rowid FROM {table} LIMIT ?
                        )""",
                        (self.cleanup_batch_size,),
                    ).rowcount
                if not deleted:
                    break
        return int(total)
