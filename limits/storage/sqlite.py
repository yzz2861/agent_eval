from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
import time
import urllib.parse
from collections.abc import Iterator
from math import floor

from deprecated.sphinx import versionadded

from limits.errors import ConfigurationError

from .base import (
    MovingWindowSupport,
    SlidingWindowCounterSupport,
    Storage,
    TimestampedSlidingWindow,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS counters (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS moving_entries (
    key TEXT NOT NULL,
    ts REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_moving_entries_key_ts
    ON moving_entries (key, ts);
CREATE INDEX IF NOT EXISTS idx_moving_entries_expiry
    ON moving_entries (expires_at);
CREATE INDEX IF NOT EXISTS idx_counters_expiry
    ON counters (expires_at);
"""


class LockTimeoutError(Exception):
    """
    Error raised when a lock on the sqlite database could not be
    acquired within the configured timeout.

    Any transaction that was in progress when the error was raised
    has been rolled back, so no partial writes are left behind.
    """


def _is_lock_error(exc: sqlite3.OperationalError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None:
        primary = code & 0xFF
        return primary in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
    return "locked" in str(exc)


def _database_from_uri(uri: str) -> str:
    parsed = urllib.parse.urlparse(uri)
    if parsed.path.lstrip("/") == ":memory:":
        return ":memory:"
    if parsed.netloc and parsed.path:
        # sqlite://relative/path.db
        database = os.path.join(parsed.netloc, parsed.path.lstrip("/"))
    elif parsed.netloc:
        database = parsed.netloc
    else:
        database = parsed.path
    if database.startswith("//"):
        # sqlite:////absolute/path produced by "sqlite://" + "/absolute/path"
        database = "/" + database.lstrip("/")
    if not database:
        raise ConfigurationError(
            f"sqlite storage uri {uri!r} does not contain a database path"
        )
    return database


@versionadded(version="5.9")
class SQLiteStorage(
    Storage, MovingWindowSupport, SlidingWindowCounterSupport, TimestampedSlidingWindow
):
    """
    Rate limit storage backed by a local sqlite database using the
    standard library :mod:`sqlite3` module.

    The backend is meant for multiple processes on a single host (for
    example pre-fork workers) that need to share rate limit state without
    running an external service such as redis.

    Concurrency & consistency notes:

    * All read-modify-write operations (quota check + accounting) run in a
      single BEGIN IMMEDIATE transaction, so concurrent processes
      serialize on the database write lock and cannot overshoot a limit.
    * If the database lock cannot be acquired within the configured
      timeout, the transaction is rolled back and
      :class:`LockTimeoutError` is raised.
    * Connections are not shared across ``fork()``: each process lazily
      opens its own connection the first time it touches the database.
    * Expired rows are removed in bounded batches (each batch is its own
      short transaction) instead of one database wide delete.
    """

    STORAGE_SCHEME = ["sqlite"]
    """The storage scheme for sqlite"""

    DEFAULT_TIMEOUT = 5.0
    """Default number of seconds to wait for the database lock"""

    DEFAULT_CLEANUP_INTERVAL = 30.0
    """Default minimum number of seconds between expired row cleanups"""

    DEFAULT_CLEANUP_BATCH_SIZE = 1000
    """Default maximum number of expired rows deleted per batch"""

    def __init__(
        self,
        uri: str,
        timeout: float = DEFAULT_TIMEOUT,
        cleanup_interval: float = DEFAULT_CLEANUP_INTERVAL,
        cleanup_batch_size: int = DEFAULT_CLEANUP_BATCH_SIZE,
        wrap_exceptions: bool = False,
        **_: float | str | bool,
    ) -> None:
        """
        :param uri: uri of the form ``sqlite:///path/to/limits.db``
         (or ``sqlite:///:memory:`` for a private in-memory database).
        :param timeout: maximum number of seconds to wait when the
         database is locked by another process before raising
         :class:`LockTimeoutError`.
        :param cleanup_interval: minimum number of seconds between two
         automatic cleanups of expired rows.
        :param cleanup_batch_size: maximum number of expired rows deleted
         in a single transaction during cleanup.
        :param wrap_exceptions: Whether to wrap storage exceptions in
         :exc:`limits.errors.StorageError` before raising it.
        """
        super().__init__(uri, wrap_exceptions=wrap_exceptions)
        self._database = _database_from_uri(uri)
        self._timeout = float(timeout)
        self._cleanup_interval = float(cleanup_interval)
        self._cleanup_batch_size = int(cleanup_batch_size)
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._last_cleanup = 0.0

    def __del__(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                pass

    @property
    def base_exceptions(self) -> type[Exception] | tuple[type[Exception], ...]:
        return (sqlite3.Error,)

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._database,
                timeout=self._timeout,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.execute("PRAGMA busy_timeout=%d" % (self._timeout * 1000))
            try:
                connection.executescript(SCHEMA)
            except sqlite3.OperationalError as exc:
                # another process may be holding the write lock; if the
                # schema is already in place the connection is usable.
                if not (_is_lock_error(exc) and self._schema_ready(connection)):
                    raise
        except sqlite3.OperationalError as exc:
            if _is_lock_error(exc):
                raise LockTimeoutError(
                    f"could not initialize sqlite database {self._database!r}: {exc}"
                ) from exc
            raise
        return connection

    @staticmethod
    def _schema_ready(connection: sqlite3.Connection) -> bool:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
            " AND name IN ('counters', 'moving_entries')"
        ).fetchall()
        return len(rows) == 2

    def _get_connection(self) -> sqlite3.Connection:
        pid = os.getpid()
        if pid != self._pid:
            # The process was forked: the connection (and the lock state)
            # inherited from the parent must not be reused.
            self._lock = threading.RLock()
            with self._lock:
                if self._connection is not None:
                    try:
                        self._connection.close()
                    except sqlite3.Error:
                        pass
                self._connection = None
                self._pid = pid
        with self._lock:
            if self._connection is None:
                self._connection = self._connect()
            return self._connection

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            connection.rollback()

    @contextlib.contextmanager
    def _transaction(self, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        """
        Run statements in a single transaction. immediate transactions
        acquire the database write lock up front so that a quota check and
        the corresponding write are atomic across processes. Any exception
        - including a lock wait failure - rolls the transaction back, and
        lock wait failures are re-raised as LockTimeoutError.
        """
        connection = self._get_connection()
        with self._lock:
            try:
                connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                try:
                    yield connection
                except BaseException:
                    self._rollback(connection)
                    raise
                connection.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                self._rollback(connection)
                if _is_lock_error(exc):
                    raise LockTimeoutError(
                        f"could not acquire lock on {self._database!r}"
                        f" within {self._timeout} seconds"
                    ) from exc
                raise

    def _get(self, connection: sqlite3.Connection, key: str, now: float) -> int:
        row = connection.execute(
            "SELECT value FROM counters WHERE key = ? AND expires_at > ?",
            (key, now),
        ).fetchone()
        return int(row[0]) if row else 0

    def _incr(
        self,
        connection: sqlite3.Connection,
        key: str,
        expiry: float,
        amount: int,
        now: float,
    ) -> int:
        connection.execute(
            """
            INSERT INTO counters (key, value, expires_at)
            VALUES (:key, :amount, :expires_at)
            ON CONFLICT(key) DO UPDATE SET
                value = CASE WHEN counters.expires_at <= :now
                    THEN :amount ELSE counters.value + :amount END,
                expires_at = CASE WHEN counters.expires_at <= :now
                    THEN :expires_at ELSE counters.expires_at END
            """,
            {
                "key": key,
                "amount": amount,
                "expires_at": now + expiry,
                "now": now,
            },
        )
        row = connection.execute(
            "SELECT value FROM counters WHERE key = ?", (key,)
        ).fetchone()
        return int(row[0])

    def incr(self, key: str, expiry: int, amount: int = 1) -> int:
        """
        increments the counter for a given rate limit key

        :param key: the key to increment
        :param expiry: amount in seconds for the key to expire in
        :param amount: the number to increment by
        """
        now = time.time()
        with self._transaction() as connection:
            value = self._incr(connection, key, expiry, amount, now)
        self._maybe_cleanup(now)
        return value

    def get(self, key: str) -> int:
        """
        :param key: the key to get the counter value for
        """
        now = time.time()
        with self._transaction(immediate=False) as connection:
            return self._get(connection, key, now)

    def get_expiry(self, key: str) -> float:
        """
        :param key: the key to get the expiry for
        """
        with self._transaction(immediate=False) as connection:
            row = connection.execute(
                "SELECT expires_at FROM counters WHERE key = ?", (key,)
            ).fetchone()
        return float(row[0]) if row else time.time()

    def clear(self, key: str) -> None:
        """
        :param key: the key to clear rate limits for
        """
        with self._transaction() as connection:
            connection.execute("DELETE FROM counters WHERE key = ?", (key,))
            connection.execute("DELETE FROM moving_entries WHERE key = ?", (key,))

    def reset(self) -> int | None:
        """
        reset storage to clear limits
        """
        with self._transaction() as connection:
            num_keys = (
                connection.execute("SELECT COUNT(*) FROM counters").fetchone()[0]
                + connection.execute(
                    "SELECT COUNT(DISTINCT key) FROM moving_entries"
                ).fetchone()[0]
            )
            connection.execute("DELETE FROM counters")
            connection.execute("DELETE FROM moving_entries")
        return int(num_keys)

    def check(self) -> bool:
        """
        check if storage is healthy
        """
        try:
            connection = self._get_connection()
            with self._lock:
                connection.execute("SELECT 1")
            return True
        except (sqlite3.Error, LockTimeoutError):
            return False

    def acquire_entry(self, key: str, limit: int, expiry: int, amount: int = 1) -> bool:
        """
        :param key: rate limit key to acquire an entry in
        :param limit: amount of entries allowed
        :param expiry: expiry of the entry
        :param amount: the number of entries to acquire
        """
        if amount > limit:
            return False
        now = time.time()
        with self._transaction() as connection:
            connection.execute(
                "DELETE FROM moving_entries WHERE key = ? AND expires_at <= ?",
                (key, now),
            )
            count = connection.execute(
                "SELECT COUNT(*) FROM moving_entries WHERE key = ? AND ts >= ?",
                (key, now - expiry),
            ).fetchone()[0]
            if count + amount > limit:
                acquired = False
            else:
                connection.executemany(
                    "INSERT INTO moving_entries (key, ts, expires_at) VALUES (?, ?, ?)",
                    [(key, now, now + expiry)] * amount,
                )
                acquired = True
        self._maybe_cleanup(now)
        return acquired

    def get_moving_window(self, key: str, limit: int, expiry: int) -> tuple[float, int]:
        """
        returns the starting point and the number of entries in the moving
        window

        :param key: rate limit key
        :param expiry: expiry of entry
        :return: (start of window, number of acquired entries)
        """
        now = time.time()
        with self._transaction(immediate=False) as connection:
            row = connection.execute(
                "SELECT MIN(ts), COUNT(*) FROM moving_entries WHERE key = ? AND ts > ?",
                (key, now - expiry),
            ).fetchone()
        if row and row[1]:
            return float(row[0]), int(row[1])
        return now, 0

    def _get_sliding_window_info(
        self,
        connection: sqlite3.Connection,
        previous_key: str,
        current_key: str,
        expiry: int,
        now: float,
    ) -> tuple[int, float, int, float]:
        previous_count = self._get(connection, previous_key, now)
        current_count = self._get(connection, current_key, now)
        if previous_count == 0:
            previous_ttl = float(0)
        else:
            previous_ttl = (1 - (((now - expiry) / expiry) % 1)) * expiry
        current_ttl = (1 - ((now / expiry) % 1)) * expiry + expiry
        return previous_count, previous_ttl, current_count, current_ttl

    def acquire_sliding_window_entry(
        self, key: str, limit: int, expiry: int, amount: int = 1
    ) -> bool:
        """
        Acquire an entry if the weighted count of the current and previous
        windows is less than or equal to the limit

        :param key: rate limit key to acquire an entry in
        :param limit: amount of entries allowed
        :param expiry: expiry of the entry
        :param amount: the number of entries to acquire
        """
        if amount > limit:
            return False
        now = time.time()
        previous_key, current_key = self.sliding_window_keys(key, expiry, now)
        with self._transaction() as connection:
            (
                previous_count,
                previous_ttl,
                current_count,
                _,
            ) = self._get_sliding_window_info(
                connection, previous_key, current_key, expiry, now
            )
            weighted_count = previous_count * previous_ttl / expiry + current_count
            if floor(weighted_count) + amount > limit:
                return False
            # The transaction holds the database write lock, so the check
            # above and this increment are atomic across processes.
            self._incr(connection, current_key, 2 * expiry, amount, now)
            return True

    def get_sliding_window(
        self, key: str, expiry: int
    ) -> tuple[int, float, int, float]:
        """
        Return the previous and current window information.

        :param key: the rate limit key
        :param expiry: the rate limit expiry
        :return: (previous count, previous ttl, current count, current ttl)
        """
        now = time.time()
        previous_key, current_key = self.sliding_window_keys(key, expiry, now)
        with self._transaction(immediate=False) as connection:
            return self._get_sliding_window_info(
                connection, previous_key, current_key, expiry, now
            )

    def clear_sliding_window(self, key: str, expiry: int) -> None:
        """
        Resets the rate limit key(s) for the sliding window

        :param key: the key to clear rate limits for
        :param expiry: the rate limit expiry
        """
        now = time.time()
        previous_key, current_key = self.sliding_window_keys(key, expiry, now)
        with self._transaction() as connection:
            connection.execute(
                "DELETE FROM counters WHERE key IN (?, ?)",
                (previous_key, current_key),
            )

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        try:
            self._cleanup_expired(now)
        except (sqlite3.Error, LockTimeoutError):
            # cleanup is best effort: another process may hold the lock
            # and expired rows are filtered out of every read anyway.
            pass

    def _cleanup_expired(self, now: float | None = None) -> int:
        """
        Delete expired rows in bounded batches. Each batch is a separate
        short transaction so the whole database is never locked for longer
        than a single batch.

        :param now: the reference timestamp, defaults to the current time
        :return: the total number of rows deleted
        """
        if now is None:
            now = time.time()
        connection = self._get_connection()
        deleted = 0
        with self._lock:
            for statement in (
                "DELETE FROM counters WHERE key IN"
                " (SELECT key FROM counters WHERE expires_at <= ? LIMIT ?)",
                "DELETE FROM moving_entries WHERE rowid IN"
                " (SELECT rowid FROM moving_entries WHERE expires_at <= ? LIMIT ?)",
            ):
                while True:
                    cursor = connection.execute(
                        statement, (now, self._cleanup_batch_size)
                    )
                    deleted += cursor.rowcount
                    if cursor.rowcount < self._cleanup_batch_size:
                        break
        return deleted
