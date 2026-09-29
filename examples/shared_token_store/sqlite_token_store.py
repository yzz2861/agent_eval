"""A local SQLite implementation of the shared token store protocol.

Both the synchronous :class:`SQLiteTokenStore` and the asynchronous
:class:`AsyncSQLiteTokenStore` operate on the same database file with the
same rules, so sync and async clients can share one store.

Schema:

* ``token``: one row per key, holding the JSON-encoded token and a
  monotonically increasing ``version`` used for compare-and-swap saves.
* ``lease``: one row per key, holding the current refresh lease. A lease
  is only valid until ``expires_at``; after that any instance may take
  over, which is how a crashed coordinator is fenced out.
"""

import asyncio
import json
import sqlite3
import threading
import time
import uuid

from authlib.oauth2.token_store import AsyncSharedTokenStore
from authlib.oauth2.token_store import SharedTokenStore
from authlib.oauth2.token_store import StoredToken


class SQLiteTokenStore(SharedTokenStore):
    """Synchronous shared token store backed by a local SQLite file."""

    def __init__(self, path, key="default"):
        self._key = key
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.isolation_level = None  # autocommit
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS token ("
                " key TEXT PRIMARY KEY,"
                " token TEXT NOT NULL,"
                " version INTEGER NOT NULL)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS lease ("
                " key TEXT PRIMARY KEY,"
                " lease_id TEXT NOT NULL,"
                " owner TEXT NOT NULL,"
                " expires_at REAL NOT NULL)"
            )

    def read(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT token, version FROM token WHERE key = ?", (self._key,)
            ).fetchone()
        if row is None:
            return None
        return StoredToken(token=json.loads(row[0]), version=row[1])

    def acquire_lease(self, owner, ttl):
        lease_id = uuid.uuid4().hex
        now = time.time()
        expires_at = now + ttl
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO lease (key, lease_id, owner, expires_at)"
                    " VALUES (?, ?, ?, ?)",
                    (self._key, lease_id, owner, expires_at),
                )
                return lease_id
            except sqlite3.IntegrityError:
                pass
            # A lease row exists: take over only if it expired. This is the
            # recovery path for a coordinator that crashed while holding
            # the lease.
            cursor = self._conn.execute(
                "UPDATE lease SET lease_id = ?, owner = ?, expires_at = ?"
                " WHERE key = ? AND expires_at < ?",
                (lease_id, owner, expires_at, self._key, now),
            )
            if cursor.rowcount == 1:
                return lease_id
            return None

    def release_lease(self, lease_id):
        with self._lock:
            # The lease_id guard prevents deleting a lease that was taken
            # over by another instance after ours expired.
            self._conn.execute(
                "DELETE FROM lease WHERE key = ? AND lease_id = ?",
                (self._key, lease_id),
            )

    def wait_for_update(self, version, timeout):
        deadline = time.monotonic() + timeout
        while True:
            stored = self.read()
            current = stored.version if stored is not None else None
            if current != version:
                return stored
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)

    def save(self, token, expected_version):
        payload = json.dumps(dict(token))
        with self._lock:
            if expected_version is None:
                try:
                    self._conn.execute(
                        "INSERT INTO token (key, token, version) VALUES (?, ?, 1)",
                        (self._key, payload),
                    )
                    return True
                except sqlite3.IntegrityError:
                    return False
            cursor = self._conn.execute(
                "UPDATE token SET token = ?, version = version + 1"
                " WHERE key = ? AND version = ?",
                (payload, self._key, expected_version),
            )
            return cursor.rowcount == 1


class AsyncSQLiteTokenStore(AsyncSharedTokenStore):
    """Async facade over :class:`SQLiteTokenStore` (same file, same rules)."""

    def __init__(self, path, key="default"):
        self._sync = SQLiteTokenStore(path, key)

    async def read(self):
        return await asyncio.to_thread(self._sync.read)

    async def acquire_lease(self, owner, ttl):
        return await asyncio.to_thread(self._sync.acquire_lease, owner, ttl)

    async def release_lease(self, lease_id):
        await asyncio.to_thread(self._sync.release_lease, lease_id)

    async def wait_for_update(self, version, timeout):
        return await asyncio.to_thread(self._sync.wait_for_update, version, timeout)

    async def save(self, token, expected_version):
        return await asyncio.to_thread(self._sync.save, token, expected_version)
