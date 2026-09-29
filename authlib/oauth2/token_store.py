"""Shared token store protocol for coordinating refresh token rotation.

When several OAuth2 client instances (threads, processes, or machines)
share a single set of *rotating* refresh tokens, the per-instance locks
inside the clients cannot stop them from refreshing the same token at
the same time. A losing instance may then replay an already-rotated
refresh token, which many authorization servers treat as token theft.

This module defines an optional, storage-agnostic protocol that lets
clients coordinate through a shared store:

* read the current token together with a monotonic ``version``;
* coordinate a single refresh through a short-lived lease, so exactly
  one instance (the coordinator) performs the HTTP refresh request;
* persist the new token with a compare-and-swap on the version, so a
  stale writer can never overwrite a newer token.

The same rules are used by the synchronous and the asynchronous
clients; the store interface itself is synchronous (a local SQLite
file, Redis, or a SQL row are all fast, blocking-safe calls), so both
client flavors share one implementation.

Crash recovery
--------------
The refresh lease carries a TTL. If the coordinator crashes after
acquiring the lease, the lease expires and another instance may acquire
it and become the new coordinator. Waiters never refresh with their
own (possibly stale) refresh token; they re-read the store until a
fresh token appears or the wait times out.

Uncertain state
---------------
If the refresh HTTP request succeeded but persisting the result fails
(compare-and-swap lost, lease expired mid-refresh, or store error),
the client raises :class:`TokenPersistenceError`. At that point the
authorization server may already have rotated the refresh token while
the shared store does not reflect it, so the state is *uncertain* and
the client must not silently retry the request. Recovery is explicit:
re-read the store, and if it does not converge, re-authorize.
"""

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass

from .rfc6749 import OAuth2Token

__all__ = [
    "TokenRecord",
    "SharedTokenStore",
    "SQLiteSharedTokenStore",
    "TokenStoreError",
    "TokenPersistenceError",
    "RefreshCoordinationTimeout",
    "read_fresh_record",
    "DEFAULT_LEASE_TTL",
    "DEFAULT_WAIT_TIMEOUT",
    "DEFAULT_POLL_INTERVAL",
]

#: How long a refresh lease stays valid. If the coordinator crashes,
#: another instance may take over once this TTL has elapsed.
DEFAULT_LEASE_TTL = 30.0

#: How long a non-coordinator instance waits for the coordinator to
#: publish a fresh token before giving up.
DEFAULT_WAIT_TIMEOUT = 60.0

#: Interval between store re-reads while waiting for the coordinator.
DEFAULT_POLL_INTERVAL = 0.2


class TokenStoreError(Exception):
    """Base error for shared token store failures."""


class TokenPersistenceError(TokenStoreError):
    """The refresh request succeeded but the new token could not be
    persisted to the shared store.

    The state is uncertain: the authorization server may have rotated
    the refresh token while the shared store still holds the old one.
    The client raises this error instead of retrying the request, so
    that the application can reconcile explicitly (re-read the store,
    or re-authorize if the store cannot converge).
    """


class RefreshCoordinationTimeout(TokenStoreError):
    """Timed out waiting for another instance to publish a fresh token."""


@dataclass
class TokenRecord:
    """A token snapshot read from the shared store."""

    token: dict
    version: int


class SharedTokenStore:
    """Protocol for a shared, versioned token store.

    Implementations must provide atomic semantics for
    :meth:`acquire_refresh_lease` and :meth:`save_token`; both the sync
    and the async clients rely on exactly these rules:

    * versions are monotonic: every successful :meth:`save_token`
      increments the version;
    * at most one live lease exists at a time; a lease is bound to the
      version it was acquired for and expires after its TTL;
    * :meth:`save_token` is a compare-and-swap: it only succeeds when
      the stored version still equals ``expected_version`` and the
      caller's lease is still valid.
    """

    def read(self):
        """Return the current :class:`TokenRecord`, or ``None`` when the
        store has not been initialized yet."""
        raise NotImplementedError()

    def acquire_refresh_lease(self, version, ttl):
        """Try to become the refresh coordinator for ``version``.

        :param version: the version this instance based its decision on.
        :param ttl: lease time-to-live in seconds; after it elapses the
            lease is considered abandoned (coordinator crash) and another
            instance may take over.
        :return: an opaque lease identifier on success, ``None`` when
            another instance already holds a live lease.
        """
        raise NotImplementedError()

    def save_token(self, token, expected_version, lease):
        """Persist ``token`` with a compare-and-swap on the version.

        Succeeds only when the stored version still equals
        ``expected_version`` and ``lease`` is a live lease held by the
        caller; the lease is consumed by a successful save.

        :return: ``True`` when the token was persisted, ``False`` when
            the compare-and-swap failed.
        """
        raise NotImplementedError()

    def release_refresh_lease(self, lease):
        """Abandon a lease without saving, e.g. when the refresh request
        itself failed. Must not release another instance's lease."""
        raise NotImplementedError()


def read_fresh_record(store, leeway):
    """Return the store's record when it holds a non-expired token.

    Shared by the sync and async clients so that both apply the exact
    same freshness rule (including the client's leeway).
    """
    record = store.read()
    if record is None:
        return None
    if OAuth2Token(dict(record.token)).is_expired(leeway=leeway):
        return None
    return record


class SQLiteSharedTokenStore(SharedTokenStore):
    """A local :class:`SharedTokenStore` backed by SQLite.

    Suitable for coordinating clients on one machine (threads or
    processes); SQLite provides the required atomicity. The store keeps
    one token row per ``key`` plus a single-row lease table.

    :param path: filesystem path of the SQLite database.
    :param key: namespace of the token inside the store, useful when one
        database serves several tokens.
    """

    def __init__(self, path, key="default"):
        self._key = key
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS token_store ("
                "key TEXT PRIMARY KEY, token TEXT NOT NULL, version INTEGER NOT NULL)"
            )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS refresh_lease ("
                "key TEXT PRIMARY KEY, lease_id TEXT NOT NULL,"
                " version INTEGER NOT NULL, expires_at REAL NOT NULL)"
            )

    def read(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT token, version FROM token_store WHERE key = ?", (self._key,)
            ).fetchone()
        if row is None:
            return None
        return TokenRecord(token=json.loads(row[0]), version=row[1])

    def initialize(self, token):
        """Seed the store with ``token`` when it is still empty.

        :return: ``True`` when the token was inserted, ``False`` when the
            store already held a token.
        """
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO token_store (key, token, version)"
                " VALUES (?, ?, 1)",
                (self._key, json.dumps(dict(token))),
            )
            return cursor.rowcount == 1

    def acquire_refresh_lease(self, version, ttl):
        lease_id = uuid.uuid4().hex
        now = time.time()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "INSERT INTO refresh_lease (key, lease_id, version, expires_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET"
                " lease_id = excluded.lease_id,"
                " version = excluded.version,"
                " expires_at = excluded.expires_at"
                " WHERE refresh_lease.expires_at < ?",
                (self._key, lease_id, version, now + ttl, now),
            )
            acquired = cursor.rowcount == 1
        return lease_id if acquired else None

    def save_token(self, token, expected_version, lease):
        now = time.time()
        payload = json.dumps(dict(token))
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT version FROM token_store WHERE key = ?", (self._key,)
                ).fetchone()
                current_version = row[0] if row else 0
                lease_row = self._conn.execute(
                    "SELECT lease_id, expires_at FROM refresh_lease WHERE key = ?",
                    (self._key,),
                ).fetchone()
                valid_lease = (
                    lease_row is not None
                    and lease_row[0] == lease
                    and lease_row[1] >= now
                )
                if current_version != expected_version or not valid_lease:
                    self._conn.execute("ROLLBACK")
                    return False
                if row is None:
                    self._conn.execute(
                        "INSERT INTO token_store (key, token, version)"
                        " VALUES (?, ?, 1)",
                        (self._key, payload),
                    )
                else:
                    self._conn.execute(
                        "UPDATE token_store SET token = ?, version = ? WHERE key = ?",
                        (payload, current_version + 1, self._key),
                    )
                self._conn.execute(
                    "DELETE FROM refresh_lease WHERE key = ?", (self._key,)
                )
                self._conn.execute("COMMIT")
                return True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def release_refresh_lease(self, lease):
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM refresh_lease WHERE key = ? AND lease_id = ?",
                (self._key, lease),
            )

    def close(self):
        with self._lock:
            self._conn.close()
