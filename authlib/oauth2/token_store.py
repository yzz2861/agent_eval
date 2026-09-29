"""Shared token store protocol for coordinating token refreshes.

When several OAuth 2.0 client instances (processes, workers, or machines)
share one account whose authorization server *rotates* refresh tokens, the
per-instance locks of the clients cannot stop them from refreshing the same
refresh token concurrently. A second refresh with an already-consumed
refresh token is usually rejected, and some providers even invalidate the
whole token family on refresh-token reuse.

This module defines an optional, storage-agnostic protocol that lets client
instances coordinate through a shared store:

1. ``read`` returns the stored token together with a monotonically
   increasing ``version``.
2. ``acquire_lease`` elects a single refresh coordinator. The lease carries
   a TTL so that a crashed coordinator is automatically fenced out once its
   lease expires; the other instances simply retry acquisition.
3. ``save`` is a compare-and-swap on ``version``: the new token is only
   persisted when the store is still at the version the coordinator read.

Both the synchronous (:class:`SharedTokenStore`) and the asynchronous
(:class:`AsyncSharedTokenStore`) protocols share the exact same semantics;
the async variant is a method-for-method mirror so that sync and async
clients follow identical storage rules.

If the refresh request itself succeeded but persisting the result failed,
the state of the store is unknown (the save may or may not have completed).
In that case :class:`TokenPersistenceUncertainError` is raised and the
refresh is *not* retried automatically, because the old refresh token has
most likely been consumed already.
"""

import os
import socket
import time
import uuid
from typing import NamedTuple

__all__ = [
    "DEFAULT_LEASE_TTL",
    "DEFAULT_WAIT_TIMEOUT",
    "StoredToken",
    "SharedTokenStore",
    "AsyncSharedTokenStore",
    "TokenPersistenceUncertainError",
    "coordinated_token_refresh",
    "async_coordinated_token_refresh",
]

#: Default lifetime of the refresh lease, in seconds. Choose a value
#: comfortably larger than the expected latency of one refresh request.
DEFAULT_LEASE_TTL = 30.0

#: Default time a non-coordinator waits for the coordinator to publish a
#: new token before it retries acquiring the lease itself.
DEFAULT_WAIT_TIMEOUT = 30.0


class TokenPersistenceUncertainError(RuntimeError):
    """The refresh request succeeded but the new token could not be saved.

    The shared store may or may not contain the new token, so the client
    must *not* silently repeat the refresh request: the previous refresh
    token has most likely been consumed, and reusing it can invalidate the
    whole token family at providers with refresh-token-rotation reuse
    detection.

    The freshly obtained token is available on the ``token`` attribute so
    that callers can persist it through a recovery path of their own.
    """

    def __init__(self, token, expected_version, message=None):
        #: The token returned by the authorization server.
        self.token = token
        #: The store version the failed save was compared against.
        self.expected_version = expected_version
        if message is None:
            message = (
                "The token refresh request succeeded, but saving the new "
                "token to the shared token store failed (expected store "
                f"version {expected_version!r}). The store state is "
                "uncertain and the refresh was NOT retried. Recover the "
                "token from the store or from the `token` attribute of "
                "this error."
            )
        super().__init__(message)


class StoredToken(NamedTuple):
    """A token snapshot as returned by ``SharedTokenStore.read``."""

    #: The token dict (``access_token``, ``refresh_token``, ...).
    token: dict
    #: Monotonically increasing version used for compare-and-swap saves.
    version: int


class SharedTokenStore:
    """Synchronous shared token store protocol.

    Implementations must provide atomic semantics for ``acquire_lease`` and
    ``save``; a single SQLite/Redis/Postgres backend is enough, no external
    consensus system is required.
    """

    def read(self):
        """Return the current :class:`StoredToken`, or ``None`` if the
        store is empty."""
        raise NotImplementedError

    def acquire_lease(self, owner, ttl):
        """Try to become the refresh coordinator.

        :param owner: A unique identifier of the calling instance, used for
            diagnostics.
        :param ttl: Lease lifetime in seconds. A crashed coordinator stops
            releasing its lease, so implementations must treat a lease
            older than ``ttl`` as expired and allow another instance to
            take over. This is the recovery mechanism for coordinator
            crashes.
        :return: An opaque lease id on success, ``None`` if another
            instance currently holds a valid lease.
        """
        raise NotImplementedError

    def release_lease(self, lease_id):
        """Release the lease identified by ``lease_id``. Releasing an
        unknown or expired lease must be a silent no-op."""
        raise NotImplementedError

    def wait_for_update(self, version, timeout):
        """Block until the stored version differs from ``version`` or
        ``timeout`` seconds elapse. Return the new :class:`StoredToken`,
        or ``None`` on timeout."""
        raise NotImplementedError

    def save(self, token, expected_version):
        """Compare-and-swap save: persist ``token`` only if the current
        store version equals ``expected_version`` (``None`` means the store
        must be empty). Return ``True`` if the token was persisted."""
        raise NotImplementedError


class AsyncSharedTokenStore:
    """Asynchronous mirror of :class:`SharedTokenStore`.

    Every method has the same contract as its synchronous counterpart; the
    coordination rules are identical for sync and async clients.
    """

    async def read(self):
        """See :meth:`SharedTokenStore.read`."""
        raise NotImplementedError

    async def acquire_lease(self, owner, ttl):
        """See :meth:`SharedTokenStore.acquire_lease`."""
        raise NotImplementedError

    async def release_lease(self, lease_id):
        """See :meth:`SharedTokenStore.release_lease`."""
        raise NotImplementedError

    async def wait_for_update(self, version, timeout):
        """See :meth:`SharedTokenStore.wait_for_update`."""
        raise NotImplementedError

    async def save(self, token, expected_version):
        """See :meth:`SharedTokenStore.save`."""
        raise NotImplementedError


def _token_expired(token, leeway):
    expires_at = token.get("expires_at")
    if not isinstance(expires_at, (int, float)):
        return False
    return expires_at - leeway <= time.time()


def _new_owner():
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}"


def coordinated_token_refresh(
    store,
    current_token,
    leeway,
    do_refresh,
    lease_ttl=DEFAULT_LEASE_TTL,
    wait_timeout=DEFAULT_WAIT_TIMEOUT,
):
    """Refresh a token under the coordination of a shared store.

    :param store: A :class:`SharedTokenStore` implementation.
    :param current_token: The token dict this instance currently holds.
    :param leeway: Expiration leeway in seconds (same semantics as the
        client's ``leeway`` parameter).
    :param do_refresh: A callable taking a refresh token string and
        performing the actual refresh HTTP request; must return the new
        token dict.
    :param lease_ttl: Lifetime of the coordination lease in seconds.
    :param wait_timeout: How long to wait for another coordinator to
        publish before retrying lease acquisition.
    :return: The token dict to use from now on. It may come from the store
        (another instance refreshed first) or from ``do_refresh``.

    The rules are:

    * Always re-read the store first; if it already holds a usable token,
      adopt it instead of refreshing.
    * Only the lease holder refreshes, and it always uses the freshest
      refresh token known to the store -- never a stale local one.
    * The new token is saved with compare-and-swap on the store version.
    * If the refresh succeeded but the save failed, raise
      :class:`TokenPersistenceUncertainError` instead of retrying.
    * If the lease cannot be acquired, wait for the coordinator to publish;
      on timeout retry acquisition (a crashed coordinator's lease expires
      after ``lease_ttl``).
    """
    owner = _new_owner()
    stored = store.read()
    while True:
        if stored is not None and not _token_expired(stored.token, leeway):
            return dict(stored.token)

        lease_id = store.acquire_lease(owner, lease_ttl)
        if lease_id is None:
            version = stored.version if stored is not None else None
            stored = store.wait_for_update(version, wait_timeout)
            # Timeout: loop again. If the coordinator crashed, its lease
            # has expired by now and acquisition will succeed.
            continue

        try:
            # Re-read inside the lease: a previous coordinator may have
            # published a fresh token just before its lease expired.
            stored = store.read()
            if stored is not None and not _token_expired(stored.token, leeway):
                return dict(stored.token)

            expected_version = stored.version if stored is not None else None
            refresh_token = None
            if stored is not None:
                refresh_token = stored.token.get("refresh_token")
            if refresh_token is None:
                refresh_token = current_token.get("refresh_token")

            new_token = do_refresh(refresh_token)

            try:
                saved = store.save(new_token, expected_version)
            except Exception as exc:
                raise TokenPersistenceUncertainError(
                    new_token, expected_version
                ) from exc

            if saved:
                return new_token

            # Lost the race (e.g. the lease expired mid-refresh and another
            # instance took over): adopt whatever the winner persisted
            # instead of refreshing again with a consumed refresh token.
            latest = store.read()
            if latest is not None and latest.version != expected_version:
                return dict(latest.token)
            raise TokenPersistenceUncertainError(new_token, expected_version)
        finally:
            store.release_lease(lease_id)


async def async_coordinated_token_refresh(
    store,
    current_token,
    leeway,
    do_refresh,
    lease_ttl=DEFAULT_LEASE_TTL,
    wait_timeout=DEFAULT_WAIT_TIMEOUT,
):
    """Async mirror of :func:`coordinated_token_refresh`.

    Follows the exact same rules, but ``store`` is an
    :class:`AsyncSharedTokenStore` and ``do_refresh`` is a coroutine
    function.
    """
    owner = _new_owner()
    stored = await store.read()
    while True:
        if stored is not None and not _token_expired(stored.token, leeway):
            return dict(stored.token)

        lease_id = await store.acquire_lease(owner, lease_ttl)
        if lease_id is None:
            version = stored.version if stored is not None else None
            stored = await store.wait_for_update(version, wait_timeout)
            continue

        try:
            stored = await store.read()
            if stored is not None and not _token_expired(stored.token, leeway):
                return dict(stored.token)

            expected_version = stored.version if stored is not None else None
            refresh_token = None
            if stored is not None:
                refresh_token = stored.token.get("refresh_token")
            if refresh_token is None:
                refresh_token = current_token.get("refresh_token")

            new_token = await do_refresh(refresh_token)

            try:
                saved = await store.save(new_token, expected_version)
            except Exception as exc:
                raise TokenPersistenceUncertainError(
                    new_token, expected_version
                ) from exc

            if saved:
                return new_token

            latest = await store.read()
            if latest is not None and latest.version != expected_version:
                return dict(latest.token)
            raise TokenPersistenceUncertainError(new_token, expected_version)
        finally:
            await store.release_lease(lease_id)
