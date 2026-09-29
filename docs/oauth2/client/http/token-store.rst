.. _shared_token_store:

Shared Token Store
==================

.. meta::
    :description: Coordinate refresh token rotation across multiple OAuth2
        client instances with a shared, versioned token store.

.. module:: authlib.oauth2.token_store

When several client instances (threads, processes, or machines) share one
set of *rotating* refresh tokens, the per-instance locks inside the clients
cannot stop them from refreshing the same token at the same time. A losing
instance may replay an already-rotated refresh token, which many
authorization servers reject or treat as token theft.

Passing a ``token_store`` to the client enables coordination through a
shared store. The same storage rules apply to the synchronous
(:class:`~authlib.integrations.requests_client.OAuth2Session`) and the
asynchronous (:class:`~authlib.integrations.httpx_client.AsyncOAuth2Client`)
clients; when no store is configured, the clients keep their previous
single-instance behavior.

Usage
-----

::

    from authlib.integrations.requests_client import OAuth2Session
    from authlib.oauth2.token_store import SQLiteSharedTokenStore

    store = SQLiteSharedTokenStore("/var/lib/myapp/tokens.db")
    store.initialize(token)  # seed once, when the store is still empty

    # every instance points at the same store
    client = OAuth2Session(
        client_id,
        client_secret,
        token=token,
        token_endpoint="https://provider.example/oauth/token",
        token_store=store,
    )

With a store configured, an expired token is handled like this:

1. The client re-reads the store; if another instance already published a
   fresh token, it adopts that token instead of refreshing with its own
   (possibly stale) refresh token.
2. Otherwise it tries to acquire a short-lived refresh **lease**. The
   winner (the coordinator) refreshes with the store's current refresh
   token and persists the result with a **compare-and-swap** on the store
   version.
3. The other instances poll the store and adopt the published token. If
   the coordinator crashes, its lease expires after
   ``token_store_lease_ttl`` seconds (default 30) and a waiting instance
   takes over. If no fresh token appears within
   ``token_store_wait_timeout`` seconds (default 60),
   :class:`RefreshCoordinationTimeout` is raised.

Uncertain state
---------------

If the refresh request succeeded but persisting the result fails (the
compare-and-swap lost, the lease expired mid-refresh, or the store raised
an error), the client raises :class:`TokenPersistenceError`. The state is
uncertain — the authorization server may already have rotated the refresh
token while the store still holds the old one — so the client does **not**
retry the request automatically. Recovery is explicit: re-read the store,
and re-authorize if it cannot converge.

Custom stores
-------------

Implement :class:`SharedTokenStore` to back the coordination with another
storage system (Redis, Postgres, ...). The contract:

* ``read()`` returns a :class:`TokenRecord` (token dict + monotonic
  ``version``), or ``None`` when uninitialized.
* ``acquire_refresh_lease(version, ttl)`` atomically grants a lease bound
  to that version, expiring after ``ttl`` seconds; returns an opaque lease
  id, or ``None`` when another instance holds a live lease.
* ``save_token(token, expected_version, lease)`` is a compare-and-swap:
  it persists only when the stored version still equals
  ``expected_version`` and the caller's lease is live, increments the
  version, and consumes the lease.
* ``release_refresh_lease(lease)`` abandons a lease without saving.

The store interface is synchronous on purpose: local SQLite, Redis, or a
SQL row are fast, blocking-safe calls, so sync and async clients share one
implementation.

See ``examples/shared_token_store_example.py`` for a runnable demo with
two clients and a local SQLite store.
