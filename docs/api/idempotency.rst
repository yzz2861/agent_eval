.. _idempotency:

Idempotency Keys
================

Mobile clients frequently retry POST requests after a network timeout.
Without protection, a blind retry may execute the responder twice and
duplicate side effects (charges, orders, notifications). Falcon provides an
optional, opt-in middleware that makes these retries safe for non-streaming,
size-bounded WSGI endpoints.

The client sends a unique, opaque key in the ``Idempotency-Key`` header. The
middleware associates the key with:

* a user/security scope (by default the ``Authorization`` header);
* the matched route (its URI template);
* a fingerprint of the request body and content type.

The same scope/route/key may only be reused with the same fingerprint. A
reuse with a different payload is rejected with ``422 Unprocessable Entity``.

Usage
-----

.. code:: python

    import falcon

    store = falcon.SQLiteIdempotencyStore('/var/lib/app/idempotency.db')
    app = falcon.App(
        middleware=[falcon.IdempotencyKeyMiddleware(store=store)]
    )

The database file may be shared by every application process (on one host or
several hosts that share the filesystem). All concurrent submitters observe
the same record.

Request lifecycle
-----------------

* The first request claims the key and executes the responder.
* A concurrent duplicate receives ``409 Conflict`` with a ``Retry-After``
  header and a JSON body. It does not wait and it does not execute the
  responder.
* Once the response is committed, retries replay the original status code,
  the selected response headers, and the exact response bytes. The responder
  is not called again. Cookies and hop-by-hop headers (e.g.
  ``Content-Length``, ``Transfer-Encoding``) are not replayed.
* Completed records expire after a configurable TTL. Expired records are
  treated as absent; :meth:`~falcon.SQLiteIdempotencyStore.purge_expired`
  removes them physically.

Unknown outcomes
----------------

The claim is leased to the owning request, which renews the lease in a
background thread while the responder runs. If the owner disappears before
committing the response (process crash, kill, power loss) and its lease
expires, the record is moved to an unknown state.

In that state, subsequent requests receive ``409 Conflict`` with error code
40901 (see :class:`~falcon.IdempotencyResultUnknown`). Falcon does not
assume the side effects never happened and does not re-run the responder or
schedule a background retry. The caller is expected to surface the ambiguity
to its user or reconcile it against the business state.

After an operator confirms what happened, the key may be released
programmatically so that a future request can start fresh:

.. code:: python

    store.release(scope, route, key)

The :meth:`~falcon.SQLiteIdempotencyStore.release` method deletes unknown
(and processing) rows only; pass ``allow_completed=True`` to also remove a
completed row before its TTL elapses.

Guarantee boundaries
--------------------

The store coordinates request deduplication only. It does not enlist in the
responder's business-database transaction, so it cannot make recording the
response and committing the business changes atomic. Specifically:

* The responder should commit (or otherwise make idempotent) its own side
  effects before returning. A recorded completion means the response bytes
  were committed to the idempotency store, not that the business transaction
  and the record committed as one unit.
* If the business commit succeeds but recording the response fails (or the
  process dies between the two), the key ends up unknown even though the
  side effect may have applied. This is deliberate: blocking on ambiguity
  is safer than silently performing the operation twice.
* The default scope is the ``Authorization`` header. Provide a custom
  ``scope_provider`` if identity is carried elsewhere.

Only synchronous WSGI applications are supported at this time; the
middleware must not be added to an :class:`falcon.asgi.App`. Streaming
responses and bodies larger than ``max_response_bytes`` are not recorded;
the claim is quarantined as unknown and the request fails with ``500`` so
that it is never partially retried.

Reference
---------

.. autoclass:: falcon.IdempotencyKeyMiddleware
    :members:

.. autoclass:: falcon.SQLiteIdempotencyStore
    :members:

.. autoclass:: falcon.IdempotencyRecord
    :members:

.. autoclass:: falcon.IdempotencyStatus
    :members:

.. autoclass:: falcon.IdempotencyInProgress

.. autoclass:: falcon.IdempotencyKeyReused

.. autoclass:: falcon.IdempotencyResultUnknown
