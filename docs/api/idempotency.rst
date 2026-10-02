.. _idempotency:

Idempotency
===========

Falcon includes optional idempotency-key middleware for non-streaming HTTP
APIs that can bound their request and response sizes. It stores records in
SQLite so that several WSGI or ASGI application processes can share the same
database file.

Usage
-----

Configure one :class:`SQLiteIdempotencyStore` per process, using the same
database path. The user-scope callback must return a value that was derived
from the authenticated principal, such as a stable user ID; do not use a value
that a client can change without authenticating.

.. code:: python

    import falcon
    from falcon.idempotency import IdempotencyMiddleware, SQLiteIdempotencyStore

    store = SQLiteIdempotencyStore('/var/lib/example/idempotency.sqlite3')

    app = falcon.App(
        middleware=IdempotencyMiddleware(
            store,
            user_scope=lambda req: req.context.user_id,
        )
    )

Clients send an ``Idempotency-Key`` header with a POST. The key is scoped to
that user and the matched route template. Reusing the same key with a different
HTTP method, path, query string, ``Content-Type``, or body is rejected with
``422 Unprocessable Entity``.

Only routed resources are protected; the resource hook runs after route
matching and is not applied to unmatched paths or sinks.

While the first request owns the key, concurrent requests receive
``409 Conflict`` and ``Idempotency-Status: processing``. After completion, a
retry does not call the responder again. Falcon replays the stored status
code, non-hop-by-hop response headers, cookies, and byte body, and adds
``Idempotency-Replayed: true``.

Unknown Results
---------------

If the owner exits after the responder may have performed work but before the
response record is committed, the stale processing lease becomes
``unknown``. A later retry then receives ``409 Conflict`` and
``Idempotency-Status: unknown``. Falcon does not run the responder again and
does not schedule a background retry.

The application or an administrator must determine the business effect through
its own system of record. Once the effect is confirmed safe to discard, call
:meth:`SQLiteIdempotencyStore.release_unknown` with ``confirmed=True``. The
explicit confirmation argument is intended to prevent accidental release.
These methods are storage APIs, not HTTP endpoints; any admin route that calls
them must have its own authentication and authorization.

Completed results expire according to ``result_ttl_seconds``.
:meth:`SQLiteIdempotencyStore.purge_expired` deletes expired completed rows; it
does not delete unknown records.

Configure ``processing_lease_seconds`` to be longer than the normal maximum
duration of a protected responder. There is no in-flight heartbeat; if that
time elapses while the owner is merely slow, Falcon conservatively treats the
result as unknown rather than allowing another responder call.

Transaction Boundary
--------------------

SQLite stores the HTTP response only. It is not part of the responder's
business database transaction and cannot atomically commit both a business
change and the idempotency record. The responder should therefore perform and
commit its business effect before returning. The middleware records the HTTP
outcome immediately afterward.

That order ensures that a committed idempotency record never claims success
before the business transaction committed, while the inverse can still happen
if the process dies between the two commits. That ambiguity is represented by
an unknown result, not by automatic retries. For effects that cannot tolerate
that window, coordinate the business operation itself (for example with an
outbox, saga, or a transactional unique operation ID).

Use SQLite on local storage that provides the required durability for the
deployment. Network filesystems, replicated block devices, and cross-region
file sharing have their own consistency semantics and are not guaranteed by
this middleware.

Limitations
-----------

- Only responder-assigned byte, text, and serializable media bodies are
  replayed. Response streams, Server-Sent Events, and scheduled response
  callbacks are rejected and left unknown.
- Bodies must fit within ``max_request_body_size`` and
  ``max_response_body_size``.
- WSGI requests must provide ``Content-Length``. ASGI chunked requests are
  read until the configured request limit.
- Request middleware that consumes the body before this component runs may
  prevent a reliable body fingerprint. Place body-consuming components after
  the idempotency middleware or expose the buffered body to them.
- Hop-by-hop headers, including ``Content-Length`` and
  ``Transfer-Encoding``, are not replayed; Falcon calculates the replay
  content length.

SQLiteIdempotencyStore
----------------------

.. autoclass:: falcon.SQLiteIdempotencyStore
   :members:

IdempotencyMiddleware
--------------------

.. autoclass:: falcon.IdempotencyMiddleware
   :members:

Stored Results
--------------

.. autoclass:: falcon.StoredIdempotentResponse
   :members:

.. autoclass:: falcon.StoredIdempotentResult
   :members:

.. autoclass:: falcon.IdempotencyState
   :members:

.. autoclass:: falcon.IdempotencyDecision
   :members:
