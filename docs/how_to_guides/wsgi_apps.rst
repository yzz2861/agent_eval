.. _wsgi_apps:

Serve WSGI applications
=======================

Hypercorn directly serves WSGI applications:

.. code-block:: shell

    $ hypercorn module:wsgi_app

WSGI Middleware
---------------

If a WSGI application is being combined with ASGI middleware it is
best to use either ``AsyncioWSGIMiddleware`` or ``TrioWSGIMiddleware``
middleware. To do so simply wrap the WSGI app with the appropriate
middleware for the hypercorn worker,

.. code-block:: python

    from hypercorn.middleware import AsyncioWSGIMiddleware, TrioWSGIMiddleware

    asyncio_app = AsyncioWSGIMiddleware(wsgi_app)
    trio_app = TrioWSGIMiddleware(wsgi_app)

which can then be passed to other middleware served by hypercorn,

Limiting the request body size
------------------------------

As the request body is stored in memory before being processed it is
important to limit the max size. This is configured by the
``wsgi_max_body_size`` configuration attribute.

When using middleware the ``AsyncioWSGIMiddleware`` and
``TrioWSGIMiddleware`` have a default max size that can be configured,

.. code-block:: python

    app = AsyncioWSGIMiddleware(wsgi_app, max_body_size=20)  # Bytes

Limiting the WSGI capacity
--------------------------

As WSGI applications run in worker threads a few slow requests can
exhaust the executor and starve everything else. The
``AsyncioWSGIMiddleware`` and ``TrioWSGIMiddleware`` can bound how many
requests execute concurrently and how many may queue waiting for a
slot,

.. code-block:: python

    app = AsyncioWSGIMiddleware(
        wsgi_app,
        max_concurrency=4,  # requests executing at once
        max_queue_size=8,  # requests waiting for a slot
        queue_timeout=5.0,  # seconds a request may wait, None waits forever
    )

Requests that arrive when the queue is full, or that wait longer than
``queue_timeout``, are rejected with a ``503`` response. A queued
request cancelled by the client leaves the queue immediately, whereas a
request already executing keeps its slot until the WSGI callable —
including response iteration and ``close()`` — has actually
finished. These limits only apply to requests served by the WSGI
middleware; ASGI requests are unaffected. By default all three limits
are ``None`` i.e. unlimited.
