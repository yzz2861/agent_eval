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

Limiting synchronous execution
------------------------------

WSGI applications run in worker threads. The ``wsgi_max_concurrency``
configuration limits how many calls can execute at once, including response
iteration and ``close()``. Calls that have not started can wait in a queue
configured by ``wsgi_max_queue_size`` for at most
``wsgi_queue_timeout`` seconds. Full queues and wait timeouts receive a
``503 Service Unavailable`` response. Client cancellation removes only calls still
waiting; calls already executing continue until their synchronous work exits.
