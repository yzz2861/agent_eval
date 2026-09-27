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

The request body is read on demand: ``wsgi.input`` only pulls data
from the client as the application reads it. This allows an
application to respond - for example rejecting the request after
reading the first line - without waiting for the full upload. The
buffering between the client and the application is bounded, as at
most a configured max size of body data is received in total. This
is configured by the ``wsgi_max_body_size`` configuration attribute.

When using middleware the ``AsyncioWSGIMiddleware`` and
``TrioWSGIMiddleware`` have a default max size that can be configured,

.. code-block:: python

    app = AsyncioWSGIMiddleware(wsgi_app, max_body_size=20)  # Bytes
