.. _contexts:

Contexts
========

Quart, like Flask, has two contexts the *application context* and the
*request context*. Both of these contexts exist per request and allow
the global proxies ``current_app``, ``request``, etc... to be resolved.
Note that these contexts are task local, and hence will not exist if a
task is spawned by ``ensure_future`` or ``create_task``.

The design principle of these contexts is that they are likely needed
in all routes, and hence rather than pass these objects around they
are made available via global proxies. This has its downsides, notably
all the arguments relating to global variables. Therefore, it is
recommended that these proxies are only used within routes so as to
isolate the scope.

Application Context
-------------------

The application context is a reference point for any information that
isn't specifically related to a request. This includes the app itself,
the ``g`` global object and a ``url_adapter`` bound only to the app. The
context is created and destroyed implicitly by the request context.

Request Context
---------------

The request context is a reference point for any information that is
related to a request. This includes the request itself, a ``url_adapter``
bound to the request and the session. It is created and destroyed by
the :func:`~quart.Quart.handle_request` method per request.

Websocket Context
-----------------

The websocket context is analogous to the request context, but is
related only to websocket requests. It is created and destroyed by the
:func:`~quart.Quart.handle_websocket_request` method per websocket
connection.

Tasks and contexts
------------------

Context is bound to a ContextVar and will be copied to tasks created
from an existing task. To explicitly copy a context Quart provides the
decorators :func:`~quart.ctx.copy_current_request_context` and
:func:`copy_current_websocket_context` which can be used as so,

.. code-block:: python

    @app.route('/')
    async def index():

        @copy_current_request_context
        async def background_task():
            method = request.method
            ...

        asyncio.ensure_future(background_task())
        ...

If you need to provide the ``request`` context in an asynchronous
generator, use the :func:`quart.helpers.stream_with_context` decorator
as discussed in :ref:`streaming_response`:

.. code-block:: python

    @app.route('/')
    async def index():

        @stream_with_context
        async def async_generator():
            async for data in request.body:
                yield data

        await consume_data(async_generator())
        ...

.. note:: These decorators must be used within an existing context, hence
          the background task is defined as a nested function.

Snapshotting a request context
-------------------------------

The ``copy_current_request_context`` decorator shares the actual
request, including its body, uploaded files and session, with the
background task. This keeps all of those resources alive until the
task finishes. If the task only needs a small amount of request
data, for example an audit task that runs after the response has
been sent, use :func:`~quart.ctx.snapshot_current_request_context`
instead,

.. code-block:: python

    @app.route('/')
    async def index():
        snapshot = snapshot_current_request_context(
            request_fields=('method', 'path'), g_fields=('user_id',)
        )

        async def audit():
            async with snapshot:
                log(request.method, request.path, g.user_id)

        asyncio.ensure_future(audit())
        ...

The snapshot deep copies the chosen request and ``g`` fields at
creation time and is read-only thereafter. It never carries the
request body, uploaded files or the session, and entering it does
not run any of the original request's teardown functions. It can be
entered after the request has finished, in any task of the same
app.
