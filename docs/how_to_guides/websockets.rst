.. _websockets:

Using websockets
================

To use a websocket declare a websocket function rather than a route
function, like so,

.. code-block:: python

    @app.websocket('/ws')
    async def ws():
        while True:
            data = await websocket.receive()
            await websocket.send(data)

``websocket`` is a global like ``request`` and shares many of the same
attributes such as ``headers``.

Manually rejecting or accepting websockets
------------------------------------------

A websocket connection is created by accepting a HTTP upgrade request,
however a server can choose to reject a websocket request. To do so
just return from the websocket function as you would with a route function,

.. code-block:: python

    @app.websocket('/ws')
    async def ws():
        if (
            websocket.authorization.username != USERNAME or
            websocket.authorization.password != PASSWORD
        ):
            return 'Invalid password', 403  # or abort(403)
        else:
            websocket.accept()  # Automatically invoked by receive or send
            ...

Sending and receiving independently
-----------------------------------

The first example given requires the client to send a message for the
server to respond. To send and receive independently requires
independent tasks,

.. code-block:: python

    async def sending():
        while True:
            await websocket.send(...)

    async def receiving():
        while True:
            data = await websocket.receive()
            ...

    @app.websocket('/ws')
    async def ws():
        producer = asyncio.create_task(sending())
        consumer = asyncio.create_task(receiving())
        await asyncio.gather(producer, consumer)

The gather line is critical, as without it the websocket function
would return triggering Quart to send a HTTP response.

Dispatching calls by id
-----------------------

:class:`~quart.WebsocketCallDispatcher` can be used inside an existing
websocket route to dispatch ``{"id", "method", "params"}`` messages to
concurrent handlers. The dispatcher returns ``{"id", "result"}`` or
``{"id", "error"}``. Send ``{"id", "method": "cancel", "params": {}}``
with the id of an active call to cancel only that call. If all concurrency
slots are in use the call immediately receives a busy error instead of
queueing. The route can still use the normal ``receive`` and ``send`` methods;
handlers receive a lifecycle-aware connection proxy for concurrent writes.

.. code-block:: python

    async def slow(connection, seconds):
        await asyncio.sleep(seconds)
        return "slow result"

    async def fast(connection, value):
        return value

    @app.websocket('/ws/calls')
    async def ws_calls():
        dispatcher = WebsocketCallDispatcher(
            websocket,
            {"slow": slow, "fast": fast},
            max_concurrency=1,
        )
        await dispatcher.serve()

Object params are passed as keyword arguments and list params are passed as
positional arguments after the connection. Invalid protocol messages close the
whole connection; before returning from :meth:`~quart.WebsocketCallDispatcher.serve`
the dispatcher cancels and waits for child call tasks to finish, preventing
closed connection writes. The connection proxy serialises simultaneous result
messages so individual JSON frames are never interleaved.

Detecting disconnection
-----------------------

When a client disconnects a ``CancelledError`` is raised, which can be
caught to handle the disconnect,

.. code-block:: python

    @app.websocket('/ws')
    async def ws():
        try:
            while True:
                data = await websocket.receive()
                await websocket.send(data)
        except asyncio.CancelledError:
            # Handle disconnection here
            raise

.. warning::

    The ``CancelledError`` must be re-raised.

Closing the connection
----------------------

An connection can be closed by awaiting the ``close`` method with the
appropriate Websocket error code,

.. code-block:: python

    @app.websocket('/ws')
    async def ws():
        await websocket.accept()
        await websocket.close(1000)

if the websocket is closed before it is accepted the server will
respond with a 403 HTTP response.

Testing websockets
------------------

To test a websocket route use the test_client like so,

.. code-block:: python

    test_client = app.test_client()
    async with test_client.websocket('/ws/') as test_websocket:
        await test_websocket.send(data)
        result = await test_websocket.receive()

If the websocket route returns a response the test_client will raise a
:class:`~quart.testing.WebsocketResponseError` exception with a
:attr:`~quart.testing.WebsocketResponseError.response` attribute. For
example,

.. code-block:: python

    test_client = app.test_client()
    try:
        async with test_client.websocket('/ws/') as test_websocket:
            await test_websocket.send(data)
    except WebsocketResponseError as error:
        assert error.response.status_code == 401

Sending and receiving Bytes or String
-------------------------------------

The WebSocket protocol allows for either bytes or strings to be sent
with a frame marker indicating which. The
:meth:`~quart.wrappers.request.Websocket.receive` method will return
either ``bytes`` or ``str`` depending on what the client sent i.e. if
the client sent a string it will be returned from the method. Equally
you can send bytes or strings.

Mixing websocket and HTTP routes
--------------------------------

Quart allows for a route to be defined both as for websockets and for
http requests. This allows responses to be sent depending upon the
type of request (WebSocket upgrade or not). As so,

.. code-block:: python

    @app.route("/ws")
    async def http():
        return "A HTTP request"

    @app.websocket("/ws")
    async def ws():
        ...  # Use the WebSocket

If the http definition is absent Quart will respond with a 400, Bad
Request, response for requests to the missing route (rather than
a 404).
