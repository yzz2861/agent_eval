.. _cors:

CORS
=====

`Cross Origin Resource Sharing <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>`_
(CORS) is an additional security check performed by modern
browsers to prevent unauthorized requests between different domains.

When developing a web API, it is common to also implement a CORS
policy. Therefore, Falcon provides an easy way to enable a simple CORS policy
via a flag passed to :class:`falcon.App` or :class:`falcon.asgi.App`.

By default, Falcon's built-in CORS support is disabled, so that any cross-origin
requests will be blocked by the browser. Passing ``cors_enable=True`` will
cause the framework to include the necessary response headers to allow access
from any origin to any route in the app. Individual responders may override this
behavior by setting the ``Access-Control-Allow-Origin`` header explicitly.

Whether or not you implement a CORS policy, we recommend also putting a robust
AuthN/Z layer in place to authorize individual clients, as needed, to protect
sensitive resources.

Directly passing the :class:`falcon.CORSMiddleware` middleware to the application
allows customization of the CORS policy applied. The middleware allows customizing
the allowed origins, if credentials should be allowed and if additional headers
can be exposed.

A :class:`~falcon.CORSPolicy` can be attached to a resource or an individual
responder. Fields that are not specified inherit the application's default policy.
Responder policies take precedence over resource policies.

.. code:: python

    class ItemsResource:
        @falcon.CORSPolicy(allow_origins='*', allow_credentials=None)
        def on_get(self, req, resp):
            resp.media = {'items': []}

        @falcon.CORSPolicy(
            allow_origins=['https://admin.example'],
            allow_headers=['X-Admin-Token'],
            allow_credentials='*',
        )
        def on_post(self, req, resp):
            resp.status = falcon.HTTP_204

A resource-wide policy can instead be assigned to its ``cors_policy`` attribute.
Preflight requests always use the policy of the responder named by
``Access-Control-Request-Method``; the policy attached to ``on_options`` is never
used in place of the target method's policy. Falcon publishes only methods that
are both supported by the route and allowed by that policy.

Usage
-----

.. tab-set::

    .. tab-item:: WSGI

        .. code:: python

            import falcon

            # Enable a simple CORS policy for all responses
            app = falcon.App(cors_enable=True)

            # Alternatively, enable CORS policy for example.com and allow
            # credentials
            app = falcon.App(middleware=falcon.CORSMiddleware(
                allow_origins='example.com', allow_credentials='*'))

    .. tab-item:: ASGI

        .. code:: python

            import falcon.asgi

            # Enable a simple CORS policy for all responses
            app = falcon.asgi.App(cors_enable=True)

            # Alternatively, Enable CORS policy for example.com and allow
            # credentials
            app = falcon.asgi.App(middleware=falcon.CORSMiddleware(
                allow_origins='example.com', allow_credentials='*'))

.. note::
    Passing the ``cors_enable`` parameter set to ``True`` is mutually exclusive
    with directly passing an instance of :class:`~falcon.CORSMiddleware` to the
    application's initializer.

    .. versionchanged:: 4.0

       Attempt to use the combination of ``cors_enable=True`` and an additional
       instance of :class:`~falcon.CORSMiddleware` now results in a
       :class:`ValueError`.

CORSMiddleware
--------------

.. autoclass:: falcon.CORSMiddleware

CORSPolicy
----------

.. autoclass:: falcon.CORSPolicy
