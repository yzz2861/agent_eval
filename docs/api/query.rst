.. _query_binding:

Dataclass Query Binding
=====================

.. automodule:: falcon.query
    :members:
    :member-order: groupwise

The bound values are constructed from the request's raw query string. Existing
multi-value access through :attr:`falcon.Request.params` and
:attr:`falcon.asgi.Request.params` is not modified.
