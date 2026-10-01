Dataclass Query Models
========================

Use :func:`falcon.bind_query` to parse a request's query string into a dataclass
before a responder runs. Scalars, optional values, repeated list parameters, and nested
dataclasses are supported. The same model and query string produce the same bound values
under WSGI and ASGI.

.. literalinclude:: ../../../examples/recipes/dataclass_query_model.py
    :language: python

.. tab-set::

    .. tab-item:: WSGI
        :sync: wsgi

        .. literalinclude:: ../../../examples/recipes/dataclass_query_wsgi.py
            :language: python

    .. tab-item:: ASGI
        :sync: asgi

        .. literalinclude:: ../../../examples/recipes/dataclass_query_asgi.py
            :language: python

For example, this query string::

    /search?q=falcon&page=2&active=true&tags=python&tags=web&
        created-on=2026-10-01&filter[price][min]=10&filter[price][max]=50

binds to:

.. code:: json

    {
        "q": "falcon",
        "page": 2,
        "active": true,
        "tags": ["python", "web"],
        "created_on": "2026-10-01",
        "filter": {
            "price": {
                "min": 10,
                "max": 50
            }
        }
    }

Repeated parameters bind to lists. ``tags=`` is a list containing one empty string,
while a lone ``tags[]=`` explicitly binds an empty list. Mixing those forms, or mixing
an object and a scalar at the same path such as ``a=1&a[b]=2``, raises
:class:`falcon.QueryBindingError`. Error objects include the failing parameter path, and the
number reported can be bounded with ``max_errors``. Unknown parameters are rejected by
default; pass ``unknown='ignore'`` to skip them.
