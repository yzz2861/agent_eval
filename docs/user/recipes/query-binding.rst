.. _query-binding:

Binding Query Parameters to a Dataclass
=======================================

For resources that accept many query string parameters, it can be convenient
to declare the expected shape once, as a :mod:`dataclasses` model, and let
the framework parse, convert, and validate the parameters before the
responder is invoked. The :func:`@falcon.bind_query <falcon.bind_query>`
decorator does exactly that, for both WSGI and ASGI responders:

.. literalinclude:: ../../../examples/recipes/query_binding_main.py
    :language: python

The binder understands the following parameter shapes:

*   **Scalars** are converted to the annotated type (``str``, ``int``,
    ``float``, ``bool``, or a custom ``converter`` callable supplied via
    :func:`~falcon.query_field`), e.g. ``page=2``.
*   **Lists** are built from repeated parameters, e.g. ``tags=a&tags=b``.
    A single empty value (``tags=``) yields a list containing one empty
    string, while the explicit marker ``tags[]=`` (on its own) yields an
    empty list. Mixing the two shapes for the same parameter is an error.
*   **Nested dataclasses** are addressed with bracketed keys, e.g.
    ``filter[price][min]=10``.
*   **Optional fields** default to ``None`` when the parameter is missing;
    other fields may declare a default (or default factory) with
    :func:`~falcon.query_field`, and a field may be renamed with an
    ``alias``.

Assuming the app from the example above is running, the bound types can be
inspected directly::

    $ curl 'http://localhost:8000/search?q=falcon&tags=web&tags=api&page=2&filter[price][min]=10&filter[in_stock]=true'
    {
        "q": {"type": "str", "value": "falcon"},
        "page": {"type": "int", "value": "2"},
        "per_page": {"type": "int", "value": "20"},
        "tags": {"type": "list", "value": "['web', 'api']"},
        "updated_since": {"type": "NoneType", "value": "None"},
        "filter": {"type": "SearchFilters", "value": "SearchFilters(price=PriceFilter(min=10.0, max=None), in_stock=True)"}
    }

When the query string cannot be bound, the responder is not called and the
client receives an HTTP 400 (:class:`~falcon.QueryBindingError`) response
listing the offending parameter paths, for instance::

    $ curl 'http://localhost:8000/search?page=abc&bogus=1'
    {
        "title": "Invalid query parameter",
        "description": "q: missing required parameter\npage: could not convert 'abc': invalid literal for int() with base 10: 'abc'\nbogus: unknown parameter"
    }

Conflicting shapes for the same parameter prefix, such as ``a=1&a[b]=2``,
are likewise rejected rather than silently resolved.

By default, unknown parameters are rejected; pass ``strict=False`` to
:func:`~falcon.bind_query <falcon.bind_query>` to ignore them instead. The
number of parameters, the bracket nesting depth, and the number of collected
errors can be capped with the ``max_params``, ``max_depth``, and
``max_errors`` options, respectively.

.. note::
    Binding never modifies the request's own parsed parameters
    (:attr:`req.params <falcon.Request.params>`); the query string is parsed
    independently for this purpose.
