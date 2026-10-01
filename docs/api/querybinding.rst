.. _querybinding:

Query Parameter Binding
=======================

Falcon can bind the request's query string to a
:mod:`dataclasses` model before the responder is invoked, using the
:func:`@falcon.bind_query <falcon.bind_query>` decorator:

.. code:: python

    import dataclasses
    from typing import Optional

    import falcon


    @dataclasses.dataclass
    class PriceFilter:
        min: Optional[float] = None
        max: Optional[float] = None


    @dataclasses.dataclass
    class SearchQuery:
        q: str
        page: int = 1
        tags: list[str] = falcon.query_field(default_factory=list)
        filter: Optional[PriceFilter] = None


    class SearchResource:
        @falcon.bind_query(SearchQuery)
        def on_get(self, req, resp, query):
            resp.media = dataclasses.asdict(query)

See also the :ref:`query-binding` recipe for a more complete example,
including nested models, custom converters, and error handling.

Binding Decorator
-----------------

.. autofunction:: falcon.bind_query

Field Metadata
--------------

.. autofunction:: falcon.query_field

Errors
------

.. autoclass:: falcon.QueryBindingError
    :members:

.. autoclass:: falcon.QueryParamError
    :members:
