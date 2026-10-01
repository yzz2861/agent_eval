"""Bind the query string to a dataclass search model.

Try it out::

    $ curl 'http://localhost:8000/search?q=falcon&tags=web&tags=api&page=2&filter[price][min]=10&filter[in_stock]=true'
"""

import dataclasses
from datetime import date
from typing import Optional

import falcon


@dataclasses.dataclass
class PriceFilter:
    """Price range, bound from ``filter[price][min]`` and ``...[max]``."""

    min: Optional[float] = None
    max: Optional[float] = None


@dataclasses.dataclass
class SearchFilters:
    """Nested filters, bound from bracketed parameters."""

    price: Optional[PriceFilter] = None
    in_stock: bool = False


@dataclasses.dataclass
class ProductSearch:
    """Product search model bound from the request's query string."""

    q: str
    page: int = 1
    per_page: int = falcon.query_field(default=20, alias='page_size')
    tags: list[str] = falcon.query_field(default_factory=list)
    updated_since: Optional[date] = falcon.query_field(
        default=None, converter=date.fromisoformat
    )
    filter: Optional[SearchFilters] = None


def describe(query):
    """Render the bound model, showing the type of each field."""
    return {
        field.name: {
            'type': type(getattr(query, field.name)).__name__,
            'value': str(getattr(query, field.name)),
        }
        for field in dataclasses.fields(query)
    }


class SearchResource:
    """Search products (WSGI flavor)."""

    @falcon.bind_query(ProductSearch)
    def on_get(self, req, resp, query):
        # NOTE: At this point, the query string has already been bound to
        #   a validated ProductSearch instance, e.g. "page" is an int and
        #   "tags" is a list of str.
        resp.media = describe(query)


class AsyncSearchResource:
    """Search products (ASGI flavor)."""

    @falcon.bind_query(ProductSearch)
    async def on_get(self, req, resp, query):
        resp.media = describe(query)


app = falcon.App()
app.add_route('/search', SearchResource())
