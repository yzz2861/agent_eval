import falcon.asgi

try:
    from .dataclass_query_model import SearchQuery
    from .dataclass_query_model import serialize_search
except ImportError:  # Allow running this recipe as a standalone script.
    from dataclass_query_model import SearchQuery
    from dataclass_query_model import serialize_search


class SearchResource:
    @falcon.bind_query(SearchQuery)
    async def on_get(self, req, resp, query):
        resp.media = serialize_search(query)


app = falcon.asgi.App()
app.add_route('/search', SearchResource())
