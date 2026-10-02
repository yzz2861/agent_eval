from __future__ import annotations

from collections.abc import Callable, Iterable

from hypercorn.app_wrappers import WSGIWrapper
from hypercorn.middleware import AsyncioWSGIMiddleware, TrioWSGIMiddleware


def wsgi_app(environ: dict, start_response: Callable) -> Iterable[bytes]:
    start_response("200 OK", [])
    return [b"ok"]


def test_wsgi_middleware_capacity_config() -> None:
    asyncio_middleware = AsyncioWSGIMiddleware(
        wsgi_app, max_concurrency=2, max_queue_size=3, queue_timeout=4
    )
    trio_middleware = TrioWSGIMiddleware(
        wsgi_app, max_concurrency=2, max_queue_size=3, queue_timeout=4
    )

    for middleware in (asyncio_middleware, trio_middleware):
        assert isinstance(middleware.wsgi_app, WSGIWrapper)
        assert middleware.wsgi_app.concurrency.max_concurrency == 2
        assert middleware.wsgi_app.concurrency.max_queue_size == 3
        assert middleware.wsgi_app.concurrency.queue_timeout == 4
