from __future__ import annotations

from starlette.requests import BODY_REPLAY_CACHE_SCOPE_KEY, BodyReplayLimitExceeded, RequestBodyCache
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodyReplayMiddleware:
    """
    Cache the request body so that it can be consumed more than once.

    This is useful when a middleware (for example, a signature verification
    middleware) needs to read the body before the endpoint consumes it again
    with `stream()` or `form()`. Bodies up to `spool_threshold` bytes are
    cached in memory; larger bodies are spooled to a temporary file.

    The cache is private to the request, is removed from the scope when the
    request finishes, and its temporary file is released on completion, on
    client disconnect, and on error.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        spool_threshold: int = 1024 * 1024,
        max_cache_size: int | None = None,
        replay_chunk_size: int = 64 * 1024,
        temp_dir: str | None = None,
    ) -> None:
        self.app = app
        self.spool_threshold = spool_threshold
        self.max_cache_size = max_cache_size
        self.replay_chunk_size = replay_chunk_size
        self.temp_dir = temp_dir

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get(BODY_REPLAY_CACHE_SCOPE_KEY) is not None:
            await self.app(scope, receive, send)
            return

        cache = RequestBodyCache(
            receive,
            spool_threshold=self.spool_threshold,
            max_cache_size=self.max_cache_size,
            replay_chunk_size=self.replay_chunk_size,
            temp_dir=self.temp_dir,
        )
        scope[BODY_REPLAY_CACHE_SCOPE_KEY] = cache
        response_started = False

        async def send_with_tracking(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, send_with_tracking)
        except BodyReplayLimitExceeded:
            if response_started:
                raise
            response = PlainTextResponse("Content Too Large", status_code=413)
            await response(scope, receive, send)
        finally:
            scope.pop(BODY_REPLAY_CACHE_SCOPE_KEY, None)
            await cache.close()
