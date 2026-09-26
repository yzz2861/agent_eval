from __future__ import annotations

import tempfile
from typing import BinaryIO

from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_MEMORY_THRESHOLD = 1024 * 1024
DEFAULT_MAX_CACHE_SIZE = 64 * 1024 * 1024
DEFAULT_REPLAY_CHUNK_SIZE = 64 * 1024

BODY_REPLAY_CACHE_SCOPE_KEY = "starlette.body_replay_cache"


class BodyReplayCacheExceeded(RuntimeError):
    """Raised when a request body grows beyond the replay cache hard limit."""


class RequestBodyCache:
    """
    Records a request body while it is consumed from the ASGI receive channel
    exactly once, and replays the cached bytes to any number of later consumers.

    Bodies up to ``memory_threshold`` bytes are kept in memory. Larger bodies
    are rolled over to an unnamed temporary file, so replays of large bodies
    are streamed from disk in ``replay_chunk_size`` chunks instead of being
    loaded back into memory as a whole. The cache never holds more than
    ``max_cache_size`` bytes: once the limit is exceeded, receiving stops and
    ``BodyReplayCacheExceeded`` is raised.
    """

    def __init__(
        self,
        receive: Receive,
        *,
        memory_threshold: int = DEFAULT_MEMORY_THRESHOLD,
        max_cache_size: int = DEFAULT_MAX_CACHE_SIZE,
        temp_dir: str | None = None,
        replay_chunk_size: int = DEFAULT_REPLAY_CHUNK_SIZE,
    ) -> None:
        if memory_threshold < 0:
            raise ValueError("memory_threshold must be a non-negative integer")
        if max_cache_size < 0:
            raise ValueError("max_cache_size must be a non-negative integer")
        if replay_chunk_size < 1:
            raise ValueError("replay_chunk_size must be a positive integer")
        self._receive = receive
        self._memory_threshold = memory_threshold
        self._max_cache_size = max_cache_size
        self._temp_dir = temp_dir
        self._replay_chunk_size = replay_chunk_size
        self._buffer = bytearray()
        self._file: BinaryIO | None = None
        self._size = 0
        self._first_pass_done = False
        self._replay_offset = 0
        self._closed = False

    @property
    def size(self) -> int:
        return self._size

    @property
    def in_memory(self) -> bool:
        return self._file is None

    async def receive(self) -> Message:
        if self._closed:
            raise RuntimeError("The body replay cache has been closed")
        if not self._first_pass_done:
            return await self._receive_and_record()
        return await self._replay()

    async def _receive_and_record(self) -> Message:
        message = await self._receive()
        if message["type"] != "http.request":
            return message
        body = message.get("body", b"")
        if body:
            await self._record(body)
        if not message.get("more_body", False):
            self._first_pass_done = True
        return message

    async def _record(self, body: bytes) -> None:
        self._size += len(body)
        if self._size > self._max_cache_size:
            raise BodyReplayCacheExceeded(
                f"Request body exceeded the replay cache limit of {self._max_cache_size} bytes"
            )
        if self._file is not None:
            await run_in_threadpool(self._file.write, body)
        elif len(self._buffer) + len(body) > self._memory_threshold:
            file = await run_in_threadpool(tempfile.TemporaryFile, mode="w+b", dir=self._temp_dir)
            if self._buffer:
                await run_in_threadpool(file.write, self._buffer)
                self._buffer.clear()
            await run_in_threadpool(file.write, body)
            self._file = file
        else:
            self._buffer += body

    async def _replay(self) -> Message:
        if self._replay_offset < self._size:
            end = min(self._replay_offset + self._replay_chunk_size, self._size)
            chunk = await self._read_slice(self._replay_offset, end - self._replay_offset)
            self._replay_offset = end
            return {"type": "http.request", "body": chunk, "more_body": True}
        # A full replay has been delivered. Rewind so that the next consumer
        # can replay the body from the start.
        self._replay_offset = 0
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _read_slice(self, offset: int, size: int) -> bytes:
        if self._file is None:
            return bytes(self._buffer[offset : offset + size])
        file = self._file

        def read_slice() -> bytes:
            file.seek(offset)
            return file.read(size)

        return await run_in_threadpool(read_slice)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buffer.clear()
        if self._file is not None:
            file, self._file = self._file, None
            await run_in_threadpool(file.close)


class BodyReplayMiddleware:
    """
    Allows the request body to be consumed more than once.

    The wrapped ASGI receive channel records the body as it is read. Once the
    body has been consumed in full, further consumers (for example an endpoint
    calling ``request.stream()`` or ``request.form()`` after a middleware read
    ``request.body()``) are served a replay of the cached bytes instead of an
    exhausted stream. The cache is private to the request and is released as
    soon as the app returns or raises, including client disconnects.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        memory_threshold: int = DEFAULT_MEMORY_THRESHOLD,
        max_cache_size: int = DEFAULT_MAX_CACHE_SIZE,
        temp_dir: str | None = None,
        replay_chunk_size: int = DEFAULT_REPLAY_CHUNK_SIZE,
    ) -> None:
        self.app = app
        self.memory_threshold = memory_threshold
        self.max_cache_size = max_cache_size
        self.temp_dir = temp_dir
        self.replay_chunk_size = replay_chunk_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        cache = RequestBodyCache(
            receive,
            memory_threshold=self.memory_threshold,
            max_cache_size=self.max_cache_size,
            temp_dir=self.temp_dir,
            replay_chunk_size=self.replay_chunk_size,
        )
        scope[BODY_REPLAY_CACHE_SCOPE_KEY] = cache
        try:
            await self.app(scope, cache.receive, send)
        finally:
            scope.pop(BODY_REPLAY_CACHE_SCOPE_KEY, None)
            await cache.aclose()
