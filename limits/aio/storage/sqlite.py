from __future__ import annotations

import asyncio
from typing import Any

from deprecated.sphinx import versionadded

from limits.storage import sqlite as sqlite_backend

from .base import (
    MovingWindowSupport,
    SlidingWindowCounterSupport,
    Storage,
)


@versionadded(version="5.9")
class SQLiteStorage(Storage, MovingWindowSupport, SlidingWindowCounterSupport):
    """
    Async SQLite storage.

    Every blocking SQLite operation runs in a worker thread, so event loops
    do not wait on database locks.
    """

    STORAGE_SCHEME = ["async+sqlite"]

    def __init__(
        self,
        uri: str | None = None,
        wrap_exceptions: bool = False,
        **options: Any,
    ) -> None:
        super().__init__(uri, wrap_exceptions=wrap_exceptions, **options)
        self._uri = uri
        self._options = options
        self._wrap_exceptions = wrap_exceptions
        self._storage: sqlite_backend.SQLiteStorage | None = None
        self._init_lock: asyncio.Lock | None = None

    async def _get_storage(self) -> sqlite_backend.SQLiteStorage:
        if self._storage is None:
            if self._init_lock is None:
                self._init_lock = asyncio.Lock()
            async with self._init_lock:
                if self._storage is None:
                    self._storage = await asyncio.to_thread(
                        sqlite_backend.SQLiteStorage,
                        self._uri,
                        self._wrap_exceptions,
                        **self._options,
                    )
        return self._storage

    @property
    def base_exceptions(
        self,
    ) -> type[Exception] | tuple[type[Exception], ...]:
        if self._storage is None:
            import sqlite3
            return sqlite3.Error
        return self._storage.base_exceptions

    async def incr(self, key: str, expiry: int, amount: int = 1) -> int:
        storage = await self._get_storage()
        return await asyncio.to_thread(storage.incr, key, expiry, amount)

    async def get(self, key: str) -> int:
        storage = await self._get_storage()
        return await asyncio.to_thread(storage.get, key)

    async def get_expiry(self, key: str) -> float:
        storage = await self._get_storage()
        return await asyncio.to_thread(storage.get_expiry, key)

    async def check(self) -> bool:
        storage = await self._get_storage()
        return await asyncio.to_thread(storage.check)

    async def reset(self) -> int | None:
        storage = await self._get_storage()
        return await asyncio.to_thread(storage.reset)

    async def clear(self, key: str) -> None:
        storage = await self._get_storage()
        await asyncio.to_thread(storage.clear, key)

    async def acquire_entry(
        self,
        key: str,
        limit: int,
        expiry: int,
        amount: int = 1,
    ) -> bool:
        storage = await self._get_storage()
        return await asyncio.to_thread(
            storage.acquire_entry, key, limit, expiry, amount
        )

    async def get_moving_window(
        self, key: str, limit: int, expiry: int
    ) -> tuple[float, int]:
        storage = await self._get_storage()
        return await asyncio.to_thread(
            storage.get_moving_window, key, limit, expiry
        )

    async def acquire_sliding_window_entry(
        self,
        key: str,
        limit: int,
        expiry: int,
        amount: int = 1,
    ) -> bool:
        storage = await self._get_storage()
        return await asyncio.to_thread(
            storage.acquire_sliding_window_entry,
            key,
            limit,
            expiry,
            amount,
        )

    async def get_sliding_window(
        self, key: str, expiry: int
    ) -> tuple[int, float, int, float]:
        storage = await self._get_storage()
        return await asyncio.to_thread(
            storage.get_sliding_window, key, expiry
        )

    async def clear_sliding_window(self, key: str, expiry: int) -> None:
        storage = await self._get_storage()
        await asyncio.to_thread(storage.clear_sliding_window, key, expiry)
