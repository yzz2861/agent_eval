from __future__ import annotations

import asyncio

from deprecated.sphinx import versionadded

from limits.aio.storage.base import (
    MovingWindowSupport,
    SlidingWindowCounterSupport,
    Storage,
)
from limits.storage.sqlite import LockTimeoutError
from limits.storage.sqlite import SQLiteStorage as SyncSQLiteStorage

__all__ = ["LockTimeoutError", "SQLiteStorage"]


@versionadded(version="5.9")
class SQLiteStorage(Storage, MovingWindowSupport, SlidingWindowCounterSupport):
    """
    Async rate limit storage backed by a local sqlite database.

    This is a thin asynchronous facade over
    :class:`limits.storage.sqlite.SQLiteStorage`: every operation is
    dispatched to a worker thread with :func:`asyncio.to_thread` so that
    waiting for the database lock never blocks the event loop.
    """

    STORAGE_SCHEME = ["async+sqlite"]
    """The storage scheme for sqlite in an async context"""

    def __init__(
        self,
        uri: str,
        timeout: float = SyncSQLiteStorage.DEFAULT_TIMEOUT,
        cleanup_interval: float = SyncSQLiteStorage.DEFAULT_CLEANUP_INTERVAL,
        cleanup_batch_size: int = SyncSQLiteStorage.DEFAULT_CLEANUP_BATCH_SIZE,
        wrap_exceptions: bool = False,
        **options: float | str | bool,
    ) -> None:
        """
        :param uri: uri of the form ``async+sqlite:///path/to/limits.db``
        :param timeout: maximum number of seconds to wait when the
         database is locked by another process before raising
         :class:`limits.storage.sqlite.LockTimeoutError`.
        :param cleanup_interval: minimum number of seconds between two
         automatic cleanups of expired rows.
        :param cleanup_batch_size: maximum number of expired rows deleted
         in a single transaction during cleanup.
        :param wrap_exceptions: Whether to wrap storage exceptions in
         :exc:`limits.errors.StorageError` before raising it.
        :param options: all remaining keyword arguments are passed to
         :class:`limits.storage.sqlite.SQLiteStorage`
        """
        super().__init__(uri, wrap_exceptions=wrap_exceptions, **options)
        self._storage = SyncSQLiteStorage(
            uri,
            timeout=timeout,
            cleanup_interval=cleanup_interval,
            cleanup_batch_size=cleanup_batch_size,
            wrap_exceptions=wrap_exceptions,
            **options,
        )

    @property
    def base_exceptions(self) -> type[Exception] | tuple[type[Exception], ...]:
        return self._storage.base_exceptions

    async def incr(self, key: str, expiry: int, amount: int = 1) -> int:
        """
        increments the counter for a given rate limit key

        :param key: the key to increment
        :param expiry: amount in seconds for the key to expire in
        :param amount: the number to increment by
        """
        return await asyncio.to_thread(self._storage.incr, key, expiry, amount)

    async def get(self, key: str) -> int:
        """
        :param key: the key to get the counter value for
        """
        return await asyncio.to_thread(self._storage.get, key)

    async def get_expiry(self, key: str) -> float:
        """
        :param key: the key to get the expiry for
        """
        return await asyncio.to_thread(self._storage.get_expiry, key)

    async def check(self) -> bool:
        """
        check if storage is healthy
        """
        return await asyncio.to_thread(self._storage.check)

    async def reset(self) -> int | None:
        """
        reset storage to clear limits
        """
        return await asyncio.to_thread(self._storage.reset)

    async def clear(self, key: str) -> None:
        """
        resets the rate limit key

        :param key: the key to clear rate limits for
        """
        return await asyncio.to_thread(self._storage.clear, key)

    async def acquire_entry(
        self, key: str, limit: int, expiry: int, amount: int = 1
    ) -> bool:
        """
        :param key: rate limit key to acquire an entry in
        :param limit: amount of entries allowed
        :param expiry: expiry of the entry
        :param amount: the number of entries to acquire
        """
        return await asyncio.to_thread(
            self._storage.acquire_entry, key, limit, expiry, amount
        )

    async def get_moving_window(
        self, key: str, limit: int, expiry: int
    ) -> tuple[float, int]:
        """
        returns the starting point and the number of entries in the moving
        window

        :param key: rate limit key
        :param expiry: expiry of entry
        :return: (start of window, number of acquired entries)
        """
        return await asyncio.to_thread(
            self._storage.get_moving_window, key, limit, expiry
        )

    async def acquire_sliding_window_entry(
        self, key: str, limit: int, expiry: int, amount: int = 1
    ) -> bool:
        """
        Acquire an entry if the weighted count of the current and previous
        windows is less than or equal to the limit

        :param key: rate limit key to acquire an entry in
        :param limit: amount of entries allowed
        :param expiry: expiry of the entry
        :param amount: the number of entries to acquire
        """
        return await asyncio.to_thread(
            self._storage.acquire_sliding_window_entry, key, limit, expiry, amount
        )

    async def get_sliding_window(
        self, key: str, expiry: int
    ) -> tuple[int, float, int, float]:
        """
        Return the previous and current window information.

        :param key: the rate limit key
        :param expiry: the rate limit expiry
        :return: (previous count, previous ttl, current count, current ttl)
        """
        return await asyncio.to_thread(self._storage.get_sliding_window, key, expiry)

    async def clear_sliding_window(self, key: str, expiry: int) -> None:
        """
        Resets the rate limit key(s) for the sliding window

        :param key: the key to clear rate limits for
        :param expiry: the rate limit expiry
        """
        return await asyncio.to_thread(self._storage.clear_sliding_window, key, expiry)
