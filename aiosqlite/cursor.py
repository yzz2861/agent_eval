# Copyright Amethyst Reese
# Licensed under the MIT license

import sqlite3
from collections.abc import AsyncIterator, Iterable
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import Connection


class Cursor:
    def __init__(self, conn: "Connection", cursor: sqlite3.Cursor) -> None:
        self.iter_chunk_size = conn._iter_chunk_size
        self._conn = conn
        self._cursor = cursor

    def __aiter__(self) -> AsyncIterator[sqlite3.Row]:
        """The cursor proxy is also an async iterator."""
        return self._fetch_chunked()

    async def _fetch_chunked(self):
        while True:
            rows = await self.fetchmany(self.iter_chunk_size)
            if not rows:
                return
            for row in rows:
                yield row

    async def _execute(self, fn, *args, timeout=None, **kwargs):
        """Execute the given function on the shared connection's thread."""
        return await self._conn._execute(fn, *args, timeout=timeout, **kwargs)

    async def execute(
        self,
        sql: str,
        parameters: Optional[Iterable[Any]] = None,
        *,
        timeout: Optional[float] = None,
    ) -> "Cursor":
        """Execute the given query."""
        if parameters is None:
            parameters = []
        await self._execute(
            self._cursor.execute, sql, parameters, timeout=timeout
        )
        return self

    async def executemany(
        self,
        sql: str,
        parameters: Iterable[Iterable[Any]],
        *,
        timeout: Optional[float] = None,
    ) -> "Cursor":
        """Execute the given multiquery."""
        await self._execute(
            self._cursor.executemany, sql, parameters, timeout=timeout
        )
        return self

    async def executescript(
        self, sql_script: str, *, timeout: Optional[float] = None
    ) -> "Cursor":
        """Execute a user script."""
        await self._execute(
            self._cursor.executescript, sql_script, timeout=timeout
        )
        return self

    async def fetchone(
        self, *, timeout: Optional[float] = None
    ) -> Optional[sqlite3.Row]:
        """Fetch a single row."""
        return await self._execute(self._cursor.fetchone, timeout=timeout)

    async def fetchmany(
        self, size: Optional[int] = None, *, timeout: Optional[float] = None
    ) -> Iterable[sqlite3.Row]:
        """Fetch up to `cursor.arraysize` number of rows."""
        args: tuple[int, ...] = ()
        if size is not None:
            args = (size,)
        return await self._execute(self._cursor.fetchmany, *args, timeout=timeout)

    async def fetchall(
        self, *, timeout: Optional[float] = None
    ) -> Iterable[sqlite3.Row]:
        """Fetch all remaining rows."""
        return await self._execute(self._cursor.fetchall, timeout=timeout)

    async def close(self, *, timeout: Optional[float] = None) -> None:
        """Close the cursor."""
        await self._execute(self._cursor.close, timeout=timeout)

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def lastrowid(self) -> Optional[int]:
        return self._cursor.lastrowid

    @property
    def arraysize(self) -> int:
        return self._cursor.arraysize

    @arraysize.setter
    def arraysize(self, value: int) -> None:
        self._cursor.arraysize = value

    @property
    def description(self) -> tuple[tuple[str, None, None, None, None, None, None], ...]:
        return self._cursor.description

    @property
    def row_factory(self) -> Optional[Callable[[sqlite3.Cursor, sqlite3.Row], object]]:
        return self._cursor.row_factory

    @row_factory.setter
    def row_factory(self, factory: Optional[type]) -> None:
        self._cursor.row_factory = factory

    @property
    def connection(self) -> sqlite3.Connection:
        return self._cursor.connection

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
