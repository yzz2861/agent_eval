# Copyright Amethyst Reese
# Licensed under the MIT license

import os
import sys
from collections.abc import AsyncIterator
from typing import Any, Optional, TYPE_CHECKING

if sys.version_info >= (3, 12):
    from sqlite3 import Blob as _SQLiteBlob
else:
    _SQLiteBlob = Any

if TYPE_CHECKING:
    from .core import Connection


class Blob:
    def __init__(
        self,
        connection: "Connection",
        blob: _SQLiteBlob,
        length: int,
        iter_chunk_size: int,
    ) -> None:
        self._connection = connection
        self._blob: Optional[_SQLiteBlob] = blob
        self._length = length
        self._iter_chunk_size = iter_chunk_size
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def __len__(self) -> int:
        if self._closed:
            raise ValueError("Blob closed")
        return self._length

    async def _execute(self, fn, *args, **kwargs):
        if self._closed:
            raise ValueError("Blob closed")
        return await self._connection._execute(fn, *args, **kwargs)

    def _call(self, method: str, *args: Any):
        blob = self._blob
        if blob is None:
            raise ValueError("Blob closed")
        return getattr(blob, method)(*args)

    async def read(self, length: int = -1) -> bytes:
        """Read up to ``length`` bytes from the current BLOB offset."""
        if self._blob is None:
            raise ValueError("Blob closed")
        return await self._execute(self._call, "read", length)

    async def write(self, data: bytes) -> None:
        """Write bytes at the current BLOB offset without changing its length."""
        if self._blob is None:
            raise ValueError("Blob closed")
        await self._execute(self._call, "write", data)

    async def seek(self, offset: int, origin: int = os.SEEK_SET) -> None:
        """Move the BLOB position to ``offset`` relative to ``origin``."""
        if self._blob is None:
            raise ValueError("Blob closed")
        await self._execute(self._call, "seek", offset, origin)

    async def tell(self) -> int:
        """Return the current BLOB position."""
        if self._blob is None:
            raise ValueError("Blob closed")
        return await self._execute(self._call, "tell")

    async def close(self) -> None:
        """Close the BLOB."""
        if self._closed:
            return

        self._closed = True
        await self._connection._close_blob_async(self)

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self.iter_chunks()

    async def iter_chunks(
        self, chunk_size: Optional[int] = None
    ) -> AsyncIterator[bytes]:
        if chunk_size is None:
            chunk_size = self._iter_chunk_size
        while True:
            chunk = await self.read(chunk_size)
            if not chunk:
                return
            yield chunk

    async def __aenter__(self) -> "Blob":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
