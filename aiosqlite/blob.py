# Copyright Amethyst Reese
# Licensed under the MIT license

"""
Async proxy for sqlite3 incremental blob IO handles
"""

import sqlite3
from collections.abc import AsyncIterator
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import Connection

#: Whether the running Python supports sqlite3 incremental blob IO (3.11+)
BLOB_SUPPORT = hasattr(sqlite3.Connection, "blobopen")


class Blob:
    """
    Async proxy for a sqlite3 incremental blob IO handle.

    All operations on the underlying sqlite3.Blob object are executed
    on the shared connection's thread. Blob handles follow the lifecycle
    of their connection: closing the connection closes any open handles.
    """

    def __init__(self, conn: "Connection", blob: Any, length: int) -> None:
        self._conn = conn
        self._blob: Optional[Any] = blob
        self._length = length
        self._closed = False
        self.iter_chunk_size = conn._iter_chunk_size

    def _check_open(self) -> None:
        if self._closed or self._blob is None:
            raise sqlite3.ProgrammingError("Cannot operate on a closed blob.")

    async def _execute(self, name: str, *args, **kwargs):
        """Execute the named blob method on the shared connection's thread."""
        self._check_open()
        fn = getattr(self._blob, name)
        return await self._conn._execute(fn, *args, **kwargs)

    async def read(self, length: int = -1) -> bytes:
        """Read at most the given number of bytes from the current position."""
        data: bytes = await self._execute("read", length)
        return data

    async def write(self, data: bytes) -> None:
        """Write the given bytes at the current position."""
        await self._execute("write", data)

    async def seek(self, offset: int, origin: int = 0) -> None:
        """Seek to the given position, relative to the given origin."""
        await self._execute("seek", offset, origin)

    async def tell(self) -> int:
        """Return the current position within the blob."""
        result: int = await self._execute("tell")
        return result

    async def close(self) -> None:
        """Close the blob handle."""
        if self._closed:
            return

        self._closed = True
        self._conn._open_blobs.discard(self)

        blob, self._blob = self._blob, None
        if (
            blob is not None
            and self._conn._running
            and self._conn._connection is not None
        ):
            await self._conn._execute(blob.close)

    def __len__(self) -> int:
        """Return the total size of the blob in bytes."""
        self._check_open()
        return self._length

    def __aiter__(self) -> AsyncIterator[bytes]:
        """Iterate over the blob in chunks from the current position."""
        return self._read_chunked()

    async def _read_chunked(self) -> AsyncIterator[bytes]:
        while True:
            chunk = await self.read(self.iter_chunk_size)
            if not chunk:
                return
            yield chunk

    async def __aenter__(self) -> "Blob":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
