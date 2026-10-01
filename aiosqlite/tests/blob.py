# Copyright Amethyst Reese
# Licensed under the MIT license

import asyncio
import sqlite3
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import IsolatedAsyncioTestCase, skipUnless

import aiosqlite
from aiosqlite.blob import BLOB_SUPPORT
from .helpers import setup_logger


@skipUnless(BLOB_SUPPORT, "incremental blob IO requires Python 3.11+")
class BlobTest(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        setup_logger()

    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.db = Path(td.name).resolve() / "test.db"

    async def asyncSetUp(self):
        self.conn = await aiosqlite.connect(self.db)
        await self.conn.execute(
            "create table files (id integer primary key, data blob)"
        )
        await self.conn.execute("insert into files (data) values (zeroblob(32))")
        await self.conn.commit()

    async def asyncTearDown(self):
        await self.conn.close()

    async def test_read_write_seek_tell(self):
        async with self.conn.blobopen("files", "data", 1) as blob:
            self.assertIsInstance(blob, aiosqlite.Blob)
            self.assertEqual(len(blob), 32)
            self.assertEqual(await blob.tell(), 0)

            await blob.write(b"hello")
            self.assertEqual(await blob.tell(), 5)

            await blob.seek(0)
            self.assertEqual(await blob.read(5), b"hello")

            await blob.seek(-2, 2)
            await blob.write(b"zz")
            await blob.seek(30)
            self.assertEqual(await blob.read(), b"zz")

        # handle is closed after exiting the context manager
        with self.assertRaises(sqlite3.ProgrammingError):
            await blob.read(1)

    async def test_readonly_rejects_write(self):
        async with self.conn.blobopen("files", "data", 1, readonly=True) as blob:
            self.assertEqual(await blob.read(4), b"\x00" * 4)
            with self.assertRaises(sqlite3.OperationalError):
                await blob.write(b"nope")

    async def test_bounds_and_offsets(self):
        async with self.conn.blobopen("files", "data", 1) as blob:
            with self.assertRaises(ValueError):
                await blob.write(b"x" * 33)
            with self.assertRaises(ValueError):
                await blob.seek(33)
            with self.assertRaises(ValueError):
                await blob.seek(-1)
            with self.assertRaises(ValueError):
                await blob.seek(0, 5)

            # reading past the end returns the remaining bytes only
            await blob.seek(30)
            self.assertEqual(await blob.read(10), b"\x00" * 2)
            self.assertEqual(await blob.read(10), b"")

    async def test_closed_blob_stable_error(self):
        blob = await self.conn.blobopen("files", "data", 1)
        await blob.close()
        await blob.close()  # closing twice is a no-op

        with self.assertRaises(sqlite3.ProgrammingError):
            await blob.read(1)
        with self.assertRaises(sqlite3.ProgrammingError):
            await blob.write(b"x")
        with self.assertRaises(sqlite3.ProgrammingError):
            await blob.seek(0)
        with self.assertRaises(sqlite3.ProgrammingError):
            await blob.tell()
        with self.assertRaises(sqlite3.ProgrammingError):
            len(blob)

        self.assertEqual(len(self.conn._open_blobs), 0)

    async def test_connection_close_closes_all_handles(self):
        blob1 = await self.conn.blobopen("files", "data", 1)
        blob2 = await self.conn.blobopen("files", "data", 1, readonly=True)
        self.assertEqual(len(self.conn._open_blobs), 2)

        await self.conn.close()

        self.assertEqual(len(self.conn._open_blobs), 0)
        for blob in (blob1, blob2):
            with self.assertRaises(sqlite3.ProgrammingError):
                await blob.read(1)
            # closing again after the connection closed is a no-op
            await blob.close()

    async def test_rollback_invalidates_handle(self):
        await self.conn.execute("insert into files (data) values (zeroblob(8))")
        blob = await self.conn.blobopen("files", "data", 1)
        await self.conn.rollback()

        with self.assertRaises(sqlite3.OperationalError):
            await blob.read(1)

        # the handle can still be closed cleanly afterwards
        await blob.close()
        self.assertEqual(len(self.conn._open_blobs), 0)

    async def test_chunked_iteration(self):
        data = bytes(range(256)) * 2
        await self.conn.execute("insert into files (data) values (?)", (data,))
        await self.conn.commit()

        async with self.conn.blobopen("files", "data", 2) as blob:
            chunks = [chunk async for chunk in blob]

        self.assertEqual(b"".join(chunks), data)
        self.assertTrue(all(len(chunk) <= 64 for chunk in chunks))
        self.assertGreater(len(chunks), 1)

    async def test_partial_write_reopen(self):
        async with self.conn.blobopen("files", "data", 1) as blob:
            await blob.write(b"partial")

        async with self.conn.blobopen("files", "data", 1) as blob:
            self.assertEqual(await blob.read(7), b"partial")
            self.assertEqual(await blob.read(), b"\x00" * 25)

    async def test_missing_row_raises(self):
        with self.assertRaises(sqlite3.OperationalError):
            await self.conn.blobopen("files", "data", 999)
        self.assertEqual(len(self.conn._open_blobs), 0)

    async def test_cancel_opening_blob(self):
        created = []

        class TrackingConnection(sqlite3.Connection):
            def blobopen(self, *args, **kwargs):
                blob = super().blobopen(*args, **kwargs)
                created.append(blob)
                return blob

        await self.conn.close()
        self.conn = await aiosqlite.connect(self.db, factory=TrackingConnection)

        # keep the connection thread busy so the open stays pending
        blocker = asyncio.ensure_future(self.conn._execute(time.sleep, 0.3))
        await asyncio.sleep(0)
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(
                self.conn.blobopen("files", "data", 1), timeout=0.05
            )
        await blocker
        # flush the queue so the cleanup runs on the connection thread
        await self.conn.execute("select 1")

        # the leaked handle was closed on the connection thread
        self.assertEqual(len(created), 1)

        def closed_flags():
            flags = []
            for raw in created:
                try:
                    raw.tell()
                    flags.append(False)
                except sqlite3.ProgrammingError:
                    flags.append(True)
            return flags

        self.assertEqual(await self.conn._execute(closed_flags), [True])
        self.assertEqual(len(self.conn._open_blobs), 0)

    async def test_cancel_read_keeps_handle_usable(self):
        async with self.conn.blobopen("files", "data", 1) as blob:
            blocker = asyncio.ensure_future(self.conn._execute(time.sleep, 0.3))
            await asyncio.sleep(0)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(blob.read(4), timeout=0.05)
            await blocker
            self.assertEqual(await blob.read(4), b"\x00" * 4)

        self.assertEqual(len(self.conn._open_blobs), 0)

    async def test_blobopen_on_closed_connection(self):
        await self.conn.close()
        with self.assertRaises(ValueError):
            await self.conn.blobopen("files", "data", 1)
