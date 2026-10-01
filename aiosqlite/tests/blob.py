# Copyright Amethyst Reese
# Licensed under the MIT license

import asyncio
import os
import sqlite3
import unittest
from threading import Event
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import aiosqlite

from .helpers import setup_logger


@unittest.skipUnless(
    hasattr(sqlite3.Connection, "blobopen"),
    "sqlite3.Connection.blobopen requires Python 3.12 or newer",
)
class BlobTest(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        setup_logger()

    async def _create_blob_row(self, db, data=b"abcdefghij"):
        await db.execute("create table test_blob (data blob)")
        row = await db.execute_insert("insert into test_blob (data) values (?)", [data])
        await db.commit()
        return row[0]

    async def test_blob_read_write_seek_and_context(self):
        async with aiosqlite.connect(":memory:") as db:
            rowid = await self._create_blob_row(db)

            async with db.blobopen("test_blob", "data", rowid) as blob:
                self.assertEqual(len(blob), 10)
                self.assertFalse(blob.closed)

                self.assertEqual(await blob.read(3), b"abc")
                self.assertEqual(await blob.tell(), 3)

                await blob.seek(0, os.SEEK_END)
                self.assertEqual(await blob.tell(), 10)
                await blob.seek(-8, os.SEEK_END)
                self.assertEqual(await blob.read(100), b"cdefghij")

                await blob.seek(2)
                await blob.write(b"XYZ")
                await blob.seek(0)
                self.assertEqual(await blob.read(), b"abXYZfghij")

        self.assertTrue(blob.closed)

    async def test_partial_write_persists_after_reopen(self):
        async with aiosqlite.connect(":memory:") as db:
            rowid = await self._create_blob_row(db)

            blob = await db.blobopen("test_blob", "data", rowid)
            await blob.seek(2)
            await blob.write(b"XY")
            await blob.close()
            await db.commit()

            async with db.blobopen("test_blob", "data", rowid) as reopened:
                self.assertEqual(await reopened.read(), b"abXYefghij")

    async def test_readonly_blob_rejects_writes(self):
        async with aiosqlite.connect(":memory:") as db:
            rowid = await self._create_blob_row(db)

            async with db.blobopen("test_blob", "data", rowid, readonly=True) as blob:
                with self.assertRaisesRegex(
                    sqlite3.OperationalError, "attempt to write a readonly database"
                ):
                    await blob.write(b"x")

                self.assertEqual(await blob.tell(), 0)

            row = await db.execute_fetchall("select data from test_blob")
            self.assertEqual(row, [(b"abcdefghij",)])

    async def test_fixed_length_and_offset_errors_keep_sqlite_meaning(self):
        async with aiosqlite.connect(":memory:") as db:
            rowid = await self._create_blob_row(db)

            async with db.blobopen("test_blob", "data", rowid) as blob:
                await blob.seek(9)
                with self.assertRaisesRegex(ValueError, "data longer than blob length"):
                    await blob.write(b"xy")
                self.assertEqual(await blob.tell(), 9)

                await blob.seek(0)
                with self.assertRaisesRegex(ValueError, "offset out of blob range"):
                    await blob.seek(11)
                self.assertEqual(await blob.tell(), 0)

                with self.assertRaisesRegex(
                    ValueError, "'origin' should be os.SEEK_SET"
                ):
                    await blob.seek(0, 42)

    async def test_async_iteration_uses_finite_chunks(self):
        async with aiosqlite.connect(":memory:", iter_chunk_size=3) as db:
            rowid = await self._create_blob_row(db)
            async with db.blobopen("test_blob", "data", rowid) as blob:
                chunks = [chunk async for chunk in blob]
                await blob.seek(0)
                explicit = [chunk async for chunk in blob.iter_chunks(4)]

        self.assertEqual(chunks, [b"abc", b"def", b"ghi", b"j"])
        self.assertEqual(explicit, [b"abcd", b"efgh", b"ij"])

    async def test_rollback_closes_open_blobs(self):
        async with aiosqlite.connect(":memory:", isolation_level=None) as db:
            rowid = await self._create_blob_row(db)
            await db.execute("BEGIN")

            blob = await db.blobopen("test_blob", "data", rowid)
            await blob.write(b"XY")
            await db.rollback()

            self.assertTrue(blob.closed)
            for operation in (
                lambda: blob.read(),
                lambda: blob.write(b"z"),
                lambda: blob.seek(0),
                lambda: blob.tell(),
            ):
                with self.assertRaisesRegex(ValueError, "Blob closed"):
                    await operation()

            with self.assertRaisesRegex(ValueError, "Blob closed"):
                len(blob)

            await blob.close()
            row = await db.execute_fetchall("select data from test_blob")
            self.assertEqual(row, [(b"abcdefghij",)])

    async def test_sql_rollback_closes_open_blob(self):
        statements = []
        async with aiosqlite.connect(":memory:", isolation_level=None) as db:
            rowid = await self._create_blob_row(db)
            await db.set_trace_callback(statements.append)
            await db.execute("BEGIN")

            blob = await db.blobopen("test_blob", "data", rowid)
            await blob.write(b"XY")
            await db.execute("ROLLBACK")

            with self.assertRaisesRegex(ValueError, "Blob closed"):
                await blob.read()
            self.assertIn("ROLLBACK", [statement.upper() for statement in statements])

            await db.execute("SELECT 1")
            self.assertTrue(statements)

    async def test_savepoint_rollback_closes_open_blob(self):
        async with aiosqlite.connect(":memory:", isolation_level=None) as db:
            rowid = await self._create_blob_row(db)
            await db.execute("BEGIN")
            await db.execute("SAVEPOINT blob_write")
            blob = await db.blobopen("test_blob", "data", rowid)
            await blob.write(b"XY")
            await db.execute("ROLLBACK TO SAVEPOINT blob_write")

            with self.assertRaisesRegex(ValueError, "Blob closed"):
                await blob.read()
            row = await db.execute_fetchall("select data from test_blob")
            self.assertEqual(row, [(b"abcdefghij",)])

    async def test_connection_close_closes_multiple_blobs(self):
        db = await aiosqlite.connect(":memory:")
        rowid = await self._create_blob_row(db)
        first = await db.blobopen("test_blob", "data", rowid)
        second = await db.blobopen("test_blob", "data", rowid, readonly=True)

        await db.close()

        self.assertTrue(first.closed)
        self.assertTrue(second.closed)
        for blob in (first, second):
            with self.assertRaisesRegex(ValueError, "Blob closed"):
                await blob.read()
            await blob.close()

    async def test_cancelled_open_closes_native_blob(self):
        async with aiosqlite.connect(":memory:") as db:
            rowid = await self._create_blob_row(db)
            started = Event()
            release = Event()
            closed = Event()
            original_connection = db._conn

            class TrackingBlob:
                def __init__(self, raw_blob):
                    self.raw_blob = raw_blob

                def read(self, length=-1):
                    return self.raw_blob.read(length)

                def write(self, data):
                    self.raw_blob.write(data)

                def seek(self, offset, origin=os.SEEK_SET):
                    self.raw_blob.seek(offset, origin)

                def tell(self):
                    return self.raw_blob.tell()

                def __len__(self):
                    return len(self.raw_blob)

                def close(self):
                    closed.set()
                    self.raw_blob.close()

            def blocking_blobopen(table, column, row, *, name, readonly):
                started.set()
                self.assertTrue(release.wait(5))
                raw_blob = sqlite3.Connection.blobopen(
                    original_connection,
                    table,
                    column,
                    row,
                    name=name,
                    readonly=readonly,
                )
                return TrackingBlob(raw_blob)

            with patch.object(db, "_open_blob", side_effect=blocking_blobopen):
                task = asyncio.ensure_future(db.blobopen("test_blob", "data", rowid))
                self.assertTrue(
                    await asyncio.wait_for(asyncio.to_thread(started.wait, 5), 6)
                )

                task.cancel()
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task

                self.assertTrue(
                    await asyncio.wait_for(asyncio.to_thread(closed.wait, 5), 6)
                )

            async with db.execute("select 1") as cursor:
                self.assertEqual(await cursor.fetchone(), (1,))

    async def test_cancelled_completed_open_closes_native_blob(self):
        async with aiosqlite.connect(":memory:") as db:
            rowid = await self._create_blob_row(db)
            task = asyncio.ensure_future(db.blobopen("test_blob", "data", rowid))
            await asyncio.sleep(0)
            task.cancel()

            with self.assertRaises(asyncio.CancelledError):
                await task

            await asyncio.sleep(0)
            self.assertFalse(db._blobs)

            async with db.execute("select 1") as cursor:
                self.assertEqual(await cursor.fetchone(), (1,))
