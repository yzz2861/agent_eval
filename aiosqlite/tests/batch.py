# Copyright Amethyst Reese
# Licensed under the MIT license

import asyncio
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import IsolatedAsyncioTestCase

import aiosqlite
from aiosqlite import BatchExecutionError

from .helpers import setup_logger


class ExecutemanyAsyncTest(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        setup_logger()

    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.db = Path(td.name).resolve() / "test.db"

    async def open_db(self):
        db = await aiosqlite.connect(self.db)
        self.addAsyncCleanup(db.close)
        await db.execute(
            "create table items (id integer primary key, val text unique)"
        )
        await db.commit()
        return db

    async def rows(self, db):
        async with db.execute("select id, val from items order by id") as cursor:
            return await cursor.fetchall()

    async def test_empty_source(self):
        db = await self.open_db()

        async def empty():
            return
            yield  # pragma: no cover

        for atomic in (True, False):
            result = await db.executemany_async(
                "insert into items values (?, ?)", empty(), atomic=atomic
            )
            self.assertEqual(result.batches_completed, 0)
            self.assertEqual(result.rows_written, 0)

        self.assertEqual(await self.rows(db), [])
        self.assertFalse(db.in_transaction)

    async def test_invalid_batch_size(self):
        db = await self.open_db()

        async def source():
            yield (1, "a")  # pragma: no cover

        with self.assertRaises(ValueError):
            await db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=0
            )

    async def test_partial_final_batch(self):
        db = await self.open_db()

        async def source():
            for i in range(7):
                yield (i, f"v{i}")

        result = await db.executemany_async(
            "insert into items values (?, ?)", source(), batch_size=3
        )
        self.assertEqual(result.batches_completed, 3)
        self.assertEqual(result.rows_written, 7)
        self.assertEqual(
            await self.rows(db), [(i, f"v{i}") for i in range(7)]
        )

    async def test_source_error_before_second_batch_atomic(self):
        db = await self.open_db()

        async def source():
            yield (1, "a")
            yield (2, "b")
            raise RuntimeError("source blew up")

        with self.assertRaises(RuntimeError):
            await db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=2
            )

        self.assertEqual(await self.rows(db), [])
        self.assertFalse(db.in_transaction)

    async def test_source_error_before_second_batch_non_atomic(self):
        db = await self.open_db()

        async def source():
            yield (1, "a")
            yield (2, "b")
            raise RuntimeError("source blew up")

        with self.assertRaises(BatchExecutionError) as ctx:
            await db.executemany_async(
                "insert into items values (?, ?)",
                source(),
                batch_size=2,
                atomic=False,
            )

        self.assertEqual(ctx.exception.result.batches_completed, 1)
        self.assertEqual(ctx.exception.result.rows_written, 2)
        self.assertIsInstance(ctx.exception.__cause__, RuntimeError)
        self.assertEqual(await self.rows(db), [(1, "a"), (2, "b")])

    async def test_unique_constraint_atomic(self):
        db = await self.open_db()
        await db.execute("insert into items values (1, 'keep')")
        await db.commit()

        async def source():
            yield (2, "a")
            yield (3, "keep")

        with self.assertRaises(sqlite3.IntegrityError):
            await db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=1
            )

        self.assertEqual(await self.rows(db), [(1, "keep")])

    async def test_unique_constraint_non_atomic(self):
        db = await self.open_db()
        await db.execute("insert into items values (1, 'keep')")
        await db.commit()

        async def source():
            yield (2, "a")
            yield (3, "b")
            yield (4, "keep")

        with self.assertRaises(BatchExecutionError) as ctx:
            await db.executemany_async(
                "insert into items values (?, ?)",
                source(),
                batch_size=2,
                atomic=False,
            )

        self.assertEqual(ctx.exception.result.batches_completed, 1)
        self.assertIsInstance(ctx.exception.__cause__, sqlite3.IntegrityError)
        self.assertEqual(
            await self.rows(db), [(1, "keep"), (2, "a"), (3, "b")]
        )

    async def test_generator_finally_runs_on_write_error(self):
        db = await self.open_db()
        await db.execute("insert into items values (1, 'keep')")
        await db.commit()
        finalized = False

        async def source():
            nonlocal finalized
            try:
                yield (1, "dup")
                yield (2, "b")  # pragma: no cover
            finally:
                finalized = True

        with self.assertRaises(sqlite3.IntegrityError):
            await db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=1
            )

        self.assertTrue(finalized)

    async def test_atomic_rolls_back_only_own_batches(self):
        db = await self.open_db()
        await db.execute("insert into items values (1, 'keep')")
        # deliberately left uncommitted; the call must not commit or
        # roll back this pre-existing transaction

        async def source():
            yield (2, "a")
            yield (3, "keep")

        with self.assertRaises(sqlite3.IntegrityError):
            await db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=1
            )

        self.assertTrue(db.in_transaction)
        await db.commit()
        self.assertEqual(await self.rows(db), [(1, "keep")])

    async def test_atomic_success_does_not_commit_outer_transaction(self):
        db = await self.open_db()
        await db.execute("insert into items values (1, 'keep')")

        async def source():
            yield (2, "a")

        result = await db.executemany_async(
            "insert into items values (?, ?)", source(), batch_size=1
        )

        self.assertEqual(result.batches_completed, 1)
        self.assertTrue(db.in_transaction)
        await db.rollback()
        self.assertEqual(await self.rows(db), [])

    async def test_cancellation_rolls_back_atomic(self):
        db = await self.open_db()
        started = asyncio.Event()
        finalized = False

        async def source():
            nonlocal finalized
            try:
                yield (1, "a")
                yield (2, "b")
                started.set()
                await asyncio.sleep(3600)
            finally:
                finalized = True

        task = asyncio.create_task(
            db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=2
            )
        )
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertTrue(finalized)
        self.assertEqual(await self.rows(db), [])
        self.assertFalse(db.in_transaction)

    async def test_prefetch_is_bounded(self):
        db = await self.open_db()
        await db.execute("insert into items values (1, 'keep')")
        await db.commit()
        pulled = 0

        async def source():
            nonlocal pulled
            for i in range(100):
                pulled += 1
                yield (1, f"dup{i}")

        with self.assertRaises(sqlite3.IntegrityError):
            await db.executemany_async(
                "insert into items values (?, ?)", source(), batch_size=3
            )

        self.assertEqual(pulled, 3)
