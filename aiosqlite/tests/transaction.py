# Copyright Amethyst Reese
# Licensed under the MIT license

import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import IsolatedAsyncioTestCase

import aiosqlite

from .helpers import setup_logger


class TransactionTest(IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        setup_logger()

    def setUp(self):
        td = TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.db = Path(td.name).resolve() / "test.db"

    async def fetch_values(self, db):
        async with db.execute("select i from t order by i") as cursor:
            return [row[0] for row in await cursor.fetchall()]

    async def test_transaction_commit_on_success(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            async with db.transaction():
                await db.execute("insert into t values (1)")
                await db.execute("insert into t values (2)")

            self.assertEqual(await self.fetch_values(db), [1, 2])

    async def test_transaction_rollback_on_exception(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            with self.assertRaises(ValueError):
                async with db.transaction():
                    await db.execute("insert into t values (1)")
                    raise ValueError("boom")

            self.assertEqual(await self.fetch_values(db), [])

    async def test_transaction_nested_savepoint_rolls_back_inner_only(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            async with db.transaction():
                await db.execute("insert into t values (1)")
                with self.assertRaises(ValueError):
                    async with db.transaction():
                        await db.execute("insert into t values (2)")
                        raise ValueError("boom")
                await db.execute("insert into t values (3)")

            self.assertEqual(await self.fetch_values(db), [1, 3])

    async def test_transaction_nested_savepoint_released_then_outer_rollback(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            with self.assertRaises(ValueError):
                async with db.transaction():
                    await db.execute("insert into t values (1)")
                    async with db.transaction():
                        await db.execute("insert into t values (2)")
                    raise ValueError("boom")

            self.assertEqual(await self.fetch_values(db), [])

    async def test_transaction_isolation_level_begin(self):
        async with aiosqlite.connect(self.db, isolation_level="IMMEDIATE") as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            async with db.transaction():
                self.assertTrue(db.in_transaction)
                await db.execute("insert into t values (1)")

            self.assertFalse(db.in_transaction)
            self.assertEqual(await self.fetch_values(db), [1])

    async def test_transaction_blocks_other_tasks_until_exit(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            entered = asyncio.Event()
            finish = asyncio.Event()

            async def holder():
                with self.assertRaises(ValueError):
                    async with db.transaction():
                        await db.execute("insert into t values (1)")
                        entered.set()
                        await finish.wait()
                        raise ValueError("rollback")

            async def waiter():
                await entered.wait()
                # This execute must wait for the transaction above to exit,
                # then establish its own transaction boundary.
                await db.execute("insert into t values (2)")
                await db.commit()

            holder_task = asyncio.create_task(holder())
            waiter_task = asyncio.create_task(waiter())
            await entered.wait()
            await asyncio.sleep(0.1)
            self.assertFalse(waiter_task.done())

            finish.set()
            await asyncio.gather(holder_task, waiter_task)

            # holder rolled back, so only the waiter's row exists
            self.assertEqual(await self.fetch_values(db), [2])

    async def test_transaction_commit_rollback_executescript_guarded(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            async with db.transaction():
                with self.assertRaises(RuntimeError):
                    await db.commit()
                with self.assertRaises(RuntimeError):
                    await db.rollback()
                with self.assertRaises(RuntimeError):
                    await db.executescript("insert into t values (1)")

            # after the context exits, direct calls work again
            await db.execute("insert into t values (1)")
            await db.commit()
            self.assertEqual(await self.fetch_values(db), [1])

    async def test_transaction_owner_cancellation_rolls_back_and_unlocks(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            entered = asyncio.Event()

            async def holder():
                async with db.transaction():
                    await db.execute("insert into t values (1)")
                    entered.set()
                    await asyncio.sleep(60)

            task = asyncio.create_task(holder())
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            # rollback completed and the connection is usable again
            self.assertEqual(await self.fetch_values(db), [])
            async with db.transaction():
                await db.execute("insert into t values (2)")
            self.assertEqual(await self.fetch_values(db), [2])

    async def test_transaction_waiter_cancellation_does_not_affect_owner(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            entered = asyncio.Event()
            finish = asyncio.Event()

            async def holder():
                async with db.transaction():
                    await db.execute("insert into t values (1)")
                    entered.set()
                    await finish.wait()

            async def waiter():
                await entered.wait()
                await db.execute("insert into t values (2)")

            holder_task = asyncio.create_task(holder())
            waiter_task = asyncio.create_task(waiter())
            await entered.wait()
            await asyncio.sleep(0.1)

            waiter_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter_task
            self.assertFalse(holder_task.done())

            finish.set()
            await holder_task
            self.assertEqual(await self.fetch_values(db), [1])

    async def test_transaction_close_inside_context(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            async with db.transaction():
                await db.execute("insert into t values (1)")
                await db.close()
            # exiting the context after close must not raise

        async with aiosqlite.connect(self.db) as db:
            self.assertEqual(await self.fetch_values(db), [])

    async def test_transaction_waits_for_other_task_transaction(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table t (i integer)")
            await db.commit()

            entered = asyncio.Event()
            finish = asyncio.Event()

            async def holder():
                async with db.transaction():
                    await db.execute("insert into t values (1)")
                    entered.set()
                    await finish.wait()

            async def second():
                await entered.wait()
                async with db.transaction():
                    await db.execute("insert into t values (2)")

            holder_task = asyncio.create_task(holder())
            second_task = asyncio.create_task(second())
            await entered.wait()
            await asyncio.sleep(0.1)
            self.assertFalse(second_task.done())

            finish.set()
            await asyncio.gather(holder_task, second_task)
            self.assertEqual(await self.fetch_values(db), [1, 2])
