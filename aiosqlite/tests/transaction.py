# Copyright Amethyst Reese
# Licensed under the MIT license

import asyncio
import sqlite3
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

    async def test_transaction_commit(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_commit (i integer)")
            await db.commit()

            async with db.transaction():
                await db.execute("insert into tx_commit values (1)")
                await db.execute("insert into tx_commit values (2)")

            rows = await db.execute_fetchall("select i from tx_commit order by i")
            self.assertEqual(rows, [(1,), (2,)])

    async def test_transaction_rollback_on_exception(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_rollback (i integer)")
            await db.commit()

            with self.assertRaises(ValueError):
                async with db.transaction():
                    await db.execute("insert into tx_rollback values (1)")
                    raise ValueError("boom")

            rows = await db.execute_fetchall("select i from tx_rollback")
            self.assertEqual(rows, [])

    async def test_transaction_nested_savepoint(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_nested (i integer)")
            await db.commit()

            async with db.transaction():
                await db.execute("insert into tx_nested values (1)")
                with self.assertRaises(ValueError):
                    async with db.transaction():
                        await db.execute("insert into tx_nested values (2)")
                        raise ValueError("inner boom")
                await db.execute("insert into tx_nested values (3)")

            rows = await db.execute_fetchall("select i from tx_nested order by i")
            self.assertEqual(rows, [(1,), (3,)])

    async def test_transaction_nested_savepoint_commit(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_nested_ok (i integer)")
            await db.commit()

            async with db.transaction():
                await db.execute("insert into tx_nested_ok values (1)")
                async with db.transaction():
                    await db.execute("insert into tx_nested_ok values (2)")

            rows = await db.execute_fetchall(
                "select i from tx_nested_ok order by i"
            )
            self.assertEqual(rows, [(1,), (2,)])

    async def test_transaction_excludes_other_tasks(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_exclude (i integer)")
            await db.commit()

            entered = asyncio.Event()
            proceed = asyncio.Event()
            order = []

            async def owner():
                async with db.transaction():
                    await db.execute("insert into tx_exclude values (1)")
                    entered.set()
                    await proceed.wait()
                    order.append("owner-write")
                order.append("owner-exit")

            async def waiter():
                await entered.wait()
                await db.execute("insert into tx_exclude values (2)")
                order.append("waiter")

            owner_task = asyncio.ensure_future(owner())
            waiter_task = asyncio.ensure_future(waiter())
            await entered.wait()
            await asyncio.sleep(0.1)
            # the waiter's execute must still be blocked by the transaction
            self.assertEqual(order, [])
            proceed.set()
            await asyncio.gather(owner_task, waiter_task)

            self.assertEqual(order, ["owner-write", "owner-exit", "waiter"])
            rows = await db.execute_fetchall("select i from tx_exclude order by i")
            self.assertEqual(rows, [(1,), (2,)])

    async def test_transaction_rollback_isolated_from_other_tasks(self):
        # a failing transaction must not roll back writes from other tasks,
        # and other tasks' writes must not land inside the failing transaction
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_isolated (i integer)")
            await db.commit()

            entered = asyncio.Event()
            proceed = asyncio.Event()

            async def owner():
                async with db.transaction():
                    await db.execute("insert into tx_isolated values (1)")
                    entered.set()
                    await proceed.wait()
                    raise ValueError("boom")

            async def waiter():
                await entered.wait()
                await db.execute("insert into tx_isolated values (2)")
                await db.commit()

            owner_task = asyncio.ensure_future(owner())
            waiter_task = asyncio.ensure_future(waiter())
            await entered.wait()
            await asyncio.sleep(0.1)
            proceed.set()
            with self.assertRaises(ValueError):
                await owner_task
            await waiter_task

            rows = await db.execute_fetchall("select i from tx_isolated")
            self.assertEqual(rows, [(2,)])

    async def test_transaction_owner_cancellation(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_cancel (i integer)")
            await db.commit()

            entered = asyncio.Event()

            async def owner():
                async with db.transaction():
                    await db.execute("insert into tx_cancel values (1)")
                    entered.set()
                    await asyncio.sleep(60)

            task = asyncio.ensure_future(owner())
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

            # rollback completed and the transaction lock was released
            rows = await db.execute_fetchall("select i from tx_cancel")
            self.assertEqual(rows, [])
            await db.execute("insert into tx_cancel values (2)")
            await db.commit()
            rows = await db.execute_fetchall("select i from tx_cancel")
            self.assertEqual(rows, [(2,)])

    async def test_waiter_cancellation_does_not_affect_owner(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_waiter (i integer)")
            await db.commit()

            entered = asyncio.Event()
            finish = asyncio.Event()

            async def owner():
                async with db.transaction():
                    await db.execute("insert into tx_waiter values (1)")
                    entered.set()
                    await finish.wait()

            async def waiter():
                await entered.wait()
                await db.execute("insert into tx_waiter values (2)")

            owner_task = asyncio.ensure_future(owner())
            waiter_task = asyncio.ensure_future(waiter())
            await entered.wait()
            await asyncio.sleep(0.1)
            waiter_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter_task

            finish.set()
            await owner_task
            rows = await db.execute_fetchall("select i from tx_waiter")
            self.assertEqual(rows, [(1,)])

    async def test_transaction_child_tasks_join(self):
        # tasks spawned inside the transaction context belong to it
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_child (i integer)")
            await db.commit()

            async with db.transaction():
                await asyncio.gather(
                    *[
                        db.execute("insert into tx_child values (?)", [i])
                        for i in range(5)
                    ]
                )

            rows = await db.execute_fetchall("select count(*) from tx_child")
            self.assertEqual(rows, [(5,)])

    async def test_concurrent_transactions_serialize(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_serial (i integer)")
            await db.commit()

            async def worker(base):
                async with db.transaction():
                    for i in range(5):
                        await db.execute(
                            "insert into tx_serial values (?)", [base + i]
                        )

            await asyncio.gather(*[worker(i * 10) for i in range(4)])

            rows = await db.execute_fetchall("select count(*) from tx_serial")
            self.assertEqual(rows, [(20,)])

    async def test_transaction_guards(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_guard (i integer)")
            await db.commit()

            async with db.transaction():
                with self.assertRaises(sqlite3.ProgrammingError):
                    await db.commit()
                with self.assertRaises(sqlite3.ProgrammingError):
                    await db.rollback()
                with self.assertRaises(sqlite3.ProgrammingError):
                    await db.executescript("select 1")
                with self.assertRaises(sqlite3.ProgrammingError):
                    await db.close()

            # everything works again after the context exits
            await db.execute("insert into tx_guard values (1)")
            await db.commit()
            rows = await db.execute_fetchall("select i from tx_guard")
            self.assertEqual(rows, [(1,)])

    async def test_commit_from_other_task_raises(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_other (i integer)")
            await db.commit()

            entered = asyncio.Event()
            finish = asyncio.Event()

            async def owner():
                async with db.transaction():
                    entered.set()
                    await finish.wait()

            owner_task = asyncio.ensure_future(owner())
            await entered.wait()
            with self.assertRaises(sqlite3.ProgrammingError):
                await db.commit()
            with self.assertRaises(sqlite3.ProgrammingError):
                await db.rollback()
            finish.set()
            await owner_task

    async def test_legacy_behavior_without_transaction(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_legacy (i integer)")
            await db.commit()
            await db.execute("insert into tx_legacy values (1)")
            await db.rollback()
            rows = await db.execute_fetchall("select i from tx_legacy")
            self.assertEqual(rows, [])
            await db.execute("insert into tx_legacy values (2)")
            await db.commit()
            rows = await db.execute_fetchall("select i from tx_legacy")
            self.assertEqual(rows, [(2,)])

    async def test_transaction_isolation_level(self):
        async with aiosqlite.connect(self.db, isolation_level="IMMEDIATE") as db:
            await db.execute("create table tx_level (i integer)")
            await db.commit()

            async with db.transaction():
                self.assertTrue(db.in_transaction)
                await db.execute("insert into tx_level values (1)")

            rows = await db.execute_fetchall("select i from tx_level")
            self.assertEqual(rows, [(1,)])

    async def test_transaction_reentrant_guard(self):
        async with aiosqlite.connect(self.db) as db:
            await db.execute("create table tx_reentry (i integer)")
            await db.commit()

            tx = db.transaction()
            async with tx:
                with self.assertRaises(RuntimeError):
                    async with tx:
                        pass
