# Copyright 2026 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression tests for the explicit transactional batch API.

The scenario behind these tests is the 300-rule import that fails halfway: an adapter
timeout on rule N must not leave the in-memory policy, role links or decision cache
ahead of what is actually stored. The controllable adapters below fail on a chosen rule
so every rollback/compensation path can be exercised deterministically, and every test
compares the in-memory snapshot against the adapter's own record -- the two are never
allowed to disagree.
"""

import threading
from unittest import IsolatedAsyncioTestCase, TestCase

import casbin
from casbin.persist import Adapter, TransactionAdapter, Transaction
from casbin.persist.adapters.asyncio import AsyncAdapter, AsyncTransactionAdapter
from casbin.persist.errors import (
    ON_DUPLICATE_FAIL,
    ON_DUPLICATE_IGNORE,
    PolicyRollbackError,
    PolicyValidationError,
)
from tests.test_enforcer import get_examples


class RuleStore:
    """in-memory adapter backend keyed by (sec, ptype, rule-tuple), shared by the sync
    and async adapters so a test can assert what the storage really holds."""

    def __init__(self):
        self.rules = set()
        self.lock = threading.RLock()
        self.calls = []

    def add(self, sec, ptype, rule):
        with self.lock:
            self.calls.append(("add", sec, ptype, tuple(rule)))
            key = (sec, ptype, tuple(rule))
            if key in self.rules:
                return False
            self.rules.add(key)
            return True

    def remove(self, sec, ptype, rule):
        with self.lock:
            self.calls.append(("remove", sec, ptype, tuple(rule)))
            key = (sec, ptype, tuple(rule))
            if key not in self.rules:
                return False
            self.rules.remove(key)
            return True

    def has(self, sec, ptype, rule):
        with self.lock:
            return (sec, ptype, tuple(rule)) in self.rules

    def snapshot(self):
        with self.lock:
            return set(self.rules)


class _ControlledFailure:
    """shared knobs for the controllable adapters.

    ``fail_at`` is 1-based: 3 means the third rule write raises. ``None`` disables
    failures. ``fail_on`` selects which single-rule operation fails (used to make the
    compensation step itself fail).
    """

    def __init__(self, store):
        self.store = store
        self.fail_at = None
        self.attempt = 0
        self.fail_on = "add"
        self.failure = RuntimeError("injected adapter failure")

    def _tick(self, op):
        self.attempt += 1
        if self.fail_at is not None and self.attempt == self.fail_at and op == self.fail_on:
            raise self.failure


class ControlledAdapter(Adapter):
    """plain adapter without transaction support: batch changes fall back to
    single-rule writes with compensation."""

    def __init__(self, store, controller):
        self.store = store
        self.controller = controller

    def load_policy(self, model):
        for sec, ptype, rule in self.store.snapshot():
            model.model[sec][ptype].policy.append(list(rule))

    def add_policy(self, sec, ptype, rule):
        self.controller._tick("add")
        return self.store.add(sec, ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        self.controller._tick("remove")
        return self.store.remove(sec, ptype, rule)

    def save_policy(self, model):
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        pass


class _RecordingTransaction(Transaction):
    def __init__(self, store, controller):
        self.store = store
        self.controller = controller
        self.staged = []
        self.closed = False

    def add_policies(self, sec, ptype, rules):
        for rule in rules:
            self.controller._tick("add")
            self.staged.append(("add", sec, ptype, tuple(rule)))

    def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            self.controller._tick("remove")
            self.staged.append(("remove", sec, ptype, tuple(rule)))

    def commit(self):
        for op, sec, ptype, rule in self.staged:
            if op == "add":
                self.store.add(sec, ptype, list(rule))
            else:
                self.store.remove(sec, ptype, list(rule))
        self.closed = True

    def rollback(self):
        # nothing was applied eagerly: dropping the staged list is the whole rollback.
        self.staged = []
        self.closed = True


class ControlledTransactionAdapter(TransactionAdapter):
    """adapter that exposes real (simulated) storage transactions."""

    def __init__(self, store, controller):
        self.store = store
        self.controller = controller
        self.transactions = []

    def load_policy(self, model):
        for sec, ptype, rule in self.store.snapshot():
            model.model[sec][ptype].policy.append(list(rule))

    def begin_transaction(self):
        tx = _RecordingTransaction(self.store, self.controller)
        self.transactions.append(tx)
        return tx

    def add_policy(self, sec, ptype, rule):
        return self.store.add(sec, ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        return self.store.remove(sec, ptype, rule)

    def add_policies(self, sec, ptype, rules):
        for rule in rules:
            self.store.add(sec, ptype, rule)
        return True

    def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            self.store.remove(sec, ptype, rule)
        return True

    def save_policy(self, model):
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        pass


# ----- async twins ---------------------------------------------------------


class AsyncControlledAdapter(AsyncAdapter):
    def __init__(self, store, controller):
        self.store = store
        self.controller = controller

    async def load_policy(self, model):
        for sec, ptype, rule in self.store.snapshot():
            model.model[sec][ptype].policy.append(list(rule))

    async def save_policy(self, model):
        pass

    async def add_policy(self, sec, ptype, rule):
        self.controller._tick("add")
        return self.store.add(sec, ptype, rule)

    async def remove_policy(self, sec, ptype, rule):
        self.controller._tick("remove")
        return self.store.remove(sec, ptype, rule)

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        pass


class _AsyncRecordingTransaction:
    def __init__(self, store, controller):
        self.store = store
        self.controller = controller
        self.staged = []

    async def add_policies(self, sec, ptype, rules):
        for rule in rules:
            self.controller._tick("add")
            self.staged.append(("add", sec, ptype, tuple(rule)))

    async def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            self.controller._tick("remove")
            self.staged.append(("remove", sec, ptype, tuple(rule)))

    async def commit(self):
        for op, sec, ptype, rule in self.staged:
            if op == "add":
                self.store.add(sec, ptype, list(rule))
            else:
                self.store.remove(sec, ptype, list(rule))

    async def rollback(self):
        self.staged = []


class AsyncControlledTransactionAdapter(AsyncTransactionAdapter):
    def __init__(self, store, controller):
        self.store = store
        self.controller = controller
        self.transactions = []

    async def load_policy(self, model):
        for sec, ptype, rule in self.store.snapshot():
            model.model[sec][ptype].policy.append(list(rule))

    async def begin_transaction(self):
        tx = _AsyncRecordingTransaction(self.store, self.controller)
        self.transactions.append(tx)
        return tx

    async def add_policy(self, sec, ptype, rule):
        return self.store.add(sec, ptype, rule)

    async def remove_policy(self, sec, ptype, rule):
        return self.store.remove(sec, ptype, rule)

    async def add_policies(self, sec, ptype, rules):
        for rule in rules:
            self.store.add(sec, ptype, rule)
        return True

    async def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            self.store.remove(sec, ptype, rule)
        return True

    async def save_policy(self, model):
        pass

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        pass


def make_enforcer(adapter):
    return casbin.Enforcer(get_examples("rbac_model.conf"), adapter)


def rules(n, prefix="u"):
    return [[f"{prefix}{i}", f"data{i}", "read"] for i in range(n)]


def memory_snapshot(e):
    return {
        "p": sorted(tuple(rule) for rule in e.get_policy()),
        "g": sorted(tuple(rule) for rule in e.get_grouping_policy()),
    }


def adapter_snapshot(store):
    grouped = {"p": set(), "g": set()}
    for sec, ptype, rule in store.snapshot():
        grouped[sec].add(rule)
    return {"p": sorted(grouped["p"]), "g": sorted(grouped["g"])}


def assert_memory_matches_storage(test_case, e, store):
    test_case.assertEqual(memory_snapshot(e), adapter_snapshot(store))


class TransactionalBatchTestBase:
    enforcer_cls = casbin.Enforcer

    def build(self, transactional, fail_at=None):
        store = RuleStore()
        controller = _ControlledFailure(store)
        controller.fail_at = fail_at
        if transactional:
            adapter = ControlledTransactionAdapter(store, controller)
        else:
            adapter = ControlledAdapter(store, controller)
        return make_enforcer(adapter), store, controller, adapter


class TestTransactionalBatch(TransactionalBatchTestBase, TestCase):
    # ------------------------------------------------------------------
    # happy path: actual changed rules are returned, order is stable, and
    # memory and storage stay identical.
    # ------------------------------------------------------------------

    def test_success_returns_effective_rules_in_order(self):
        for transactional in (False, True):
            e, store, _, _ = self.build(transactional)
            batch = rules(5)
            added = e.add_policies_transaction(batch)

            self.assertEqual(added, batch)
            self.assertEqual(e.get_policy()[-5:], batch)
            assert_memory_matches_storage(self, e, store)

    def test_nth_rule_failure_rolls_back_everything_fallback(self):
        # rule 3 of 5 times out inside the single-rule fallback: the first two writes
        # must be compensated and the in-memory policy must be untouched.
        e, store, controller, _ = self.build(transactional=False, fail_at=3)
        before_memory = memory_snapshot(e)
        before_storage = store.snapshot()

        with self.assertRaises(RuntimeError) as ctx:
            e.add_policies_transaction(rules(5))
        self.assertIs(ctx.exception, controller.failure)

        self.assertEqual(memory_snapshot(e), before_memory)
        self.assertEqual(store.snapshot(), before_storage)
        assert_memory_matches_storage(self, e, store)
        # two adds landed, both had to be undone through inverse remove calls.
        self.assertEqual(
            [call[0] for call in store.calls],
            ["add", "add", "remove", "remove"],
        )

    def test_nth_rule_failure_rolls_back_everything_transaction(self):
        e, store, controller, adapter = self.build(transactional=True, fail_at=3)
        before_memory = memory_snapshot(e)

        with self.assertRaises(RuntimeError):
            e.add_policies_transaction(rules(5))

        self.assertEqual(memory_snapshot(e), before_memory)
        assert_memory_matches_storage(self, e, store)
        # the failed transaction must have been rolled back and never committed.
        self.assertEqual(len(adapter.transactions), 1)
        self.assertEqual(adapter.transactions[0].staged, [])

    def test_transaction_context_manager_rolls_back_on_exception(self):
        store = RuleStore()
        controller = _ControlledFailure(store)
        adapter = ControlledTransactionAdapter(store, controller)
        with self.assertRaises(RuntimeError):
            with adapter.begin_transaction() as tx:
                tx.add_policies("p", "p", rules(2))
                raise RuntimeError("boom")
        self.assertEqual(store.snapshot(), set())

    def test_duplicate_rules_fail_the_whole_batch_by_default(self):
        e, store, _, _ = self.build(transactional=True)
        existing = ["u0", "data0", "read"]
        e.add_policies_transaction([existing])

        with self.assertRaises(PolicyValidationError):
            e.add_policies_transaction([existing, ["u9", "data9", "read"]])
        # validation runs before any write: the second rule never reached storage.
        assert_memory_matches_storage(self, e, store)
        self.assertFalse(store.has("p", "p", ["u9", "data9", "read"]))

    def test_duplicate_rules_can_be_ignored_with_one_batch_outcome(self):
        e, store, _, _ = self.build(transactional=False)
        existing = ["u0", "data0", "read"]
        e.add_policies_transaction([existing])

        added = e.add_policies_transaction(
            [existing, ["u1", "data1", "read"]], on_duplicate=ON_DUPLICATE_IGNORE
        )
        self.assertEqual(added, [["u1", "data1", "read"]])
        assert_memory_matches_storage(self, e, store)

    def test_intra_batch_duplicates_are_rejected(self):
        e, store, _, _ = self.build(transactional=False)
        dup = rules(2) + [rules(2)[0]]
        with self.assertRaises(PolicyValidationError):
            e.add_policies_transaction(dup)
        assert_memory_matches_storage(self, e, store)

    def test_empty_batch_is_rejected(self):
        e, store, _, _ = self.build(transactional=True)
        with self.assertRaises(PolicyValidationError):
            e.add_policies_transaction([])
        assert_memory_matches_storage(self, e, store)

    def test_malformed_rules_are_rejected_before_any_write(self):
        e, store, controller, _ = self.build(transactional=False)
        for bad in (None, [[]], [["only", "two"]], [["ok", "ok", ""]], [["a", "b", 1]]):
            controller.attempt = 0
            with self.assertRaises(PolicyValidationError):
                e.add_policies_transaction(bad)
        self.assertEqual(store.calls, [])

    def test_unknown_ptype_is_rejected(self):
        e, _, _, _ = self.build(transactional=True)
        with self.assertRaises(PolicyValidationError):
            e.add_named_policies_transaction("nope", [["x", "y", "z"]])

    def test_remove_path_success_and_rollback(self):
        for transactional in (False, True):
            e, store, controller, _ = self.build(transactional)
            batch = rules(4)
            e.add_policies_transaction(batch)
            controller.attempt = 0
            controller.fail_at = 2
            controller.fail_on = "remove"

            before = memory_snapshot(e)
            with self.assertRaises(RuntimeError):
                e.remove_policies_transaction(batch)

            self.assertEqual(memory_snapshot(e), before)
            assert_memory_matches_storage(self, e, store)

    def test_remove_missing_rule_fail_or_ignore(self):
        e, store, _, _ = self.build(transactional=True)
        e.add_policies_transaction(rules(2))

        with self.assertRaises(PolicyValidationError):
            e.remove_policies_transaction([["ghost", "g", "read"]])

        removed = e.remove_policies_transaction(
            [["ghost", "g", "read"], ["u0", "data0", "read"]], on_missing=ON_DUPLICATE_IGNORE
        )
        self.assertEqual(removed, [["u0", "data0", "read"]])
        assert_memory_matches_storage(self, e, store)

    def test_role_links_roll_back_with_grouping_batch(self):
        e, store, controller, _ = self.build(transactional=False, fail_at=2)
        e.add_grouping_policies_transaction([["alice", "admin"]])
        self.assertTrue(e.get_role_manager().has_link("alice", "admin"))

        with self.assertRaises(RuntimeError):
            e.add_grouping_policies_transaction([["bob", "admin"], ["carol", "admin"]])

        self.assertFalse(e.get_role_manager().has_link("bob", "admin"))
        self.assertFalse(e.get_role_manager().has_link("carol", "admin"))
        self.assertTrue(e.get_role_manager().has_link("alice", "admin"))
        assert_memory_matches_storage(self, e, store)

    def test_cache_is_restored_to_pre_call_decisions(self):
        e, store, controller, _ = self.build(transactional=False, fail_at=2)
        cached = casbin.CachedEnforcer(get_examples("rbac_model.conf"), e.get_adapter())
        cached.enforce("u0", "data0", "read")
        self.assertEqual(len(cached.get_cache()), 1)

        with self.assertRaises(RuntimeError):
            cached.add_policies_transaction(rules(3))
        # a failed change cannot leave a decision cached against a half-applied policy.
        self.assertEqual(len(cached.get_cache()), 0)
        assert_memory_matches_storage(self, cached, store)

    def test_compensation_failure_is_surfaced_not_hidden(self):
        e, store, controller, adapter = self.build(transactional=False, fail_at=3)

        # make the compensating remove fail too: storage can no longer be healed.
        original_remove = adapter.remove_policy

        def broken_remove(sec, ptype, rule):
            raise RuntimeError("compensation storage down")

        adapter.remove_policy = broken_remove
        try:
            with self.assertRaises(PolicyRollbackError) as ctx:
                e.add_policies_transaction(rules(5))
            self.assertEqual(len(ctx.exception.failed_rules), 2)
        finally:
            adapter.remove_policy = original_remove
        # memory must still be back at the pre-call state even if storage is not.
        self.assertEqual(memory_snapshot(e), {"p": [], "g": []})

    def test_concurrent_batches_do_not_overwrite_each_other(self):
        e, store, _, _ = self.build(transactional=False)
        errors = []

        def worker(start):
            try:
                e.add_policies_transaction(rules(50, prefix=f"w{start}_"))
            except Exception as exc:  # pragma: no cover - failure path diagnostic
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(e.get_policy()), 200)
        assert_memory_matches_storage(self, e, store)

    def test_synced_enforcer_serializes_concurrent_transactional_batches(self):
        store = RuleStore()
        controller = _ControlledFailure(store)
        adapter = ControlledAdapter(store, controller)
        synced = casbin.SyncedEnforcer(get_examples("rbac_model.conf"), adapter)
        errors = []

        def worker(start):
            try:
                synced.add_policies_transaction(rules(40, prefix=f"s{start}_"))
            except Exception as exc:  # pragma: no cover - failure path diagnostic
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(synced.get_policy()), 200)
        assert_memory_matches_storage(self, synced, store)

    def test_synced_enforcer_exposes_grouping_transaction_api(self):
        store = RuleStore()
        controller = _ControlledFailure(store)
        synced = casbin.SyncedEnforcer(
            get_examples("rbac_model.conf"), ControlledAdapter(store, controller)
        )
        added = synced.add_grouping_policies_transaction([["alice", "admin"], ["bob", "admin"]])
        self.assertEqual(added, [["alice", "admin"], ["bob", "admin"]])
        self.assertTrue(synced.has_role_for_user("alice", "admin"))
        removed = synced.remove_grouping_policies_transaction([["bob", "admin"]])
        self.assertEqual(removed, [["bob", "admin"]])
        self.assertFalse(synced.has_role_for_user("bob", "admin"))
        assert_memory_matches_storage(self, synced, store)

    def test_single_rule_return_values_stay_compatible(self):
        e, store, _, _ = self.build(transactional=True)
        self.assertTrue(e.add_policy("u0", "data0", "read"))
        self.assertFalse(e.add_policy("u0", "data0", "read"))
        self.assertTrue(e.remove_policy("u0", "data0", "read"))
        self.assertFalse(e.remove_policy("u0", "data0", "read"))
        assert_memory_matches_storage(self, e, store)

    def test_watcher_is_notified_only_on_success(self):
        class RecordingWatcher:
            def __init__(self):
                self.calls = []

            def update_for_add_policies(self, sec, ptype, rules):
                self.calls.append(("add", sec, ptype, [list(r) for r in rules]))

            def update_for_remove_policies(self, sec, ptype, rules):
                self.calls.append(("remove", sec, ptype, [list(r) for r in rules]))

            def update(self):
                self.calls.append(("update",))

        e, store, controller, _ = self.build(transactional=False, fail_at=2)
        watcher = RecordingWatcher()
        e.set_watcher(watcher)
        with self.assertRaises(RuntimeError):
            e.add_policies_transaction(rules(3))
        self.assertEqual(watcher.calls, [])

        controller.fail_at = None
        batch = rules(3)
        e.add_policies_transaction(batch)
        self.assertEqual(watcher.calls, [("add", "p", "p", batch)])
        e.remove_policies_transaction(batch)
        self.assertEqual(watcher.calls[-1], ("remove", "p", "p", batch))

    def test_works_without_adapter_and_with_auto_save_disabled(self):
        e = casbin.Enforcer(get_examples("rbac_model.conf"))
        added = e.add_policies_transaction(rules(3))
        self.assertEqual(added, rules(3))
        removed = e.remove_policies_transaction(rules(3))
        self.assertEqual(removed, rules(3))
        self.assertEqual(e.get_policy(), [])

        e.enable_auto_save(False)
        e, store, _, _ = self.build(transactional=True)
        e.enable_auto_save(False)
        e.add_policies_transaction(rules(2))
        # adapter was bypassed, only the in-memory model changed
        self.assertEqual(store.snapshot(), set())
        self.assertEqual(len(e.get_policy()), 2)

    def test_priority_model_rolls_back_too(self):
        store = RuleStore()
        controller = _ControlledFailure(store)
        controller.fail_at = 2
        e = casbin.Enforcer(
            get_examples("priority_model.conf"),
            ControlledAdapter(store, controller),
        )
        before = memory_snapshot(e)
        batch = [
            ["alice", "data1", "write", "allow"],
            ["bob", "data2", "read", "allow"],
            ["carol", "data3", "read", "allow"],
        ]
        with self.assertRaises(RuntimeError):
            e.add_policies_transaction(batch)
        self.assertEqual(memory_snapshot(e), before)
        assert_memory_matches_storage(self, e, store)


class AsyncTransactionalBatchTestBase:
    async def build(self, transactional, fail_at=None):
        store = RuleStore()
        controller = _ControlledFailure(store)
        controller.fail_at = fail_at
        if transactional:
            adapter = AsyncControlledTransactionAdapter(store, controller)
        else:
            adapter = AsyncControlledAdapter(store, controller)
        e = casbin.AsyncEnforcer(get_examples("rbac_model.conf"), adapter)
        await e.load_policy()
        return e, store, controller, adapter


class TestAsyncTransactionalBatch(AsyncTransactionalBatchTestBase, IsolatedAsyncioTestCase):
    async def test_async_success_and_stable_order(self):
        for transactional in (False, True):
            e, store, _, _ = await self.build(transactional)
            batch = rules(4)
            added = await e.add_policies_transaction(batch)
            self.assertEqual(added, batch)
            assert_memory_matches_storage(self, e, store)

    async def test_async_nth_failure_rolls_back_fallback(self):
        e, store, controller, _ = await self.build(transactional=False, fail_at=3)
        before = memory_snapshot(e)
        with self.assertRaises(RuntimeError):
            await e.add_policies_transaction(rules(5))
        self.assertEqual(memory_snapshot(e), before)
        assert_memory_matches_storage(self, e, store)
        self.assertEqual(
            [call[0] for call in store.calls],
            ["add", "add", "remove", "remove"],
        )

    async def test_async_nth_failure_rolls_back_transaction(self):
        e, store, controller, adapter = await self.build(transactional=True, fail_at=2)
        before = memory_snapshot(e)
        with self.assertRaises(RuntimeError):
            await e.add_policies_transaction(rules(4))
        self.assertEqual(memory_snapshot(e), before)
        assert_memory_matches_storage(self, e, store)
        self.assertEqual(adapter.transactions[0].staged, [])

    async def test_async_validation_runs_before_writes(self):
        e, store, _, _ = await self.build(transactional=True)
        with self.assertRaises(PolicyValidationError):
            await e.add_policies_transaction([])
        with self.assertRaises(PolicyValidationError):
            await e.add_policies_transaction([["bad"]])
        self.assertEqual(store.calls, [])

    async def test_async_remove_path_rollback(self):
        e, store, controller, _ = await self.build(transactional=False)
        batch = rules(3)
        await e.add_policies_transaction(batch)
        controller.attempt = 0
        controller.fail_at = 2
        controller.fail_on = "remove"
        before = memory_snapshot(e)
        with self.assertRaises(RuntimeError):
            await e.remove_policies_transaction(batch)
        self.assertEqual(memory_snapshot(e), before)
        assert_memory_matches_storage(self, e, store)

    async def test_async_grouping_rollback_restores_role_links(self):
        e, store, controller, _ = await self.build(transactional=True, fail_at=1)
        with self.assertRaises(RuntimeError):
            await e.add_grouping_policies_transaction([["bob", "admin"], ["carol", "admin"]])
        self.assertFalse(e.get_role_manager().has_link("bob", "admin"))
        assert_memory_matches_storage(self, e, store)

    async def test_async_compensation_failure_raises_rollback_error(self):
        e, store, controller, adapter = await self.build(transactional=False, fail_at=2)

        async def broken_remove(sec, ptype, rule):
            raise RuntimeError("compensation down")

        adapter.remove_policy = broken_remove
        with self.assertRaises(PolicyRollbackError):
            await e.add_policies_transaction(rules(3))
        self.assertEqual(memory_snapshot(e), {"p": [], "g": []})

    async def test_async_duplicate_modes(self):
        e, store, _, _ = await self.build(transactional=False)
        await e.add_policies_transaction([["u0", "data0", "read"]])
        with self.assertRaises(PolicyValidationError):
            await e.add_policies_transaction([["u0", "data0", "read"], ["u1", "data1", "read"]])
        added = await e.add_policies_transaction(
            [["u0", "data0", "read"], ["u1", "data1", "read"]], on_duplicate=ON_DUPLICATE_IGNORE
        )
        self.assertEqual(added, [["u1", "data1", "read"]])
        assert_memory_matches_storage(self, e, store)
