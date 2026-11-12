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

"""Tests for the configurable matcher execution budget."""

import os
import pytest
import tempfile
import threading
import time
from unittest import TestCase

import casbin
from casbin.util import MatcherBudget
from casbin.util.expression import (
    MatcherBudgetExceeded,
    MatcherError,
    MatcherFunctionError,
    MatcherTimeout,
    REASON_ENFORCE_TIMEOUT,
    REASON_FUNCTION_EXCEPTION,
    REASON_FUNCTION_LIMIT,
    REASON_NON_BOOLEAN,
    REASON_POLICY_LIMIT,
    REASON_RECURSIVE_ENFORCER,
    REASON_REGEX_LENGTH,
    REASON_REGEX_TIMEOUT,
    REASON_UNKNOWN_FUNCTION,
)

REGEX_MODEL = (
    "[request_definition]\n"
    "r = sub, obj, act\n"
    "[policy_definition]\n"
    "p = sub, obj, act\n"
    "[policy_effect]\n"
    "e = some(where (p.eft == allow))\n"
    "[matchers]\n"
    "m = r.sub == p.sub && regexMatch(r.obj, p.obj) && r.act == p.act\n"
)

CUSTOM_MODEL = (
    "[request_definition]\n"
    "r = sub, obj, act\n"
    "[policy_definition]\n"
    "p = sub, obj, act\n"
    "[policy_effect]\n"
    "e = some(where (p.eft == allow))\n"
    "[matchers]\n"
    "m = r.sub == p.sub && custom(r.obj, p.obj) && r.act == p.act\n"
)

BASIC_MODEL = (
    "[request_definition]\n"
    "r = sub, obj, act\n"
    "[policy_definition]\n"
    "p = sub, obj, act\n"
    "[policy_effect]\n"
    "e = some(where (p.eft == allow))\n"
    "[matchers]\n"
    "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
)


class MatcherBudgetTestBase(TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="pycasbin-budget-")

    def write_model(self, name, content):
        path = os.path.join(self.scratch, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def write_policy(self, name, rows):
        path = os.path.join(self.scratch, name)
        with open(path, "w") as f:
            for row in rows:
                f.write(", ".join(row) + "\n")
        return path

    def enforcer(self, model, policy):
        return casbin.Enforcer(
            self.write_model("model.conf", model),
            self.write_policy("policy.csv", policy),
        )


class DefaultOffTest(MatcherBudgetTestBase):
    def test_budget_is_disabled_by_default_and_keeps_legacy_behaviour(self):
        e = self.enforcer(REGEX_MODEL, [["p", "alice", "/alice/.*", "read"]])
        self.assertFalse(e.get_matcher_budget().enabled())
        self.assertTrue(e.enforce("alice", "/alice/data", "read"))
        self.assertFalse(e.enforce("alice", "/bob/data", "read"))

        # A catastrophic pattern still runs uncapped while the budget is off.
        e2 = self.enforcer(REGEX_MODEL, [["p", "alice", "(a+)+b", "read"]])
        self.assertFalse(e2.enforce("alice", "a" * 20 + "x", "read"))

    def test_invalid_budget_values_are_rejected(self):
        with self.assertRaises(ValueError):
            MatcherBudget(wall_time=0)
        with self.assertRaises(ValueError):
            MatcherBudget(regex_timeout=-1)
        with self.assertRaises(ValueError):
            MatcherBudget(max_policy_evaluations=0)
        with self.assertRaises(ValueError):
            MatcherBudget(max_function_calls=-2)
        with self.assertRaises(ValueError):
            MatcherBudget(max_regex_pattern_length=0)

    def test_removing_the_budget_restores_unbounded_enforcement(self):
        e = self.enforcer(REGEX_MODEL, [["p", "alice", "/alice/.*", "read"]])
        e.set_matcher_budget(MatcherBudget(max_regex_pattern_length=3))
        allowed, _explain, reason = e.enforce_safe("alice", "/alice/x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_REGEX_LENGTH)

        e.set_matcher_budget(None)
        self.assertFalse(e.get_matcher_budget().enabled())
        self.assertTrue(e.enforce("alice", "/alice/x", "read"))


class RegexBudgetTest(MatcherBudgetTestBase):
    def test_pattern_length_budget_denies_long_patterns(self):
        e = self.enforcer(REGEX_MODEL, [["p", "alice", "/alice/.*", "read"]])
        e.set_matcher_budget(MatcherBudget(max_regex_pattern_length=5))

        allowed, explain, reason = e.enforce_safe("alice", "/alice/x", "read")
        self.assertFalse(allowed)
        self.assertEqual(explain, [])
        self.assertEqual(reason, REASON_REGEX_LENGTH)
        with self.assertRaises(MatcherBudgetExceeded):
            e.enforce_ex("alice", "/alice/x", "read")

    def test_pattern_length_boundary_allows_shorter_patterns(self):
        pattern = "abc"
        e = self.enforcer(REGEX_MODEL, [["p", "alice", pattern, "read"]])
        e.set_matcher_budget(MatcherBudget(max_regex_pattern_length=len(pattern)))
        allowed, _explain, reason = e.enforce_safe("alice", "abcd", "read")
        self.assertTrue(allowed)
        self.assertIsNone(reason)

    def test_catastrophic_backtracking_is_rejected_in_bounded_time(self):
        # This input takes multiple seconds in plain CPython re (exponential
        # backtracking); the regex budget must reject it far sooner.
        e = self.enforcer(REGEX_MODEL, [["p", "alice", "(a+)+b", "read"]])
        e.set_matcher_budget(MatcherBudget(regex_timeout=0.15))

        started = time.monotonic()
        allowed, _explain, reason = e.enforce_safe("alice", "a" * 26 + "x", "read")
        elapsed = time.monotonic() - started

        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_REGEX_TIMEOUT)
        self.assertLess(elapsed, 1.0)
        with self.assertRaises(MatcherTimeout):
            e.enforce_ex("alice", "a" * 26 + "x", "read")

    def test_regex_budget_does_not_change_normal_results(self):
        e = self.enforcer(REGEX_MODEL, [["p", "alice", "(a+)+b", "read"]])
        e.set_matcher_budget(MatcherBudget(regex_timeout=1.0, max_regex_pattern_length=64))
        self.assertEqual(e.enforce_safe("alice", "aaab", "read"), (True, ["alice", "(a+)+b", "read"], None))
        self.assertEqual(e.enforce_safe("alice", "zzz", "read"), (False, [], None))


class PolicyEvaluationBudgetTest(MatcherBudgetTestBase):
    def _long_policy_enforcer(self, size):
        rows = [["p", f"user{i}", f"/data{i}", "read"] for i in range(size)]
        return self.enforcer(REGEX_MODEL, rows)

    def test_long_policy_list_is_capped(self):
        e = self._long_policy_enforcer(200)
        e.set_matcher_budget(MatcherBudget(max_policy_evaluations=20))

        allowed, _explain, reason = e.enforce_safe("user199", "/data199", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_POLICY_LIMIT)

    def test_policy_evaluation_boundary(self):
        # Five rules, limit of five: every rule may be evaluated and the final
        # matching rule still grants access.
        e = self._long_policy_enforcer(5)
        e.set_matcher_budget(MatcherBudget(max_policy_evaluations=5))
        allowed, _explain, reason = e.enforce_safe("user4", "/data4", "read")
        self.assertTrue(allowed)
        self.assertIsNone(reason)

        # Limit of four means the fifth (matching) rule is never reached.
        e.set_matcher_budget(MatcherBudget(max_policy_evaluations=4))
        allowed, _explain, reason = e.enforce_safe("user4", "/data4", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_POLICY_LIMIT)


class CustomFunctionBudgetTest(MatcherBudgetTestBase):
    def _custom_enforcer(self, model=CUSTOM_MODEL):
        return self.enforcer(model, [["p", "alice", "x", "read"]])

    def test_custom_function_call_limit(self):
        e = self._custom_enforcer()
        calls = []
        e.add_function("custom", lambda a, b: calls.append(1) or True)
        e.set_matcher_budget(MatcherBudget(max_function_calls=1))

        # One call within the limit: normal allow.
        self.assertEqual(e.enforce_safe("alice", "x", "read"), (True, ["alice", "x", "read"], None))
        self.assertEqual(len(calls), 1)

        # Fresh enforce, limit one but matcher calls the function twice.
        two_call_model = CUSTOM_MODEL.replace(
            "custom(r.obj, p.obj)", "custom(r.obj, p.obj) && custom(r.act, p.act)"
        )
        e2 = self._custom_enforcer(two_call_model)
        e2.add_function("custom", lambda a, b: True)
        e2.set_matcher_budget(MatcherBudget(max_function_calls=1))
        allowed, _explain, reason = e2.enforce_safe("alice", "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_FUNCTION_LIMIT)

    def test_registered_custom_function_still_works_without_a_budget(self):
        e = self._custom_enforcer()
        e.add_function("custom", lambda a, b: True)
        self.assertTrue(e.enforce("alice", "x", "read"))

    def test_whitelist_rejects_unlisted_functions_at_registration(self):
        e = self._custom_enforcer()
        e.set_function_whitelist(["custom"])
        self.assertEqual(e.get_function_whitelist(), frozenset({"custom"}))
        with self.assertRaises(ValueError):
            e.add_function("backdoor", lambda a, b: True)
        # the listed name still registers fine
        e.add_function("custom", lambda a, b: True)
        self.assertTrue(e.enforce("alice", "x", "read"))

    def test_whitelist_survives_model_reload(self):
        model_path = self.write_model("model.conf", CUSTOM_MODEL)
        policy_path = self.write_policy("policy.csv", [["p", "alice", "x", "read"]])
        e = casbin.Enforcer(model_path, policy_path)
        e.set_function_whitelist(["custom"])

        e.load_model()
        # load_model() rebuilds the FunctionMap; the restriction must remain
        with self.assertRaises(ValueError):
            e.add_function("backdoor", lambda a, b: True)
        self.assertEqual(e.get_function_whitelist(), frozenset({"custom"}))

    def test_builtin_names_cannot_be_overridden(self):
        e = self._custom_enforcer()
        with self.assertRaises(ValueError):
            e.add_function("regexMatch", lambda a, b: True)
        with self.assertRaises(ValueError):
            e.add_function("keyMatch", lambda a, b: True)

    def test_unknown_function_in_matcher_is_denied(self):
        unknown_model = CUSTOM_MODEL.replace("custom(", "ghost(")
        e = self._custom_enforcer(unknown_model)
        e.set_matcher_budget(MatcherBudget(wall_time=5.0))

        allowed, _explain, reason = e.enforce_safe("alice", "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_UNKNOWN_FUNCTION)
        with self.assertRaises(MatcherFunctionError):
            e.enforce_ex("alice", "x", "read")

    def test_function_that_raises_is_denied_stably(self):
        e = self._custom_enforcer()

        def exploding(a, b):
            raise RuntimeError("boom")

        e.add_function("custom", exploding)
        e.set_matcher_budget(MatcherBudget(wall_time=5.0))
        allowed, _explain, reason = e.enforce_safe("alice", "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_FUNCTION_EXCEPTION)

    def test_non_boolean_function_result_is_denied(self):
        e = self._custom_enforcer()
        e.add_function("custom", lambda a, b: 1)
        e.set_matcher_budget(MatcherBudget(wall_time=5.0))
        allowed, _explain, reason = e.enforce_safe("alice", "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_NON_BOOLEAN)

    def test_recursive_enforcer_call_is_denied(self):
        e = self._custom_enforcer()

        def recursive(a, b, enforcer=e):
            return enforcer.enforce("alice", "x", "read")

        e.add_function("custom", recursive)
        e.set_matcher_budget(MatcherBudget(wall_time=5.0))
        started = time.monotonic()
        allowed, _explain, reason = e.enforce_safe("alice", "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_RECURSIVE_ENFORCER)
        self.assertLess(time.monotonic() - started, 1.0)


class WallTimeBudgetTest(MatcherBudgetTestBase):
    def test_slow_custom_function_hits_wall_time_budget(self):
        e = casbin.Enforcer(
            self.write_model("model.conf", CUSTOM_MODEL),
            self.write_policy("policy.csv", [["p", "alice", "x", "read"]]),
        )

        def slow(a, b):
            time.sleep(0.3)
            return True

        e.add_function("custom", slow)
        e.set_matcher_budget(MatcherBudget(wall_time=0.1))
        started = time.monotonic()
        allowed, _explain, reason = e.enforce_safe("alice", "x", "read")
        elapsed = time.monotonic() - started
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_ENFORCE_TIMEOUT)
        self.assertLess(elapsed, 1.0)
        with self.assertRaises(MatcherTimeout):
            e.enforce_ex("alice", "x", "read")

    def test_wall_time_boundary_allows_fast_requests(self):
        e = casbin.Enforcer(
            self.write_model("model.conf", BASIC_MODEL),
            self.write_policy("policy.csv", [["p", "alice", "data1", "read"]]),
        )
        e.set_matcher_budget(MatcherBudget(wall_time=5.0))
        self.assertEqual(e.enforce_safe("alice", "data1", "read"), (True, ["alice", "data1", "read"], None))


class ConcurrencyBudgetTest(MatcherBudgetTestBase):
    # The regex guard deliberately forks short-lived workers from threads; CPython
    # warns about fork-in-threads, but these children only run re.search plus one
    # pipe write, so the deadlock scenario the warning guards against cannot occur.
    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_concurrent_requests_have_independent_budgets(self):
        model_path = self.write_model("model.conf", REGEX_MODEL)
        policy_path = self.write_policy("policy.csv", [["p", "alice", "(a+)+b", "read"]])
        outcomes = []
        lock = threading.Lock()

        def catastrophic_request():
            enforcer = casbin.Enforcer(model_path, policy_path)
            enforcer.set_matcher_budget(MatcherBudget(regex_timeout=0.1))
            decision = enforcer.enforce_safe("alice", "a" * 26 + "x", "read")
            with lock:
                outcomes.append(decision)

        def healthy_request():
            enforcer = casbin.Enforcer(model_path, policy_path)
            enforcer.set_matcher_budget(MatcherBudget(regex_timeout=5.0))
            decision = enforcer.enforce_safe("alice", "aaab", "read")
            with lock:
                outcomes.append(decision)

        threads = [threading.Thread(target=catastrophic_request) for _ in range(4)]
        threads.append(threading.Thread(target=healthy_request))
        started = time.monotonic()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertLess(time.monotonic() - started, 5.0)

        denials = [o for o in outcomes if o[2] == REASON_REGEX_TIMEOUT]
        allows = [o for o in outcomes if o[0] is True and o[2] is None]
        self.assertEqual(len(denials), 4)
        self.assertEqual(len(allows), 1)

    @pytest.mark.filterwarnings("ignore::DeprecationWarning")
    def test_shared_enforcer_is_safe_under_concurrent_load(self):
        model_path = self.write_model("model.conf", BASIC_MODEL)
        policy_path = self.write_policy("policy.csv", [["p", "alice", "data1", "read"]])
        enforcer = casbin.Enforcer(model_path, policy_path)
        enforcer.set_matcher_budget(MatcherBudget(wall_time=5.0, max_policy_evaluations=10))
        errors = []

        def worker():
            for _ in range(20):
                allowed, _explain, reason = enforcer.enforce_safe("alice", "data1", "read")
                if not allowed or reason is not None:
                    errors.append((allowed, reason))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [])


class CachePollutionTest(MatcherBudgetTestBase):
    def test_protection_denial_is_not_written_to_allow_cache(self):
        model_path = self.write_model("model.conf", REGEX_MODEL)
        policy_path = self.write_policy("policy.csv", [["p", "alice", "(a+)+b", "read"]])
        enforcer = casbin.CachedEnforcer(model_path, policy_path)
        enforcer.set_matcher_budget(MatcherBudget(regex_timeout=0.1))

        request = ("alice", "a" * 26 + "x", "read")
        allowed, explain, reason = enforcer.enforce_safe(*request)
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_REGEX_TIMEOUT)
        self.assertEqual(explain, [])
        # nothing was cached for the rejected request
        self.assertEqual(len(enforcer.get_cache()), 0)

        # the raw enforce_ex path raises and likewise must not cache anything
        with self.assertRaises(MatcherError):
            enforcer.enforce_ex(*request)
        self.assertEqual(len(enforcer.get_cache()), 0)

        # lifting the budget evaluates the request fresh; healthy decisions cache normally
        enforcer.set_matcher_budget(MatcherBudget())
        self.assertTrue(enforcer.enforce("alice", "aaab", "read"))
        self.assertEqual(len(enforcer.get_cache()), 1)

    def test_function_failure_denial_is_not_cached(self):
        model_path = self.write_model("model.conf", CUSTOM_MODEL)
        policy_path = self.write_policy("policy.csv", [["p", "alice", "x", "read"]])
        enforcer = casbin.CachedEnforcer(model_path, policy_path)

        def exploding(a, b):
            raise RuntimeError("boom")

        enforcer.add_function("custom", exploding)
        enforcer.set_matcher_budget(MatcherBudget(wall_time=5.0))
        allowed, _explain, reason = enforcer.enforce_safe("alice", "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_FUNCTION_EXCEPTION)
        self.assertEqual(len(enforcer.get_cache()), 0)

    def test_synced_enforcers_delegate_budget_controls(self):
        model_path = self.write_model("model.conf", REGEX_MODEL)
        policy_path = self.write_policy("policy.csv", [["p", "alice", "(a+)+b", "read"]])

        synced = casbin.SyncedEnforcer(model_path, policy_path)
        synced.set_matcher_budget(MatcherBudget(regex_timeout=0.1))
        self.assertTrue(synced.get_matcher_budget().enabled())
        allowed, _explain, reason = synced.enforce_safe("alice", "a" * 26 + "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_REGEX_TIMEOUT)

        synced_cached = casbin.SyncedCachedEnforcer(model_path, policy_path)
        synced_cached.set_matcher_budget(MatcherBudget(regex_timeout=0.1))
        allowed, _explain, reason = synced_cached.enforce_safe("alice", "a" * 26 + "x", "read")
        self.assertFalse(allowed)
        self.assertEqual(reason, REASON_REGEX_TIMEOUT)
        self.assertEqual(len(synced_cached.get_cache()), 0)


class BuiltinCompatibilityTest(MatcherBudgetTestBase):
    def test_builtin_matchers_keep_their_results_under_a_budget(self):
        # regexMatch: same booleans as the unbounded engine, incl. casing.
        e = self.enforcer(REGEX_MODEL, [["p", "alice", "[A-Z]+", "read"]])
        e.set_matcher_budget(MatcherBudget(regex_timeout=5.0, max_regex_pattern_length=128))
        self.assertTrue(e.enforce("alice", "ABC", "read"))
        self.assertFalse(e.enforce("alice", "abc", "read"))

    def test_key_ip_time_matchers_are_unaffected(self):
        key_model = (
            "[request_definition]\n"
            "r = sub, obj, act\n"
            "[policy_definition]\n"
            "p = sub, obj, act\n"
            "[policy_effect]\n"
            "e = some(where (p.eft == allow))\n"
            "[matchers]\n"
            "m = r.sub == p.sub && keyMatch(r.obj, p.obj) && r.act == p.act\n"
        )
        e = casbin.Enforcer(
            self.write_model("key.conf", key_model),
            self.write_policy("key.csv", [["p", "alice", "/foo/*", "read"]]),
        )
        e.set_matcher_budget(MatcherBudget(wall_time=5.0, max_function_calls=100))
        self.assertTrue(e.enforce("alice", "/foo/bar", "read"))
        self.assertFalse(e.enforce("alice", "/baz/bar", "read"))

        ip_model = (
            "[request_definition]\n"
            "r = sub, ip, act\n"
            "[policy_definition]\n"
            "p = sub, ip, act\n"
            "[policy_effect]\n"
            "e = some(where (p.eft == allow))\n"
            "[matchers]\n"
            "m = r.sub == p.sub && ipMatch(r.ip, p.ip) && r.act == p.act\n"
        )
        ip_enforcer = casbin.Enforcer(
            self.write_model("ip.conf", ip_model),
            self.write_policy("ip.csv", [["p", "alice", "192.168.2.0/24", "read"]]),
        )
        ip_enforcer.set_matcher_budget(MatcherBudget(wall_time=5.0))
        self.assertTrue(ip_enforcer.enforce("alice", "192.168.2.12", "read"))
        self.assertFalse(ip_enforcer.enforce("alice", "10.0.0.1", "read"))
