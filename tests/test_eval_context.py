"""Execution-context isolation for RestrictionCapableEval."""

import threading

from RestrictedPython import ExecutionContext
from RestrictedPython import RestrictedCompileCache
from RestrictedPython import safe_builtins
from RestrictedPython.Eval import DefaultGuardProvider
from RestrictedPython.Eval import RestrictionCapableEval


class RecordingGuardProvider:
    def __init__(self, label):
        self.label = label
        self.calls = []

    def guarded_getattr(self, object, name):
        self.calls.append((object, name))
        return getattr(object, name)

    def guarded_getitem(self, object, key):
        return object[key]

    def guarded_getiter(self, object):
        return object


def _context(tenant, version, builtins=None, guard_key=None):
    return ExecutionContext(
        tenant_id=tenant,
        policy_version=version,
        builtins=builtins,
        guard_key=guard_key)


def test_eval_uses_tenant_guard_provider_per_call():
    provider_a = RecordingGuardProvider("a")
    provider_b = RecordingGuardProvider("b")
    expression = "value.upper()"

    eval_a = RestrictionCapableEval(
        expression, guard_provider=provider_a)
    eval_b = RestrictionCapableEval(
        expression, guard_provider=provider_b)

    assert eval_a(value="abc") == "ABC"
    assert eval_b(value="xyz") == "XYZ"
    assert provider_a.calls == [("abc", "upper")]
    assert provider_b.calls == [("xyz", "upper")]


def test_eval_global_scope_is_fresh_per_evaluation():
    provider = DefaultGuardProvider()
    ob = RestrictionCapableEval("value + 1", guard_provider=provider)

    first_scope = ob._build_global_scope({"value": 1})
    second_scope = ob._build_global_scope({"value": 2})

    assert first_scope is not second_scope
    assert first_scope["value"] == 1
    assert second_scope["value"] == 2
    # Tenant guards are installed on the per-call scope only.
    assert first_scope["_getattr_"] == provider.guarded_getattr
    assert second_scope["_getattr_"] == provider.guarded_getattr


def test_eval_keeps_tenant_builtins_on_isolated_scope():
    builtins_a = dict(safe_builtins)
    builtins_b = dict(safe_builtins)
    builtins_b["custom_marker"] = 42
    context_a = _context(
        "tenant-a", 1, builtins=builtins_a, guard_key="g-a")
    context_b = _context(
        "tenant-b", 1, builtins=builtins_b, guard_key="g-b")

    ob_a = RestrictionCapableEval("value", context=context_a)
    ob_b = RestrictionCapableEval("value", context=context_b)

    scope_a = ob_a._build_global_scope({"value": 1})
    scope_b = ob_b._build_global_scope({"value": 2})

    assert scope_a["__builtins__"] is builtins_a
    assert scope_b["__builtins__"] is builtins_b
    assert "custom_marker" not in scope_a["__builtins__"]
    assert scope_b["__builtins__"]["custom_marker"] == 42


def test_eval_instance_globals_are_not_shared():
    first = RestrictionCapableEval("value")
    second = RestrictionCapableEval("value")
    first.globals["tenant_only"] = "secret"

    assert "tenant_only" not in second.globals


def test_eval_compiles_through_tenant_cache():
    cache = RestrictedCompileCache()
    context = _context("tenant-a", 1, guard_key="g-a")
    first = RestrictionCapableEval(
        "value * 2", context=context, cache=cache)
    second = RestrictionCapableEval(
        "value * 2", context=context, cache=cache)

    first.prepRestrictedCode()
    second.prepRestrictedCode()

    assert len(cache) == 1
    assert first.rcode is second.rcode


def test_concurrent_evaluations_keep_guards_and_builtins_isolated():
    builtins = dict(safe_builtins)
    worker_count = 8
    barrier = threading.Barrier(worker_count)
    seen = {}
    errors = []

    def worker(worker_id):
        provider = RecordingGuardProvider(worker_id)
        context = _context(
            worker_id, 1, builtins=builtins, guard_key=("guard", worker_id))
        ob = RestrictionCapableEval(
            "value.upper()", context=context, guard_provider=provider)
        barrier.wait()
        try:
            for _ in range(50):
                result = ob(value="v{0}".format(worker_id))
                assert result == "V{0}".format(worker_id)
            seen[worker_id] = provider
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(worker_id,))
        for worker_id in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(seen) == worker_count
    for worker_id, provider in seen.items():
        assert all(
            label == "v{0}".format(worker_id)
            for label, _name in provider.calls)


def test_eval_policy_upgrade_uses_fresh_compilation():
    cache = RestrictedCompileCache()
    old_context = _context(
        "tenant-a", 1, guard_key="g-a")
    new_context = _context(
        "tenant-a", 2, guard_key="g-a")

    old_eval = RestrictionCapableEval(
        "value + 1", context=old_context, cache=cache)
    new_eval = RestrictionCapableEval(
        "value + 1", context=new_context, cache=cache)
    old_eval.prepRestrictedCode()
    new_eval.prepRestrictedCode()

    assert len(cache) == 2
    assert old_eval.rcode is not new_eval.rcode
    assert old_eval(value=1) == 2
    assert new_eval(value=1) == 2

    cache.invalidate(tenant_id="tenant-a", policy_version=1)
    assert len(cache) == 1

    refetched = RestrictionCapableEval(
        "value + 1", context=new_context, cache=cache)
    refetched.prepRestrictedCode()
    assert refetched.rcode is new_eval.rcode


def test_explicit_builtins_override_context_default():
    context_builtins = dict(safe_builtins)
    context = _context(
        "tenant-a", 1, builtins=context_builtins, guard_key="g-a")
    ob = RestrictionCapableEval("value", context=context)
    custom_builtins = {"marker": 7}
    ob.set_global("__builtins__", custom_builtins)

    scope = ob._build_global_scope({"value": 1})

    assert scope["__builtins__"] is custom_builtins
    assert scope["__builtins__"] is not context_builtins
