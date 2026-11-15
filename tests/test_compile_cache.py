"""Tenant-aware compile cache isolation tests."""

import gc
import threading

import pytest

from RestrictedPython import ExecutionContext
from RestrictedPython import RestrictedCompileCache
from RestrictedPython import compile_restricted_eval
from RestrictedPython import compile_restricted_exec


SOURCE = "value * 2"


def _context(tenant, version, builtins=None, builtins_key=None,
             guard_provider=None, guard_key=None):
    return ExecutionContext(
        tenant_id=tenant,
        policy_version=version,
        builtins=builtins,
        builtins_key=builtins_key,
        guard_provider=guard_provider,
        guard_key=guard_key)


def test_cache_reuses_code_within_same_context():
    cache = RestrictedCompileCache()
    context = _context("tenant-a", 1)

    first = compile_restricted_eval(
        SOURCE, context=context, cache=cache)
    second = compile_restricted_eval(
        SOURCE, context=context, cache=cache)

    assert first.code is second.code
    assert len(cache) == 1


def test_cache_isolates_tenants_for_same_source():
    cache = RestrictedCompileCache()
    context_a = _context("tenant-a", 1)
    context_b = _context("tenant-b", 1)

    result_a = compile_restricted_eval(
        SOURCE, context=context_a, cache=cache)
    result_b = compile_restricted_eval(
        SOURCE, context=context_b, cache=cache)

    assert result_a.code is not result_b.code
    assert len(cache) == 2


def test_cache_invalidates_on_policy_upgrade():
    cache = RestrictedCompileCache()
    old_context = _context("tenant-a", 1)
    new_context = _context("tenant-a", 2)

    old_result = compile_restricted_eval(
        SOURCE, context=old_context, cache=cache)
    new_result = compile_restricted_eval(
        SOURCE, context=new_context, cache=cache)

    assert old_result.code is not new_result.code
    assert len(cache) == 2

    removed = cache.invalidate(tenant_id="tenant-a", policy_version=1)
    assert removed == 1
    assert len(cache) == 1

    refetched = compile_restricted_eval(
        SOURCE, context=new_context, cache=cache)
    assert refetched.code is new_result.code


class _Guard:
    def __init__(self, label):
        self.label = label


def test_cache_distinguishes_builtins_collections():
    cache = RestrictedCompileCache()
    builtins_a = {"len": len}
    builtins_b = {"len": len, "abs": abs}
    context_a = _context("tenant-a", 1, builtins=builtins_a)
    context_b = _context("tenant-a", 1, builtins=builtins_b)

    result_a = compile_restricted_eval(
        SOURCE, context=context_a, cache=cache)
    result_b = compile_restricted_eval(
        SOURCE, context=context_b, cache=cache)

    assert result_a.code is not result_b.code
    assert len(cache) == 2


def test_cache_distinguishes_guard_providers():
    cache = RestrictedCompileCache()
    context_a = _context(
        "tenant-a", 1, guard_provider=_Guard("a"))
    context_b = _context(
        "tenant-a", 1, guard_provider=_Guard("b"))

    result_a = compile_restricted_eval(
        SOURCE, context=context_a, cache=cache)
    result_b = compile_restricted_eval(
        SOURCE, context=context_b, cache=cache)

    assert result_a.code is not result_b.code
    assert len(cache) == 2


def test_explicit_identity_keys_control_sharing():
    cache = RestrictedCompileCache()
    # Two different builtins objects but the same published version key
    # intentionally describe the same restricted builtins contract.
    context_a = _context(
        "tenant-a", 1, builtins={"len": len}, builtins_key="builtins-v3")
    context_b = _context(
        "tenant-a", 1, builtins={"len": len}, builtins_key="builtins-v3")

    result_a = compile_restricted_eval(
        SOURCE, context=context_a, cache=cache)
    result_b = compile_restricted_eval(
        SOURCE, context=context_b, cache=cache)

    assert result_a.code is result_b.code
    assert len(cache) == 1


def test_eviction_drops_weak_context_reference():
    cache = RestrictedCompileCache(maxsize=1)
    builtins = {"len": len}
    guard = _Guard("tenant-a")
    context = _context(
        "tenant-a", 1, builtins=builtins, guard_provider=guard,
        builtins_key="builtins-v1", guard_key="guard-v1")

    compile_restricted_eval(SOURCE, context=context, cache=cache)
    entry = next(iter(cache._entries.values()))
    assert entry.context_ref() is context

    # A second context forces the first entry out of the bounded cache.
    replacement = _context("tenant-b", 1)
    compile_restricted_eval(SOURCE, context=replacement, cache=cache)

    assert len(cache) == 1
    assert entry.context_ref is None


def test_weakref_does_not_pin_discarded_context():
    cache = RestrictedCompileCache()
    context = _context("tenant-a", 1, builtins={"len": len})
    compile_restricted_eval(SOURCE, context=context, cache=cache)
    entry = next(iter(cache._entries.values()))
    assert entry.context_ref() is context

    del context
    gc.collect()
    # A weak reference never extends the lifetime of tenant state.
    assert entry.context_ref() is None


def test_invalidate_tenant_keeps_other_tenants():
    cache = RestrictedCompileCache()
    context_a = _context("tenant-a", 1)
    context_b = _context("tenant-b", 1)
    compile_restricted_eval(SOURCE, context=context_a, cache=cache)
    compile_restricted_eval(SOURCE, context=context_b, cache=cache)

    removed = cache.invalidate(tenant_id="tenant-a")
    assert removed == 1
    assert len(cache) == 1

    still_cached = compile_restricted_eval(
        SOURCE, context=context_b, cache=cache)
    assert len(cache) == 1
    assert still_cached in [entry.result for entry in
                            cache._entries.values()]


def test_lru_order_drops_oldest_entry():
    cache = RestrictedCompileCache(maxsize=2)
    first = _context("tenant-a", 1)
    second = _context("tenant-b", 1)
    third = _context("tenant-c", 1)

    compile_restricted_eval(SOURCE, context=first, cache=cache)
    compile_restricted_eval(SOURCE, context=second, cache=cache)
    # Refresh the first entry so the second becomes the eviction target.
    compile_restricted_eval(SOURCE, context=first, cache=cache)
    compile_restricted_eval(SOURCE, context=third, cache=cache)

    assert len(cache) == 2
    cached_contexts = [
        key[-1][0] for key in cache._entries]
    assert "tenant-b" not in cached_contexts
    assert set(cached_contexts) == {"tenant-a", "tenant-c"}


def test_concurrent_compiles_keep_tenant_entries_distinct():
    cache = RestrictedCompileCache()
    tenant_count = 8
    barrier = threading.Barrier(tenant_count)
    results = {}
    errors = []

    def worker(tenant):
        barrier.wait()
        try:
            context = _context(tenant, 1, guard_key=('guard', tenant))
            for _ in range(25):
                result = compile_restricted_eval(
                    SOURCE, context=context, cache=cache)
                results.setdefault(tenant, result.code)
                assert results[tenant] is result.code
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(tenant,))
        for tenant in range(tenant_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(cache) == tenant_count
    # Every tenant maps to its own cache key; the repeated hits assert
    # stable reuse per tenant even while other tenants compile in parallel.
    cached_tenants = {key[-1][0] for key in cache._entries}
    assert cached_tenants == set(range(tenant_count))
    cached_codes = [
        entry.result.code for entry in cache._entries.values()]
    assert len(cache._entries) == len(cached_codes)
    for tenant, code in results.items():
        matching = [
            entry for entry in cache._entries.values()
            if entry.key[-1][0] == tenant]
        assert len(matching) == 1
        assert matching[0].result.code is code


def test_concurrent_compiles_share_single_tenant_entry():
    cache = RestrictedCompileCache()
    context = _context("tenant-a", 1)
    worker_count = 8
    barrier = threading.Barrier(worker_count)
    codes = []
    errors = []

    def worker():
        barrier.wait()
        try:
            for _ in range(25):
                result = compile_restricted_eval(
                    SOURCE, context=context, cache=cache)
                codes.append(result.code)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker)
               for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(cache) == 1
    assert len(set(codes)) == 1


def test_compile_without_context_does_not_use_cache():
    cache = RestrictedCompileCache()
    first = compile_restricted_eval(SOURCE, cache=cache)
    second = compile_restricted_eval(SOURCE, cache=cache)

    assert len(cache) == 0
    assert first.code is not second.code


def test_failed_compilation_is_not_cached():
    cache = RestrictedCompileCache()
    context = _context("tenant-a", 1)
    result = compile_restricted_exec(
        "_forbidden = 1", context=context, cache=cache)

    assert result.errors
    assert result.code is None
    assert len(cache) == 0


def test_cache_requires_positive_maxsize():
    with pytest.raises(ValueError):
        RestrictedCompileCache(maxsize=0)


def test_cache_clear_releases_references():
    cache = RestrictedCompileCache()
    context = _context(
        "tenant-a", 1, builtins={"len": len}, guard_provider=_Guard("a"))
    compile_restricted_eval(SOURCE, context=context, cache=cache)
    entry = next(iter(cache._entries.values()))

    cache.clear()

    assert len(cache) == 0
    assert entry.context_ref is None
