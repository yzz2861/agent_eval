"""Tests for the optional RestrictedPython execution adapter."""

import ast

import pytest

from RestrictedPython.execution_adapter import (
    RestrictedExecutionAdapter,
    _LifecyclePrepare,
    compile_lifecycle_restricted,
)
from RestrictedPython.execution_lifecycle import (
    CapabilityDeniedError,
    ContextRevokedError,
    ContextSuspendedError,
    ExecutionContext,
    Policy,
    bind,
)


def make_context(name, budgets=None):
    return ExecutionContext(
        Policy(
            name=name,
            capabilities=frozenset(['log', 'write']),
            budgets=dict(budgets or {}),
        )
    )


def host_capabilities(log):
    return {'log': lambda message: log.append(message)}


SOURCE = """
def make_gen(log):
    register_cleanup(lambda: log.append('cleanup'))
    capability('log', 'start')
    yield 1
    for chunk in iter_guard(['a', 'b']):
        capability('log', chunk)
        yield chunk
    capability('log', 'end')
    yield 2
"""


NESTED_SOURCE = """
def inner():
    yield 10
    yield 11

def outer():
    yield from inner()
    yield 20
"""


def test_prepare_rewrites_public_names_and_yield_from():
    extra = chr(10) + "result = iter_guard([])" + chr(10)
    tree = ast.parse(NESTED_SOURCE + extra)
    prepared = _LifecyclePrepare().visit(tree)
    yield_from_nodes = [
        node for node in ast.walk(prepared)
        if isinstance(node, ast.YieldFrom)
    ]
    assert len(yield_from_nodes) == 1
    first = yield_from_nodes[0].value
    assert isinstance(first, ast.Call)
    assert first.func.id == '_getiter_'
    names = {
        node.id for node in ast.walk(prepared)
        if isinstance(node, ast.Name)
    }
    assert 'iter_guard' not in names
    assert '_getiter_' in names


def test_compile_lifecycle_restricted_passes_policy():
    compiled = compile_lifecycle_restricted(SOURCE)
    assert compiled.errors == ()
    assert compiled.code is not None


def test_compile_rejects_restricted_violations():
    result = compile_lifecycle_restricted('x = ().__class__')
    assert result.errors
    assert result.code is None


def test_restricted_generator_runs_under_lifecycle():
    log = []
    adapter = RestrictedExecutionAdapter()
    ctx = make_context('A')
    scope = adapter.run(SOURCE, ctx, host_capabilities(log))
    bound = ctx.capture().run(lambda: bind(scope['make_gen'](log)))
    assert list(bound) == [1, 'a', 'b', 2]
    assert log == ['start', 'a', 'b', 'end', 'cleanup']
    assert ctx.capability_usage['log'] == 4


def test_yield_from_is_lifecycle_bound_in_restricted_code():
    adapter = RestrictedExecutionAdapter()
    ctx = make_context('A')
    scope = adapter.run(NESTED_SOURCE, ctx, {})
    bound = ctx.capture().run(lambda: bind(scope['outer']()))
    assert list(bound) == [10, 11, 20]
    assert bound.owner is ctx


def test_resume_in_other_request_keeps_original_capabilities():
    log_a = []
    log_b = []
    adapter = RestrictedExecutionAdapter()
    ctx_a = make_context('A')
    ctx_b = make_context('B')
    scope_a = adapter.run(SOURCE, ctx_a, host_capabilities(log_a))
    scope_b = adapter.run(SOURCE, ctx_b, host_capabilities(log_b))
    gen_a = ctx_a.capture().run(
        lambda: bind(scope_a['make_gen'](log_a)))
    gen_b = ctx_b.capture().run(
        lambda: bind(scope_b['make_gen'](log_b)))

    # Deterministic A/B/B/A rotation across the two requests.
    assert ctx_b.capture().run(lambda: next(gen_a)) == 1
    assert ctx_a.capture().run(lambda: next(gen_b)) == 1
    assert ctx_a.capture().run(lambda: next(gen_b)) == 'a'
    assert ctx_b.capture().run(lambda: next(gen_a)) == 'a'

    assert gen_a.owner is ctx_a
    assert gen_b.owner is ctx_b
    assert ctx_a.capability_usage['log'] == 2
    assert ctx_b.capability_usage['log'] == 2
    assert log_a == ['start', 'a']
    assert log_b == ['start', 'a']


def test_suspended_context_blocks_restricted_resume():
    log = []
    adapter = RestrictedExecutionAdapter()
    ctx = make_context('A')
    scope = adapter.run(SOURCE, ctx, host_capabilities(log))
    bound = ctx.capture().run(lambda: bind(scope['make_gen'](log)))
    next(bound)
    ctx.suspend()
    with pytest.raises(ContextSuspendedError):
        next(bound)
    ctx.resume()
    assert next(bound) == 'a'


def test_revoked_context_only_allows_cleanup():
    log = []
    adapter = RestrictedExecutionAdapter()
    ctx = make_context('A')
    scope = adapter.run(SOURCE, ctx, host_capabilities(log))
    bound = ctx.capture().run(lambda: bind(scope['make_gen'](log)))
    next(bound)
    ctx.revoke()
    with pytest.raises(ContextRevokedError):
        next(bound)
    bound.close()
    assert 'cleanup' in log
    assert ctx.capability_usage['log'] == 1


def test_capability_denied_during_cleanup_frame():
    source = """
def gen():
    try:
        yield 1
    finally:
        capability('log', 'should-not-run')
"""
    adapter = RestrictedExecutionAdapter()
    ctx = make_context('A')
    log = []
    scope = adapter.run(source, ctx, host_capabilities(log))
    bound = ctx.capture().run(lambda: bind(scope['gen']()))
    next(bound)
    errors = ctx.revoke()
    assert any(
        isinstance(error, CapabilityDeniedError)
        for error in errors
    )
    assert log == []
    assert ctx.capability_usage['log'] == 0
