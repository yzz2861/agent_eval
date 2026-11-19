"""Tests for lifecycle-bound restricted generators."""

import threading
import contextvars

import pytest

from RestrictedPython.execution_lifecycle import CLEANUP_MODE
from RestrictedPython.execution_lifecycle import CURRENT_CONTEXT
from RestrictedPython.execution_lifecycle import CapabilityDeniedError
from RestrictedPython.execution_lifecycle import ContextRevokedError
from RestrictedPython.execution_lifecycle import ContextSuspendedError
from RestrictedPython.execution_lifecycle import ExecutionContext
from RestrictedPython.execution_lifecycle import LifecycleError
from RestrictedPython.execution_lifecycle import Policy
from RestrictedPython.execution_lifecycle import bind
from RestrictedPython.execution_lifecycle import current_bound


def make_context(name, capabilities=('log', 'write'), budgets=None):
    policy = Policy(
        name=name,
        capabilities=frozenset(capabilities),
        budgets=dict(budgets or {}),
    )
    return ExecutionContext(policy)


def test_basic_iteration_and_exhaustion():
    ctx = make_context('A')
    bound = bind(iter([1, 2]), ctx)
    assert next(bound) == 1
    assert next(bound) == 2
    with pytest.raises(StopIteration):
        next(bound)
    assert bound._exhausted


def test_send_values():
    ctx = make_context('A')

    def echo():
        received = yield 'start'
        yield received

    bound = bind(echo(), ctx)
    assert next(bound) == 'start'
    assert bound.send('payload') == 'payload'


def test_send_before_start_rejected():
    ctx = make_context('A')
    bound = bind((x for x in ()), ctx)
    with pytest.raises(TypeError):
        bound.send(1)


def test_throw_lifecycle_checked():
    ctx = make_context('A')

    def gen():
        yield 1
        try:
            yield 2
        except ValueError:
            yield 'recovered'
        yield 4

    bound = bind(gen(), ctx)
    assert next(bound) == 1
    assert next(bound) == 2
    assert bound.throw(ValueError('boom')) == 'recovered'
    assert next(bound) == 4
    with pytest.raises(StopIteration):
        next(bound)
    assert bound._exhausted


def test_generator_bound_at_creation_ignores_later_ambient_ctx():
    ctx_a = make_context('A')
    ctx_b = make_context('B', budgets={'log': 5})
    seen = []

    def gen():
        seen.append(CURRENT_CONTEXT.get().policy.name)
        yield 1
        seen.append(CURRENT_CONTEXT.get().policy.name)
        yield 2

    bound = ctx_a.capture().run(lambda: bind(gen()))
    assert bound.owner is ctx_a
    assert bound.policy.name == 'A'
    # Resume while an unrelated request context is ambient.
    ctx_b.capture().run(lambda: next(bound))
    assert seen == ['A']
    ctx_b.capture().run(lambda: next(bound))
    assert seen == ['A', 'A']


def test_suspend_blocks_resume_but_allows_resume_then_close():
    ctx = make_context('A')
    bound = bind((x for x in range(5)), ctx)
    next(bound)
    ctx.suspend()
    assert ctx.is_suspended
    with pytest.raises(ContextSuspendedError):
        next(bound)
    with pytest.raises(ContextSuspendedError):
        bound.throw(RuntimeError())
    ctx.resume()
    assert ctx.is_active
    assert next(bound) == 1
    bound.close()
    with pytest.raises(ContextRevokedError):
        next(bound)


def test_revoked_context_rejects_resume_throw_and_send():
    ctx = make_context('A')
    bound = bind((x for x in range(5)), ctx)
    next(bound)
    ctx.revoke()
    assert ctx.is_revoked
    for op in (lambda: next(bound),
               lambda: bound.send(1),
               lambda: bound.throw(RuntimeError())):
        with pytest.raises(ContextRevokedError):
            op()
    # close() stays idempotent and controlled after revocation.
    bound.close()
    bound.close()


def test_close_runs_registered_cleanup_once_and_blocks_side_effects():
    ctx = make_context('A')
    cleaned = []

    def gen():
        _register_cleanup_(lambda: cleaned.append('gen-cleanup'))
        try:
            yield 1
            yield 2
        finally:
            # Business capability use during teardown must be refused.
            with pytest.raises(CapabilityDeniedError):
                ctx.use_capability('log')
            cleaned.append('finally-ran')

    bound = bind(gen(), ctx)
    next(bound)
    bound.close()
    bound.close()
    assert cleaned == ['finally-ran', 'gen-cleanup']
    assert ctx.cleanup_count == 2


def test_revoke_closes_all_bound_objects_and_runs_cleanups():
    ctx = make_context('A')
    events = []

    def gen(label):
        try:
            yield label
        finally:
            events.append(f'closed-{label}')

    g1 = bind(gen('one'), ctx)
    g2 = bind(gen('two'), ctx)
    next(g1)
    next(g2)
    ctx.register_cleanup(lambda: events.append('request-cleanup'))
    errors = ctx.revoke()
    assert errors == []
    assert sorted(events) == ['closed-one', 'closed-two', 'request-cleanup']
    assert ctx.cleanup_count == 3
    # Revocation is terminal: suspend/resume are impossible.
    with pytest.raises(LifecycleError):
        ctx.resume()


def test_capability_budget_and_unknown_capability_enforced():
    ctx = make_context('A', budgets={'log': 2})
    ctx.use_capability('log')
    ctx.use_capability('log')
    with pytest.raises(CapabilityDeniedError):
        ctx.use_capability('log')
    assert ctx.capability_usage['log'] == 2
    with pytest.raises(CapabilityDeniedError):
        ctx.use_capability('missing')


def test_capability_charged_inside_owning_context_only():
    ctx_a = make_context('A')
    ctx_b = make_context('B')

    def gen():
        ctx_a.use_capability('log')
        yield 1

    bound = bind(gen(), ctx_a)
    ctx_b.capture().run(lambda: next(bound))
    assert ctx_a.capability_usage['log'] == 1
    assert ctx_b.capability_usage['log'] == 0


def test_contextvar_does_not_leak_between_reentrant_frames():
    ctx = make_context('A')
    marker = contextvars.ContextVar('marker', default='root')

    def inner():
        assert marker.get() == 'outer'
        marker.set('inner')
        yield 'i'
        assert marker.get() == 'inner'

    def outer():
        marker.set('outer')
        try:
            yield from bind(inner())
            assert marker.get() == 'outer'
            yield 'o'
        finally:
            marker.set('root')

    bound = bind(outer(), ctx)
    assert next(bound) == 'i'
    assert next(bound) == 'o'
    assert marker.get() == 'root'
    bound.close()
    assert marker.get() == 'root'


def test_nested_yield_from_lifecycle_checks_apply():
    ctx = make_context('A')

    def inner():
        yield 10
        yield 11

    def outer():
        yield from bind(inner())
        yield 20

    bound = bind(outer(), ctx)
    assert list(bound) == [10, 11, 20]
    ctx2 = make_context('B')
    bound2 = bind(outer(), ctx2)
    next(bound2)
    ctx2.revoke()
    with pytest.raises(ContextRevokedError):
        next(bound2)


def test_bind_is_idempotent_and_requires_owner():
    ctx = make_context('A')
    bound = bind(iter([1]), ctx)
    assert bind(bound) is bound
    with pytest.raises(LifecycleError):
        bind(iter([1]))


def test_thread_handoff_preserves_owner_and_isolation():
    ctx_a = make_context('A')
    ctx_b = make_context('B')
    holder = {}

    def gen():
        yield CURRENT_CONTEXT.get().policy.name
        yield CURRENT_CONTEXT.get().policy.name

    bound = ctx_a.capture().run(lambda: bind(gen()))

    def drive():
        # A different thread with a different ambient context.
        holder['value'] = ctx_b.capture().run(lambda: next(bound))

    thread = threading.Thread(target=drive)
    thread.start()
    thread.join()
    assert holder['value'] == 'A'
    assert next(bound) == 'A'
    assert bound.owner is ctx_a


def test_cleanup_mode_cannot_perform_business_capability():
    ctx = make_context('A')

    def attempt():
        token = CLEANUP_MODE.set(True)
        try:
            ctx.use_capability('log')
        finally:
            CLEANUP_MODE.reset(token)

    with pytest.raises(CapabilityDeniedError):
        ctx.capture().run(attempt)
    assert ctx.capability_usage['log'] == 0


def _register_cleanup_(callback):
    bound = current_bound()
    bound.register_cleanup(callback)
