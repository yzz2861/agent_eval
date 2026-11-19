"""Deterministic two-context rotation demo (no web, no async).

Run with the project interpreter, e.g. python demo_lifecycle.py.
Two request contexts A and B each create a restricted generator.
The generators are then resumed in a fixed A/B/B/A order while the
*other* context is ambient, proving that each generator keeps the
policy and capabilities captured at creation time.  The demo finishes
by suspending/revoking the contexts and prints capability and cleanup
counts.
"""

from RestrictedPython.execution_adapter import RestrictedExecutionAdapter
from RestrictedPython.execution_lifecycle import (
    ContextRevokedError,
    ContextSuspendedError,
    ExecutionContext,
    Policy,
    bind,
)

SOURCE = """
def make_gen(log):
    register_cleanup(lambda: log.append('cleanup'))
    capability('log', 'start')
    yield 1
    for chunk in iter_guard(['a', 'b']):
        capability('log', chunk)
        yield chunk
"""


def make_context(name):
    return ExecutionContext(
        Policy(
            name=name,
            capabilities=frozenset(['log']),
            budgets={'log': 10},
        )
    )


def main():
    adapter = RestrictedExecutionAdapter()
    log_a = []
    log_b = []
    ctx_a = make_context('A')
    ctx_b = make_context('B')
    host_a = {'log': lambda message: log_a.append(message)}
    host_b = {'log': lambda message: log_b.append(message)}

    scope_a = adapter.run(SOURCE, ctx_a, host_a)
    scope_b = adapter.run(SOURCE, ctx_b, host_b)
    gen_a = ctx_a.capture().run(
        lambda: bind(scope_a['make_gen'](log_a)))
    gen_b = ctx_b.capture().run(
        lambda: bind(scope_b['make_gen'](log_b)))

    # Fixed, deterministic cross-request rotation.
    print('resume A under ambient B ->',
          ctx_b.capture().run(lambda: next(gen_a)))
    print('resume B under ambient A ->',
          ctx_a.capture().run(lambda: next(gen_b)))
    print('resume B under ambient A ->',
          ctx_a.capture().run(lambda: next(gen_b)))
    print('resume A under ambient B ->',
          ctx_b.capture().run(lambda: next(gen_a)))

    print('owners:', gen_a.owner.policy.name, gen_b.owner.policy.name)
    print('A capability usage:', dict(ctx_a.capability_usage))
    print('B capability usage:', dict(ctx_b.capability_usage))

    # Temporary suspension blocks business work, then allows resume.
    ctx_a.suspend()
    try:
        next(gen_a)
    except ContextSuspendedError:
        print('suspended A rejects resume: yes')
    ctx_a.resume()
    print('A resumed, next value ->', next(gen_a))

    # Permanent revocation: only controlled cleanup remains.
    ctx_b.revoke()
    try:
        next(gen_b)
    except ContextRevokedError:
        print('revoked B rejects resume: yes')
    gen_b.close()
    print('B log after cleanup:', log_b)
    print('A cleanup count:', ctx_a.cleanup_count)
    print('B cleanup count:', ctx_b.cleanup_count)
    print('B business capability calls:', ctx_b.capability_usage['log'])


if __name__ == '__main__':
    main()
