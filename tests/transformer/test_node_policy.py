import ast
import operator

import pytest

from RestrictedPython import compile_restricted
from RestrictedPython import compile_restricted_exec
from RestrictedPython.transformer import CAPABILITY_WITH_STATEMENTS
from RestrictedPython.transformer import DEFAULT_POLICY_NAME
from RestrictedPython.transformer import RestrictingNodeTransformer


_INPLACE_OPS = {
    '+=': operator.iadd,
    '-=': operator.isub,
}


def _inplacevar(op, value, expr):
    return _INPLACE_OPS[op](value, expr)


def _write(value):
    return value


class WithStatementsPolicy(RestrictingNodeTransformer):
    policy_name = 'WithStatementsPolicy'
    enabled_capabilities = frozenset({CAPABILITY_WITH_STATEMENTS})


WITH_SOURCE = (
    'def use_context(ctx):\n'
    '    with ctx() as value:\n'
    '        return value\n'
)


def test_policy_rejects_with_without_enabled_capability():
    """Nodes behind a switch fail closed unless the caller opts in."""
    result = compile_restricted_exec(WITH_SOURCE)
    assert result.code is None
    assert result.errors == (
        'Line 2, col 4: policy "RestrictingNodeTransformer" rejected node '
        'With: the capability for this node type is not enabled by the '
        'caller (required capability: "with_statements")',
    )


def test_policy_allows_with_when_capability_is_enabled():
    """The same node is admitted once the caller enables the switch."""
    result = compile_restricted_exec(
        WITH_SOURCE, policy=WithStatementsPolicy)
    assert result.errors == ()
    assert result.warnings == []
    assert result.code is not None


def test_capability_does_not_admit_other_reviewed_out_nodes():
    """Enabling ``with`` must not open any other node type."""
    nested_match = (
        'def use_context(ctx):\n'
        '    with ctx():\n'
        '        match 1:\n'
        '            case _:\n'
        '                pass\n'
    )
    result = compile_restricted_exec(
        nested_match, policy=WithStatementsPolicy)
    assert result.code is None
    assert result.errors == (
        'Line 3, col 8: policy "WithStatementsPolicy" rejected node Match: '
        'this node type is not known to RestrictedPython and has not '
        'passed a security review',
    )


def test_policy_error_reports_the_custom_policy_name():
    """Capability errors carry the calling application policy name."""
    class NamedDefaultPolicy(RestrictingNodeTransformer):
        policy_name = 'LowCodePlatformPolicy'

    result = compile_restricted_exec(WITH_SOURCE, policy=NamedDefaultPolicy)
    assert result.errors == (
        'Line 2, col 4: policy "LowCodePlatformPolicy" rejected node With: '
        'the capability for this node type is not enabled by the caller '
        '(required capability: "with_statements")',
    )


MATCH_SOURCE = (
    'def classify(value):\n'
    '    match value:\n'
    '        case 1:\n'
    '            return "one"\n'
    '        case _:\n'
    '            return "other"\n'
)


def test_policy_rejects_unknown_match_nodes():
    """Unreviewed nodes are rejected with line, column and a warning."""
    result = compile_restricted_exec(MATCH_SOURCE)
    assert result.code is None
    assert result.errors == (
        'Line 2, col 4: policy "RestrictingNodeTransformer" rejected node '
        'Match: this node type is not known to RestrictedPython and has '
        'not passed a security review',
    )
    assert result.warnings == [
        'Line 2, col 4: Match statement is not known to policy '
        '"RestrictingNodeTransformer"',
    ]


TRY_STAR_SOURCE = (
    'def split_errors():\n'
    '    try:\n'
    '        pass\n'
    '    except* ValueError:\n'
    '        pass\n'
)


def test_policy_rejects_exception_groups():
    """``try/except*`` is explicitly denied and cannot be enabled."""
    result = compile_restricted_exec(TRY_STAR_SOURCE)
    assert result.code is None
    assert result.errors == (
        'Line 2, col 4: policy "RestrictingNodeTransformer" rejected node '
        'TryStar: this node type is explicitly forbidden and cannot be '
        'enabled',
    )


def test_compile_restricted_raises_structured_syntax_error():
    """The raised SyntaxError exposes position and policy metadata."""
    with pytest.raises(SyntaxError) as exc_info:
        compile_restricted(
            WITH_SOURCE,
            filename='submitted_snippet')
    error = exc_info.value
    assert error.lineno == 2
    assert error.offset == 5
    assert error.filename == 'submitted_snippet'
    assert error.policy == DEFAULT_POLICY_NAME
    assert error.node == 'With'
    assert 'with_statements' in str(error)


def test_synthetic_node_without_location_is_rejected():
    """Nodes without coordinates fail closed with ``None`` positions."""
    transformer = RestrictingNodeTransformer()
    transformer.visit(ast.Match(
        subject=ast.Constant(1),
        cases=[]))
    assert transformer.errors == [
        'Line None, col None: policy "RestrictingNodeTransformer" rejected '
        'node Match: this node type is not known to RestrictedPython and '
        'has not passed a security review',
    ]


def test_allowed_nodes_keep_working_under_the_default_policy():
    """Reviewed nodes and generators keep their existing legal behavior."""
    result = compile_restricted_exec(
        'total = sum(item for item in (1, 2, 3))\n')
    assert result.errors == ()
    namespace = {'_getiter_': lambda obj: obj}
    exec(result.code, namespace)
    assert namespace['total'] == 6


def test_missing_guard_variable_keeps_runtime_name_error():
    """A missing guard stays a runtime NameError, not a compile error."""
    result = compile_restricted_exec(
        'total = sum(item for item in (1, 2, 3))\n')
    assert result.errors == ()
    with pytest.raises(NameError, match='_getiter_'):
        exec(result.code, {})


NESTED_TRY_SOURCE = (
    'def nested_try(value):\n'
    '    try:\n'
    '        try:\n'
    '            return 1 / value\n'
    '        except ZeroDivisionError:\n'
    '            return "inner"\n'
    '    except Exception:\n'
    '        return "outer"\n'
)


def test_nested_try_statements_are_allowed():
    """Nested try/except keeps working under the default policy."""
    result = compile_restricted_exec(NESTED_TRY_SOURCE)
    assert result.errors == ()
    assert result.warnings == []
    namespace = {'_getattr_': getattr}
    exec(result.code, namespace)
    assert namespace['nested_try'](0) == 'inner'
    assert namespace['nested_try'](2) == 0.5


DECORATOR_SOURCE = (
    'def memoize(func):\n'
    '    cache = {}\n'
    '    def wrapper(key):\n'
    '        if key not in cache:\n'
    '            cache[key] = func(key)\n'
    '        return cache[key]\n'
    '    return wrapper\n'
    '\n'
    '@memoize\n'
    'def compute(key):\n'
    '    return key * 2\n'
)


def test_decorated_functions_are_allowed():
    """Decorators and the calls they wrap remain legal nodes."""
    result = compile_restricted_exec(DECORATOR_SOURCE)
    assert result.errors == ()
    assert result.warnings == []
    namespace = {
        '_write_': _write,
        '_getattr_': getattr,
        '_getiter_': lambda obj: obj,
        '_getitem_': lambda obj, key: obj[key],
    }
    exec(result.code, namespace)
    assert namespace['compute'](21) == 42
    assert namespace['compute'](21) == 42


GENERATOR_SOURCE = (
    'def running_total(values):\n'
    '    total = 0\n'
    '    for value in values:\n'
    '        total += value\n'
    '        yield total\n'
    '\n'
    'def delegated(values):\n'
    '    yield from running_total(values)\n'
)


def test_generators_and_yield_from_are_allowed():
    """Generators and ``yield from`` remain legal under the policy."""
    result = compile_restricted_exec(GENERATOR_SOURCE)
    assert result.errors == ()
    assert result.warnings == []
    namespace = {
        '_getiter_': lambda obj: obj,
        '_inplacevar_': _inplacevar,
    }
    exec(result.code, namespace)
    assert list(namespace['running_total']([1, 2, 3])) == [1, 3, 6]
    assert list(namespace['delegated']([1, 2, 3])) == [1, 3, 6]
