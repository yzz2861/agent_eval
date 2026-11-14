import platform
import types

import pytest

from RestrictedPython import CompileResult
from RestrictedPython import compile_restricted
from RestrictedPython import compile_restricted_eval
from RestrictedPython import compile_restricted_exec
from RestrictedPython import compile_restricted_function
from RestrictedPython import compile_restricted_single
from RestrictedPython.transformer import CAPABILITY_WITH_STATEMENTS
from RestrictedPython.transformer import RestrictingNodeTransformer
from tests.helper import restricted_eval


def test_compile__compile_restricted_invalid_code_input():
    with pytest.raises(TypeError):
        compile_restricted(object(), '<string>', 'exec')
    with pytest.raises(TypeError):
        compile_restricted(object(), '<string>', 'eval')
    with pytest.raises(TypeError):
        compile_restricted(object(), '<string>', 'single')


def test_compile__compile_restricted_invalid_policy_input():
    with pytest.raises(TypeError):
        compile_restricted("pass", '<string>', 'exec', policy=object)


def test_compile__compile_restricted_invalid_mode_input():
    with pytest.raises(TypeError):
        compile_restricted("pass", '<string>', 'invalid')


INVALID_ASSINGMENT = """
1 = 2
"""


def test_compile__invalid_syntax():
    with pytest.raises(SyntaxError) as err:
        compile_restricted(INVALID_ASSINGMENT, '<string>', 'exec')
    assert "SyntaxError: cannot assign to literal here." in str(err.value)


def test_compile__compile_restricted_exec__1():
    """It returns a CompileResult on success."""
    result = compile_restricted_exec('a = 42')
    assert result.__class__ == CompileResult
    assert result.errors == ()
    assert result.warnings == []
    assert result.used_names == {}
    glob = {}
    exec(result.code, glob)
    assert glob['a'] == 42


def test_compile__compile_restricted_exec__2():
    """It compiles without restrictions if there is no policy."""
    result = compile_restricted_exec('_a = 42', policy=None)
    assert result.errors == ()
    assert result.warnings == []
    assert result.used_names == {}
    glob = {}
    exec(result.code, glob)
    assert glob['_a'] == 42


def test_compile__compile_restricted_exec__3():
    """It returns a tuple of errors if the code is not allowed.

    There is no code in this case.
    """
    result = compile_restricted_exec('_a = 42\n_b = 43')
    errors = (
        'Line 1: "_a" is an invalid variable name because it starts with "_"',
        'Line 2: "_b" is an invalid variable name because it starts with "_"')
    assert result.errors == errors
    assert result.warnings == []
    assert result.used_names == {}
    assert result.code is None


def test_compile__compile_restricted_exec__4():
    """It does not return code on a SyntaxError."""
    result = compile_restricted_exec('asdf|')
    assert result.code is None
    assert result.warnings == []
    assert result.used_names == {}
    assert result.errors == (
        "Line 1: SyntaxError: invalid syntax at statement: 'asdf|'",)


def test_compile__compile_restricted_exec__5():
    """It does not return code if the code contains a NULL byte."""
    result = compile_restricted_exec('a = 5\x00')
    assert result.code is None
    assert result.warnings == []
    assert result.used_names == {}
    assert result.errors == (
        'Line None: SyntaxError: source code string cannot contain null'
        ' bytes at statement: None',)


EXEC_STATEMENT = """\
def no_exec():
    exec 'q = 1'
"""


def test_compile__compile_restricted_exec__10():
    """It is a SyntaxError to use the `exec` statement."""
    result = compile_restricted_exec(EXEC_STATEMENT)
    assert (
        'Line 2: SyntaxError: Missing parentheses in call to \'exec\'. Did'
        ' you mean exec(...)? at statement: "exec \'q = 1\'"',
    ) == result.errors


FUNCTION_DEF = """\
def a():
    pass
"""


def test_compile__compile_restricted_eval__1():
    """It compiles code as an Expression.

    Function definitions are not allowed in Expressions.
    """
    result = compile_restricted_eval(FUNCTION_DEF)
    assert result.errors == (
        "Line 1: SyntaxError: invalid syntax at statement: 'def a():'",)


def test_compile__compile_restricted_eval__2():
    """It compiles code as an Expression."""
    assert restricted_eval('4 * 6') == 24


def test_compile__compile_restricted_eval__used_names():
    result = compile_restricted_eval("a + b + func(x)")
    assert result.errors == ()
    assert result.warnings == []
    assert result.used_names == {'a': True, 'b': True, 'x': True, 'func': True}


def test_compile__compile_restricted_single__1():
    """It compiles code as an Interactive."""
    result = compile_restricted_single('x = 4 * 6')

    assert result.errors == ()
    assert result.warnings == []
    assert result.code is not None
    locals = {}
    exec(result.code, {}, locals)
    assert locals["x"] == 24


def test_compile__compile_restricted__2():
    """It compiles code as an Interactive."""
    code = compile_restricted('x = 4 * 6', filename="<string>", mode="single")
    locals = {}
    exec(code, {}, locals)
    assert locals["x"] == 24


PRINT_EXAMPLE = """
def a():
    print('Hello World!')
"""


def test_compile_restricted():
    """It emits Python warnings.

    For actual tests for print statement see: test_print_stmt.py
    """
    with pytest.warns(SyntaxWarning) as record:
        result = compile_restricted(PRINT_EXAMPLE, '<string>', 'exec')
        assert isinstance(result, types.CodeType)
        assert len(record) == 1
        assert record[0].message.args[0] == \
            "Line 2: Prints, but never reads 'printed' variable."


EVAL_EXAMPLE = """
def a():
    eval('2 + 2')
"""


def test_compile_restricted_eval():
    """This test checks compile_restricted itself if that raise Python errors.
    """
    with pytest.raises(SyntaxError,
                       match="Line 3: Eval calls are not allowed."):
        compile_restricted(EVAL_EXAMPLE, '<string>', 'exec')


def test_compile___compile_restricted_mode__1(recwarn, mocker):
    """It warns when using another Python implementation than CPython."""
    if platform.python_implementation() == 'CPython':  # pragma: no cover
        # Using CPython we have to fake the check:
        mocker.patch('RestrictedPython.compile.IS_CPYTHON', new=False)
    compile_restricted('42')
    assert len(recwarn) == 1
    w = recwarn.pop()
    assert w.category == RuntimeWarning
    assert str(w.message) == str(
        'RestrictedPython is only supported on CPython: use on other Python '
        'implementations may create security issues.'
    )


@pytest.mark.skipif(
    platform.python_implementation() == 'CPython',
    reason='Warning only present if not CPython.')
def test_compile_CPython_warning(recwarn, mocker):  # pragma: no cover
    """It warns when using another Python implementation than CPython."""
    assert platform.python_implementation() != 'CPython'
    with pytest.warns(RuntimeWarning) as record:
        compile_restricted('42')
    assert len(record) == 1
    assert str(record[0].message) == str(
        'RestrictedPython is only supported on CPython: use on other Python '
        'implementations may create security issues.'
    )


class WithStatementsPolicy(RestrictingNodeTransformer):
    """Policy enabling the reviewed ``with`` capability."""

    policy_name = 'WithStatementsPolicy'
    enabled_capabilities = frozenset({CAPABILITY_WITH_STATEMENTS})


WITH_SOURCE = (
    'def use_context(ctx):\n'
    '    with ctx() as value:\n'
    '        return value\n'
)


def test_compile__policy_violation_carries_location_and_policy():
    """SyntaxErrors from policy violations expose line, column and policy."""
    with pytest.raises(SyntaxError) as err:
        compile_restricted(
            WITH_SOURCE,
            filename='submitted_snippet')
    syntax_error = err.value
    assert syntax_error.filename == 'submitted_snippet'
    assert syntax_error.lineno == 2
    assert syntax_error.offset == 5
    assert syntax_error.policy == 'RestrictingNodeTransformer'
    assert syntax_error.node == 'With'
    assert 'with_statements' in syntax_error.msg


def test_compile__policy_violation_keeps_error_tuple():
    """The collected error strings stay available through ``args``."""
    with pytest.raises(SyntaxError) as err:
        compile_restricted(WITH_SOURCE)
    assert err.value.args[0] == (
        'Line 2, col 4: policy "RestrictingNodeTransformer" rejected node '
        'With: the capability for this node type is not enabled by the '
        'caller (required capability: "with_statements")',
    )


def test_compile__non_policy_syntax_error_has_no_policy_metadata():
    """Plain syntax errors keep their previous handling."""
    with pytest.raises(SyntaxError) as err:
        compile_restricted(INVALID_ASSINGMENT)
    assert err.value.policy is None
    assert err.value.node is None
    assert "SyntaxError: cannot assign to literal here." in str(err.value)


def test_compile__function_uses_node_admission_policy():
    """compile_restricted_function applies the same default-deny policy."""
    result = compile_restricted_function(
        '',
        'with ctx() as value:\n    return value\n',
        'use_context')
    assert result.code is None
    assert result.errors == (
        'Line 1, col 0: policy "RestrictingNodeTransformer" rejected node '
        'With: the capability for this node type is not enabled by the '
        'caller (required capability: "with_statements")',
    )
    allowed = compile_restricted_function(
        '',
        'return 1 + 1\n',
        'add_two',
        policy=WithStatementsPolicy)
    assert allowed.errors == ()
    assert allowed.code is not None
