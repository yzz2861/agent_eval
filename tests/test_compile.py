import ast
import platform
import types

import pytest

from RestrictedPython import BudgetExceededError
from RestrictedPython import CompileBudget
from RestrictedPython import CompileResult
from RestrictedPython import compile_restricted
from RestrictedPython import compile_restricted_eval
from RestrictedPython import compile_restricted_exec
from RestrictedPython import compile_restricted_single
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


def _deep_expression_ast(depth):
    """Build an attribute chain AST of ``depth`` levels, iteratively."""
    node = ast.Name(id='x', ctx=ast.Load(), lineno=1, col_offset=0)
    for _ in range(depth):
        node = ast.Attribute(
            value=node, attr='a', ctx=ast.Load(), lineno=1, col_offset=0)
    return ast.Expression(node)


def test_compile__budget_normal_script_unaffected():
    """The default budget does not change normal compilation."""
    result = compile_restricted_exec('a = 42')
    assert result.errors == ()
    assert result.code is not None


def test_compile__budget_exceeded_ast_depth():
    """Deeply nested ASTs are rejected with a located diagnostic."""
    with pytest.raises(BudgetExceededError) as exc:
        compile_restricted_eval(
            _deep_expression_ast(5000),
            budget=CompileBudget(max_ast_depth=100))
    assert exc.value.resource == 'ast_depth'
    assert exc.value.phase == 'parse'
    assert exc.value.limit == 100
    assert exc.value.actual == 101
    assert exc.value.lineno == 1


def test_compile__budget_exceeded_ast_nodes():
    source = 'x = [' + ','.join(['1'] * 500) + ']'
    with pytest.raises(BudgetExceededError) as exc:
        compile_restricted_exec(source, budget=CompileBudget(max_ast_nodes=10))
    assert exc.value.resource == 'ast_nodes'
    assert exc.value.lineno == 1


def test_compile__budget_exceeded_constant_size():
    source = 'result = "' + 'x' * 200000 + '"'
    with pytest.raises(BudgetExceededError) as exc:
        compile_restricted_exec(
            source, budget=CompileBudget(max_constant_size=1000))
    assert exc.value.resource == 'constant_size'
    assert exc.value.actual == 200000
    assert exc.value.lineno == 1
    assert exc.value.col_offset == 9


def test_compile__budget_exceeded_source_length():
    with pytest.raises(BudgetExceededError) as exc:
        compile_restricted_exec(
            'pass', budget=CompileBudget(max_source_length=2))
    assert exc.value.resource == 'source_length'
    assert exc.value.phase == 'parse'


def test_compile__budget_exceeded_code_size():
    source = '\n'.join('a%d = %d' % (i, i) for i in range(200))
    with pytest.raises(BudgetExceededError) as exc:
        compile_restricted_exec(source, budget=CompileBudget(max_code_size=10))
    assert exc.value.resource == 'code_size'
    assert exc.value.phase == 'code_object'


def test_compile__budget_recursion_guard():
    """Interpreter recursion limits become budget errors, not crashes."""
    source = 'x' + '.attr' * 100000
    with pytest.raises(BudgetExceededError) as exc:
        compile_restricted_eval(source, budget=CompileBudget())
    assert exc.value.resource == 'ast_depth'


def test_compile__budget_exceeded_is_syntax_error():
    """Budget errors stay catchable as SyntaxError for compatibility."""
    with pytest.raises(SyntaxError):
        compile_restricted(
            'pass', '<string>', 'exec',
            budget=CompileBudget(max_source_length=2))


def test_compile__budget_failure_leaves_no_stale_state():
    """A failed compilation does not affect subsequent compilations."""
    with pytest.raises(BudgetExceededError):
        compile_restricted_exec('pass', budget=CompileBudget(max_ast_nodes=1))
    result = compile_restricted_exec('pass')
    assert result.errors == ()
    assert result.code is not None
