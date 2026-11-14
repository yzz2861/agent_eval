from __future__ import annotations

import ast
import collections.abc
import contextlib
import dataclasses
import os
import sys
import types
import typing
import warnings

from RestrictedPython._compat import IS_CPYTHON
from RestrictedPython._types import cast_not_none
from RestrictedPython.transformer import RestrictingNodeTransformer
from RestrictedPython.transformer import copy_locations


# Temporary workaround for missing _typeshed
ReadableBuffer: typing.TypeAlias = bytes | bytearray


class CompileResult(typing.NamedTuple):
    code: types.CodeType | None
    errors: collections.abc.Sequence[str]
    warnings: collections.abc.Sequence[str]
    used_names: collections.abc.Mapping[str, bool]


syntax_error_template = (
    'Line {lineno}: {type}: {msg} at statement: {statement!r}'
)

NOT_CPYTHON_WARNING = (
    'RestrictedPython is only supported on CPython: use on other Python '
    'implementations may create security issues.'
)

_T_ast_compilable: typing.TypeAlias = (
    ast.Module | ast.Expression | ast.Interactive)
_T_source: typing.TypeAlias = str | ReadableBuffer | _T_ast_compilable


class BudgetExceededError(SyntaxError):
    """A configurable compile budget was exceeded.

    This is a subclass of 'SyntaxError' so existing error handling keeps
    working, while the structured attributes allow callers (e. g. different
    tenants) to distinguish *which* limit was hit and *where*:

    resource ... name of the exhausted budget, e. g. 'ast_depth'
    limit ...... configured limit ('None' if not known)
    actual ..... measured value ('None' if it could not be measured,
                 e. g. when the interpreter hit its recursion limit first)
    phase ...... compilation phase: 'parse', 'transform',
                 'compile' or 'code_object'
    filename ... filename the source was compiled with
    lineno ..... 1-based source line responsible for the violation, if known
    col_offset . 0-based source column responsible for the violation, if known
    """

    def __init__(
            self,
            resource: str,
            limit: int | None,
            actual: int | None,
            *,
            phase: str,
            filename: str | bytes | os.PathLike[typing.Any] = '<string>',
            lineno: int | None = None,
            col_offset: int | None = None,
    ) -> None:
        self.resource = resource
        self.limit = limit
        self.actual = actual
        self.phase = phase
        self.filename = filename
        self.lineno = lineno
        self.col_offset = col_offset
        detail = '{0} budget exceeded during {1}'.format(resource, phase)
        if actual is not None and limit is not None:
            detail = '{0}: {1} > limit {2}'.format(detail, actual, limit)
        elif limit is not None:
            detail = '{0}: limit {1}'.format(detail, limit)
        if lineno is not None:
            detail = 'Line {0}, column {1}: {2}'.format(
                lineno, col_offset if col_offset is not None else 0, detail)
        super().__init__(detail)


@dataclasses.dataclass(frozen=True)
class CompileBudget:
    """Configurable limits for restricted compilation.

    Every limit is optional; 'None' means 'unlimited'.  The budgets cover
    all compilation phases:

    max_source_length .. length of str/bytes source (parse phase)
    max_ast_depth ...... nesting depth of the parsed AST (parse phase)
    max_ast_nodes ...... total number of AST nodes (parse phase)
    max_constant_size .. size of str/bytes constants (parse phase)
    max_code_size ...... summed bytecode size of all code objects produced
                         by the final compile() call
    """

    max_source_length: int | None = None
    max_ast_depth: int | None = None
    max_ast_nodes: int | None = None
    max_constant_size: int | None = None
    max_code_size: int | None = None


# Generous defaults which keep pathological inputs (deeply nested
# expressions, huge constants, ...) from stalling or crashing the
# interpreter while leaving normal scripts unaffected.
DEFAULT_COMPILE_BUDGET = CompileBudget(
    max_source_length=None,
    max_ast_depth=1000,
    max_ast_nodes=100000,
    max_constant_size=1000000,
    max_code_size=1000000,
)


def _node_location(node: ast.AST) -> tuple[int | None, int | None]:
    return (
        getattr(node, 'lineno', None),
        getattr(node, 'col_offset', None))


@contextlib.contextmanager
def _recursion_guard(
        phase: str,
        filename: str | bytes | os.PathLike[typing.Any]
) -> typing.Iterator[None]:
    """Convert interpreter level recursion failures into budget errors."""
    try:
        yield
    except RecursionError:
        raise BudgetExceededError(
            'ast_depth',
            sys.getrecursionlimit(),
            None,
            phase=phase,
            filename=filename) from None


def _check_source_budget(
        source: _T_source,
        budget: CompileBudget,
        filename: str | bytes | os.PathLike[typing.Any]
) -> None:
    if budget.max_source_length is None:
        return
    if isinstance(source, (str, bytes, bytearray)):
        length = len(source)
        if length > budget.max_source_length:
            raise BudgetExceededError(
                'source_length',
                budget.max_source_length,
                length,
                phase='parse',
                filename=filename)


def _check_ast_budget(
        tree: ast.AST,
        budget: CompileBudget,
        filename: str | bytes | os.PathLike[typing.Any]
) -> None:
    """Check depth, node count and constant sizes of 'tree'.

    The walk is iterative so that checking itself cannot trigger a
    'RecursionError' on deeply nested input.
    """
    if (budget.max_ast_depth is None
            and budget.max_ast_nodes is None
            and budget.max_constant_size is None):
        return
    node_count = 0
    # Location-less helper nodes (e. g. 'Load') inherit the position of
    # their nearest ancestor so diagnostics always point at source code.
    stack: list[tuple[ast.AST, int, int | None, int | None]] = [
        (tree, 1, None, None)]
    while stack:
        node, depth, lineno, col_offset = stack.pop()
        node_count += 1
        own_lineno, own_col_offset = _node_location(node)
        if own_lineno is not None:
            lineno, col_offset = own_lineno, own_col_offset
        if (budget.max_ast_nodes is not None
                and node_count > budget.max_ast_nodes):
            raise BudgetExceededError(
                'ast_nodes',
                budget.max_ast_nodes,
                node_count,
                phase='parse',
                filename=filename,
                lineno=lineno,
                col_offset=col_offset)
        if (budget.max_ast_depth is not None
                and depth > budget.max_ast_depth):
            raise BudgetExceededError(
                'ast_depth',
                budget.max_ast_depth,
                depth,
                phase='parse',
                filename=filename,
                lineno=lineno,
                col_offset=col_offset)
        if (budget.max_constant_size is not None
                and isinstance(node, ast.Constant)
                and isinstance(node.value, (str, bytes))):
            size = len(node.value)
            if size > budget.max_constant_size:
                raise BudgetExceededError(
                    'constant_size',
                    budget.max_constant_size,
                    size,
                    phase='parse',
                    filename=filename,
                    lineno=lineno,
                    col_offset=col_offset)
        for child in ast.iter_child_nodes(node):
            stack.append((child, depth + 1, lineno, col_offset))


def _check_code_budget(
        code: types.CodeType,
        budget: CompileBudget,
        filename: str | bytes | os.PathLike[typing.Any]
) -> None:
    """Check summed bytecode size of 'code' and nested code objects.

    The walk is iterative and every code object is visited at most once.
    """
    if budget.max_code_size is None:
        return
    total = 0
    seen: set[int] = set()
    stack = [code]
    while stack:
        code_object = stack.pop()
        if id(code_object) in seen:
            continue
        seen.add(id(code_object))
        total += len(code_object.co_code)
        if total > budget.max_code_size:
            raise BudgetExceededError(
                'code_size',
                budget.max_code_size,
                total,
                phase='code_object',
                filename=filename)
        for const in code_object.co_consts:
            if isinstance(const, types.CodeType):
                stack.append(const)


def _resolve_budget(budget: CompileBudget | None) -> CompileBudget:
    return DEFAULT_COMPILE_BUDGET if budget is None else budget


def _compile_restricted_mode(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        mode: typing.Literal["exec", "eval", "single"] = "exec",
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        budget: CompileBudget | None = None,
) -> CompileResult:

    if not IS_CPYTHON:
        warnings.warn_explicit(
            NOT_CPYTHON_WARNING, RuntimeWarning, 'RestrictedPython', 0)

    budget = _resolve_budget(budget)
    byte_code = None
    collected_errors: list[str] = []
    collected_warnings: list[str] = []
    used_names: dict[str, bool] = {}
    _check_source_budget(source, budget, filename)
    if policy is None:
        # Unrestricted Source Checks
        with _recursion_guard('compile', filename):
            byte_code = compile(source, filename, mode=mode, flags=flags,
                                dont_inherit=dont_inherit)
        _check_code_budget(byte_code, budget, filename)
    elif issubclass(policy, RestrictingNodeTransformer):
        allowed_source_types = [
            str,
            bytes,
            bytearray,
            ast.Module,
            ast.Expression,
            ast.Interactive]
        if not issubclass(type(source), tuple(allowed_source_types)):
            raise TypeError('Not allowed source type: '
                            '"{0.__class__.__name__}".'.format(source))
        c_ast: _T_ast_compilable | None = None
        # workaround for pypy issue https://bitbucket.org/pypy/pypy/issues/2552
        if isinstance(source, (ast.Module, ast.Expression, ast.Interactive)):
            c_ast = source
        else:
            try:
                with _recursion_guard('parse', filename):
                    c_ast = typing.cast(
                        _T_ast_compilable, ast.parse(
                            source, filename, mode))
            except BudgetExceededError:
                raise
            except SyntaxError as v:
                collected_errors.append(syntax_error_template.format(
                    lineno=v.lineno,
                    type=v.__class__.__name__,
                    msg=v.msg,
                    statement=v.text.strip() if v.text else None
                ))
        if c_ast:
            # Reject over-budget trees before the (recursive) transformer
            # or the compiler can choke on them.  On failure nothing is
            # cached and no half-transformed AST is compiled: 'byte_code'
            # stays 'None' and the error propagates.
            _check_ast_budget(c_ast, budget, filename)
            policy_instance = policy(
                collected_errors, collected_warnings, used_names)
            with _recursion_guard('transform', filename):
                policy_instance.visit(c_ast)
            if not collected_errors:
                with _recursion_guard('compile', filename):
                    byte_code = compile(c_ast, filename, mode=mode  # ,
                                        # flags=flags,
                                        # dont_inherit=dont_inherit
                                        )
                _check_code_budget(byte_code, budget, filename)
    else:
        raise TypeError('Unallowed policy provided for RestrictedPython')
    return CompileResult(
        byte_code,
        tuple(collected_errors),
        collected_warnings,
        used_names)


def compile_restricted_exec(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        budget: CompileBudget | None = None,
) -> CompileResult:
    """Compile restricted for the mode `exec`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='exec',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        budget=budget)


def compile_restricted_eval(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        budget: CompileBudget | None = None,
) -> CompileResult:
    """Compile restricted for the mode `eval`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='eval',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        budget=budget)


def compile_restricted_single(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        budget: CompileBudget | None = None,
) -> CompileResult:
    """Compile restricted for the mode `single`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='single',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        budget=budget)


def compile_restricted_function(
        p: str,  # parameters
        body: _T_source,
        name: str,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        # List of globals (e.g. ['here', 'context', ...])
        globalize: list[str] | None = None,
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        budget: CompileBudget | None = None,
) -> CompileResult:
    """Compile a restricted code object for a function.

    Documentation see:
    http://restrictedpython.readthedocs.io/en/latest/usage/index.html#RestrictedPython.compile_restricted_function
    """
    budget = _resolve_budget(budget)
    # Parse the parameters and body, then combine them.
    body_ast: list[ast.stmt]
    if isinstance(body, ast.Expression):
        _body_ast = ast.Expr(body.body)
        copy_locations(_body_ast, body.body)
        body_ast = [_body_ast]
    elif isinstance(body, (ast.Module, ast.Interactive)):
        body_ast = body.body
    else:
        try:
            _check_source_budget(body, budget, '<func code>')
            with _recursion_guard('parse', '<func code>'):
                body_ast = ast.parse(body, '<func code>', 'exec').body
        except BudgetExceededError:
            raise
        except SyntaxError as v:
            error = syntax_error_template.format(
                lineno=v.lineno,
                type=v.__class__.__name__,
                msg=v.msg,
                statement=v.text.strip() if v.text else None)
            return CompileResult(
                code=None, errors=(error,), warnings=(), used_names={})

    # The compiled code is actually executed inside a function
    # (that is called when the code is called) so reading and assigning to a
    # global variable like this`printed += 'foo'` would throw an
    # UnboundLocalError.
    # We don't want the user to need to understand this.
    if globalize:
        body_ast.insert(0, ast.Global(globalize))
    wrapper_ast = ast.parse('def masked_function_name(%s): pass' % p,
                            '<func wrapper>', 'exec')
    # In case the name you chose for your generated function is not a
    # valid python identifier we set it after the fact
    function_ast = wrapper_ast.body[0]
    assert isinstance(function_ast, ast.FunctionDef)
    function_ast.name = name

    function_ast.body = body_ast
    wrapper_ast = ast.fix_missing_locations(wrapper_ast)

    result = _compile_restricted_mode(
        wrapper_ast,
        filename=filename,
        mode='exec',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        budget=budget)

    return result


def compile_restricted(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<unknown>',
        mode: typing.Literal["exec", "eval", "single"] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        budget: CompileBudget | None = None,
) -> types.CodeType:
    """Replacement for the built-in compile() function.

    policy ... `ast.NodeTransformer` class defining the restrictions.

    """
    if mode in ['exec', 'eval', 'single']:
        result = _compile_restricted_mode(
            source,
            filename=filename,
            mode=mode,
            flags=flags,
            dont_inherit=dont_inherit,
            policy=policy,
            budget=budget)
    else:
        raise TypeError('unknown mode %s', mode)
    for warning in result.warnings:
        warnings.warn(
            warning,
            SyntaxWarning
        )
    if result.errors:
        raise SyntaxError(result.errors)
    return cast_not_none(result.code)
