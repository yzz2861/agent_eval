from __future__ import annotations

import ast
import collections.abc
import os
import re
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

# Matches the position prefix of node admission policy errors, e.g.
# 'Line 3, col 4: policy "RestrictingNodeTransformer" rejected node ...'.
_POLICY_ERROR_RE = re.compile(
    r'^Line (?P<lineno>[0-9]+|None), col (?P<col>[0-9]+|None): '
    r'policy "(?P<policy>.+?)" rejected node '
    r'(?P<node>[A-Za-z_][A-Za-z0-9_]*): .*$')

_T_ast_compilable: typing.TypeAlias = (
    ast.Module | ast.Expression | ast.Interactive)
_T_source: typing.TypeAlias = str | ReadableBuffer | _T_ast_compilable


def _instantiate_policy(
        policy: type[RestrictingNodeTransformer],
        collected_errors: list[str],
        collected_warnings: list[str],
        used_names: dict[str, bool]) -> RestrictingNodeTransformer:
    """Create the policy instance used to transform a source unit.

    The policy class is supplied by the caller.  It is instantiated with the
    shared error/warning/used-name containers so that every node admission
    violation is reported back through the :class:`CompileResult` instead of
    raising an exception while the AST is still being visited.
    """
    return policy(collected_errors, collected_warnings, used_names)


def _build_syntax_error(
        errors: collections.abc.Sequence[str],
        filename: str | bytes | os.PathLike[typing.Any]) -> SyntaxError:
    """Build a SyntaxError from collected restriction errors.

    The complete error tuple stays available through ``args`` so existing
    string based error handling keeps working.  For node admission policy
    errors the source line, column and policy name are additionally exposed
    through the standard SyntaxError attributes (and dedicated attributes),
    instead of raising a generic syntax error without location data.
    """
    first_error = errors[0]
    lineno: int | None = None
    offset: int | None = None
    policy_name: str | None = None
    node_name: str | None = None
    match = _POLICY_ERROR_RE.match(first_error)
    if match is not None:
        if match.group('lineno') != 'None':
            lineno = int(match.group('lineno'))
        if match.group('col') != 'None':
            # Python offsets are 1-based while AST columns are 0-based.
            offset = int(match.group('col')) + 1
        policy_name = match.group('policy')
        node_name = match.group('node')
    syntax_error = SyntaxError(errors)
    syntax_error.filename = os.fspath(filename)
    syntax_error.lineno = lineno
    syntax_error.offset = offset
    syntax_error.msg = first_error
    syntax_error.policy = policy_name  # type: ignore[attr-defined]
    syntax_error.node = node_name  # type: ignore[attr-defined]
    return syntax_error


def _compile_restricted_mode(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        mode: typing.Literal["exec", "eval", "single"] = "exec",
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
) -> CompileResult:

    if not IS_CPYTHON:
        warnings.warn_explicit(
            NOT_CPYTHON_WARNING, RuntimeWarning, 'RestrictedPython', 0)

    byte_code = None
    collected_errors: list[str] = []
    collected_warnings: list[str] = []
    used_names: dict[str, bool] = {}
    if policy is None:
        # Unrestricted Source Checks
        byte_code = compile(source, filename, mode=mode, flags=flags,
                            dont_inherit=dont_inherit)
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
                c_ast = typing.cast(
                    _T_ast_compilable, ast.parse(
                        source, filename, mode))
            except SyntaxError as v:
                collected_errors.append(syntax_error_template.format(
                    lineno=v.lineno,
                    type=v.__class__.__name__,
                    msg=v.msg,
                    statement=v.text.strip() if v.text else None
                ))
        if c_ast:
            policy_instance = _instantiate_policy(
                policy, collected_errors, collected_warnings,
                used_names)
            policy_instance.visit(c_ast)
            if not collected_errors:
                byte_code = compile(c_ast, filename, mode=mode  # ,
                                    # flags=flags,
                                    # dont_inherit=dont_inherit
                                    )
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
) -> CompileResult:
    """Compile restricted for the mode `exec`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='exec',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy)


def compile_restricted_eval(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
) -> CompileResult:
    """Compile restricted for the mode `eval`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='eval',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy)


def compile_restricted_single(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
) -> CompileResult:
    """Compile restricted for the mode `single`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='single',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy)


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
) -> CompileResult:
    """Compile a restricted code object for a function.

    Documentation see:
    http://restrictedpython.readthedocs.io/en/latest/usage/index.html#RestrictedPython.compile_restricted_function
    """
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
            body_ast = ast.parse(body, '<func code>', 'exec').body
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
        policy=policy)

    return result


def compile_restricted(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<unknown>',
        mode: typing.Literal["exec", "eval", "single"] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
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
            policy=policy)
    else:
        raise TypeError('unknown mode %s', mode)
    for warning in result.warnings:
        warnings.warn(
            warning,
            SyntaxWarning
        )
    if result.errors:
        raise _build_syntax_error(result.errors, filename)
    return cast_not_none(result.code)
