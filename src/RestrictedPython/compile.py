from __future__ import annotations

import ast
import collections.abc
import os
import types
import typing
import warnings

from RestrictedPython._compat import IS_CPYTHON
from RestrictedPython._types import cast_not_none
from RestrictedPython.artifacts import build_compile_artifact
from RestrictedPython.artifacts import CompileArtifact
from RestrictedPython.artifacts import CompileEnvironment
from RestrictedPython.artifacts import T_FeatureInput
from RestrictedPython.transformer import RestrictingNodeTransformer
from RestrictedPython.transformer import copy_locations


# Temporary workaround for missing _typeshed
ReadableBuffer: typing.TypeAlias = bytes | bytearray


class CompileResult(tuple):
    """The historical four-value compile result plus an optional artifact.

    The tuple part intentionally keeps its original four fields so existing
    unpacking and indexing code continues to work.  The artifact is available
    through the ``artifact`` attribute (and through index ``4`` for callers
    which prefer a uniform accessor).
    """

    _fields: typing.ClassVar[tuple[str, ...]] = (
        'code',
        'errors',
        'warnings',
        'used_names',
    )
    _field_defaults: typing.ClassVar[dict[str, typing.Any]] = {
        'artifact': None,
    }
    __match_args__ = _fields

    artifact: CompileArtifact | None

    def __new__(
        cls,
        code: types.CodeType | None,
        errors: collections.abc.Sequence[str],
        warnings: collections.abc.Sequence[str],
        used_names: collections.abc.Mapping[str, bool],
        artifact: CompileArtifact | None = None,
    ) -> CompileResult:
        result = tuple.__new__(cls, (code, errors, warnings, used_names))
        result.artifact = artifact
        return result

    @property
    def code(self) -> types.CodeType | None:
        return typing.cast(types.CodeType | None, tuple.__getitem__(self, 0))

    @property
    def errors(self) -> collections.abc.Sequence[str]:
        return typing.cast(
            collections.abc.Sequence[str], tuple.__getitem__(self, 1))

    @property
    def warnings(self) -> collections.abc.Sequence[str]:
        return typing.cast(
            collections.abc.Sequence[str], tuple.__getitem__(self, 2))

    @property
    def used_names(self) -> collections.abc.Mapping[str, bool]:
        return typing.cast(
            collections.abc.Mapping[str, bool], tuple.__getitem__(self, 3))

    def __getitem__(self, index: int | slice) -> typing.Any:
        if index == 4:
            return self.artifact
        return tuple.__getitem__(self, index)

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, tuple):
            return NotImplemented  # type: ignore[return-value]
        if isinstance(other, CompileResult):
            if self.artifact is None or other.artifact is None:
                return bool(tuple.__eq__(self, other))
            return bool(
                tuple.__eq__(self, other)
                and self.artifact == other.artifact
            )
        if isinstance(other, tuple) and len(other) == 5:
            return bool(
                tuple.__eq__(self, other[:4])
                and self.artifact == other[4]
            )
        return bool(tuple.__eq__(self, other))

    __hash__ = tuple.__hash__

    def __ne__(self, other: typing.Any) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result  # type: ignore[return-value]
        return not result

    def __repr__(self) -> str:
        return (
            f'{type(self).__name__}('
            f'code={self.code!r}, '
            f'errors={self.errors!r}, '
            f'warnings={self.warnings!r}, '
            f'used_names={self.used_names!r}, '
            f'artifact={self.artifact!r})'
        )

    def __copy__(self) -> CompileResult:
        return self

    def __deepcopy__(self, memo: dict[int, typing.Any]) -> CompileResult:
        return self

    def __getnewargs__(self) -> tuple[typing.Any, ...]:
        return (
            self.code,
            self.errors,
            self.warnings,
            self.used_names,
            self.artifact,
        )

    def _asdict(self) -> dict[str, typing.Any]:
        return {
            'code': self.code,
            'errors': self.errors,
            'warnings': self.warnings,
            'used_names': self.used_names,
        }

    @classmethod
    def _make(
        cls,
        iterable: collections.abc.Iterable[typing.Any],
    ) -> CompileResult:
        values = tuple(iterable)
        if len(values) == len(cls._fields):
            values += (None,)
        return cls(*values)

    def _replace(self, **changes: typing.Any) -> CompileResult:
        unknown = set(changes) - set(self._fields) - {'artifact'}
        if unknown:
            raise ValueError(f'Got unexpected field names: {unknown!r}')
        values = [
            changes.get(name, getattr(self, name))
            for name in self._fields
        ]
        artifact = changes.get('artifact', self.artifact)
        return type(self)(*values, artifact=artifact)

    def approval_record(self) -> typing.Any:
        """Return the text-only approval record for this compile result."""
        if self.artifact is None:
            return None
        return self.artifact.approval_record()

    @property
    def approval(self) -> typing.Any:
        return self.approval_record()

    @property
    def summary(self) -> str | None:
        if self.artifact is None:
            return None
        return self.artifact.to_json()

    def matches_approval(self, approval: typing.Any) -> bool:
        """Return whether ``approval`` still applies to this result."""
        from RestrictedPython.artifacts import approval_applies

        return approval_applies(approval, self)


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


def _compile_restricted_mode(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        mode: typing.Literal["exec", "eval", "single"] = "exec",
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        *,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
        _artifact: CompileArtifact | None = None,
) -> CompileResult:

    if not IS_CPYTHON:
        warnings.warn_explicit(
            NOT_CPYTHON_WARNING, RuntimeWarning, 'RestrictedPython', 0)

    artifact = _artifact
    if artifact is None:
        artifact = build_compile_artifact(
            source,
            mode=mode,
            flags=flags,
            dont_inherit=dont_inherit,
            policy=policy,
            guard_version=guard_version,
            policy_version=policy_version,
            language_features=language_features,
            environment=environment,
        )

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
            policy_instance = policy(
                collected_errors, collected_warnings, used_names)
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
        used_names,
        artifact)


def compile_restricted_exec(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        *,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
) -> CompileResult:
    """Compile restricted for the mode `exec`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='exec',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment)


def compile_restricted_eval(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        *,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
) -> CompileResult:
    """Compile restricted for the mode `eval`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='eval',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment)


def compile_restricted_single(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        *,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
) -> CompileResult:
    """Compile restricted for the mode `single`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='single',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment)


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
        *,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
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
            artifact = build_compile_artifact(
                body,
                mode='function',
                flags=flags,
                dont_inherit=dont_inherit,
                policy=policy,
                guard_version=guard_version,
                policy_version=policy_version,
                language_features=language_features,
                environment=environment)
            return CompileResult(
                code=None,
                errors=(error,),
                warnings=(),
                used_names={},
                artifact=artifact)

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

    artifact = build_compile_artifact(
        wrapper_ast,
        mode='function',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment)
    result = _compile_restricted_mode(
        wrapper_ast,
        filename=filename,
        mode='exec',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment,
        _artifact=artifact)

    return result


def compile_restricted(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<unknown>',
        mode: typing.Literal["exec", "eval", "single"] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        *,
        return_artifact: bool = False,
        with_artifact: bool = False,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
) -> types.CodeType | CompileResult:
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
            guard_version=guard_version,
            policy_version=policy_version,
            language_features=language_features,
            environment=environment)
    else:
        raise TypeError('unknown mode %s', mode)
    for warning in result.warnings:
        warnings.warn(
            warning,
            SyntaxWarning
        )
    if result.errors:
        raise SyntaxError(result.errors)
    if return_artifact or with_artifact:
        return result
    return cast_not_none(result.code)


def compile_restricted_with_artifact(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<unknown>',
        mode: typing.Literal["exec", "eval", "single"] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        *,
        guard_version: str | None = None,
        policy_version: str | None = None,
        language_features: T_FeatureInput = None,
        environment: CompileEnvironment | collections.abc.Mapping[
            str, typing.Any] | None = None,
) -> CompileResult:
    """Compile and return the code together with its reviewable artifact."""
    if mode not in ['exec', 'eval', 'single']:
        raise TypeError('unknown mode %s', mode)
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode=mode,
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        guard_version=guard_version,
        policy_version=policy_version,
        language_features=language_features,
        environment=environment)


compile_restricted_artifact = compile_restricted_with_artifact
compile_restricted_descriptor = compile_restricted_with_artifact
compile_restricted_with_descriptor = compile_restricted_with_artifact
compile_restricted_exec_artifact = compile_restricted_exec
compile_restricted_eval_artifact = compile_restricted_eval
compile_restricted_single_artifact = compile_restricted_single
compile_restricted_function_artifact = compile_restricted_function
