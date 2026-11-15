from __future__ import annotations

import ast
import collections
import collections.abc
import hashlib
import os
import threading
import types
import typing
import weakref
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


@typing.final
class ExecutionContext(object):
    """Tenant-specific execution context bound to a compiled script.

    The context identifies everything that may change the semantics of
    restricted code or of the guards and builtins it runs with:

    * the tenant owning the script,
    * the policy version applied while compiling,
    * the restricted builtins collection,
    * the guard provider supplying the guard functions.

    Two contexts share a cached code object only when every identifying
    part is equal. A tenant that rotates its policy version, swaps its
    builtins collection or replaces its guard provider therefore never
    receives a stale object compiled for an older context.
    """

    __slots__ = (
        'tenant_id',
        'policy_version',
        'builtins',
        'builtins_key',
        'guard_provider',
        'guard_key',
        '_hash',
        '__weakref__',
    )

    def __init__(
            self,
            tenant_id: typing.Hashable,
            policy_version: typing.Hashable,
            builtins: collections.abc.Mapping[str, typing.Any] | None = None,
            builtins_key: typing.Hashable | None = None,
            guard_provider: typing.Any = None,
            guard_key: typing.Hashable | None = None,
    ) -> None:
        object.__setattr__(self, 'tenant_id', tenant_id)
        object.__setattr__(self, 'policy_version', policy_version)
        object.__setattr__(self, 'builtins', builtins)
        object.__setattr__(self, 'builtins_key', builtins_key)
        object.__setattr__(self, 'guard_provider', guard_provider)
        object.__setattr__(self, 'guard_key', guard_key)
        object.__setattr__(
            self,
            '_hash',
            hash(self.identity_parts()))

    def identity_parts(self) -> tuple[typing.Hashable, ...]:
        """Return the hashable parts discriminating two contexts."""
        if self.builtins_key is not None:
            builtins_identity: typing.Hashable = self.builtins_key
        elif self.builtins is not None:
            builtins_identity = ('builtins-id', id(self.builtins))
        else:
            builtins_identity = ('builtins-id', None)
        if self.guard_key is not None:
            guard_identity: typing.Hashable = self.guard_key
        elif self.guard_provider is not None:
            guard_identity = ('guard-id', id(self.guard_provider))
        else:
            guard_identity = ('guard-id', None)
        return (
            self.tenant_id,
            self.policy_version,
            builtins_identity,
            guard_identity,
        )

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExecutionContext):
            return NotImplemented
        return self.identity_parts() == other.identity_parts()

    def __repr__(self) -> str:
        return (
            'ExecutionContext(tenant_id={0!r}, policy_version={1!r})'.format(
                self.tenant_id, self.policy_version))


class _CacheEntry:
    """A cached compilation result plus the context it belongs to.

    The context is referenced weakly so eviction releases the tenant
    builtins collection and guard provider instead of keeping sensitive
    objects alive for the lifetime of the process.
    """

    __slots__ = ('result', 'context_ref', 'key')

    def __init__(
            self,
            key: tuple[typing.Hashable, ...],
            result: CompileResult,
            context: ExecutionContext,
    ) -> None:
        self.key = key
        self.result = result
        self.context_ref: (
            weakref.ReferenceType[ExecutionContext] | None) = (
            weakref.ref(context))

    def release(self) -> None:
        """Drop references owned by the cache for this entry."""
        self.context_ref = None


class RestrictedCompileCache:
    """Thread-safe, bounded LRU cache for restricted compilation.

    Cache keys combine the source, the compilation parameters and the
    ExecutionContext. The same source compiled for another tenant,
    policy version, builtins collection or guard provider gets a
    distinct cache entry, while legitimate reuse within one context is
    preserved.
    """

    def __init__(self, maxsize: int = 128) -> None:
        if maxsize < 1:
            raise ValueError('maxsize must be a positive integer')
        self._maxsize = maxsize
        self._entries: collections.OrderedDict[
            tuple[typing.Hashable, ...], _CacheEntry] = (
                collections.OrderedDict())
        self._lock = threading.RLock()

    @property
    def maxsize(self) -> int:
        return self._maxsize

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __contains__(self, key: tuple[typing.Hashable, ...]) -> bool:
        with self._lock:
            return key in self._entries

    @staticmethod
    def build_key(
            source: _T_source,
            filename: str | bytes | os.PathLike[typing.Any],
            mode: str,
            flags: int,
            dont_inherit: bool,
            policy: type[ast.NodeTransformer] | None,
            context: ExecutionContext,
    ) -> tuple[typing.Hashable, ...]:
        if isinstance(source, (str, bytes, bytearray)):
            if isinstance(source, str):
                source_bytes = source.encode('utf-8')
            else:
                source_bytes = bytes(source)
            source_identity: typing.Hashable = (
                'source', hashlib.sha256(source_bytes).digest())
        else:
            source_identity = ('ast', id(source))
        filename_identity = (
            filename if isinstance(filename, str) else os.fspath(filename))
        policy_identity: typing.Hashable
        if policy is None:
            policy_identity = None
        else:
            policy_identity = (policy.__module__, policy.__qualname__)
        return (
            source_identity,
            filename_identity,
            mode,
            flags,
            dont_inherit,
            policy_identity,
            context.identity_parts(),
        )

    def get(
            self,
            key: tuple[typing.Hashable, ...],
    ) -> CompileResult | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return entry.result

    def put(
            self,
            key: tuple[typing.Hashable, ...],
            result: CompileResult,
            context: ExecutionContext,
    ) -> None:
        with self._lock:
            if key in self._entries:
                self._entries.move_to_end(key)
                return
            self._entries[key] = _CacheEntry(key, result, context)
            while len(self._entries) > self._maxsize:
                _, evicted = self._entries.popitem(last=False)
                evicted.release()

    def invalidate(
            self,
            tenant_id: typing.Hashable | None = None,
            policy_version: typing.Hashable | None = None,
    ) -> int:
        """Drop entries, optionally scoped to one tenant/version.

        Returns the number of removed entries. Every removed entry
        releases its weak context reference.
        """
        removed = 0
        with self._lock:
            for key in list(self._entries):
                context_parts = typing.cast(
                    tuple[typing.Hashable, ...], key[-1])
                tenant, version = context_parts[0], context_parts[1]
                if tenant_id is not None and tenant != tenant_id:
                    continue
                if policy_version is not None and version != policy_version:
                    continue
                entry = self._entries.pop(key)
                entry.release()
                removed += 1
        return removed

    def clear(self) -> None:
        with self._lock:
            for entry in self._entries.values():
                entry.release()
            self._entries.clear()


# Shared, process-wide cache used when callers pass an ExecutionContext
# without providing their own cache instance.
default_compile_cache = RestrictedCompileCache()


def _compile_restricted_mode(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        mode: typing.Literal["exec", "eval", "single"] = "exec",
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        context: ExecutionContext | None = None,
        cache: RestrictedCompileCache | None = None,
) -> CompileResult:

    if not IS_CPYTHON:
        warnings.warn_explicit(
            NOT_CPYTHON_WARNING, RuntimeWarning, 'RestrictedPython', 0)

    if context is not None:
        active_cache = cache if cache is not None else default_compile_cache
        cache_key = active_cache.build_key(
            source, filename, mode, flags, dont_inherit, policy, context)
        cached_result = active_cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        result = _compile_restricted_mode_uncached(
            source,
            filename=filename,
            mode=mode,
            flags=flags,
            dont_inherit=dont_inherit,
            policy=policy)
        if result.code is not None and not result.errors:
            active_cache.put(cache_key, result, context)
        return result

    return _compile_restricted_mode_uncached(
        source,
        filename=filename,
        mode=mode,
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy)


def _compile_restricted_mode_uncached(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        mode: typing.Literal["exec", "eval", "single"] = "exec",
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
) -> CompileResult:

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
            except SyntaxError as value:
                collected_errors.append(syntax_error_template.format(
                    lineno=value.lineno,
                    type=value.__class__.__name__,
                    msg=value.msg,
                    statement=value.text.strip() if value.text else None
                ))
        if c_ast:
            policy_instance = policy(
                collected_errors, collected_warnings, used_names)
            policy_instance.visit(c_ast)
            if not collected_errors:
                byte_code = compile(c_ast, filename, mode=mode)
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
        context: ExecutionContext | None = None,
        cache: RestrictedCompileCache | None = None,
) -> CompileResult:
    """Compile restricted for the mode `exec`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='exec',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        context=context,
        cache=cache)


def compile_restricted_eval(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        context: ExecutionContext | None = None,
        cache: RestrictedCompileCache | None = None,
) -> CompileResult:
    """Compile restricted for the mode `eval`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='eval',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        context=context,
        cache=cache)


def compile_restricted_single(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<string>',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        context: ExecutionContext | None = None,
        cache: RestrictedCompileCache | None = None,
) -> CompileResult:
    """Compile restricted for the mode `single`."""
    return _compile_restricted_mode(
        source,
        filename=filename,
        mode='single',
        flags=flags,
        dont_inherit=dont_inherit,
        policy=policy,
        context=context,
        cache=cache)


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
        context: ExecutionContext | None = None,
        cache: RestrictedCompileCache | None = None,
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
        except SyntaxError as value:
            error = syntax_error_template.format(
                lineno=value.lineno,
                type=value.__class__.__name__,
                msg=value.msg,
                statement=value.text.strip() if value.text else None)
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
        context=context,
        cache=cache)

    return result


def compile_restricted(
        source: _T_source,
        filename: str | bytes | os.PathLike[typing.Any] = '<unknown>',
        mode: typing.Literal["exec", "eval", "single"] = 'exec',
        flags: int = 0,
        dont_inherit: bool = False,
        policy: type[ast.NodeTransformer] | None = RestrictingNodeTransformer,
        context: ExecutionContext | None = None,
        cache: RestrictedCompileCache | None = None,
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
            context=context,
            cache=cache)
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
