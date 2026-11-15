##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""Restricted Python Expressions."""

import ast
import collections
import threading
import types
import typing

from RestrictedPython._types import cast_not_none
from RestrictedPython.compile import ExecutionContext
from RestrictedPython.compile import RestrictedCompileCache
from RestrictedPython.compile import compile_restricted_eval


nltosp = str.maketrans(chr(13) + chr(10), '  ')

# No restrictions.
default_guarded_getattr = getattr

_T = typing.TypeVar('_T')
_TK = typing.TypeVar('_TK', contravariant=True)
_TV = typing.TypeVar('_TV', covariant=True)


class _GetItem(typing.Protocol[_TK, _TV]):
    def __getitem__(self, key: _TK) -> _TV: ...  # pragma: no cover


def default_guarded_getitem(ob: _GetItem[_TK, _TV], index: _TK) -> _TV:
    # No restrictions.
    return ob[index]


def default_guarded_getiter(ob: _T) -> _T:
    # No restrictions.
    return ob


class GuardProvider(typing.Protocol):
    """Object supplying the guard callables for restricted code.

    Tenant-specific implementations return guards bound to that tenant,
    so the eval machinery never stores one tenant guard on a shared
    object used by another tenant.
    """

    def guarded_getattr(self, object: typing.Any, name: str) -> typing.Any:
        ...  # pragma: no cover

    def guarded_getitem(
            self, object: typing.Any, key: typing.Any) -> typing.Any:
        ...  # pragma: no cover

    def guarded_getiter(self, object: typing.Any) -> typing.Any:
        ...  # pragma: no cover


class DefaultGuardProvider:
    """Guard provider backed by the module-level default guards."""

    __slots__ = ()

    def guarded_getattr(self, object: typing.Any, name: str) -> typing.Any:
        return default_guarded_getattr(object, name)

    def guarded_getitem(
            self, object: typing.Any, key: typing.Any) -> typing.Any:
        return default_guarded_getitem(object, key)

    def guarded_getiter(self, object: typing.Any) -> typing.Any:
        return default_guarded_getiter(object)


class RestrictionCapableEval:
    """A base class for restricted code."""

    # restricted
    rcode: types.CodeType | None = None

    # unrestricted
    ucode: types.CodeType | None = None

    # Names used by the expression
    used: tuple[str, ...] | None = None

    def __init__(
            self,
            expr: str,
            context: ExecutionContext | None = None,
            cache: RestrictedCompileCache | None = None,
            guard_provider: GuardProvider | None = None,
    ):
        """Create a restricted expression

        where:

          expr -- a string containing the expression to be evaluated.

        When ``context`` is given the restricted code is compiled
        through the tenant-aware compile cache. ``guard_provider``
        supplies per-tenant guards without sharing mutable state across
        concurrent evaluations.
        """
        expr = expr.strip()
        self.__name__ = expr
        expr = expr.translate(nltosp)
        self.expr = expr
        # Per-instance globals: a class-level mutable dict would let one
        # tenant leak names into another tenant expression instance.
        self.globals: dict[str, typing.Any] = {'__builtins__': None}
        self._explicit_globals: set[str] = set()
        self.context = context
        self.cache = cache
        self.guard_provider = guard_provider or DefaultGuardProvider()
        self._compile_lock = threading.RLock()
        # Catch syntax errors.
        self.prepUnrestrictedCode()

    def set_global(self, name: str, value: typing.Any) -> None:
        """Register an explicit global for this expression only.

        Unlike mutating ``self.globals`` directly this marks the name as
        host-provided, so the tenant context never silently overrides an
        explicit ``__builtins__`` configuration.
        """
        self._explicit_globals.add(name)
        self.globals[name] = value

    def prepRestrictedCode(self) -> None:
        if self.rcode is None:
            with self._compile_lock:
                if self.rcode is not None:
                    return
                result = compile_restricted_eval(
                    self.expr,
                    '<string>',
                    context=self.context,
                    cache=self.cache)
                if result.errors:
                    raise SyntaxError(result.errors[0])
                self.used = tuple(result.used_names)
                self.rcode = result.code

    def prepUnrestrictedCode(self) -> None:
        if self.ucode is None:
            exp_node = ast.parse(
                self.expr,
                '<string>',
                'eval')

            co = compile(exp_node, '<string>', 'eval')

            # Examine the ast to discover which names the expression needs.
            if self.used is None:
                used = set()
                for node in ast.walk(exp_node):
                    if isinstance(node, ast.Name):
                        if isinstance(node.ctx, ast.Load):
                            used.add(node.id)

                self.used = tuple(used)

            self.ucode = co

    def _build_global_scope(
            self,
            mapping: collections.abc.Mapping[str, typing.Any],
    ) -> dict[str, typing.Any]:
        # Every evaluation gets a fresh dict so concurrent requests can
        # never write their _getattr_ guard or __builtins__ collection
        # into a scope reused by another request/tenant.
        global_scope = {
            '_getattr_': self.guard_provider.guarded_getattr,
            '_getitem_': self.guard_provider.guarded_getitem,
            '_getiter_': self.guard_provider.guarded_getiter,
        }

        global_scope.update(self.globals)

        if (self.context is not None
                and self.context.builtins is not None
                and '__builtins__' not in self._explicit_globals):
            global_scope['__builtins__'] = self.context.builtins

        for name in cast_not_none(self.used):
            if (name not in global_scope) and (name in mapping):
                global_scope[name] = mapping[name]

        return global_scope

    def eval(self,
             mapping: collections.abc.Mapping[str,
                                              typing.Any]) -> typing.Any:
        # This default implementation is probably not very useful. :-(
        # This is meant to be overridden.
        self.prepRestrictedCode()

        global_scope = self._build_global_scope(mapping)

        return eval(cast_not_none(self.rcode), global_scope)

    def __call__(self, **kw: typing.Any) -> typing.Any:
        return self.eval(kw)
