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
"""Per-tenant attribute capability policies for restricted execution.

The stock guards only restrict a handful of names and write operations, so
a ``_getattr_`` which falls back to the builtin ``getattr`` lets restricted
code walk introspection attributes such as
``().__class__.__base__.__subclasses__()``.  This module adds an explicit,
per-tenant :class:`AttributePolicy` which decides separately whether an
attribute may be *read*, *called*, *iterated* or *written*.

By default a policy denies

* dunder attributes (names starting with ``__``),
* the introspection attributes of tracebacks, frames, code objects,
  generators, coroutines and asynchronous generators
  (see ``transformer.INSPECT_ATTRIBUTES``).

Legitimate business objects regain access through an explicit whitelist.
Every denial raises :class:`AttributePolicyError` carrying a stable,
auditable error code; the exception message never contains the ``repr()``
of the inspected object nor any memory address.
"""

import types

from RestrictedPython.Guards import full_write_guard
from RestrictedPython.Guards import guarded_delattr
from RestrictedPython.Guards import guarded_setattr
from RestrictedPython.transformer import INSPECT_ATTRIBUTES


READ = 'read'
CALL = 'call'
ITERATE = 'iterate'
WRITE = 'write'

OPERATIONS = frozenset([READ, CALL, ITERATE, WRITE])

# Stable error codes, suitable for audit logs and alerting rules.
ERR_READ_DENIED = 'RP-ATTR-READ-DENIED'
ERR_CALL_DENIED = 'RP-ATTR-CALL-DENIED'
ERR_ITERATE_DENIED = 'RP-ATTR-ITERATE-DENIED'
ERR_WRITE_DENIED = 'RP-ATTR-WRITE-DENIED'

_ERROR_CODES = {
    READ: ERR_READ_DENIED,
    CALL: ERR_CALL_DENIED,
    ITERATE: ERR_ITERATE_DENIED,
    WRITE: ERR_WRITE_DENIED,
}

# Iterating these objects leaks frames, code or generator internals even
# without touching a named attribute.
_FORBIDDEN_ITER_TYPES = (
    types.TracebackType,
    types.FrameType,
    types.CodeType,
    types.GeneratorType,
    types.CoroutineType,
    types.AsyncGeneratorType,
)

_sentinel = object()


class AttributePolicyError(Exception):
    """A tenant policy denied an attribute capability.

    The message deliberately contains only the stable error ``code``, the
    ``operation``, the attribute name, the *type name* of the object and
    the policy (tenant) name -- never ``repr(obj)`` or a memory address,
    so it is safe to propagate back into the restricted script.
    """

    def __init__(self, code, operation, attribute, policy_name, type_name):
        self.code = code
        self.operation = operation
        self.attribute = attribute
        self.policy = policy_name
        super().__init__(
            '[{code}] {operation} of attribute {attribute!r} on {type_name} '
            'denied by policy {policy!r}'.format(
                code=code,
                operation=operation,
                attribute=attribute,
                type_name=type_name,
                policy=policy_name,
            )
        )


class AttributePolicy:
    """Capability policy deciding attribute access for one tenant.

    ``name`` identifies the tenant in audit messages.  ``allow`` maps an
    operation (``read``/``call``/``iterate``/``write``) to a mapping of
    type (or the wildcard ``'*'``) to a collection of attribute names;
    whitelisted entries bypass the default denies.  ``extra_deny`` adds
    tenant specific attribute names to the deny list.  ``deny_dunder``
    (default ``True``) rejects every attribute whose name starts with
    ``__``.
    """

    def __init__(self, name, allow=None, extra_deny=(), deny_dunder=True):
        self.name = name
        self.deny_dunder = deny_dunder
        self.denied_names = frozenset(INSPECT_ATTRIBUTES) | frozenset(
            extra_deny)
        self._allow = {}
        for operation, entries in (allow or {}).items():
            if operation not in OPERATIONS:
                raise ValueError(
                    'unknown attribute operation {!r}'.format(operation))
            self._allow[operation] = {
                key: frozenset(names) for key, names in entries.items()
            }

    def _is_whitelisted(self, operation, obj, name):
        entries = self._allow.get(operation, {})
        for cls in type(obj).__mro__:
            names = entries.get(cls)
            if names and (name in names or '*' in names):
                return True
        names = entries.get('*')
        return bool(names and (name in names or '*' in names))

    def check(self, operation, obj, name):
        """Raise :class:`AttributePolicyError` if access is denied."""
        if operation not in OPERATIONS:
            raise ValueError(
                'unknown attribute operation {!r}'.format(operation))
        if type(name) is not str:
            raise TypeError('attribute name must be str')
        if self._is_whitelisted(operation, obj, name):
            return
        if self.deny_dunder and name.startswith('__'):
            self._deny(operation, obj, name)
        if name in self.denied_names:
            self._deny(operation, obj, name)

    def _deny(self, operation, obj, name):
        raise AttributePolicyError(
            _ERROR_CODES[operation], operation, name, self.name,
            type(obj).__name__)

    def guard_getattr(self):
        """Return a ``_getattr_`` implementation enforcing this policy."""
        policy = self

        def policy_getattr(obj, name, default=_sentinel):
            policy.check(READ, obj, name)
            if default is _sentinel:
                return getattr(obj, name)
            return getattr(obj, name, default)
        return policy_getattr

    def guard_getiter(self):
        """Return a ``_getiter_`` implementation enforcing this policy."""
        policy = self

        def policy_getiter(it):
            if isinstance(it, _FORBIDDEN_ITER_TYPES) and not (
                    policy._is_whitelisted(ITERATE, it, '*')):
                raise AttributePolicyError(
                    ERR_ITERATE_DENIED, ITERATE, '<iteration>',
                    policy.name, type(it).__name__)
            return iter(it)
        return policy_getiter

    def guard_apply(self):
        """Return an ``_apply_`` implementation enforcing this policy."""
        policy = self

        def policy_apply(func, *args, **kwargs):
            name = getattr(func, '__name__', None)
            if type(name) is str:
                target = getattr(func, '__self__', func)
                policy.check(CALL, target, name)
            return func(*args, **kwargs)
        return policy_apply

    def guard_write(self):
        """Return a ``_write_`` implementation enforcing this policy.

        The returned wrapper checks the ``write`` capability and then
        delegates to the stock ``full_write_guard`` machinery, so the
        behaviour of ``_full_write_guard`` and ``guarded_setattr`` is
        preserved unchanged.
        """
        policy = self

        def policy_write(ob):
            return _PolicyWriteWrapper(ob, policy)
        return policy_write

    def guards(self):
        """Return the guard mapping to merge into restricted globals."""
        return {
            '_getattr_': self.guard_getattr(),
            '_getiter_': self.guard_getiter(),
            '_apply_': self.guard_apply(),
            '_write_': self.guard_write(),
        }


class _PolicyWriteWrapper:
    """Check the write capability, then defer to the stock write guard."""

    def __init__(self, ob, policy):
        self.__dict__['ob'] = ob
        self.__dict__['policy'] = policy

    def __setattr__(self, name, value):
        self.__dict__['policy'].check(WRITE, self.__dict__['ob'], name)
        guarded_setattr(self.__dict__['ob'], name, value)

    def __delattr__(self, name):
        self.__dict__['policy'].check(WRITE, self.__dict__['ob'], name)
        guarded_delattr(self.__dict__['ob'], name)

    def __setitem__(self, key, value):
        if type(key) is str:
            self.__dict__['policy'].check(WRITE, self.__dict__['ob'], key)
        full_write_guard(self.__dict__['ob'])[key] = value

    def __delitem__(self, key):
        if type(key) is str:
            self.__dict__['policy'].check(WRITE, self.__dict__['ob'], key)
        del full_write_guard(self.__dict__['ob'])[key]
