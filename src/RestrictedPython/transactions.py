"""Transactional execution layer for RestrictedPython.

This layer is opt-in: default RestrictedPython execution does not
change. A host application creates a Transaction, documents which data
objects and write capabilities are allowed inside the restricted
program, and executes compiled code through it. All writes are
collected on copy-on-write shadows until commit; on error or
permission denial the host objects stay untouched.

Rules use real copies of mutated objects (never shallow copies of the
shared host graph), keep object identity via an identity map so aliases
and self-references behave correctly, and commit atomically with a host
version check. Only the standard library is used.
"""

from __future__ import annotations

import threading
import typing

from RestrictedPython import compile_restricted
from RestrictedPython.Guards import raise_
from RestrictedPython.Guards import safe_builtins
from RestrictedPython.Guards import safer_getattr
from RestrictedPython.PrintCollector import PrintCollector
from RestrictedPython.transformer import INSPECT_ATTRIBUTES


__all__ = [
    'Binding',
    'CommitError',
    'Transaction',
    'TransactionError',
    'TransactionStateError',
    'UnsupportedWritable',
    'VersionConflict',
    'WritePermissionDenied',
    'WriteRecord',
    'transactional_exec',
]


class TransactionError(Exception):
    """Base class for transaction layer errors."""


class TransactionStateError(TransactionError):
    """Transaction used after commit or abort."""


class UnsupportedWritable(TransactionError):
    """Type unable to participate in documented writes.

    Raised before any host side effect. Only list, dict and
    explicitly documented attribute hosts are supported.
    """


class WritePermissionDenied(TransactionError):
    """Write attempted without a documented capability."""


class VersionConflict(TransactionError):
    """Host changed outside the transaction since allow."""


class CommitError(TransactionError):
    """Commit failed; every host object was restored."""


class Binding(typing.NamedTuple):
    # Documentation of one data object and its write capabilities.
    host: typing.Any
    name: str
    writable_attrs: typing.Tuple[str, ...] = ()
    version_getter: typing.Optional[
        typing.Callable[[typing.Any], typing.Any]] = None


class WriteRecord(typing.NamedTuple):
    """One collected write against a host object.

    host is the real host, kind is 'item' or 'attribute', operation is
    the verb (e.g. 'set', 'delete', 'append'), path is key/index or
    attribute name.
    """

    host: typing.Any
    kind: str
    operation: str
    path: typing.Any


class _HostInfo:
    # Bookkeeping for one documented or reachable host object.

    __slots__ = ('host', 'proxy', 'kind', 'writable_attrs',
                 'version_getter', 'initial_version', 'records')

    def __init__(self, host, kind, writable_attrs, version_getter):
        self.host = host
        self.proxy = None
        self.kind = kind
        self.writable_attrs = frozenset(writable_attrs or ())
        self.version_getter = version_getter
        self.initial_version = (
            version_getter(host) if version_getter is not None else None)
        self.records = []


class _TxProxy:
    # Base class for copy-on-write proxies of host objects.

    def __init__(self, tx, host, info):
        object.__setattr__(self, '_tx', tx)
        object.__setattr__(self, '_host', host)
        object.__setattr__(self, '_info', info)
        object.__setattr__(self, '_shadow', None)

    def _check_live(self):
        if self._tx._finished:
            raise TransactionStateError('transaction is no longer active')

    def _materialize(self):
        raise NotImplementedError

    def _ensure_shadow(self):
        self._check_live()
        if self._shadow is None:
            self._materialize()
        return self._shadow

    def _record(self, operation, path):
        self._info.records.append(
            WriteRecord(self._host, self._kind, operation, path))


class _ListProxy(_TxProxy):
    _kind = 'item'

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        raise WritePermissionDenied(
            "list objects only support documented item writes, not "
            "attribute %r" % (name,))

    def __delattr__(self, name):
        if name.startswith("_"):
            object.__delattr__(self, name)
            return
        raise WritePermissionDenied(
            "list objects do not support attribute deletion")

    def _materialize(self):
        shadow = []
        object.__setattr__(self, '_shadow', shadow)
        for element in self._host:
            shadow.append(self._tx._wrap(element))

    def _target(self):
        return self._shadow if self._shadow is not None else self._host

    def __len__(self):
        self._check_live()
        return len(self._target())

    def __bool__(self):
        self._check_live()
        return bool(self._target())

    def __iter__(self):
        self._check_live()
        for element in self._target():
            yield self._tx._wrap(element)

    def __reversed__(self):
        self._check_live()
        for element in reversed(self._target()):
            yield self._tx._wrap(element)

    def __contains__(self, value):
        self._check_live()
        return self._unwrap_for_compare(value) in self._target()

    def _unwrap_for_compare(self, value):
        return self._tx._unwrap(value)

    def __getitem__(self, index):
        self._check_live()
        target = self._target()
        if isinstance(index, slice):
            return [self._tx._wrap(item)
                    for item in target[index]]
        return self._tx._wrap(target[index])

    def __setitem__(self, index, value):
        shadow = self._ensure_shadow()
        if isinstance(index, slice):
            shadow[index] = [self._tx._wrap(item)
                             for item in value]
        else:
            shadow[index] = self._tx._wrap(value)
        self._record('set', index)

    def __delitem__(self, index):
        shadow = self._ensure_shadow()
        del shadow[index]
        self._record('delete', index)

    def append(self, value):
        self._ensure_shadow().append(self._tx._wrap(value))
        self._record('append', len(self._shadow) - 1)

    def extend(self, iterable):
        shadow = self._ensure_shadow()
        start = len(shadow)
        wrapped = [self._tx._wrap(item) for item in iterable]
        shadow.extend(wrapped)
        self._record('extend', slice(start, len(shadow)))

    def insert(self, index, value):
        self._ensure_shadow().insert(index, self._tx._wrap(value))
        self._record('insert', index)

    def pop(self, index=-1):
        shadow = self._ensure_shadow()
        value = shadow.pop(index)
        self._record('pop', index)
        return value

    def remove(self, value):
        shadow = self._ensure_shadow()
        shadow.remove(self._tx._unwrap(value))
        self._record('remove', None)

    def clear(self):
        self._ensure_shadow().clear()
        self._record('clear', None)

    def index(self, value, *args):
        self._check_live()
        return self._target().index(
            self._tx._unwrap(value), *args)

    def count(self, value):
        self._check_live()
        return self._target().count(self._tx._unwrap(value))

    def copy(self):
        self._check_live()
        return [self._tx._wrap(item) for item in self._target()]

    def sort(self, **kwargs):
        self._ensure_shadow().sort(**kwargs)
        self._record('sort', None)

    def reverse(self):
        self._ensure_shadow().reverse()
        self._record('reverse', None)

    def __eq__(self, other):
        self._check_live()
        return self._target() == self._tx._unwrap(other)

    def __ne__(self, other):
        self._check_live()
        return self._target() != self._tx._unwrap(other)

    def __lt__(self, other):
        self._check_live()
        return self._target() < self._tx._unwrap(other)

    def __le__(self, other):
        self._check_live()
        return self._target() <= self._tx._unwrap(other)

    def __gt__(self, other):
        self._check_live()
        return self._target() > self._tx._unwrap(other)

    def __ge__(self, other):
        self._check_live()
        return self._target() >= self._tx._unwrap(other)

    def __add__(self, other):
        self._check_live()
        return self.copy() + list(self._tx._unwrap(other))

    def __mul__(self, count):
        self._check_live()
        return self.copy() * count

    def __repr__(self):
        self._check_live()
        return repr(self._target())


class _DictProxy(_TxProxy):
    _kind = 'item'

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        raise WritePermissionDenied(
            "dict objects only support documented item writes, not "
            "attribute %r" % (name,))

    def __delattr__(self, name):
        if name.startswith("_"):
            object.__delattr__(self, name)
            return
        raise WritePermissionDenied(
            "dict objects do not support attribute deletion")

    def _materialize(self):
        shadow = {}
        object.__setattr__(self, '_shadow', shadow)
        for key, value in self._host.items():
            shadow[key] = self._tx._wrap(value)

    def _target(self):
        return self._shadow if self._shadow is not None else self._host

    def __len__(self):
        self._check_live()
        return len(self._target())

    def __bool__(self):
        self._check_live()
        return bool(self._target())

    def __iter__(self):
        self._check_live()
        return iter(self._target())

    def __contains__(self, key):
        self._check_live()
        return key in self._target()

    def __getitem__(self, key):
        self._check_live()
        return self._tx._wrap(self._target()[key])

    def __setitem__(self, key, value):
        self._ensure_shadow()[key] = self._tx._wrap(value)
        self._record('set', key)

    def __delitem__(self, key):
        del self._ensure_shadow()[key]
        self._record('delete', key)

    def get(self, key, default=None):
        self._check_live()
        if key in self._target():
            return self._tx._wrap(self._target()[key])
        return default

    def setdefault(self, key, default=None):
        shadow = self._ensure_shadow()
        if key not in shadow:
            shadow[key] = self._tx._wrap(default)
            self._record('set', key)
        return shadow[key]

    def update(self, mapping=(), **kwargs):
        shadow = self._ensure_shadow()
        if hasattr(mapping, 'items'):
            pairs = list(mapping.items())
        else:
            pairs = list(mapping)
        for key, value in pairs:
            shadow[key] = self._tx._wrap(value)
            self._record('set', key)
        for key, value in kwargs.items():
            shadow[key] = self._tx._wrap(value)
            self._record('set', key)

    def pop(self, key, *default):
        shadow = self._ensure_shadow()
        value = shadow.pop(key, *default)
        self._record('delete', key)
        return value

    def popitem(self):
        shadow = self._ensure_shadow()
        item = shadow.popitem()
        self._record('popitem', None)
        return item

    def clear(self):
        self._ensure_shadow().clear()
        self._record('clear', None)

    def keys(self):
        self._check_live()
        return self._target().keys()

    def values(self):
        self._check_live()
        return [self._tx._wrap(v) for v in self._target().values()]

    def items(self):
        self._check_live()
        return [(key, self._tx._wrap(value))
                for key, value in self._target().items()]

    def copy(self):
        self._check_live()
        return {key: self._tx._wrap(value)
                for key, value in self._target().items()}

    def __eq__(self, other):
        self._check_live()
        return self._target() == self._tx._unwrap(other)

    def __ne__(self, other):
        self._check_live()
        return self._target() != self._tx._unwrap(other)

    def __repr__(self):
        self._check_live()
        return repr(self._target())


class _AttrProxy(_TxProxy):
    _kind = 'attribute'

    def _host_attr_names(self):
        host = self._host
        names = set()
        host_dict = getattr(type(host), '__dict__', None)
        for cls in type(host).__mro__:
            class_slots = getattr(cls, '__slots__', None)
            if class_slots:
                if isinstance(class_slots, str):
                    class_slots = (class_slots,)
                for name in class_slots:
                    if hasattr(host, name):
                        names.add(name)
        if host_dict is not None and hasattr(host, '__dict__'):
            names.update(vars(host).keys())
        return names

    def _materialize(self):
        shadow = {}
        object.__setattr__(self, '_shadow', shadow)
        for name in self._host_attr_names():
            shadow[name] = self._tx._wrap(getattr(self._host, name))

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)
        tx = object.__getattribute__(self, '_tx')
        tx._check_active()
        if name in INSPECT_ATTRIBUTES or name.startswith('_'):
            raise AttributeError(name)
        shadow = object.__getattribute__(self, '_shadow')
        host = object.__getattribute__(self, '_host')
        if shadow is not None and name in shadow:
            value = shadow[name]
        else:
            value = getattr(host, name)
        return tx._wrap(value)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            object.__setattr__(self, name, value)
            return
        self._check_live()
        if name not in self._info.writable_attrs:
            raise WritePermissionDenied(
                'attribute %r is not a documented writable '
                'capability of %r' % (name, type(self._host)))
        shadow = self._ensure_shadow()
        shadow[name] = self._tx._wrap(value)
        self._record('set', name)

    def __delattr__(self, name):
        if name.startswith('_'):
            raise WritePermissionDenied(
                'internal attributes cannot be deleted')
        self._check_live()
        if name not in self._info.writable_attrs:
            raise WritePermissionDenied(
                'attribute %r is not a documented writable '
                'capability of %r' % (name, type(self._host)))
        shadow = self._ensure_shadow()
        if name not in shadow:
            raise AttributeError(name)
        del shadow[name]
        self._record('delete', name)

    def __repr__(self):
        self._check_live()
        return '<transactional attribute proxy for %r>' % (
            type(self._host),)

# Built-in value types that are immutable data and pass through untouched.
_PASSTHROUGH_TYPES = (
    bool, int, float, complex, str, bytes, tuple, frozenset, range,
    type(None),
)

_PROXY_BY_KIND = {
    "list": _ListProxy,
    "dict": _DictProxy,
    "attribute": _AttrProxy,
}


class Transaction:
    # An explicit, opt-in transactional execution context.

    def __init__(self):
        self._infos = {}
        self._bindings = {}
        self._finished = False
        self._committed = False
        self._lock = threading.RLock()

    def allow_object(self, host, name=None, writable_attrs=(),
                     version_getter=None):
        # Document one host object and its write capabilities.
        with self._lock:
            self._check_active()
            info = self._register(host, writable_attrs, version_getter,
                                  documented=True)
            proxy = info.proxy
            if name is not None:
                self._bindings[name] = proxy
            return proxy

    def _register(self, host, writable_attrs, version_getter, documented):
        host_id = id(host)
        existing = self._infos.get(host_id)
        if existing is not None:
            return existing
        if isinstance(host, list):
            kind = "list"
        elif isinstance(host, dict):
            kind = "dict"
        elif self._is_attribute_host(host):
            kind = "attribute"
            if documented:
                self._validate_writable_attrs(host, writable_attrs)
        else:
            raise UnsupportedWritable(
                "objects of type %r cannot be documented for "
                "transactional writes" % (type(host),))
        info = _HostInfo(host, kind, writable_attrs, version_getter)
        proxy = _PROXY_BY_KIND[kind](self, host, info)
        info.proxy = proxy
        self._infos[host_id] = info
        return info

    @staticmethod
    def _is_attribute_host(host):
        cls = type(host)
        if isinstance(host, _TxProxy) or type(host) in (list, dict):
            return False
        class_slots = getattr(cls, "__slots__", None)
        if class_slots:
            return True
        return hasattr(host, "__dict__")

    @staticmethod
    def _validate_writable_attrs(host, writable_attrs):
        for attr in writable_attrs:
            if not isinstance(attr, str) or attr.startswith("_"):
                raise UnsupportedWritable(
                    "writable attribute names must be public strings")
            if not hasattr(host, attr):
                raise UnsupportedWritable(
                    "writable attribute %r does not exist on %r"
                    % (attr, type(host)))

    def _check_active(self):
        if self._finished:
            raise TransactionStateError(
                "transaction is no longer active")

    def _wrap(self, value):
        # Transactional view of any host value; plain data passes through.
        if value is None:
            return value
        if isinstance(value, _TxProxy):
            return value
        if isinstance(value, _PASSTHROUGH_TYPES):
            return value
        if callable(value):
            raise UnsupportedWritable(
                "callable host values cannot be exposed to the "
                "transaction: %r" % (value,))
        if isinstance(value, (list, dict)) or self._is_attribute_host(
                value):
            info = self._infos.get(id(value))
            if info is None:
                # Reachable undocumented container becomes an anonymous
                # host so its writes never reach the real object.
                info = self._register(value, (), None, documented=False)
            return info.proxy
        raise UnsupportedWritable(
            "objects of type %r are not supported transactional data"
            % (type(value),))

    def _unwrap(self, value):
        # Inverse of _wrap for comparisons and membership tests.
        if isinstance(value, _TxProxy):
            return value._host
        return value

    # -- RestrictedPython guard hooks ---------------------------------

    def guard_write(self, value):
        # Implementation of the restricted _write_ hook.
        self._check_active()
        if isinstance(value, _TxProxy):
            return value
        if isinstance(value, (list, dict)) or self._is_attribute_host(
                value):
            info = self._infos.get(id(value))
            if info is None:
                raise WritePermissionDenied(
                    "undocumented object %r is not writable in this "
                    "transaction" % (type(value),))
            return info.proxy
        raise WritePermissionDenied(
            "objects of type %r have no documented write capability"
            % (type(value),))

    def guard_getitem(self, value, key):
        self._check_active()
        return self._wrap(value[key])

    def guard_getattr(self, value, name, default=raise_):
        self._check_active()
        if name in INSPECT_ATTRIBUTES or name.startswith("_"):
            raise AttributeError(name)
        if isinstance(value, _TxProxy):
            # Proxy methods (append, items, ...) are the documented write
            # capabilities and stay unwrapped; data attributes are wrapped.
            if name in type(value).__dict__ or any(
                    name in cls.__dict__
                    for cls in type(value).__mro__
                    if cls is not object):
                return getattr(value, name)
            raw = self._proxy_attr(value, name, default)
            if raw is raise_ or raw is None:
                return raw
            return self._wrap(raw)
        # Values created inside the restricted program are not host data
        # and keep their ordinary, already-isolated behavior.
        if self._infos.get(id(value)) is None:
            if default is raise_:
                return getattr(value, name)
            return getattr(value, name, default)
        raw = safer_getattr(value, name, default)
        if raw is raise_ or raw is None:
            return raw
        return self._wrap(raw)

    def _proxy_attr(self, proxy, name, default):
        try:
            return getattr(proxy, name)
        except AttributeError:
            if default is raise_:
                raise
            return default

    def guard_getiter(self, value):
        self._check_active()
        if isinstance(value, _TxProxy):
            return iter(value)
        return iter(value)

    @staticmethod
    def guard_inplace(operator, value, operand):
        # Implementation of the restricted _inplacevar_ hook.  Mutable
        # in-place operators are rejected here because restricted syntax
        # only allows augmented assignment on plain names.
        if operator == "+=":
            return value + operand
        if operator == "-=":
            return value - operand
        if operator == "*=":
            return value * operand
        if operator == "/=":
            return value / operand
        if operator == "//=":
            return value // operand
        if operator == "%=":
            return value % operand
        if operator == "**=":
            return value ** operand
        if operator == ">>=":
            return value >> operand
        if operator == "<<=":
            return value << operand
        if operator == "&=":
            return value & operand
        if operator == "|=":
            return value | operand
        if operator == "^=":
            return value ^ operand
        if operator == "@=":
            return value @ operand
        raise WritePermissionDenied(
            "operator %r is not allowed" % (operator,))

    def guard_setattr(self, value, name, attr_value):
        target = self.guard_write(value)
        setattr(target, name, attr_value)

    def guard_delattr(self, value, name):
        target = self.guard_write(value)
        delattr(target, name)

    def guard_hasattr(self, value, name):
        try:
            self.guard_getattr(value, name)
        except AttributeError:
            return False
        return True

    def print_collector(self, _getattr_=None):
        # The transformer calls this as _print_(_getattr_).
        return PrintCollector(self.guard_getattr)

    def restricted_globals(self, extra=None):
        # Build the explicit guard namespace for one restricted execution.
        self._check_active()
        builtins = safe_builtins.copy()
        builtins["getattr"] = self.guard_getattr
        builtins["hasattr"] = self.guard_hasattr
        builtins["setattr"] = self.guard_setattr
        builtins["delattr"] = self.guard_delattr
        namespace = {
            "__builtins__": builtins,
            "_write_": self.guard_write,
            "_getitem_": self.guard_getitem,
            "_getattr_": self.guard_getattr,
            "_getiter_": self.guard_getiter,
            "_inplacevar_": self.guard_inplace,
            "_print_": self.print_collector,
            "_unpack_sequence_": _guarded_unpack_sequence,
            "_iter_unpack_sequence_": _guarded_iter_unpack_sequence,
        }
        namespace.update(self._bindings)
        if extra:
            namespace.update(extra)
        return namespace

    def execute(self, source, filename="<transaction>", extra=None):
        # Compile and run restricted source against this transaction.
        self._check_active()
        code = compile_restricted(source, filename=filename, mode="exec")
        namespace = self.restricted_globals(extra)
        with self._lock:
            self._check_active()
            exec(code, namespace)
        return namespace

    def write_sets(self):
        # Tuple of (host object, its collected WriteRecord tuple) pairs.
        # A mapping cannot be used because host objects may themselves be
        # unhashable containers (for example dicts).
        return tuple(
            (info.host, tuple(info.records))
            for info in self._infos.values()
            if info.records
        )

    def writes(self):
        # Flat tuple of every collected write, grouped by host.
        records = []
        for info in self._infos.values():
            records.extend(info.records)
        return tuple(records)

    def changed_objects(self):
        # Host objects with at least one collected write.
        return tuple(
            info.host for info in self._infos.values() if info.records)

    @property
    def lock(self):
        # Re-entrant lock serializing commit with external observers.
        return self._lock

    @property
    def finished(self):
        # True after commit or abort.
        return self._finished

    @property
    def committed(self):
        # True only after a successful commit.
        return self._committed

    # -- commit --------------------------------------------------------

    def commit(self, validators=()):
        # Validate host versions, run validators, then apply atomically.
        with self._lock:
            self._check_active()
            dirty = [info for info in self._infos.values()
                     if info.proxy._shadow is not None]
            try:
                self._check_versions(dirty)
                for validator in validators:
                    validator(self)
            except Exception as exc:
                self._finished = True
                if isinstance(exc, TransactionError):
                    raise
                raise CommitError(
                    "commit validation failed: %s" % (exc,)) from exc
            snapshots = [(info, self._snapshot(info)) for info in dirty]
            try:
                memo = {}
                for info in dirty:
                    self._apply(info, memo)
            except Exception as exc:
                for info, snapshot in reversed(snapshots):
                    self._restore(info, snapshot)
                self._finished = True
                raise CommitError(
                    "commit failed and all changes were rolled back: "
                    "%s" % (exc,)) from exc
            self._finished = True
            self._committed = True
            return True

    def _check_versions(self, dirty):
        for info in self._infos.values():
            if info.version_getter is None:
                continue
            current = info.version_getter(info.host)
            if current != info.initial_version:
                raise VersionConflict(
                    "host %r changed from version %r to %r outside the "
                    "transaction"
                    % (type(info.host), info.initial_version, current))

    def abort(self):
        # Discard every collected write without touching the hosts.
        with self._lock:
            if self._finished:
                return False
            self._finished = True
            return True

    # Alias matching common transaction vocabulary.
    rollback = abort

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is None and not self._finished:
            self.commit()
        elif not self._finished:
            self.abort()
        return False

    def _snapshot(self, info):
        host = info.host
        if info.kind == "list":
            return list(host)
        if info.kind == "dict":
            return dict(host)
        snapshot = {}
        if hasattr(host, "__dict__"):
            snapshot["__dict__"] = dict(vars(host))
        for cls in type(host).__mro__:
            class_slots = getattr(cls, "__slots__", None)
            if not class_slots:
                continue
            if isinstance(class_slots, str):
                class_slots = (class_slots,)
            for name in class_slots:
                if hasattr(host, name):
                    snapshot[name] = getattr(host, name)
        return snapshot

    def _restore(self, info, snapshot):
        host = info.host
        if info.kind == "list":
            host[:] = snapshot
            return
        if info.kind == "dict":
            host.clear()
            host.update(snapshot)
            return
        if hasattr(host, "__dict__"):
            host.__dict__.clear()
            host.__dict__.update(snapshot.get("__dict__", {}))
        for cls in type(host).__mro__:
            class_slots = getattr(cls, "__slots__", None)
            if not class_slots:
                continue
            if isinstance(class_slots, str):
                class_slots = (class_slots,)
            for name in class_slots:
                if name in snapshot:
                    setattr(host, name, snapshot[name])
                elif hasattr(host, name):
                    delattr(host, name)

    def _resolve(self, value, memo):
        # Turn a shadow value into the value that should live on the real
        # host graph, preserving identity, aliases and self references.
        if isinstance(value, _TxProxy):
            host_id = id(value._host)
            if host_id in memo:
                return memo[host_id]
            if value._shadow is None:
                memo[host_id] = value._host
                return value._host
            return self._apply(
                self._infos[host_id], memo)
        if isinstance(value, list):
            new_list = []
            memo[id(value)] = new_list
            new_list.extend(
                self._resolve(item, memo) for item in value)
            return new_list
        if isinstance(value, dict):
            new_dict = {}
            memo[id(value)] = new_dict
            for key, item in value.items():
                new_dict[key] = self._resolve(item, memo)
            return new_dict
        return value

    def _apply(self, info, memo):
        host = info.host
        host_id = id(host)
        if host_id in memo:
            return memo[host_id]
        proxy = info.proxy
        shadow = proxy._shadow
        if info.kind == "list":
            memo[host_id] = host
            host[:] = [self._resolve(item, memo) for item in shadow]
            return host
        if info.kind == "dict":
            memo[host_id] = host
            host.clear()
            for key, item in shadow.items():
                host[key] = self._resolve(item, memo)
            return host
        memo[host_id] = host
        for name in list(getattr(host, "__dict__", {}).keys()):
            if name not in shadow:
                delattr(host, name)
        for name, item in shadow.items():
            setattr(host, name, self._resolve(item, memo))
        for cls in type(host).__mro__:
            class_slots = getattr(cls, "__slots__", None)
            if not class_slots:
                continue
            if isinstance(class_slots, str):
                class_slots = (class_slots,)
            for name in class_slots:
                if name in shadow:
                    setattr(
                        host, name,
                        self._resolve(shadow[name], memo))
                elif hasattr(host, name):
                    delattr(host, name)
        return host


def _guarded_iter_unpack_sequence(iterable, spec, _getiter_):
    # Generator variant of the sequence unpack guard for for-loops.
    for item in _getiter_(iterable):
        yield _guarded_unpack_sequence(item, spec, _getiter_)


def _guarded_unpack_sequence(iterable, spec, _getiter_):
    # Mirror of Guards.guarded_unpack_sequence using the tx _getiter_.
    result = list(_getiter_(iterable))
    if len(result) < spec["min_len"]:
        return result
    for index, child_spec in spec["childs"]:
        result[index] = _guarded_unpack_sequence(
            result[index], child_spec, _getiter_)
    return result


def transactional_exec(source, bindings=(), validators=(),
                       filename="<transaction>", extra=None):
    # Convenience wrapper: one transaction for one restricted program.
    tx = Transaction()
    for binding in bindings:
        tx.allow_object(
            binding.host,
            name=binding.name,
            writable_attrs=binding.writable_attrs,
            version_getter=binding.version_getter)
    namespace = tx.execute(source, filename=filename, extra=extra)
    tx.commit(validators=validators)
    return tx, namespace
