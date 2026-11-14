"""
Custom handlers may be created to handle other objects. Each custom handler
must derive from :class:`jsonpickle.handlers.BaseHandler` and
implement ``flatten`` and ``restore``.

A handler can be bound to other types by calling
:func:`jsonpickle.handlers.register`.

"""

import array
import collections
import copy
import datetime
import inspect
import io
import queue
import re
import threading
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, NoReturn, TypeAlias, TypeVar

from . import tags, util

T = TypeVar("T")

if TYPE_CHECKING:
    from .pickler import Pickler
    from .unpickler import Unpickler

ContextType: TypeAlias = "Pickler | Unpickler"
RestoreType: TypeAlias = "Unpickler"
HandlerType: TypeAlias = type
KeyType: TypeAlias = type | str
HandlerReturn: TypeAlias = dict[str, Any] | str | None
DateTime: TypeAlias = datetime.date | datetime.time


DIRECTION_ENCODE = "encode"
DIRECTION_DECODE = "decode"
DIRECTION_BOTH = "both"
_VALID_DIRECTIONS = (DIRECTION_ENCODE, DIRECTION_DECODE, DIRECTION_BOTH)

SOURCE_BUILTIN = "builtin"
SOURCE_USER = "user"

DEFAULT_PRIORITY = 0


class HandlerConflictError(Exception):
    """Two different handlers tie for the same type, direction and priority.

    Handler selection is deterministic: the highest priority wins and ties
    between *different* handlers are never resolved by registration order.
    Register one of the conflicting handlers with an explicit higher
    priority (or unregister the other one) to resolve the conflict.
    """


def _handler_key(handler: Any) -> type:
    """Identity used to tell whether two registrations are the same handler.

    Handler classes identify themselves; handler instances identify with
    their class, so re-registering a fresh instance of the same handler
    class is an idempotent update rather than a conflict.
    """
    return handler if util._is_type(handler) else type(handler)


def _handler_name(handler: Any) -> str:
    """Human-readable handler name; never includes object contents."""
    return util.importable_name(_handler_key(handler))


def _directions_overlap(first: str, second: str) -> bool:
    return first == DIRECTION_BOTH or second == DIRECTION_BOTH or first == second


class HandlerRegistration:
    """A single deterministic handler registration."""

    __slots__ = (
        "cls",
        "handler",
        "priority",
        "direction",
        "source",
        "base",
        "sequence",
    )

    def __init__(
        self,
        cls: type,
        handler: Any,
        priority: float,
        direction: str,
        source: str,
        base: bool,
        sequence: int,
    ) -> None:
        self.cls = cls
        self.handler = handler
        self.priority = priority
        self.direction = direction
        self.source = source
        self.base = base
        self.sequence = sequence

    @property
    def name(self) -> str:
        return _handler_name(self.handler)

    def __repr__(self) -> str:
        return (
            f"HandlerRegistration(type={util.importable_name(self.cls)}, "
            f"handler={self.name}, priority={self.priority}, "
            f"direction={self.direction}, source={self.source}, base={self.base})"
        )


class HandlerSelection:
    """Audit record describing the outcome of one handler selection."""

    __slots__ = ("key", "direction", "match", "handler", "priority", "source")

    def __init__(
        self,
        key: str,
        direction: str | None,
        match: str,
        handler: str | None,
        priority: float | None,
        source: str | None,
    ) -> None:
        self.key = key
        self.direction = direction
        self.match = match
        self.handler = handler
        self.priority = priority
        self.source = source

    def __repr__(self) -> str:
        return (
            f"HandlerSelection(key={self.key}, direction={self.direction}, "
            f"match={self.match}, handler={self.handler}, "
            f"priority={self.priority}, source={self.source})"
        )


class Registry:
    """Deterministic handler registry.

    Every registration carries a priority, a direction ("encode", "decode"
    or "both") and a source (e.g. "builtin" or "user").  Selection depends
    only on those attributes -- never on registration order -- so the same
    set of registrations produces the same result on every machine.  All
    mutations are atomic and guarded by a lock, so a failed registration
    never leaves partial state behind and concurrent registrations from
    multiple threads cannot lose handlers or reorder priorities.
    """

    def __init__(self, audit_limit: int = 4096) -> None:
        self._lock = threading.RLock()
        self._exact: dict = {}
        self._base: dict = {}
        self._names: dict = {}
        self._sequence = 0
        self._audit: collections.deque = collections.deque(maxlen=audit_limit)

    def get(
        self,
        cls_or_name: "type | str",
        default: Any | None = None,
        *,
        direction: "str | None" = None,
    ) -> Any:
        """
        :param cls_or_name: the type or its fully qualified name
        :param default: default value, if a matching handler is not found
        :param direction: optional "encode" or "decode"; only handlers
            registered for that direction (or "both") are eligible

        Looks up a handler by type reference or its fully
        qualified name. If a direct match
        is not found, the search is performed over all
        handlers registered with base=True.

        Every lookup is recorded in the audit log; see :meth:`audit`.
        """
        _record, registration = self._resolve(cls_or_name, direction, audit=True)
        return default if registration is None else registration.handler

    def explain(
        self, cls_or_name: "type | str", *, direction: "str | None" = None
    ) -> HandlerSelection:
        """Return the selection record for a lookup without recording it."""
        record, _registration = self._resolve(cls_or_name, direction, audit=False)
        return record

    def audit(self) -> list:
        """Return a snapshot of the recorded handler selections."""
        with self._lock:
            return list(self._audit)

    def clear_audit(self) -> None:
        """Drop all recorded handler selections."""
        with self._lock:
            self._audit.clear()

    def _resolve(
        self, cls_or_name: "type | str", direction: "str | None", audit: bool
    ) -> tuple:
        if direction is not None and direction not in (
            DIRECTION_ENCODE,
            DIRECTION_DECODE,
        ):
            raise ValueError(
                f"direction must be 'encode' or 'decode', got {direction!r}"
            )
        with self._lock:
            if util._is_type(cls_or_name):
                cls = cls_or_name
                key = util.importable_name(cls)
            elif isinstance(cls_or_name, str):
                cls = self._names.get(cls_or_name)
                key = cls_or_name
            else:
                cls = None
                key = type(cls_or_name).__name__

            registration = None
            match = "none"
            if cls is not None:
                # registrations attached to this exact class (with or without
                # base=True) always win over registrations inherited from
                # base classes
                exact_candidates = list(self._exact.get(cls, ()))
                exact_candidates.extend(self._base.get(cls, ()))
                registration = self._best(exact_candidates, direction, key)
                if registration is not None:
                    match = "exact"
                else:
                    candidates = []
                    for base_cls, registrations in self._base.items():
                        if base_cls is not cls and issubclass(cls, base_cls):
                            candidates.extend(registrations)
                    registration = self._best(candidates, direction, key)
                    if registration is not None:
                        match = "base"

            record = HandlerSelection(
                key=key,
                direction=direction,
                match=match,
                handler=None if registration is None else registration.name,
                priority=None if registration is None else registration.priority,
                source=None if registration is None else registration.source,
            )
            if audit:
                self._audit.append(record)
            return record, registration

    @staticmethod
    def _best(candidates: Any, direction: "str | None", key: str) -> Any:
        eligible = [
            registration
            for registration in candidates
            if direction is None
            or registration.direction == DIRECTION_BOTH
            or registration.direction == direction
        ]
        if not eligible:
            return None
        best_priority = max(registration.priority for registration in eligible)
        winners = [
            registration
            for registration in eligible
            if registration.priority == best_priority
        ]
        identities = {_handler_key(registration.handler) for registration in winners}
        if len(identities) > 1:
            names = sorted(
                _handler_name(registration.handler) for registration in winners
            )
            raise HandlerConflictError(
                f"handler conflict for type {key} "
                f"(direction={direction or 'any'}, priority={best_priority}): "
                + " vs ".join(names)
            )
        return winners[0]

    def register(
        self,
        cls: type,
        handler: "KeyType | None" = None,
        base: bool = False,
        *,
        priority: float = DEFAULT_PRIORITY,
        direction: str = DIRECTION_BOTH,
        source: str = SOURCE_USER,
    ) -> Callable[[HandlerType], HandlerType] | None:
        """Register the a custom handler for a class

        :param cls: The custom object class to handle
        :param handler: The custom handler class (if
            None, a decorator wrapper is returned)
        :param base: Indicates whether the handler should
            be registered for all subclasses
        :param priority: Selection priority; the highest priority handler
            wins. A tie between different handlers raises
            :class:`HandlerConflictError` instead of picking the first one.
        :param direction: "encode", "decode" or "both" (the default);
            restricts which direction the handler is eligible for.
        :param source: Free-form origin label (e.g. "builtin" or "user"),
            recorded in registrations and the audit log.

        This function can be also used as a decorator
        by omitting the `handler` argument::

            @jsonpickle.handlers.register(Foo, base=True)
            class FooHandler(jsonpickle.handlers.BaseHandler):
                pass

        Registration is atomic: the registry is validated first and mutated
        afterwards, so a failing registration never leaves partial state.
        """
        if handler is None:

            def _register(handler_cls: HandlerType) -> HandlerType:
                self.register(
                    cls,
                    handler=handler_cls,
                    base=base,
                    priority=priority,
                    direction=direction,
                    source=source,
                )
                return handler_cls

            return _register
        if not util._is_type(cls):
            raise TypeError(f"expected a class/type, got {type(cls).__name__}")
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(
                f"direction must be one of {_VALID_DIRECTIONS}, got {direction!r}"
            )
        if isinstance(priority, bool) or not isinstance(priority, (int, float)):
            raise TypeError(f"priority must be a number, got {type(priority).__name__}")
        if not callable(handler):
            raise TypeError(
                f"handler for {util.importable_name(cls)} must be callable, "
                f"got {type(handler).__name__}"
            )
        if not isinstance(source, str):
            raise TypeError(f"source must be a string, got {type(source).__name__}")
        with self._lock:
            collection = self._base if base else self._exact
            new_key = _handler_key(handler)
            # conflict detection spans both collections: exact and base
            # registrations for the same class share one selection pool
            for existing in list(self._exact.get(cls, ())) + list(
                self._base.get(cls, ())
            ):
                if (
                    _handler_key(existing.handler) is not new_key
                    and existing.priority == priority
                    and _directions_overlap(existing.direction, direction)
                ):
                    raise HandlerConflictError(
                        f"handler conflict for type {util.importable_name(cls)} "
                        f"(direction={direction}, priority={priority}): "
                        f"{existing.name} vs {_handler_name(handler)}"
                    )
            kept = []
            for existing in collection.get(cls, ()):
                if (
                    _handler_key(existing.handler) is new_key
                    and existing.direction == direction
                ):
                    # idempotent update of an existing registration
                    continue
                kept.append(existing)
            self._sequence += 1
            kept.append(
                HandlerRegistration(
                    cls=cls,
                    handler=handler,
                    priority=priority,
                    direction=direction,
                    source=source,
                    base=base,
                    sequence=self._sequence,
                )
            )
            collection[cls] = kept
            # store the fully qualified name for the ugly cases like
            # _sre.SRE_Pattern that cannot be loaded back directly
            self._names[util.importable_name(cls)] = cls
        return None

    def unregister(self, cls: type) -> None:
        """Remove every registration for the given class (atomically)."""
        with self._lock:
            self._exact.pop(cls, None)
            self._base.pop(cls, None)
            if util._is_type(cls):
                self._names.pop(util.importable_name(cls), None)


registry = Registry()
register = registry.register
unregister = registry.unregister
get = registry.get
audit = registry.audit
clear_audit = registry.clear_audit
explain = registry.explain


def handler_accepts_handler_context(fn: Callable[..., Any]) -> bool:
    """
    Check if the handler function has a handler_context parameter.
    """
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False

    param = params.get("handler_context")
    if param is None:
        return False

    return param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
        inspect.Parameter.VAR_KEYWORD,
    )


class BaseHandler:
    def __init__(self, context: Any):
        """
        Initialize a new handler to handle a registered type.

        :Parameters:
          - `context`: reference to pickler/unpickler

        """
        self.context = context

    def flatten(self, obj: Any, data: dict[str, Any]) -> HandlerReturn:
        """
        Flatten `obj` into a json-friendly form and write result to `data`.

        :param object obj: The object to be serialized.
        :param dict data: A partially filled dictionary which will contain the
            json-friendly representation of `obj` once this method has
            finished.
        """
        raise NotImplementedError(f"You must implement flatten() in {self.__class__}")

    def restore(self, data: dict[str, Any]) -> Any:
        """
        Restore an object of the registered type from the json-friendly
        representation `obj` and return it.
        """
        raise NotImplementedError(f"You must implement restore() in {self.__class__}")

    @classmethod
    def handles(self, cls: type) -> type:
        """
        Register this handler for the given class. Suitable as a decorator,
        e.g.::

            @MyCustomHandler.handles
            class MyCustomClass:
                def __reduce__(self):
                    ...
        """
        registry.register(cls, self)
        return cls

    def __call__(self, context: ContextType) -> "BaseHandler":
        """This permits registering either Handler instances or classes

        :Parameters:
          - `context`: reference to pickler/unpickler
        """
        self.context = context
        return self


class ArrayHandler(BaseHandler):
    """Flatten and restore array.array objects"""

    def flatten(self, obj: array.array, data: dict[str, Any]) -> HandlerReturn:  # type: ignore[type-arg]
        data["typecode"] = obj.typecode
        data["values"] = self.context.flatten(obj.tolist(), reset=False)
        return data

    def restore(self, data: dict[str, Any]) -> array.array:  # type: ignore[type-arg]
        typecode = data["typecode"]
        values = self.context.restore(data["values"], reset=False)
        if typecode == "c":
            values = [bytes(x) for x in values]
        return array.array(typecode, values)


register(array.array, ArrayHandler, source=SOURCE_BUILTIN)


class DatetimeHandler(BaseHandler):
    """Custom handler for datetime objects

    Datetime objects use __reduce_ex__, and they generate binary strings
    encoding the payload. This handler encodes that payload to reconstruct
    the object.

    """

    def flatten(self, obj: DateTime, data: dict[str, Any]) -> HandlerReturn:
        pickler = self.context
        if not pickler.unpicklable:
            if hasattr(obj, "isoformat"):
                result = obj.isoformat()
            else:
                result = str(obj)
            return result
        cls, args = obj.__reduce_ex__(util.PICKLE_PROTOCOL)  # type: ignore[str-unpack]
        flatten = pickler.flatten
        payload = util.b64encode(args[0])  # type: ignore[arg-type]
        args = [payload] + [flatten(i, reset=False) for i in args[1:]]
        data["__reduce__"] = (flatten(cls, reset=False), args)
        return data

    def restore(self, data: dict[str, Any]) -> Any:
        cls, args = data["__reduce__"]
        unpickler = self.context
        restore = unpickler.restore
        cls = restore(cls, reset=False)
        value = util.b64decode(args[0])
        params = (value,) + tuple([restore(i, reset=False) for i in args[1:]])
        return cls.__new__(cls, *params)


register(datetime.datetime, DatetimeHandler, source=SOURCE_BUILTIN)
register(datetime.date, DatetimeHandler, source=SOURCE_BUILTIN)
register(datetime.time, DatetimeHandler, source=SOURCE_BUILTIN)


class RegexHandler(BaseHandler):
    """Flatten _sre.SRE_Pattern (compiled regex) objects"""

    def flatten(self, obj: re.Pattern[Any], data: dict[str, Any]) -> HandlerReturn:
        pattern = obj.pattern
        if isinstance(pattern, bytes):
            pattern = self.context._flatten_bytestring(pattern)
        data["pattern"] = pattern
        data["flags"] = obj.flags
        return data

    def restore(self, data: dict[str, Any]) -> re.Pattern[Any]:
        pattern = data["pattern"]
        if isinstance(pattern, dict):
            if tags.B85 in pattern:
                pattern = self.context._restore_base85(pattern)
            else:
                pattern = self.context._restore_base64(pattern)
        return re.compile(pattern, data.get("flags", 0))


register(type(re.compile("")), RegexHandler, source=SOURCE_BUILTIN)


class QueueHandler(BaseHandler):
    """Opaquely serializes Queue objects

    Queues contains mutex and condition variables which cannot be serialized.
    Construct a new Queue instance when restoring.

    """

    def flatten(self, obj: queue.Queue[Any], data: dict[str, Any]) -> HandlerReturn:
        return data

    def restore(self, data: dict[str, Any]) -> queue.Queue[Any]:
        return queue.Queue()


register(queue.Queue, QueueHandler, source=SOURCE_BUILTIN)


class CloneFactory:
    """Serialization proxy for collections.defaultdict's default_factory"""

    def __init__(self, exemplar: Any) -> None:
        self.exemplar = exemplar

    def __call__(self, clone: Callable[[Any], Any] = copy.copy) -> Any:
        """Create new instances by making copies of the provided exemplar"""
        return clone(self.exemplar)

    def __repr__(self) -> str:
        return f"<CloneFactory object at 0x{id(self):x} ({self.exemplar})>"


class UUIDHandler(BaseHandler):
    """Serialize uuid.UUID objects"""

    def flatten(self, obj: uuid.UUID, data: dict[str, Any]) -> HandlerReturn:
        data["hex"] = obj.hex
        return data

    def restore(self, data: dict[str, Any]) -> uuid.UUID:
        return uuid.UUID(data["hex"])


register(uuid.UUID, UUIDHandler, source=SOURCE_BUILTIN)


class LockHandler(BaseHandler):
    """Serialize threading.Lock objects"""

    def flatten(self, obj: Any, data: dict[str, Any]) -> HandlerReturn:
        data["locked"] = obj.locked()
        return data

    def restore(self, data: dict[str, Any]) -> Any:
        lock = threading.Lock()
        if data.get("locked", False):
            lock.acquire()
        return lock


_lock = threading.Lock()
register(_lock.__class__, LockHandler, source=SOURCE_BUILTIN)


class TextIOHandler(BaseHandler):
    """Serialize file descriptors as None because we cannot roundtrip"""

    def flatten(self, obj: io.TextIOBase, data: dict[str, Any]) -> None:
        return None

    def restore(self, data: dict[str, Any]) -> NoReturn:
        """Restore should never get called because flatten() returns None"""
        raise AssertionError("Restoring IO.TextIOHandler is not supported")


register(io.TextIOWrapper, TextIOHandler, source=SOURCE_BUILTIN)


class PassthroughHandler(BaseHandler):
    """
    Hand objects to the backend untouched instead of flattening them.

    Backends can support types that jsonpickle would otherwise flatten into a
    py/object payload. simplejson in use_decimal mode, for example, writes
    decimal.Decimal out as a plain json number. You will normally want to register
    this using base=True.

    This handler is not registered for any type by default. The backend must know
    how to encode and decode the object, so ensure that it can before using this!

    Example usage::

        jsonpickle.handlers.register(
            decimal.Decimal, PassthroughHandler, base=True
        )

    """

    def flatten(self, obj: Any, data: dict[str, Any]) -> Any:
        # the pickler logged a reference before dispatching here, but the
        # backend writes obj as an opaque value that no py/id entry can
        # point at. therefore, drop the reference so that a repeat of the
        # same instance is encoded again instead of becoming a dangling reference
        self.context._unlog_ref(obj)
        return obj

    def restore(self, data: dict[str, Any]) -> NoReturn:
        """
        Restore should never get called because flatten() returns obj
        """
        raise AssertionError("Restoring PassthroughHandler is not supported")
