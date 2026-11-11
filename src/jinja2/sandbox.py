"""A sandbox layer that ensures unsafe operations cannot be performed.
Useful when the template itself comes from an untrusted source.
"""

import inspect
import operator
import types
import typing as t
from _string import formatter_field_name_split  # type: ignore
from collections import abc
from collections import deque
from functools import update_wrapper
from string import Formatter

from markupsafe import EscapeFormatter
from markupsafe import Markup

from .environment import Environment
from .exceptions import SecurityError
from .exceptions import TemplateRuntimeError
from .exceptions import UndefinedError
from .runtime import Context
from .runtime import Undefined
from .utils import missing

F = t.TypeVar("F", bound=t.Callable[..., t.Any])

#: maximum number of items a range may produce
MAX_RANGE = 100000

#: Reason codes returned by strict attribute checking.  They are stable
#: application-facing values and do not include object representations or
#: exception messages from the inspected object.
ATTRIBUTE_REASON_MISSING = "missing"
ATTRIBUTE_REASON_POLICY_DENIED = "policy_denied"
ATTRIBUTE_REASON_UNRENDERABLE = "unrenderable"


class AttributeAccessReason:
    """Names for the reason codes produced by strict attribute checking."""

    MISSING = ATTRIBUTE_REASON_MISSING
    POLICY_DENIED = ATTRIBUTE_REASON_POLICY_DENIED
    UNRENDERABLE = ATTRIBUTE_REASON_UNRENDERABLE


class AttributeAccessPolicy:
    """Values accepted by the ``attribute_policy`` environment option."""

    LEGACY = "legacy"
    STRICT = "strict"


#: Containers whose item lookup is implemented by a built-in type.  A
#: subclass that overrides ``__getitem__`` is not considered safe here.
_SAFE_ITEM_TYPES = (dict, list, tuple, str, bytes, bytearray, range)

_STATIC_LOOKUP_FAILED = object()

#: Unsafe function attributes.
UNSAFE_FUNCTION_ATTRIBUTES: set[str] = set()

#: Unsafe method attributes. Function attributes are unsafe for methods too.
UNSAFE_METHOD_ATTRIBUTES: set[str] = set()

#: unsafe generator attributes.
UNSAFE_GENERATOR_ATTRIBUTES = {"gi_frame", "gi_code"}

#: unsafe attributes on coroutines
UNSAFE_COROUTINE_ATTRIBUTES = {"cr_frame", "cr_code"}

#: unsafe attributes on async generators
UNSAFE_ASYNC_GENERATOR_ATTRIBUTES = {"ag_code", "ag_frame"}

_mutable_spec: tuple[tuple[type[t.Any], frozenset[str]], ...] = (
    (
        abc.MutableSet,
        frozenset(
            [
                "add",
                "clear",
                "difference_update",
                "discard",
                "pop",
                "remove",
                "symmetric_difference_update",
                "update",
            ]
        ),
    ),
    (
        abc.MutableMapping,
        frozenset(["clear", "pop", "popitem", "setdefault", "update"]),
    ),
    (
        abc.MutableSequence,
        frozenset(
            ["append", "clear", "pop", "reverse", "insert", "sort", "extend", "remove"]
        ),
    ),
    (
        deque,
        frozenset(
            [
                "append",
                "appendleft",
                "clear",
                "extend",
                "extendleft",
                "pop",
                "popleft",
                "remove",
                "rotate",
            ]
        ),
    ),
)


def safe_range(*args: int) -> range:
    """A range that can't generate ranges with a length of more than
    MAX_RANGE items.
    """
    rng = range(*args)

    if len(rng) > MAX_RANGE:
        raise OverflowError(
            "Range too big. The sandbox blocks ranges larger than"
            f" MAX_RANGE ({MAX_RANGE})."
        )

    return rng


def unsafe(f: F) -> F:
    """Marks a function or method as unsafe.

    .. code-block: python

        @unsafe
        def delete(self):
            pass
    """
    f.unsafe_callable = True  # type: ignore
    return f


def is_internal_attribute(obj: t.Any, attr: str) -> bool:
    """Test if the attribute given is an internal python attribute.  For
    example this function returns `True` for the `func_code` attribute of
    python objects.  This is useful if the environment method
    :meth:`~SandboxedEnvironment.is_safe_attribute` is overridden.

    >>> from jinja2.sandbox import is_internal_attribute
    >>> is_internal_attribute(str, "mro")
    True
    >>> is_internal_attribute(str, "upper")
    False
    """
    if isinstance(obj, types.FunctionType):
        if attr in UNSAFE_FUNCTION_ATTRIBUTES:
            return True
    elif isinstance(obj, types.MethodType):
        if attr in UNSAFE_FUNCTION_ATTRIBUTES or attr in UNSAFE_METHOD_ATTRIBUTES:
            return True
    elif isinstance(obj, type):
        if attr == "mro":
            return True
    elif isinstance(obj, (types.CodeType, types.TracebackType, types.FrameType)):
        return True
    elif isinstance(obj, types.GeneratorType):
        if attr in UNSAFE_GENERATOR_ATTRIBUTES:
            return True
    elif hasattr(types, "CoroutineType") and isinstance(obj, types.CoroutineType):
        if attr in UNSAFE_COROUTINE_ATTRIBUTES:
            return True
    elif hasattr(types, "AsyncGeneratorType") and isinstance(
        obj, types.AsyncGeneratorType
    ):
        if attr in UNSAFE_ASYNC_GENERATOR_ATTRIBUTES:
            return True
    return attr.startswith("__")


def modifies_known_mutable(obj: t.Any, attr: str) -> bool:
    """This function checks if an attribute on a builtin mutable object
    (list, dict, set or deque) or the corresponding ABCs would modify it
    if called.

    >>> modifies_known_mutable({}, "clear")
    True
    >>> modifies_known_mutable({}, "keys")
    False
    >>> modifies_known_mutable([], "append")
    True
    >>> modifies_known_mutable([], "index")
    False

    If called with an unsupported object, ``False`` is returned.

    >>> modifies_known_mutable("foo", "upper")
    False
    """
    for typespec, unsafe in _mutable_spec:
        if isinstance(obj, typespec):
            return attr in unsafe
    return False


def _find_class_attribute(
    cls: type[t.Any], name: str
) -> tuple[bool, t.Any, type[t.Any] | None]:
    """Find an attribute in a class hierarchy without running user code."""
    try:
        mro = type.__getattribute__(cls, "__mro__")
    except Exception:
        mro = (cls,)

    for base in mro:
        try:
            namespace = type.__getattribute__(base, "__dict__")
        except Exception:
            continue

        if name in namespace:
            return True, namespace[name], base

    return False, missing, None


def _builtin_item_owner(obj: t.Any) -> type[t.Any] | None:
    """Return the built-in type implementing item access, if it is safe."""
    for item_type in _SAFE_ITEM_TYPES:
        if isinstance(obj, item_type):
            found, _, owner = _find_class_attribute(type(obj), "__getitem__")

            if found and owner is item_type:
                return item_type

    return None


class SandboxedEnvironment(Environment):
    """The sandboxed environment.  It works like the regular environment but
    tells the compiler to generate sandboxed code.  Additionally subclasses of
    this environment may override the methods that tell the runtime what
    attributes or functions are safe to access.

    If the template tries to access insecure code a :exc:`SecurityError` is
    raised.  However also other exceptions may occur during the rendering so
    the caller has to ensure that all exceptions are caught.
    """

    sandboxed = True

    #: default callback table for the binary operators.  A copy of this is
    #: available on each instance of a sandboxed environment as
    #: :attr:`binop_table`
    default_binop_table: dict[str, t.Callable[[t.Any, t.Any], t.Any]] = {
        "+": operator.add,
        "-": operator.sub,
        "*": operator.mul,
        "/": operator.truediv,
        "//": operator.floordiv,
        "**": operator.pow,
        "%": operator.mod,
    }

    #: default callback table for the unary operators.  A copy of this is
    #: available on each instance of a sandboxed environment as
    #: :attr:`unop_table`
    default_unop_table: dict[str, t.Callable[[t.Any], t.Any]] = {
        "+": operator.pos,
        "-": operator.neg,
    }

    #: a set of binary operators that should be intercepted.  Each operator
    #: that is added to this set (empty by default) is delegated to the
    #: :meth:`call_binop` method that will perform the operator.  The default
    #: operator callback is specified by :attr:`binop_table`.
    #:
    #: The following binary operators are interceptable:
    #: ``//``, ``%``, ``+``, ``*``, ``-``, ``/``, and ``**``
    #:
    #: The default operation form the operator table corresponds to the
    #: builtin function.  Intercepted calls are always slower than the native
    #: operator call, so make sure only to intercept the ones you are
    #: interested in.
    #:
    #: .. versionadded:: 2.6
    intercepted_binops: frozenset[str] = frozenset()

    #: a set of unary operators that should be intercepted.  Each operator
    #: that is added to this set (empty by default) is delegated to the
    #: :meth:`call_unop` method that will perform the operator.  The default
    #: operator callback is specified by :attr:`unop_table`.
    #:
    #: The following unary operators are interceptable: ``+``, ``-``
    #:
    #: The default operation form the operator table corresponds to the
    #: builtin function.  Intercepted calls are always slower than the native
    #: operator call, so make sure only to intercept the ones you are
    #: interested in.
    #:
    #: .. versionadded:: 2.6
    intercepted_unops: frozenset[str] = frozenset()

    def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
        strict = kwargs.pop("strict_attribute_checking", None)
        attribute_policy = kwargs.pop("attribute_policy", None)

        for alias in (
            "strict_attributes",
            "strict_attribute_access",
            "strict_attr_access",
            "strict",
        ):
            alias_value = kwargs.pop(alias, None)

            if alias_value is not None:
                if strict is not None and bool(strict) != bool(alias_value):
                    raise TypeError(f"strict_attribute_checking and {alias} conflict")

                strict = alias_value

        if attribute_policy is not None:
            if isinstance(attribute_policy, bool):
                policy_strict = attribute_policy
            elif attribute_policy == AttributeAccessPolicy.STRICT:
                policy_strict = True
            elif attribute_policy in {
                AttributeAccessPolicy.LEGACY,
                "default",
                None,
            }:
                policy_strict = False
            else:
                raise ValueError(f"unknown attribute policy {attribute_policy!r}")

            if strict is not None and bool(strict) != policy_strict:
                raise TypeError(
                    "strict_attribute_checking and attribute_policy conflict"
                )

            strict = policy_strict

        if strict is None:
            strict = False

        super().__init__(*args, strict_attribute_checking=bool(strict), **kwargs)
        self.globals["range"] = safe_range
        self.binop_table = self.default_binop_table.copy()
        self.unop_table = self.default_unop_table.copy()

    @property
    def strict_attributes(self) -> bool:
        """Alias for :attr:`strict_attribute_checking`."""
        return self.strict_attribute_checking

    @strict_attributes.setter
    def strict_attributes(self, value: bool) -> None:
        self.strict_attribute_checking = bool(value)

    def is_safe_attribute(self, obj: t.Any, attr: str, value: t.Any) -> bool:
        """The sandboxed environment will call this method to check if the
        attribute of an object is safe to access.  Per default all attributes
        starting with an underscore are considered private as well as the
        special attributes of internal python objects as returned by the
        :func:`is_internal_attribute` function.  When strict attribute
        checking is enabled, *value* is the static definition from the class
        or instance dictionary, which may be a descriptor rather than the
        resolved value.
        """
        return not (attr.startswith("_") or is_internal_attribute(obj, attr))

    def is_safe_item(self, obj: t.Any, item: t.Any) -> bool:
        """Check if an item lookup is allowed in strict mode.

        String items use the same name policy as attributes.  Non-string
        items are only allowed for containers with a built-in item
        implementation; override this method to permit other mappings.
        """
        if isinstance(item, str):
            return self.is_safe_attribute(obj, item, missing)

        return _builtin_item_owner(obj) is not None

    def is_safe_callable(self, obj: t.Any) -> bool:
        """Check if an object is safely callable. By default callables
        are considered safe unless decorated with :func:`unsafe`.

        This also recognizes the Django convention of setting
        ``func.alters_data = True``.
        """
        return not (
            getattr(obj, "unsafe_callable", False) or getattr(obj, "alters_data", False)
        )

    def call_binop(
        self, context: Context, operator: str, left: t.Any, right: t.Any
    ) -> t.Any:
        """For intercepted binary operator calls (:meth:`intercepted_binops`)
        this function is executed instead of the builtin operator.  This can
        be used to fine tune the behavior of certain operators.

        .. versionadded:: 2.6
        """
        return self.binop_table[operator](left, right)

    def call_unop(self, context: Context, operator: str, arg: t.Any) -> t.Any:
        """For intercepted unary operator calls (:meth:`intercepted_unops`)
        this function is executed instead of the builtin operator.  This can
        be used to fine tune the behavior of certain operators.

        .. versionadded:: 2.6
        """
        return self.unop_table[operator](arg)

    def getitem(self, obj: t.Any, argument: str | t.Any) -> t.Any | Undefined:
        """Subscribe an object from sandboxed code."""
        if self.strict_attribute_checking:
            return self._strict_getitem(obj, argument)

        return self._legacy_getitem(obj, argument)

    def _legacy_getitem(self, obj: t.Any, argument: str | t.Any) -> t.Any | Undefined:
        try:
            return obj[argument]
        except (TypeError, LookupError):
            if isinstance(argument, str):
                try:
                    attr = str(argument)
                except Exception:
                    pass
                else:
                    try:
                        value = getattr(obj, attr)
                    except AttributeError:
                        pass
                    else:
                        fmt = self.wrap_str_format(value)
                        if fmt is not None:
                            return fmt
                        if self.is_safe_attribute(obj, argument, value):
                            return value
                        return self.unsafe_undefined(obj, argument)
        return self.undefined(obj=obj, name=argument)

    def getattr(self, obj: t.Any, attribute: str) -> t.Any | Undefined:
        """Subscribe an object from sandboxed code and prefer the
        attribute.  The attribute passed *must* be a bytestring.
        """
        if self.strict_attribute_checking:
            return self._strict_getattr(obj, attribute)

        return self._legacy_getattr(obj, attribute)

    def _legacy_getattr(self, obj: t.Any, attribute: str) -> t.Any | Undefined:
        try:
            value = getattr(obj, attribute)
        except AttributeError:
            try:
                return obj[attribute]
            except (TypeError, LookupError):
                pass
        else:
            fmt = self.wrap_str_format(value)
            if fmt is not None:
                return fmt
            if self.is_safe_attribute(obj, attribute, value):
                return value
            return self.unsafe_undefined(obj, attribute)
        return self.undefined(obj=obj, name=attribute)

    def _strict_getattr(self, obj: t.Any, attribute: str) -> t.Any | Undefined:
        return self._strict_string_access(obj, attribute, prefer_item=False)

    def _strict_getitem(self, obj: t.Any, argument: str | t.Any) -> t.Any | Undefined:
        if isinstance(argument, str):
            return self._strict_string_access(obj, argument, prefer_item=True)

        return self._strict_item(obj, argument)

    def _strict_string_access(
        self, obj: t.Any, name: str, *, prefer_item: bool
    ) -> t.Any | Undefined:
        if prefer_item and _builtin_item_owner(obj) is not None:
            result = self._strict_item(obj, name)

            if not (
                isinstance(result, Undefined)
                and result.reason_code == ATTRIBUTE_REASON_MISSING
            ):
                return result

            static = self._static_lookup(obj, name)

            if static is _STATIC_LOOKUP_FAILED or static is missing:
                return result

            return self._strict_static_value(obj, name, static)

        static = self._static_lookup(obj, name)

        if static is _STATIC_LOOKUP_FAILED:
            return self._strict_undefined(obj, name, ATTRIBUTE_REASON_POLICY_DENIED)

        if static is not missing:
            return self._strict_static_value(obj, name, static)

        return self._strict_fallback(obj, name, prefer_item=prefer_item)

    def _static_lookup(self, obj: t.Any, name: str) -> t.Any:
        """Look up a definition without invoking descriptors or getattr."""
        try:
            return inspect.getattr_static(obj, name, missing)
        except Exception:
            return _STATIC_LOOKUP_FAILED

    def _strict_static_value(
        self, obj: t.Any, name: str, static: t.Any
    ) -> t.Any | Undefined:
        if not self.is_safe_attribute(obj, name, static):
            return self._strict_undefined(obj, name, ATTRIBUTE_REASON_POLICY_DENIED)

        found, value = self._call_getattr(obj, name)

        if found:
            return value

        return self._strict_undefined(obj, name, ATTRIBUTE_REASON_MISSING)

    def _strict_fallback(
        self, obj: t.Any, name: str, *, prefer_item: bool
    ) -> t.Any | Undefined:
        obj_type = type(obj)
        has_getattr = _find_class_attribute(obj_type, "__getattr__")[0]
        has_getitem = _find_class_attribute(obj_type, "__getitem__")[0]
        getattribute_owner = _find_class_attribute(obj_type, "__getattribute__")[2]
        has_custom_getattribute = getattribute_owner not in {None, object}

        if not (has_getattr or has_getitem or has_custom_getattribute):
            return self._strict_undefined(obj, name, ATTRIBUTE_REASON_MISSING)

        if isinstance(name, str):
            allowed = self.is_safe_attribute(obj, name, missing)
        else:
            allowed = self.is_safe_item(obj, name)

        if not allowed:
            return self._strict_undefined(obj, name, ATTRIBUTE_REASON_POLICY_DENIED)

        can_getattr = has_getattr or has_custom_getattribute

        if prefer_item and has_getitem:
            found, value = self._call_getitem(obj, name)

            if found:
                return value

        if can_getattr:
            found, value = self._call_getattr_safe(obj, name)

            if found:
                return value

        if has_getitem and not prefer_item:
            found, value = self._call_getitem(obj, name)

            if found:
                return value

        return self._strict_undefined(obj, name, ATTRIBUTE_REASON_MISSING)

    def _strict_item(self, obj: t.Any, item: t.Any) -> t.Any | Undefined:
        if not self.is_safe_item(obj, item):
            return self._strict_undefined(obj, item, ATTRIBUTE_REASON_POLICY_DENIED)

        found, value = self._call_getitem(obj, item)

        if found:
            return value

        return self._strict_undefined(obj, item, ATTRIBUTE_REASON_MISSING)

    def _call_getattr(self, obj: t.Any, name: str) -> tuple[bool, t.Any]:
        try:
            value = getattr(obj, name)
        except (AttributeError, LookupError):
            return False, None
        except Exception:
            return True, self._strict_undefined(
                obj, name, ATTRIBUTE_REASON_UNRENDERABLE
            )

        try:
            return True, self._wrap_value(value)
        except Exception:
            return True, self._strict_undefined(
                obj, name, ATTRIBUTE_REASON_UNRENDERABLE
            )

    def _call_getattr_safe(self, obj: t.Any, name: str) -> tuple[bool, t.Any]:
        try:
            value = getattr(obj, name)
        except AttributeError:
            return False, None
        except Exception:
            return True, self._strict_undefined(
                obj, name, ATTRIBUTE_REASON_UNRENDERABLE
            )

        try:
            return True, self._wrap_value(value)
        except Exception:
            return True, self._strict_undefined(
                obj, name, ATTRIBUTE_REASON_UNRENDERABLE
            )

    def _call_getitem(self, obj: t.Any, item: t.Any) -> tuple[bool, t.Any]:
        try:
            value = obj[item]
        except (AttributeError, TypeError, LookupError):
            return False, None
        except Exception:
            return True, self._strict_undefined(
                obj, item, ATTRIBUTE_REASON_UNRENDERABLE
            )

        try:
            return True, self._wrap_value(value)
        except Exception:
            return True, self._strict_undefined(
                obj, item, ATTRIBUTE_REASON_UNRENDERABLE
            )

    def _wrap_value(self, value: t.Any) -> t.Any:
        fmt = self.wrap_str_format(value)
        return value if fmt is None else fmt

    def _strict_undefined(self, obj: t.Any, name: t.Any, reason: str) -> Undefined:
        hints = {
            ATTRIBUTE_REASON_MISSING: "attribute or item is undefined.",
            ATTRIBUTE_REASON_POLICY_DENIED: (
                "attribute or item access was denied by the sandbox policy."
            ),
            ATTRIBUTE_REASON_UNRENDERABLE: (
                "attribute or item value could not be read safely."
            ),
        }
        exc = (
            SecurityError
            if reason == ATTRIBUTE_REASON_POLICY_DENIED
            else UndefinedError
        )
        return self._make_undefined(
            hints[reason],
            name=name if isinstance(name, str) else None,
            obj=obj,
            exc=exc,
            reason=reason,
        )

    def _make_undefined(
        self,
        hint: str,
        *,
        name: str | None,
        obj: t.Any,
        exc: type[TemplateRuntimeError],
        reason: str,
    ) -> Undefined:
        try:
            return self.undefined(
                hint,
                name=name,
                obj=obj,
                exc=exc,
                reason=reason,
            )
        except TypeError:
            undefined = self.undefined(hint, name=name, obj=obj, exc=exc)

            try:
                object.__setattr__(undefined, "_undefined_reason", reason)
            except (AttributeError, TypeError):
                pass

            return undefined

    def unsafe_undefined(self, obj: t.Any, attribute: str) -> Undefined:
        """Return an undefined object for unsafe attributes."""
        return self._make_undefined(
            f"access to attribute {attribute!r} of"
            f" {type(obj).__name__!r} object is unsafe.",
            name=attribute,
            obj=obj,
            exc=SecurityError,
            reason=ATTRIBUTE_REASON_POLICY_DENIED,
        )

    def wrap_str_format(self, value: t.Any) -> t.Callable[..., str] | None:
        """If the given value is a ``str.format`` or ``str.format_map`` method,
        return a new function than handles sandboxing. This is done at access
        rather than in :meth:`call`, so that calls made without ``call`` are
        also sandboxed.
        """
        if not isinstance(
            value, (types.MethodType, types.BuiltinMethodType)
        ) or value.__name__ not in ("format", "format_map"):
            return None

        f_self: t.Any = value.__self__

        if not isinstance(f_self, str):
            return None

        str_type: type[str] = type(f_self)
        is_format_map = value.__name__ == "format_map"
        formatter: SandboxedFormatter

        if isinstance(f_self, Markup):
            formatter = SandboxedEscapeFormatter(self, escape=f_self.escape)
        else:
            formatter = SandboxedFormatter(self)

        vformat = formatter.vformat

        def wrapper(*args: t.Any, **kwargs: t.Any) -> str:
            if is_format_map:
                if kwargs:
                    raise TypeError("format_map() takes no keyword arguments")

                if len(args) != 1:
                    raise TypeError(
                        f"format_map() takes exactly one argument ({len(args)} given)"
                    )

                kwargs = args[0]
                args = ()

            return str_type(vformat(f_self, args, kwargs))

        return update_wrapper(wrapper, value)

    def call(
        __self,  # noqa: B902
        __context: Context,
        __obj: t.Any,
        *args: t.Any,
        **kwargs: t.Any,
    ) -> t.Any:
        """Call an object from sandboxed code."""

        # the double prefixes are to avoid double keyword argument
        # errors when proxying the call.
        if not __self.is_safe_callable(__obj):
            raise SecurityError(f"{__obj!r} is not safely callable")
        return __context.call(__obj, *args, **kwargs)


class ImmutableSandboxedEnvironment(SandboxedEnvironment):
    """Works exactly like the regular `SandboxedEnvironment` but does not
    permit modifications on the builtin mutable objects `list`, `set`, and
    `dict` by using the :func:`modifies_known_mutable` function.
    """

    def is_safe_attribute(self, obj: t.Any, attr: str, value: t.Any) -> bool:
        if not super().is_safe_attribute(obj, attr, value):
            return False

        return not modifies_known_mutable(obj, attr)


class SandboxedFormatter(Formatter):
    def __init__(self, env: Environment, **kwargs: t.Any) -> None:
        self._env = env
        super().__init__(**kwargs)

    def get_field(
        self, field_name: str, args: t.Sequence[t.Any], kwargs: t.Mapping[str, t.Any]
    ) -> tuple[t.Any, str]:
        first, rest = formatter_field_name_split(field_name)
        obj = self.get_value(first, args, kwargs)
        for is_attr, i in rest:
            if is_attr:
                obj = self._env.getattr(obj, i)
            else:
                obj = self._env.getitem(obj, i)
        return obj, first


class SandboxedEscapeFormatter(SandboxedFormatter, EscapeFormatter):
    pass
