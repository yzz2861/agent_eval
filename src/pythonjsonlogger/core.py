"""Core functionality shared by all JSON loggers"""

### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
import base64
from contextlib import contextmanager
from contextvars import ContextVar, Token
import datetime as datetime_module
import enum
from datetime import datetime, timezone
import logging
import re
import string
import sys
from typing import TypeAlias, Any
from collections.abc import Container, Iterator, Mapping, Sequence
import uuid

## Installed

## Application


### CONSTANTS
### ============================================================================
RESERVED_ATTRS: list[str] = [
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
]
"""Default reserved attributes.

These come from the [default attributes of `LogRecord` objects](http://docs.python.org/library/logging.html#logrecord-attributes).

Note:
    Although considered a constant, this list is dependent on the Python version due to
    different `LogRecord` objects having different attributes in different Python versions.

*Changed in 3.0*: `RESERVED_ATTRS` is now `list[str]` instead of `tuple[str, ...]`.
"""

if sys.version_info >= (3, 12):
    # taskName added in python 3.12
    RESERVED_ATTRS.append("taskName")
    RESERVED_ATTRS.sort()


STYLE_STRING_TEMPLATE_REGEX = re.compile(
    r"\$(?:\$|\{(?P<braced>.+?)\}|(?P<named>[_a-z][_a-z0-9]*))", re.IGNORECASE
)  # $ style
STYLE_PERCENT_REGEX = re.compile(r"%(?:%|\((?P<named>.+?)\))", re.IGNORECASE)  # % style

## Type Aliases
## -----------------------------------------------------------------------------
LogData: TypeAlias = dict[str, Any]
"""Type alias

*Changed in 4.0*: renamed from `LogRecord` to `LogData`
"""

ContextData: TypeAlias = Mapping[str, Any]
"""A request-scoped mapping of correlation fields."""


### CONTEXT
### ============================================================================
log_context: ContextVar[ContextData | None] = ContextVar(
    "pythonjsonlogger.log_context", default=None
)
"""Default [`ContextVar`](https://docs.python.org/3/library/contextvars.html) used for
correlation fields.

Applications can set this directly or pass a different `ContextVar` to a formatter via
`context_var`. Values are copied and sanitized when a log record is formatted, so
mutating the mapping after calling `set` does not change an in-flight record.
"""

# Convenient aliases for callers that prefer a more explicit name.
context: ContextVar[ContextData | None] = log_context
context_var: ContextVar[ContextData | None] = log_context
request_context: ContextVar[ContextData | None] = log_context
correlation_context: ContextVar[ContextData | None] = log_context
CONTEXT_VAR = log_context
CORRELATION_CONTEXT = log_context
REQUEST_CONTEXT = log_context
context_vars: ContextVar[ContextData | None] = log_context
CONTEXT = log_context
trace_context: ContextVar[ContextData | None] = log_context
trace_context_var: ContextVar[ContextData | None] = log_context

_MISSING = object()
_DROP = object()
_CONTEXT_WHOLE = object()
_CONTEXT_ALL = object()

# The snapshot is scoped to a single synchronous `format` call. It is intentionally a
# module-level ContextVar rather than formatter state: formatter instances are shared by
# process-level loggers, while the snapshot belongs to the record being formatted.
_format_context_snapshot: ContextVar[Any] = ContextVar(
    "pythonjsonlogger.format_context_snapshot", default=_MISSING
)

_CONTEXT_DROP_POLICY_NAMES = {"drop", "discard", "ignore", "omit", "skip"}
_CONTEXT_REPLACE_POLICY_NAMES = {"replace", "stringify", "marker"}


def set_log_context(fields: ContextData | None = None, **kwargs: Any) -> Token[ContextData | None]:
    """Set the current task's correlation context.

    Passing `None` clears the context for the current context/task. The returned token
    can be used with [`reset_log_context`][pythonjsonlogger.core.reset_log_context].
    """
    if fields is None and not kwargs:
        return log_context.set(None)
    if fields is not None and not isinstance(fields, Mapping):
        raise TypeError("log context must be a mapping or None")
    value = dict(fields) if fields is not None else {}
    value.update(kwargs)
    return log_context.set(value)


def get_log_context() -> dict[str, Any] | None:
    """Return a shallow copy of the current task's correlation context."""
    value = log_context.get(None)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return None
    try:
        return dict(value)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def reset_log_context(token: Token[ContextData | None]) -> None:
    """Restore the context that was active before the matching `set` call."""
    log_context.reset(token)


def update_log_context(**fields: Any) -> Token[ContextData | None]:
    """Merge fields into the current task's correlation context."""
    current = log_context.get(None)
    if isinstance(current, Mapping):
        try:
            updated = dict(current)
        except Exception:  # pylint: disable=broad-exception-caught
            updated = {}
    else:
        updated = {}
    updated.update(fields)
    return log_context.set(updated)


def clear_log_context() -> Token[ContextData | None]:
    """Clear the current task's correlation context and return a reset token."""
    return log_context.set(None)


@contextmanager
def bind_log_context(fields: ContextData | None = None, **kwargs: Any) -> Iterator[None]:
    """Bind correlation fields for the duration of a block."""
    merged: dict[str, Any] = {}
    if fields is not None:
        merged.update(fields)
    merged.update(kwargs)
    token = update_log_context(**merged)
    try:
        yield
    finally:
        reset_log_context(token)


# Common short names. The context manager is deliberately named `bind_*` so these
# names can continue to refer to the ContextVar itself.
set_context = set_log_context
get_context = get_log_context
reset_context = reset_log_context
update_context = update_log_context
clear_context = clear_log_context
use_log_context = bind_log_context
bind_context = bind_log_context
bind_correlation_context = bind_log_context
context_scope = bind_log_context
log_context_binding = bind_log_context

set_correlation_context = set_log_context
get_correlation_context = get_log_context
reset_correlation_context = reset_log_context
update_correlation_context = update_log_context
clear_correlation_context = clear_log_context


def _safe_type_name(value: Any) -> str:
    try:
        return type(value).__name__
    except Exception:  # pylint: disable=broad-exception-caught
        return "object"


def _context_fallback(
    value: Any,
    reason: str,
    policy: str | Any,
) -> Any:
    """Return the configured fallback for an unsafe context value."""
    if callable(policy):
        try:
            return policy(value, reason)
        except TypeError:
            try:
                return policy(value)
            except Exception:  # pylint: disable=broad-exception-caught
                return _DROP
        except Exception:  # pylint: disable=broad-exception-caught
            return _DROP
    if isinstance(policy, str) and policy.lower() in _CONTEXT_REPLACE_POLICY_NAMES:
        return f"<{reason}:{_safe_type_name(value)}>"
    return _DROP


def _sanitize_context_value(
    value: Any,
    *,
    depth: int,
    max_depth: int,
    max_items: int,
    policy: str | Any,
    default: Any,
    seen: set[int],
    allow_default: bool = True,
) -> Any:
    """Recursively copy a context value into JSON-safe primitives.

    The function never calls `str`/`repr` on arbitrary objects. Unsafe values are
    dropped or replaced according to `policy`.
    """
    if value is None or isinstance(value, (str, bool, int, float)):
        return value

    if isinstance(value, (bytes, bytearray)):
        try:
            return base64.urlsafe_b64encode(bytes(value)).decode("utf8")
        except Exception:  # pylint: disable=broad-exception-caught
            return _context_fallback(value, "unserializable", policy)

    if isinstance(value, uuid.UUID):
        return str(value)

    if isinstance(value, (datetime_module.datetime, datetime_module.date, datetime_module.time)):
        try:
            return value.isoformat()
        except Exception:  # pylint: disable=broad-exception-caught
            return _context_fallback(value, "unserializable", policy)

    if isinstance(value, enum.Enum):
        return _sanitize_context_value(
            value.value,
            depth=depth,
            max_depth=max_depth,
            max_items=max_items,
            policy=policy,
            default=default,
            seen=seen,
            allow_default=False,
        )

    if isinstance(value, Mapping):
        if depth > max_depth:
            return _context_fallback(value, "max-depth", policy)
        identity = id(value)
        if identity in seen:
            return _context_fallback(value, "circular-reference", policy)
        seen.add(identity)
        result: dict[str, Any] = {}
        saw_entry = False
        processed = 0
        try:
            for key, item in value.items():
                if processed >= max_items:
                    break
                processed += 1
                saw_entry = True
                if not isinstance(key, str):
                    continue
                sanitized = _sanitize_context_value(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    policy=policy,
                    default=default,
                    seen=seen,
                )
                if sanitized is not _DROP:
                    result[key] = sanitized
        except Exception:  # pylint: disable=broad-exception-caught
            return _context_fallback(value, "unserializable", policy)
        finally:
            seen.discard(identity)
        if saw_entry and not result:
            return _DROP
        return result

    if isinstance(value, (list, tuple)):
        if depth > max_depth:
            return _context_fallback(value, "max-depth", policy)
        identity = id(value)
        if identity in seen:
            return _context_fallback(value, "circular-reference", policy)
        seen.add(identity)
        result_items: list[Any] = []
        try:
            for item in value[:max_items]:
                sanitized = _sanitize_context_value(
                    item,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    policy=policy,
                    default=default,
                    seen=seen,
                )
                if sanitized is not _DROP:
                    result_items.append(sanitized)
        except Exception:  # pylint: disable=broad-exception-caught
            return _context_fallback(value, "unserializable", policy)
        finally:
            seen.discard(identity)
        if value and not result_items:
            return _DROP
        return result_items

    if allow_default and callable(default):
        try:
            converted = default(value)
        except Exception:  # pylint: disable=broad-exception-caught
            converted = _DROP
        if converted is not _DROP and converted is not value:
            sanitized = _sanitize_context_value(
                converted,
                depth=depth,
                max_depth=max_depth,
                max_items=max_items,
                policy=policy,
                default=default,
                seen=seen,
                allow_default=False,
            )
            if sanitized is not _DROP:
                return sanitized

    return _context_fallback(value, "unserializable", policy)


def sanitize_context(
    context_data: Any,
    *,
    policy: str | Any = "drop",
    default: Any = None,
    max_depth: int = 4,
    max_items: int = 32,
) -> dict[str, Any]:
    """Return a JSON-safe, detached copy of a context mapping.

    Non-mapping roots are ignored. Nested mappings deeper than `max_depth`, values
    with circular references, non-string keys, and unsupported objects are dropped by
    default. Set `policy="replace"` (or provide a callable policy) to emit a safe
    marker instead. `default` may be a callable used to convert otherwise unsupported
    objects. This function never raises for malformed context data.
    """
    if not isinstance(context_data, Mapping):
        return {}
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    if max_items < 1:
        raise ValueError("max_items must be >= 1")
    sanitized = _sanitize_context_value(
        context_data,
        depth=0,
        max_depth=max_depth,
        max_items=max_items,
        policy=policy,
        default=default,
        seen=set(),
    )
    return sanitized if isinstance(sanitized, dict) else {}


sanitize_log_context = sanitize_context


### FUNCTIONS
### ============================================================================
def merge_record_extra(
    record: logging.LogRecord,
    target: dict[Any, Any],
    reserved: Container[str],
    rename_fields: dict[str, str] | None = None,
) -> dict[Any, Any]:
    """
    Merges extra attributes from LogRecord object into target dictionary

    Args:
        record: logging.LogRecord
        target: dict to update
        reserved: dict or list with reserved keys to skip
        rename_fields: an optional dict, used to rename field names in the output.
            e.g. Rename `levelname` to `log.level`: `{'levelname': 'log.level'}`

    *Changed in 3.1*: `reserved` is now `Container[str]`.
    """
    if rename_fields is None:
        rename_fields = {}
    for key, value in record.__dict__.items():
        # this allows to have numeric keys
        if key not in reserved and not (hasattr(key, "startswith") and key.startswith("_")):
            target[rename_fields.get(key, key)] = value
    return target


### CLASSES
### ============================================================================
class BaseJsonFormatter(logging.Formatter):
    """Base class for all formatters

    Must not be used directly.

    *New in 3.1*
    """

    _style: logging.PercentStyle | str  # type: ignore[assignment]

    ## Parent Methods
    ## -------------------------------------------------------------------------
    # pylint: disable=too-many-arguments,super-init-not-called
    def __init__(
        self,
        fmt: str | Sequence[str] | None = None,
        datefmt: str | None = None,
        style: str = "%",
        validate: bool = True,
        *,
        prefix: str = "",
        rename_fields: dict[str, str] | None = None,
        rename_fields_keep_missing: bool = False,
        static_fields: dict[str, Any] | None = None,
        reserved_attrs: Sequence[str] | None = None,
        timestamp: bool | str = False,
        defaults: dict[str, Any] | None = None,
        exc_info_as_array: bool = False,
        stack_info_as_array: bool = False,
        context_fields: Mapping[str, Any] | Sequence[str] | bool | None = None,
        context_var: ContextVar[Any] | None = None,
        context: ContextVar[Any] | Mapping[str, Any] | Sequence[str] | bool | None = None,
        context_vars: Mapping[str, ContextVar[Any]] | None = None,
        context_keys: Mapping[str, Any] | Sequence[str] | bool | None = None,
        correlation_fields: Mapping[str, Any] | Sequence[str] | bool | None = None,
        correlation_keys: Mapping[str, Any] | Sequence[str] | bool | None = None,
        context_key: str | None = None,
        contextvars: Mapping[str, Any] | Sequence[str] | bool | None = None,
        context_policy: str | Any = "drop",
        context_on_error: str | Any | None = None,
        on_context_error: str | Any | None = None,
        context_default: Any = None,
        context_max_depth: int = 4,
        context_max_items: int = 32,
    ) -> None:
        """
        Args:
            fmt: String format or `Sequence` of field names of fields to log.
            datefmt: format to use when formatting `asctime` field
            style: how to extract log fields from `fmt`. Ignored if `fmt` is a `Sequence[str]`.
            validate: validate `fmt` against style, if implementing a custom `style` you
                must set this to `False`. Ignored if `fmt` is a `Sequence[str]`.
            defaults: a dictionary containing default fields that are added before all other fields and
                may be overridden. The supplied fields are still subject to `rename_fields`.
            prefix: an optional string prefix added at the beginning of
                the formatted string
            rename_fields: an optional dict, used to rename field names in the output.
                Rename `message` to `@message`: `{'message': '@message'}`
            rename_fields_keep_missing: When renaming fields, include missing fields in the output.
            static_fields: an optional dict, used to add fields with static values to all logs
            reserved_attrs: an optional list of fields that will be skipped when
                outputting json log record. Pass a list or tuple, not a string.
                Defaults to [all log record attributes][pythonjsonlogger.core.RESERVED_ATTRS].
            timestamp: an optional string/boolean field to add a timestamp when
                outputting the json log record. If string is passed, timestamp will be added
                to log record using string as key. If True boolean is passed, timestamp key
                will be "timestamp". Defaults to False/off.
            exc_info_as_array: break the exc_info into a list of lines based on line breaks,
                including cached exception text in records received over a transport.
            stack_info_as_array: break the stack_info into a list of lines based on line breaks.
            context_fields: correlation fields to read from a context mapping. May be a
                sequence of context keys, a mapping of `output_field -> context_key`, or
                `True`/`"*"` to include every context key. The fields are snapshotted
                once per record and never stored on the formatter.
            context_var: the `ContextVar` containing the context mapping. Defaults to
                [`log_context`][pythonjsonlogger.core.log_context].
            context: alias for `context_var` when a `ContextVar` is supplied, or for
                `context_fields` when a field configuration is supplied.
            context_vars: an optional mapping of `output_field -> ContextVar` for
                per-field context values.
            context_policy: how unsafe context values are handled: `"drop"` (default)
                or `"replace"`. A callable receives `(value, reason)` and may return a
                replacement value.
            context_on_error: alias for `context_policy`.
            context_default: optional callable used to convert otherwise unsupported
                context objects. The result is still sanitized.
            context_max_depth: maximum nesting depth for mappings/sequences in context
                values. Defaults to 4.
            context_max_items: maximum number of items retained per mapping/sequence.
                Defaults to 32.

        *Changed in 3.1*:

        - you can now use custom values for style by setting validate to `False`.
          The value is stored in `self._style` as a string. The `parse` method will need to be
          overridden in order to support the new style.
        - Renaming fields now preserves the order that fields were added in and avoids adding
          missing fields. The original behaviour, missing fields have a value of `None`, is still
          available by setting `rename_fields_keep_missing` to `True`.

        *Changed in 3.2*: `defaults` argument is no longer ignored.

        *Added in 3.3*: `exc_info_as_array` and `stack_info_as_array` options are added.

        *Added in 4.0*:

        - `fmt` now supports comma separated lists (`style=","`). Note that this style is specific
          to `python-json-logger` and thus care should be taken to not to pass this format to other
          logging Formatter implementations.
        - `fmt` now supports sequences of strings (e.g. lists and tuples) of field names.

        *Added in 4.3*: `context_fields` provides request-scoped correlation fields
        backed by `contextvars`.
        """
        ## logging.Formatter compatibility
        ## ---------------------------------------------------------------------
        if fmt is None or isinstance(fmt, str):
            if style in logging._STYLES:
                _style = logging._STYLES[style][0](fmt)  # type: ignore[operator]
                if validate:
                    _style.validate()
                self._style = _style
                self._fmt = _style._fmt

            elif style == "," or not validate:
                self._style = style
                self._fmt = fmt
                # TODO: Validate comma format

            else:
                raise ValueError("Style must be one of: '%{$,'")

            self._required_fields = self.parse()

        # Note: we do this check second as string is still a Sequence[str]
        elif isinstance(fmt, Sequence):
            self._style = "__sequence__"
            self._fmt = str(fmt)
            self._required_fields = list(fmt)

        self.datefmt = datefmt

        ## JSON Logging specific
        ## ---------------------------------------------------------------------
        self.prefix = prefix

        # Recreate these dicts so DictConfigurator `ext://` / `cfg://` prefixes
        # are converted (ConvertingDict only converts on `__getitem__`) and so
        # later mutation of the caller's dict cannot change formatter state.
        # For more details see: https://github.com/nhairs/python-json-logger/pull/45
        self.rename_fields = (
            {key: rename_fields[key] for key in rename_fields} if rename_fields is not None else {}
        )
        self.static_fields = (
            {key: static_fields[key] for key in static_fields} if static_fields is not None else {}
        )
        self.defaults = {key: defaults[key] for key in defaults} if defaults is not None else {}

        ## Context correlation
        ## ---------------------------------------------------------------------
        if context_key is not None:
            if context_fields is not None:
                raise TypeError("context_fields and context_key cannot both be supplied")
            context_fields = [context_key]
        if context_keys is not None:
            if context_fields is not None:
                raise TypeError("context_fields and context_keys cannot both be supplied")
            context_fields = context_keys
        if correlation_fields is not None:
            if context_fields is not None:
                raise TypeError("context_fields and correlation_fields cannot both be supplied")
            context_fields = correlation_fields
        if correlation_keys is not None:
            if context_fields is not None:
                raise TypeError("context_fields and correlation_keys cannot both be supplied")
            context_fields = correlation_keys
        if contextvars is not None:
            if context_fields is not None:
                raise TypeError("context_fields and contextvars cannot both be supplied")
            context_fields = contextvars

        source_was_explicit = context_var is not None or isinstance(context, ContextVar)
        if context_var is not None and context is not None and isinstance(context, ContextVar):
            raise TypeError("context_var and context cannot both supply a ContextVar")
        if context_vars is not None:
            if context_fields is not None or (
                context is not None and not isinstance(context, ContextVar)
            ):
                raise TypeError("context_vars cannot be combined with context_fields or context")
            context_fields = context_vars

        if isinstance(context, ContextVar):
            if context_var is None:
                context_var = context
        elif context is not None:
            if context_fields is not None:
                raise TypeError("context_fields and context cannot both be supplied")
            context_fields = context

        if source_was_explicit and context_fields is None:
            context_fields = True

        self.context_var: ContextVar[Any] = context_var if context_var is not None else log_context
        if not isinstance(self.context_var, ContextVar):
            raise TypeError("context_var must be a ContextVar")

        policy = context_on_error if context_on_error is not None else context_policy
        if on_context_error is not None:
            if context_on_error is not None:
                raise TypeError("context_on_error and on_context_error cannot both be supplied")
            policy = on_context_error
        if policy is None:
            policy = "drop"
        if isinstance(policy, str):
            normalized_policy = policy.lower()
            if normalized_policy in _CONTEXT_DROP_POLICY_NAMES:
                policy = "drop"
            elif normalized_policy in _CONTEXT_REPLACE_POLICY_NAMES:
                policy = "replace"
            else:
                raise ValueError("context_policy must be 'drop', 'replace', or a callable")
        elif not callable(policy):
            raise TypeError("context_policy must be 'drop', 'replace', or a callable")

        if context_default is not None and not callable(context_default):
            raise TypeError("context_default must be callable")
        if context_max_depth < 0:
            raise ValueError("context_max_depth must be >= 0")
        if context_max_items < 1:
            raise ValueError("context_max_items must be >= 1")

        self.context_policy = policy
        self.context_on_error = policy
        self.context_default = context_default
        self.context_max_depth = context_max_depth
        self.context_max_items = context_max_items
        self._context_bindings = self._normalize_context_fields(
            context_fields, default_var=self.context_var
        )
        self._has_context = bool(self._context_bindings)

        # Public, config-only attributes. Request values live in the per-format
        # snapshot and are never assigned to the formatter instance.
        if isinstance(context_fields, Mapping):
            self.context_fields = {key: context_fields[key] for key in context_fields}
        elif isinstance(context_fields, Sequence) and not isinstance(context_fields, str):
            self.context_fields = list(context_fields)
        else:
            self.context_fields = context_fields

        self.rename_fields_keep_missing = rename_fields_keep_missing
        if reserved_attrs is None:
            reserved_attrs = RESERVED_ATTRS
        elif isinstance(reserved_attrs, str):
            raise TypeError("reserved_attrs must be a sequence of field names, not a string")
        self.reserved_attrs = set(reserved_attrs)
        self.timestamp = timestamp

        self._skip_fields = set(self._required_fields)
        self._skip_fields.update(self.reserved_attrs)
        self.exc_info_as_array = exc_info_as_array
        self.stack_info_as_array = stack_info_as_array
        return

    def usesTime(self) -> bool:
        """Return whether the parsed format fields include `asctime`."""
        return "asctime" in self._required_fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a log record and serializes to json

        When `record.msg` is a `dict`, adding `exc_info` and `stack_info` does not
        modify the caller's dict.

        Args:
            record: the record to format

        *Changed in 4.2.0*: a `dict` `record.msg` is copied instead of modified
        in place.

        *Changed in 4.3*: correlation fields are snapshotted once at the start of
        formatting. The snapshot is local to this call and is never stored on the
        formatter instance.
        """
        context_snapshot = self._snapshot_context()
        context_token = _format_context_snapshot.set(context_snapshot)
        try:
            message_dict: dict[str, Any] = {}
            # TODO: logging.LogRecord.msg and logging.LogRecord.message in typeshed
            #        are always type of str. We shouldn't need to override that.
            if isinstance(record.msg, dict):
                message_dict = record.msg.copy()
                record.message = ""
            else:
                record.message = record.getMessage()

            # only format time if needed
            if "asctime" in self._required_fields:
                record.asctime = self.formatTime(record, self.datefmt)

            # Display formatted exception, but allow overriding it in the
            # user-supplied dict.
            if record.exc_info and not message_dict.get("exc_info"):
                message_dict["exc_info"] = self.formatException(record.exc_info)
            if not message_dict.get("exc_info") and record.exc_text:
                message_dict["exc_info"] = (
                    record.exc_text.splitlines() if self.exc_info_as_array else record.exc_text
                )

            # Display formatted record of stack frames
            # default format is a string returned from :func:`traceback.print_stack`
            if record.stack_info and not message_dict.get("stack_info"):
                message_dict["stack_info"] = self.formatStack(record.stack_info)

            log_data: LogData = {}
            self.add_fields(log_data, record, message_dict)
            log_data = self.process_log_record(log_data)

            return self.serialize_log_record(log_data)
        finally:
            _format_context_snapshot.reset(context_token)

    def _normalize_context_fields(
        self,
        fields: Mapping[str, Any] | Sequence[str] | bool | None,
        *,
        default_var: ContextVar[Any],
    ) -> tuple[tuple[str, Any, ContextVar[Any]], ...]:
        """Normalize the public context configuration into immutable bindings."""
        if fields is None or fields is False:
            return ()
        if fields is True or fields == "*":
            return (("*", _CONTEXT_ALL, default_var),)

        if isinstance(fields, str):
            field_items: Sequence[Any] = [fields]
        elif isinstance(fields, Mapping):
            # Copy by indexing so DictConfigurator conversion prefixes are evaluated
            # and later mutation of the caller's mapping cannot affect this formatter.
            bindings: list[tuple[str, Any, ContextVar[Any]]] = []
            for output_field in fields:
                if not isinstance(output_field, str):
                    raise TypeError("context field names must be strings")
                spec = fields[output_field]
                if isinstance(spec, ContextVar):
                    bindings.append((output_field, _CONTEXT_WHOLE, spec))
                elif spec is None:
                    bindings.append((output_field, output_field, default_var))
                elif isinstance(spec, str):
                    bindings.append((output_field, spec, default_var))
                else:
                    raise TypeError(
                        "context_fields values must be context keys or ContextVar objects"
                    )
            return tuple(bindings)
        elif isinstance(fields, Sequence):
            field_items = list(fields)
        else:
            raise TypeError("context_fields must be a sequence, mapping, True, False, or None")

        bindings = []
        for output_field in field_items:
            if isinstance(output_field, ContextVar):
                bindings.append((output_field.name, _CONTEXT_WHOLE, output_field))
                continue
            if not isinstance(output_field, str):
                raise TypeError("context field names must be strings")
            if output_field == "*":
                bindings.append((output_field, _CONTEXT_ALL, default_var))
            else:
                bindings.append((output_field, output_field, default_var))
        return tuple(bindings)

    def _snapshot_context(self) -> dict[str, Any]:
        """Copy and sanitize the current context exactly once for this record."""
        if not self._has_context:
            return {}

        snapshot: dict[str, Any] = {}
        values_by_var: dict[int, Any] = {}
        sanitized_by_var: dict[int, dict[str, Any]] = {}
        for output_field, source, value_var in self._context_bindings:
            try:
                identity = id(value_var)
                if identity not in values_by_var:
                    values_by_var[identity] = value_var.get(None)
                raw_value = values_by_var[identity]
                if raw_value is None:
                    continue

                if source is _CONTEXT_ALL:
                    if identity not in sanitized_by_var:
                        sanitized_by_var[identity] = sanitize_context(
                            raw_value,
                            policy=self.context_policy,
                            default=self.context_default,
                            max_depth=self.context_max_depth,
                            max_items=self.context_max_items,
                        )
                    sanitized = sanitized_by_var[identity]
                    for key, value in sanitized.items():
                        snapshot[key] = value
                    continue

                if isinstance(raw_value, Mapping):
                    if identity not in sanitized_by_var:
                        sanitized_by_var[identity] = sanitize_context(
                            raw_value,
                            policy=self.context_policy,
                            default=self.context_default,
                            max_depth=self.context_max_depth,
                            max_items=self.context_max_items,
                        )
                    sanitized_mapping = sanitized_by_var[identity]
                    if source is _CONTEXT_WHOLE:
                        # A per-field ContextVar usually holds the value itself, but
                        # accepting a context mapping here makes both styles ergonomic.
                        value = (
                            sanitized_mapping[output_field]
                            if output_field in sanitized_mapping
                            else sanitized_mapping
                        )
                    elif source in sanitized_mapping:
                        value = sanitized_mapping[source]
                    else:
                        continue
                elif (
                    source is _CONTEXT_WHOLE
                    or source == output_field
                    or len(self._context_bindings) == 1
                ):
                    value = _sanitize_context_value(
                        raw_value,
                        depth=0,
                        max_depth=self.context_max_depth,
                        max_items=self.context_max_items,
                        policy=self.context_policy,
                        default=self.context_default,
                        seen=set(),
                    )
                else:
                    continue

                if value is not _DROP:
                    snapshot[output_field] = value
            except Exception:  # pylint: disable=broad-exception-caught
                # Context data must never make logging fail or block a request.
                continue
        return snapshot

    def _merge_context_fields(self, log_data: LogData, snapshot: Mapping[str, Any]) -> None:
        for key, value in snapshot.items():
            log_data[self._get_rename(key)] = value

    def set_context(
        self, fields: ContextData | None = None, **kwargs: Any
    ) -> Token[ContextData | None]:
        """Set correlation fields on the formatter's configured context variable."""
        if fields is None and not kwargs:
            return self.context_var.set(None)
        if fields is not None and not isinstance(fields, Mapping):
            raise TypeError("log context must be a mapping or None")
        value = dict(fields) if fields is not None else {}
        value.update(kwargs)
        return self.context_var.set(value)

    def get_context(self) -> dict[str, Any] | None:
        """Return a shallow copy of the configured context variable's value."""
        value = self.context_var.get(None)
        if not isinstance(value, Mapping):
            return None
        try:
            return dict(value)
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def reset_context(self, token: Token[ContextData | None]) -> None:
        """Reset the configured context variable using a previous token."""
        self.context_var.reset(token)

    def update_context(self, **fields: Any) -> Token[ContextData | None]:
        """Merge fields into the configured context variable."""
        current = self.context_var.get(None)
        updated = dict(current) if isinstance(current, Mapping) else {}
        updated.update(fields)
        return self.context_var.set(updated)

    def clear_context(self) -> Token[ContextData | None]:
        """Clear the configured context variable and return a reset token."""
        return self.context_var.set(None)

    @contextmanager
    def bind_context(self, fields: ContextData | None = None, **kwargs: Any) -> Iterator[None]:
        """Bind correlation fields for the duration of a block."""
        merged: dict[str, Any] = {}
        if fields is not None:
            merged.update(fields)
        merged.update(kwargs)
        token = self.update_context(**merged)
        try:
            yield
        finally:
            self.reset_context(token)

    ## JSON Formatter Specific Methods
    ## -------------------------------------------------------------------------
    def parse(self) -> list[str]:
        """Parses format string looking for substitutions

        This method is responsible for returning a list of fields (as strings)
        to include in all log messages.

        You can support custom styles by overriding this method.

        Returns:
            list of fields to be extracted and serialized
        """
        if self._fmt is None:
            return []

        if isinstance(self._style, str):
            if self._style == "__sequence__":
                raise RuntimeError("Must not call parse when fmt is a sequence of strings")

            if self._style == ",":
                return [field.strip() for field in self._fmt.split(",") if field.strip()]

            raise ValueError(f"Style {self._style!r} is not supported")

        if isinstance(self._style, logging.StringTemplateStyle):
            # String templates support both ${name} and $name, and $$ is an escaped literal
            return [
                match.group("braced") or match.group("named")
                for match in STYLE_STRING_TEMPLATE_REGEX.finditer(self._fmt)
                if match.group("braced") or match.group("named")
            ]

        if isinstance(self._style, logging.StrFormatStyle):
            return [
                field_name
                for _, field_name, _, _ in string.Formatter().parse(self._fmt)
                if field_name
            ]

        if isinstance(self._style, logging.PercentStyle):
            # PercentStyle is parent class of StringTemplateStyle and StrFormatStyle
            # so it must be checked last.
            return [
                match.group("named")
                for match in STYLE_PERCENT_REGEX.finditer(self._fmt)
                if match.group("named")
            ]

        raise ValueError(f"Style {self._style!r} is not supported")

    def serialize_log_record(self, log_data: LogData) -> str:
        """Returns the final representation of the data to be logged

        Args:
            log_data: the data

        *Changed in 4.0*: `log_record` renamed to `log_data`
        """
        return self.prefix + self.jsonify_log_record(log_data)

    def add_fields(
        self,
        log_data: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        """Extract fields from a LogRecord for logging

        This method can be overridden to implement custom logic for adding fields.

        Args:
            log_data: data that will be logged
            record: the record to extract data from
            message_dict: dictionary that was logged instead of a message. e.g
                `logger.info({"is_this_message_dict": True})`

        *Changed in 4.0*: `log_record` renamed to `log_data`
        """
        for field in self.defaults:
            log_data[self._get_rename(field)] = self.defaults[field]

        for field in self._required_fields:
            log_data[self._get_rename(field)] = record.__dict__.get(field)

        context_snapshot = _format_context_snapshot.get()
        if context_snapshot is _MISSING:
            # Support direct calls to `add_fields` outside `format` without storing
            # request state on the formatter.
            context_snapshot = self._snapshot_context()
        self._merge_context_fields(log_data, context_snapshot)

        for data_dict in [self.static_fields, message_dict]:
            for key, value in data_dict.items():
                log_data[self._get_rename(key)] = value

        merge_record_extra(
            record,
            log_data,
            reserved=self._skip_fields,
            rename_fields=self.rename_fields,
        )

        if self.timestamp:
            key = self.timestamp if isinstance(self.timestamp, str) else "timestamp"
            log_data[self._get_rename(key)] = datetime.fromtimestamp(
                record.created, tz=timezone.utc
            )

        if self.rename_fields_keep_missing:
            for field in self.rename_fields.values():
                if field not in log_data:
                    log_data[field] = None
        return

    def _get_rename(self, key: str) -> str:
        return self.rename_fields.get(key, key)

    # Child Methods
    # ..........................................................................
    def jsonify_log_record(self, log_data: LogData) -> str:
        """Convert the log data into a JSON string.

        Child classes MUST override this method.

        Args:
            log_data: the data to serialize

        *Changed in 4.0*: `log_record` renamed to `log_data`
        """
        raise NotImplementedError()

    def process_log_record(self, log_data: LogData) -> LogData:
        """Custom processing of the data to be logged.

        Child classes can override this method to alter the log record before it
        is serialized.

        Args:
            log_data: incoming data

        *Changed in 4.0*: `log_record` renamed to `log_data`
        """
        return log_data

    def formatException(self, ei) -> str | list[str]:  # type: ignore[override]
        """Format and return the specified exception information.

        If exc_info_as_array is set to True, This method returns an array of strings.
        """
        exception_info_str = super().formatException(ei)
        return exception_info_str.splitlines() if self.exc_info_as_array else exception_info_str

    def formatStack(self, stack_info) -> str | list[str]:  # type: ignore[override]
        """Format and return the specified stack information.

        If stack_info_as_array is set to True, This method returns an array of strings.
        """
        stack_info_str = super().formatStack(stack_info)
        return stack_info_str.splitlines() if self.stack_info_as_array else stack_info_str
