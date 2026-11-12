"""Core functionality shared by all JSON loggers"""

### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
import dataclasses
from datetime import datetime, timezone
import logging
import re
import string
import sys
from typing import TypeAlias, Any
from collections.abc import Container, Sequence

## Installed

## Application
from .exception import ProjectionViolationError


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

TRUNCATED_VALUE_MARKER = "__truncated__"
"""Marker appended to (or used as) values truncated by a projection policy."""

DEFAULT_CIRCULAR_MARKER = "__circular_reference__"
"""Default marker used to replace circular references in projected values."""


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


def projection_placeholder(reason: str) -> str:
    """Return a JSON-safe placeholder value explaining why data was removed.

    Args:
        reason: short machine readable reason, e.g. 'max_depth_exceeded'
    """
    return f"{TRUNCATED_VALUE_MARKER}:{reason}"


def sanitize_projection_value(
    value: Any,
    policy: FieldProjectionPolicy,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> Any:
    """Bound a value so it is safe to serialize under a projection policy.

    Enforces maximum nesting depth, maximum value size (in bytes), maximum
    collection/mapping size, and replaces circular references with a stable
    marker. Values of types not handled here are returned unchanged so that
    custom json_default functions and encoders still apply.

    Args:
        value: the value to sanitize
        policy: the projection policy to enforce

    Raises:
        ProjectionViolationError: if policy.on_violation is 'reject' and
            the value exceeds a configured bound.
    """
    if _seen is None:
        _seen = set()

    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) <= policy.max_value_bytes:
            return value
        if policy.on_violation == "reject":
            raise ProjectionViolationError(
                f"string value exceeds max_value_bytes ({policy.max_value_bytes})"
            )
        keep = max(policy.max_value_bytes - len(TRUNCATED_VALUE_MARKER), 0)
        return encoded[:keep].decode("utf-8", errors="ignore") + TRUNCATED_VALUE_MARKER

    if isinstance(value, (bytes, bytearray)):
        if len(value) <= policy.max_value_bytes:
            return value
        if policy.on_violation == "reject":
            raise ProjectionViolationError(
                f"bytes value exceeds max_value_bytes ({policy.max_value_bytes})"
            )
        return value[: policy.max_value_bytes]

    if isinstance(value, dict):
        if _depth >= policy.max_depth:
            return _container_violation(policy, "max_depth_exceeded")
        marker = _circular_marker_if_seen(value, policy, _seen)
        if marker is not None:
            return marker
        try:
            result: dict[Any, Any] = {}
            truncated = False
            for index, (key, item) in enumerate(value.items()):
                if index >= policy.max_items:
                    truncated = True
                    break
                result[key] = sanitize_projection_value(item, policy, _depth + 1, _seen)
            if truncated and TRUNCATED_VALUE_MARKER not in result:
                result[TRUNCATED_VALUE_MARKER] = projection_placeholder("max_items_exceeded")
            return result
        finally:
            _seen.discard(id(value))

    if isinstance(value, (list, tuple, set, frozenset)):
        if _depth >= policy.max_depth:
            return _container_violation(policy, "max_depth_exceeded")
        marker = _circular_marker_if_seen(value, policy, _seen)
        if marker is not None:
            return marker
        try:
            items = [
                sanitize_projection_value(item, policy, _depth + 1, _seen)
                for item in list(value)[: policy.max_items]
            ]
            if len(value) > policy.max_items:
                items.append(projection_placeholder("max_items_exceeded"))
            return items
        finally:
            _seen.discard(id(value))

    return value


def _container_violation(policy: FieldProjectionPolicy, reason: str) -> Any:
    if policy.on_violation == "reject":
        raise ProjectionViolationError(f"value violates projection policy: {reason}")
    return projection_placeholder(reason)


def _circular_marker_if_seen(
    value: Any, policy: FieldProjectionPolicy, seen: set[int]
) -> str | None:
    if id(value) in seen:
        return policy.circular_marker
    seen.add(id(value))
    return None


### CLASSES
### ============================================================================
@dataclasses.dataclass(frozen=True)
class FieldProjectionPolicy:
    """Explicit policy controlling which fields may appear in JSON output.

    When a policy is attached to a formatter, the output key set becomes a
    security boundary: only required fields (from `fmt`) and explicitly
    allowed extras, message-dict keys, static fields, and defaults are
    emitted. `rename_fields` is applied *after* projection, so a forbidden
    field cannot re-enter the output by being renamed to an allowed name.

    Values are bounded so the serialized record stays parseable and small:
    nesting depth, per-value size, per-record size, and collection size are
    all limited, and circular references are replaced with a stable marker.
    """

    allowed_extra_fields: Container[str] = frozenset()
    """Record extra attributes (from `logger.info(..., extra=...)`) allowed in the output."""

    allowed_message_keys: Container[str] = frozenset()
    """Keys allowed from a dict logged as the message (including `exc_info` / `stack_info`)."""

    allowed_static_fields: Container[str] = frozenset()
    """`static_fields` entries allowed in the output."""

    allowed_default_fields: Container[str] = frozenset()
    """`defaults` entries allowed in the output."""

    max_depth: int = 16
    """Maximum nesting depth for container values."""

    max_value_bytes: int = 64 * 1024
    """Maximum size in bytes of a single string or bytes value."""

    max_record_bytes: int = 1024 * 1024
    """Maximum size in bytes of the serialized record."""

    max_items: int = 256
    """Maximum number of elements kept in a single collection or mapping."""

    circular_marker: str = DEFAULT_CIRCULAR_MARKER
    """Stable marker used to replace circular references."""

    on_violation: str = "placeholder"
    """How to handle bound violations: 'placeholder' replaces the offending
    value with a reason placeholder, 'reject' raises `ProjectionViolationError`."""

    def __post_init__(self) -> None:
        if self.on_violation not in ("placeholder", "reject"):
            raise ValueError("on_violation must be 'placeholder' or 'reject'")
        for name in (
            "allowed_extra_fields",
            "allowed_message_keys",
            "allowed_static_fields",
            "allowed_default_fields",
        ):
            if isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a container of field names, not a string")
        for name in ("max_depth", "max_value_bytes", "max_record_bytes", "max_items"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")
        return


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
        field_projection: FieldProjectionPolicy | None = None,
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
            field_projection: an optional `FieldProjectionPolicy` that explicitly controls
                which fields may appear in the output and bounds serialized values.
                Defaults to `None` which preserves the legacy behaviour of merging
                all record extras.

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
        self.field_projection = field_projection
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
        """
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
        if self.field_projection is not None:
            self._add_fields_projected(log_data, record, message_dict, self.field_projection)
            return

        for field in self.defaults:
            log_data[self._get_rename(field)] = self.defaults[field]

        for field in self._required_fields:
            log_data[self._get_rename(field)] = record.__dict__.get(field)

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

    def _add_fields_projected(
        self,
        log_data: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
        policy: FieldProjectionPolicy,
    ) -> None:
        """Extract fields from a LogRecord under an explicit projection policy.

        Only fields allowed by the policy are emitted, and `rename_fields` is
        applied after projection so forbidden fields cannot be renamed back
        into the output. Category priority is deterministic (highest first):
        required fields, static fields, message dict, record extras, defaults.
        A lower-priority field never overwrites a key already emitted by a
        higher-priority category.
        """
        allowed_keys = (
            set(self._required_fields)
            | set(policy.allowed_extra_fields)
            | set(policy.allowed_message_keys)
            | set(policy.allowed_static_fields)
            | set(policy.allowed_default_fields)
        )

        for field in self._required_fields:
            log_data[self._get_rename(field)] = sanitize_projection_value(
                record.__dict__.get(field), policy
            )

        for key, value in self.static_fields.items():
            if key in policy.allowed_static_fields:
                self._set_projected_field(log_data, key, value, policy)

        for key, value in message_dict.items():
            if key in policy.allowed_message_keys:
                self._set_projected_field(log_data, key, value, policy)

        for key, value in record.__dict__.items():
            if key in self._skip_fields:
                continue
            if hasattr(key, "startswith") and key.startswith("_"):
                continue
            if key not in policy.allowed_extra_fields:
                continue
            self._set_projected_field(log_data, key, value, policy)

        for key, value in self.defaults.items():
            if key in policy.allowed_default_fields:
                self._set_projected_field(log_data, key, value, policy)

        if self.timestamp:
            key = self.timestamp if isinstance(self.timestamp, str) else "timestamp"
            output_key = self._get_rename(key)
            if output_key not in log_data:
                log_data[output_key] = datetime.fromtimestamp(record.created, tz=timezone.utc)

        if self.rename_fields_keep_missing:
            for key, target in self.rename_fields.items():
                if key in allowed_keys and target not in log_data:
                    log_data[target] = None
        return

    def _set_projected_field(
        self,
        log_data: dict[str, Any],
        key: str,
        value: Any,
        policy: FieldProjectionPolicy,
    ) -> None:
        output_key = self._get_rename(key)
        if output_key in log_data:
            # A higher-priority category already emitted this key.
            return
        log_data[output_key] = sanitize_projection_value(value, policy)
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
