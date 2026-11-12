"""JSON formatter using the standard library's `json` for encoding.

Module contains the `JsonFormatter` and a custom `JsonEncoder` which supports a greater
variety of types.
"""

### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
import datetime
import json
from typing import Any
from collections.abc import Callable
import warnings

## Application
from . import core
from . import defaults as d
from .exception import ProjectionViolationError


### CLASSES
### ============================================================================
class JsonEncoder(json.JSONEncoder):
    """A custom encoder extending [json.JSONEncoder](https://docs.python.org/3/library/json.html#json.JSONEncoder)"""

    def default(self, o: Any) -> Any:
        if d.use_datetime_any(o):
            return self.format_datetime_obj(o)

        if d.use_exception_default(o):
            return d.exception_default(o)

        if d.use_traceback_default(o):
            return d.traceback_default(o)

        if d.use_enum_default(o):
            return d.enum_default(o)

        if d.use_bytes_default(o):
            return d.bytes_default(o)

        if d.use_dataclass_default(o):
            return d.dataclass_default(o)

        if d.use_type_default(o):
            return d.type_default(o)

        try:
            return super().default(o)
        except TypeError:
            return d.unknown_default(o)

    def format_datetime_obj(self, o: datetime.time | datetime.date | datetime.datetime) -> str:
        """Format datetime objects found in `self.default`

        This allows subclasses to change the datetime format without understanding the
        internals of the default method.
        """
        return d.datetime_any(o)


class JsonFormatter(core.BaseJsonFormatter):
    """JSON formatter using the standard library's [`json`](https://docs.python.org/3/library/json.html) for encoding"""

    def __init__(
        self,
        *args,
        json_default: Callable | None = None,
        json_encoder: Callable | None = None,
        json_serializer: Callable = json.dumps,
        json_indent: int | str | None = None,
        json_ensure_ascii: bool = True,
        **kwargs,
    ) -> None:
        """
        Args:
            args: see [BaseJsonFormatter][pythonjsonlogger.core.BaseJsonFormatter]
            json_default: a function for encoding non-standard objects
            json_encoder: custom JSON encoder
            json_serializer: a [`json.dumps`](https://docs.python.org/3/library/json.html#json.dumps)-compatible callable
                that will be used to serialize the log record.
            json_indent: indent parameter for the `json_serializer`
            json_ensure_ascii: `ensure_ascii` parameter for the `json_serializer`
            kwargs: see [BaseJsonFormatter][pythonjsonlogger.core.BaseJsonFormatter]
        """
        super().__init__(*args, **kwargs)

        self.json_default = json_default
        self.json_encoder = json_encoder
        self.json_serializer = json_serializer
        self.json_indent = json_indent
        self.json_ensure_ascii = json_ensure_ascii
        if not self.json_encoder and not self.json_default:
            self.json_encoder = JsonEncoder
        return

    def jsonify_log_record(self, log_data: core.LogData) -> str:
        """Returns a json string of the log data."""
        if self.field_projection is not None:
            return self._jsonify_projected_log_record(log_data, self.field_projection)
        return self._serialize(log_data)

    def _serialize(self, log_data: core.LogData) -> str:
        return self.json_serializer(
            log_data,
            default=self.json_default,
            cls=self.json_encoder,
            indent=self.json_indent,
            ensure_ascii=self.json_ensure_ascii,
        )

    def _jsonify_projected_log_record(
        self, log_data: core.LogData, policy: core.FieldProjectionPolicy
    ) -> str:
        """Serialize projected log data, enforcing record level bounds.

        The output is always valid JSON or a `ProjectionViolationError` is
        raised; unserializable values are never silently dropped into the
        output and the record never exceeds `policy.max_record_bytes`.
        """
        try:
            result = self._serialize(log_data)
        except ProjectionViolationError:
            raise
        except Exception as exc:
            if policy.on_violation == "reject":
                raise ProjectionViolationError(
                    f"log record could not be serialized: {exc}"
                ) from exc
            log_data = self._replace_unserializable_values(log_data)
            try:
                result = self._serialize(log_data)
            except Exception as repair_exc:
                raise ProjectionViolationError(
                    f"log record could not be serialized: {repair_exc}"
                ) from repair_exc

        if not isinstance(result, str):
            raise TypeError(
                "json_serializer must return a str when a field projection policy "
                f"is used, got {type(result).__name__}"
            )

        return self._enforce_max_record_bytes(log_data, policy, result)

    def _replace_unserializable_values(self, log_data: core.LogData) -> core.LogData:
        repaired: core.LogData = {}
        for key, value in log_data.items():
            try:
                self._serialize({key: value})
            except Exception:  # pylint: disable=broad-exception-caught
                repaired[key] = core.projection_placeholder("unserializable_value")
            else:
                repaired[key] = value
        return repaired

    def _enforce_max_record_bytes(
        self, log_data: core.LogData, policy: core.FieldProjectionPolicy, result: str
    ) -> str:
        limit = policy.max_record_bytes
        if len(result.encode("utf-8")) <= limit:
            return result
        if policy.on_violation == "reject":
            raise ProjectionViolationError(
                f"log record exceeds max_record_bytes ({limit})"
            )

        required_keys = {self._get_rename(field) for field in self._required_fields}
        log_data = dict(log_data)
        while len(result.encode("utf-8")) > limit:
            string_keys = [
                key
                for key, value in log_data.items()
                if isinstance(value, str) and len(value) > 32
            ]
            if string_keys:
                key = max(string_keys, key=lambda k: len(log_data[k]))
                if key in required_keys:
                    log_data[key] = log_data[key][: len(log_data[key]) // 2]
                else:
                    log_data[key] = core.projection_placeholder("max_record_bytes_exceeded")
            else:
                candidates = [key for key in log_data if key not in required_keys]
                if not candidates:
                    raise ProjectionViolationError(
                        f"log record exceeds max_record_bytes ({limit})"
                    )
                key = max(candidates, key=lambda k: len(repr(log_data[k])))
                del log_data[key]
            result = self._serialize(log_data)
        return result


### DEPRECATED COMPATIBILITY
### ============================================================================
def __getattr__(name: str):
    if name == "RESERVED_ATTRS":
        warnings.warn(
            "RESERVED_ATTRS has been moved to pythonjsonlogger.core",
            DeprecationWarning,
        )
        return core.RESERVED_ATTRS
    raise AttributeError(f"module {__name__} has no attribute {name}")
