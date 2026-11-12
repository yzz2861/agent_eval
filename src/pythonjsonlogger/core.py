"""Core functionality shared by all JSON loggers"""

### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
import builtins
from datetime import datetime, timezone
import linecache
import logging
import re
import string
import sys
from types import TracebackType
from typing import TypeAlias, Any, Pattern
from collections.abc import Container, Sequence

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

REDACTED_PLACEHOLDER = "[REDACTED]"
"""Marker used for every value removed by exception sanitization."""

TRUNCATED_PLACEHOLDER = "[TRUNCATED]"
"""Marker used when exception, stack, or frame output reaches a configured limit."""

_SENSITIVE_KEY_WORDS = (
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "clientsecret",
    "authorization",
    "proxyauthorization",
    "cookie",
    "credential",
    "sessionid",
    "sessid",
    "jwt",
    "dsn",
    "dburl",
    "databaseurl",
    "connectionstring",
    "connectionstr",
    "connectionuri",
    "connstr",
    "connuri",
    "databaseuri",
    "dburi",
)

_KEY_NAME_PATTERN = (
    r"(?:[A-Za-z0-9_.-]*"
    r"(?:password|passwd|passphrase|pwd|pass|secret|token|api[\s_-]?key|apikey|"
    r"access[\s_-]?key|private[\s_-]?key|client[\s_-]?secret|authorization|"
    r"proxy[\s_-]?authorization|cookie|set[\s_-]?cookie|credential|session[\s_-]?id|"
    r"jwt|dsn|db[\s_-]?(?:url|uri)|database[\s_-]?(?:url|uri)|"
    r"connection[\s_-]?(?:string|str|uri)|conn[\s_-]?uri|"
    r"jsessionid|phpsessid|session(?:[_-]?(?:id|token|key))?|"
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|amqp)[_-]?url)"
    r"[A-Za-z0-9_.-]*)"
)

# These expressions intentionally replace values with a fixed marker. They never
# preserve the original value (or its length) in the emitted text.
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.IGNORECASE | re.DOTALL
)
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)\b((?:proxy-)?authorization|set-cookie|cookie|x-api-key|x-auth-token)"
    r"(\s*[:=]\s*)([^\r\n]*)"
)
_QUOTED_ASSIGNMENT_RE = re.compile(
    rf"(?ix)(?P<key_quote>['\"]?)(?P<key>{_KEY_NAME_PATTERN})(?P=key_quote)"
    r"(?P<sep>\s*(?:[:=])\s*)"
    r"(?P<quote>[\"'])(?P<value>.*?)(?P=quote)"
)
_UNQUOTED_ASSIGNMENT_RE = re.compile(
    rf"(?ix)(?P<key>{_KEY_NAME_PATTERN})(?P<sep>\s*(?:[:=])\s*)" r"(?P<value>[^\r\n,;&}]+)"
)
_CONNECTION_URL_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|mssql|"
    r"oracle|amqp(?:s)?|jdbc:[a-z0-9]+|clickhouse(?:sql)?|snowflake|sqlite|libsql|"
    r"cassandra|neo4j|bolt|cockroachdb)(?:\+[a-z0-9_.-]+)?://[^\s\"'<>]+"
)
_CONNECTION_STRING_RE = re.compile(
    r"(?i)(?:[A-Za-z][A-Za-z0-9 _-]*=[^;\r\n]*;){1,}" r"[A-Za-z][A-Za-z0-9 _-]*=[^;\r\n}]+"
)
_URL_WITH_USERINFO_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]*:[^\s/@]+@[^\s\"'<>]*")
_SENSITIVE_QUERY_RE = re.compile(
    r"(?i)((?:[?&])(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
    r"api[_-]?key|apikey|client[_-]?secret|password|passwd|secret|"
    r"auth|key|sig|signature|session|sessionid|sessid|jsessionid|phpsessid)="
    r")([^&#\s\"'<>]+)"
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)((?:bearer|basic|digest|negotiate|token)\s+)([A-Za-z0-9._~+/=\-]+)"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_PROVIDER_TOKEN_RE = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|(?:sk|pk)[-_][A-Za-z0-9_-]{10,})\b"
)

_EXCEPTION_GROUP_TYPES: tuple[type, ...] = ()
_EXCEPTION_GROUP_DESCRIPTORS: dict[str, Any] = {}
if sys.version_info >= (3, 11):
    _EXCEPTION_GROUP_TYPES = (builtins.BaseExceptionGroup,)
    _EXCEPTION_GROUP_DESCRIPTORS = {
        name: builtins.BaseExceptionGroup.__dict__.get(name) for name in ("message", "exceptions")
    }

## Type Aliases
## -----------------------------------------------------------------------------
LogData: TypeAlias = dict[str, Any]
"""Type alias

*Changed in 4.0*: renamed from `LogRecord` to `LogData`
"""


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
class ExceptionSanitizer:
    """Render exception and stack information without exposing sensitive values.

    This class deliberately avoids the standard library's generic traceback formatting:
    ``traceback`` can call arbitrary ``str``/``repr`` implementations and does not
    provide a bounded representation of frame locals. Instead, values are rendered
    recursively only for a small allowlist of built-in containers and scalar types.
    All other objects are represented by their type and a fixed placeholder.

    ``redact_patterns`` are caller supplied regular expressions. Every match is
    replaced with :data:`REDACTED_PLACEHOLDER`; the replacement never includes the
    matched text or its length.
    """

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        *,
        redact_patterns: Sequence[str | Pattern[str]] | None = None,
        sensitive_key_patterns: Sequence[str | Pattern[str]] | None = None,
        max_frames: int = 50,
        max_frame_chars: int = 4096,
        max_total_bytes: int = 32768,
        capture_locals: bool = True,
        marker: str = REDACTED_PLACEHOLDER,
        max_value_chars: int = 512,
        max_value_items: int = 20,
        max_value_depth: int = 3,
    ) -> None:
        self.redact_patterns = self._compile_patterns(redact_patterns)
        self.sensitive_key_patterns = self._compile_patterns(sensitive_key_patterns)
        self.max_frames = max(1, int(max_frames))
        self.max_frame_chars = max(1, int(max_frame_chars))
        self.max_total_bytes = max(1, int(max_total_bytes))
        self.capture_locals = capture_locals
        self.marker = marker
        self.max_value_chars = max(1, int(max_value_chars))
        self.max_value_items = max(1, int(max_value_items))
        self.max_value_depth = max(0, int(max_value_depth))
        self._max_chain = 64
        return

    ## Pattern handling
    ## -------------------------------------------------------------------------
    @staticmethod
    def _compile_patterns(
        patterns: Sequence[str | Pattern[str]] | str | Pattern[str] | None,
    ) -> list[Pattern[str]]:
        if patterns is None:
            return []
        pattern_items: Sequence[str | Pattern[str]]
        if isinstance(patterns, (str, re.Pattern)):
            pattern_items = [patterns]
        else:
            pattern_items = patterns

        compiled: list[Pattern[str]] = []
        for pattern in pattern_items:
            if isinstance(pattern, re.Pattern):
                compiled.append(pattern)
            else:
                compiled.append(re.compile(pattern))
        return compiled

    def _is_sensitive_key(self, key: Any) -> bool:
        if type(key) is not str:
            return False

        for pattern in self.sensitive_key_patterns:
            if pattern.search(key):
                return True

        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if any(word in normalized for word in _SENSITIVE_KEY_WORDS):
            return True
        return normalized in {
            "auth",
            "authentication",
            "pass",
            "session",
            "sid",
            "conn",
            "connection",
        }

    ## Text handling
    ## -------------------------------------------------------------------------
    def sanitize_text(self, text: str) -> str:
        """Redact sensitive key/value shapes and caller patterns from text.

        The marker is always the same, so the output never reveals the length of a
        replaced value.

        Args:
            text: text to sanitize

        Returns:
            The sanitized text.
        """
        if type(text) is not str:
            return f"<{self._safe_type_name(text)} {self.marker}>"

        text = _PEM_PRIVATE_KEY_RE.sub(self.marker, text)
        text = _CONNECTION_STRING_RE.sub(self._redact_connection_string, text)
        text = _SENSITIVE_HEADER_RE.sub(
            lambda match: f"{match.group(1)}{match.group(2)}{self.marker}", text
        )
        text = _QUOTED_ASSIGNMENT_RE.sub(
            lambda match: (
                f"{match.group('key_quote')}{match.group('key')}{match.group('key_quote')}"
                f"{match.group('sep')}{self.marker}"
            ),
            text,
        )
        text = _UNQUOTED_ASSIGNMENT_RE.sub(
            lambda match: f"{match.group('key')}{match.group('sep')}{self.marker}", text
        )
        text = _CONNECTION_URL_RE.sub(self.marker, text)
        text = _URL_WITH_USERINFO_RE.sub(self.marker, text)
        text = _SENSITIVE_QUERY_RE.sub(lambda match: f"{match.group(1)}{self.marker}", text)
        text = _AUTH_SCHEME_RE.sub(lambda match: f"{match.group(1)}{self.marker}", text)
        text = _JWT_RE.sub(self.marker, text)
        text = _PROVIDER_TOKEN_RE.sub(self.marker, text)

        for pattern in self.redact_patterns:
            text = pattern.sub(lambda match: self.marker, text)
        return text

    def _redact_connection_string(self, match: re.Match[str]) -> str:
        candidate = match.group(0)
        if re.search(_KEY_NAME_PATTERN, candidate, re.IGNORECASE):
            return self.marker
        return candidate

    def redact_text(self, text: str) -> str:
        """Alias for :meth:`sanitize_text`."""
        return self.sanitize_text(text)

    @staticmethod
    def _safe_type_name(value: Any) -> str:
        try:
            return type(value).__name__
        except Exception:  # pylint: disable=broad-exception-caught
            return "object"

    @staticmethod
    def _byte_length(text: str) -> int:
        return len(text.encode("utf-8", errors="replace"))

    def _truncate_text(self, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        keep = max(0, max_chars - len(TRUNCATED_PLACEHOLDER))
        return text[:keep] + TRUNCATED_PLACEHOLDER

    def _truncate_bytes(self, text: str, max_bytes: int) -> str:
        if self._byte_length(text) <= max_bytes:
            return text
        marker = TRUNCATED_PLACEHOLDER
        if max_bytes <= len(marker):
            return marker[:max_bytes]
        keep = max_bytes - len(marker)
        prefix = text.encode("utf-8", errors="replace")[:keep]
        return prefix.decode("utf-8", errors="ignore") + marker

    ## Value handling
    ## -------------------------------------------------------------------------
    def sanitize_value(self, value: Any, *, key: Any = None, depth: int = 0) -> str:
        """Return a bounded, sanitized representation of a value.

        Only exact built-in scalar and container types are traversed. Subclasses and
        arbitrary objects are never passed to ``str``, ``repr``, or attribute
        iteration.

        Args:
            value: value to render
            key: optional mapping/local key associated with the value
            depth: current recursive depth

        Returns:
            A safe string representation.
        """
        return self._render_value(value, key=key, depth=depth, seen=set())

    def _render_value(  # pylint: disable=too-many-branches
        self, value: Any, *, key: Any, depth: int, seen: set[int]
    ) -> str:
        if self._is_sensitive_key(key):
            return self.marker

        value_type = type(value)
        if value is None:
            return "None"
        if value_type is bool:
            return "True" if value else "False"
        if value_type is int or value_type is float:
            return str(value)
        if value_type is str:
            return self._render_string(value)
        if value_type is bytes:
            text = value[: self.max_value_chars].decode("utf-8", errors="backslashreplace")
            return "b" + self._render_string(text)

        if value_type in (list, tuple, set, frozenset, dict):
            if depth >= self.max_value_depth:
                return f"<{self._safe_type_name(value)} {TRUNCATED_PLACEHOLDER}>"
            object_id = id(value)
            if object_id in seen:
                return "<cycle>"
            seen.add(object_id)
            try:
                if value_type is dict:
                    rendered = self._render_dict(value, depth, seen)
                elif value_type is list:
                    rendered = self._render_sequence(value, depth, seen, "[", "]")
                elif value_type is tuple:
                    rendered = self._render_sequence(value, depth, seen, "(", ")", tuple_=True)
                else:
                    rendered = self._render_sequence(value, depth, seen, "{", "}")
            except Exception:  # pylint: disable=broad-exception-caught
                rendered = f"<{self._safe_type_name(value)} {self.marker}>"
            finally:
                seen.discard(object_id)
            return self._truncate_text(rendered, self.max_value_chars)

        return f"<{self.sanitize_text(self._safe_type_name(value))} {self.marker}>"

    def _render_string(self, value: str) -> str:
        # Bound the input to a predictable size before applying regular expressions.
        # A value beyond the representation limit cannot expose bytes that are not
        # emitted; truncation happens after redaction.
        if len(value) > 65536:
            value = value[:65536]
        sanitized = self._truncate_text(self.sanitize_text(value), self.max_value_chars)
        return self._truncate_text(repr(sanitized), self.max_value_chars)

    def _render_text_value(self, value: str) -> str:
        if len(value) > 65536:
            value = value[:65536]
        return self._truncate_text(self.sanitize_text(value), self.max_value_chars)

    def _render_key(self, key: Any) -> str:
        if type(key) is str:
            return repr(self._truncate_text(self.sanitize_text(key), 128))
        if key is None or type(key) in (bool, int, float):
            return self._render_value(key, key=None, depth=0, seen=set())

        return f"<{self.sanitize_text(self._safe_type_name(key))} {self.marker}>"

    def _render_sequence(
        self,
        value: Sequence[Any] | set[Any] | frozenset[Any],
        depth: int,
        seen: set[int],
        opener: str,
        closer: str,
        tuple_: bool = False,
    ) -> str:
        items: list[str] = []
        size = len(value)
        for index, item in enumerate(value):
            if index >= self.max_value_items:
                items.append(TRUNCATED_PLACEHOLDER)
                break
            items.append(self._render_value(item, key=None, depth=depth + 1, seen=seen))

        if tuple_ and size == 1:
            return f"({items[0]},)"
        return f"{opener}{', '.join(items)}{closer}"

    def _render_dict(self, value: dict[Any, Any], depth: int, seen: set[int]) -> str:
        items: list[str] = []
        for index, (item_key, item_value) in enumerate(value.items()):
            if index >= self.max_value_items:
                items.append(TRUNCATED_PLACEHOLDER)
                break
            rendered_key = self._render_key(item_key)
            rendered_value = self._render_value(
                item_value, key=item_key, depth=depth + 1, seen=seen
            )
            items.append(f"{rendered_key}: {rendered_value}")
        return "{" + ", ".join(items) + "}"

    ## Exception handling
    ## -------------------------------------------------------------------------
    @staticmethod
    def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
        try:
            return getattr(obj, name, default)
        except Exception:  # pylint: disable=broad-exception-caught
            return default

    @staticmethod
    def _exception_slot(exc: BaseException, name: str, default: Any = None) -> Any:
        """Read a BaseException C-level slot without invoking user overrides."""
        descriptor = BaseException.__dict__.get(name)
        if descriptor is None:
            return default
        try:
            return descriptor.__get__(exc, type(exc))
        except Exception:  # pylint: disable=broad-exception-caught
            return default

    @staticmethod
    def _exception_group_slot(exc: BaseException, name: str, default: Any = None) -> Any:
        descriptor = _EXCEPTION_GROUP_DESCRIPTORS.get(name)
        if descriptor is None:
            return default
        try:
            return descriptor.__get__(exc, type(exc))
        except Exception:  # pylint: disable=broad-exception-caught
            return default

    @staticmethod
    def _is_exception_group(exc: BaseException) -> bool:
        return bool(_EXCEPTION_GROUP_TYPES) and isinstance(exc, _EXCEPTION_GROUP_TYPES)

    def _exception_group_leaves(
        self, exc: BaseException, seen: set[int] | None = None
    ) -> list[BaseException]:
        if seen is None:
            seen = set()
        if id(exc) in seen:
            return []
        seen.add(id(exc))

        children = self._exception_group_slot(exc, "exceptions", ())
        if type(children) is not tuple:
            return []

        leaves: list[BaseException] = []
        for child in children[: self.max_value_items]:
            if not isinstance(child, BaseException):
                continue
            if self._is_exception_group(child):
                leaves.extend(self._exception_group_leaves(child, seen))
            else:
                leaves.append(child)
            if len(leaves) >= self.max_value_items:
                break
        return leaves

    def _exception_entries(self, exc_value: BaseException | None, tb: Any) -> list[Any]:
        entries: list[Any] = []
        seen: set[int] = set()
        current = exc_value
        current_tb = tb
        relation: str | None = None

        while isinstance(current, BaseException) and id(current) not in seen:
            entries.append((current, current_tb, relation))
            seen.add(id(current))
            if len(entries) >= self._max_chain:
                break

            cause = self._exception_slot(current, "__cause__")
            if isinstance(cause, BaseException):
                next_exception = cause
                relation = "cause"
            else:
                suppressed_value = self._exception_slot(current, "__suppress_context__", False)
                suppressed = type(suppressed_value) is bool and suppressed_value
                context = None if suppressed else self._exception_slot(current, "__context__")
                if isinstance(context, BaseException):
                    next_exception = context
                    relation = "context"
                else:
                    break

            current = next_exception
            current_tb = self._exception_slot(current, "__traceback__")

        return entries

    def _exception_message(self, exc: BaseException) -> str:
        args = self._exception_slot(exc, "args", ())
        if type(args) is not tuple:
            return self.marker

        is_group = self._is_exception_group(exc)
        if is_group and args:
            if type(args[0]) is str:
                message = self._render_text_value(args[0])
            else:
                message = self._render_value(args[0], key=None, depth=0, seen=set())
            children = self._exception_group_slot(exc, "exceptions", ())
            child_count = len(children) if type(children) is tuple else 0
            return f"{message} ({child_count} sub-exception(s))"

        if not args:
            return ""
        if len(args) == 1:
            if type(args[0]) is str:
                return self._render_text_value(args[0])
            return self._render_value(args[0], key=None, depth=0, seen=set())

        truncated_args = len(args) > self.max_value_items
        selected_args = args[: self.max_value_items]
        rendered = [
            (
                self._render_text_value(arg)
                if type(arg) is str
                else self._render_value(arg, key=None, depth=0, seen=set())
            )
            for arg in selected_args
        ]
        if truncated_args:
            rendered.append(TRUNCATED_PLACEHOLDER)
        return ", ".join(rendered)

    def _exception_name(self, exc: BaseException | None, exc_type: Any = None) -> str:
        if exc is not None:
            return self.sanitize_text(self._safe_type_name(exc))
        if exc_type is not None:
            return self.sanitize_text(self._safe_getattr(exc_type, "__name__", "Exception"))
        return "Exception"

    def _exception_line(self, exc: BaseException, exc_type: Any = None) -> str:
        name = self._exception_name(exc, exc_type)
        message = self._exception_message(exc)
        line = f"{name}: {message}" if message else name
        return self._truncate_text(line, self.max_frame_chars)

    def _exception_notes(self, exc: BaseException) -> list[str]:
        try:
            instance_dict = BaseException.__dict__["__dict__"].__get__(exc, type(exc))
            notes = instance_dict.get("__notes__", ())
        except Exception:  # pylint: disable=broad-exception-caught
            notes = ()
        if type(notes) not in (list, tuple):
            return []
        return [
            self._truncate_text(self.sanitize_text(note), self.max_frame_chars)
            for note in notes[: self.max_value_items]
            if type(note) is str
        ]

    @staticmethod
    def _traceback_frames(tb: Any) -> list[Any]:
        frames: list[Any] = []
        seen: set[int] = set()
        while isinstance(tb, TracebackType) and id(tb) not in seen:
            frames.append(tb)
            seen.add(id(tb))
            tb = tb.tb_next
        return frames

    def _render_frame(self, tb: Any) -> str:  # pylint: disable=too-many-branches
        try:
            frame = tb.tb_frame
            code = frame.f_code
            filename = code.co_filename
            function = code.co_name
            lineno = tb.tb_lineno
        except Exception:  # pylint: disable=broad-exception-caught
            return f"  <frame {self.marker}>"

        safe_filename = (
            self.sanitize_text(str(filename))
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )
        safe_function = self.sanitize_text(str(function)).replace("\n", "\\n")
        lines = [f'  File "{safe_filename}", line {lineno}, in {safe_function}']
        try:
            source = linecache.getline(filename, lineno).rstrip()
        except Exception:  # pylint: disable=broad-exception-caught
            source = ""
        if source:
            lines.append("    " + self.sanitize_text(source))

        if self.capture_locals:
            try:
                local_items = frame.f_locals
                rendered_locals: list[str] = []
                # At module scope ``f_locals`` is ``f_globals``. Dumping all globals
                # is neither useful for the traceback nor safe for a bounded formatter.
                if local_items is not frame.f_globals:
                    for index, (name, value) in enumerate(local_items.items()):
                        if index >= self.max_value_items:
                            rendered_locals.append(f"    {TRUNCATED_PLACEHOLDER}")
                            break
                        safe_name = self._truncate_text(
                            self.sanitize_text(str(name)).replace("\n", "\\n"), 128
                        )
                        rendered_value = self._render_value(value, key=name, depth=0, seen=set())
                        rendered_locals.append(f"    {safe_name} = {rendered_value}")
            except Exception:  # pylint: disable=broad-exception-caught
                rendered_locals = [f"    {TRUNCATED_PLACEHOLDER}"]
            if rendered_locals:
                lines.append("    locals:")
                lines.extend(rendered_locals)

        block = "\n".join(lines)
        return self._truncate_text(block, self.max_frame_chars)

    def format_exception(
        self,
        exc_info: tuple[Any, Any, Any],
        *,
        as_array: bool = False,
    ) -> str | list[str]:  # pylint: disable=too-many-locals,too-many-branches
        """Format and sanitize exception information.

        Args:
            exc_info: The ``(type, value, traceback)`` tuple supplied by logging.
            as_array: Split the result into lines.

        Returns:
            Sanitized exception text, or a list of lines when ``as_array`` is true.
        """
        try:
            exc_type, exc_value, tb = exc_info
        except Exception:  # pylint: disable=broad-exception-caught
            result = self.marker
            return [result] if as_array else result

        entries = self._exception_entries(exc_value, tb)
        if not entries:
            name = self._exception_name(None, exc_type)
            result = self._truncate_text(f"{name}: {self.marker}", self.max_frame_chars)
            return result.splitlines() if as_array else result

        # Entries are collected outer-exception first; tracebacks are rendered root
        # first like the standard library does.
        entries_out = list(reversed(entries))
        frames_by_entry: dict[int, list[Any]] = {}
        flat_frames: list[tuple[int, Any]] = []
        for entry_index, entry in enumerate(entries_out):
            if entry[0] is None:
                frames_by_entry[entry_index] = []
                continue
            frames = self._traceback_frames(entry[1])
            frames_by_entry[entry_index] = frames
            flat_frames.extend((entry_index, frame) for frame in frames)

        selected_frames: set[tuple[int, Any]] = set()
        if len(flat_frames) > self.max_frames:
            keep_head = self.max_frames // 2
            keep_tail = self.max_frames - keep_head
            selected_frames.update(flat_frames[:keep_head])
            if keep_tail:
                selected_frames.update(flat_frames[-keep_tail:])
        else:
            selected_frames.update(flat_frames)

        message_lines: dict[int, list[str]] = {}
        for entry_index, entry in enumerate(entries_out):
            exc = entry[0]
            if exc is None:
                message_lines[entry_index] = [f"... {TRUNCATED_PLACEHOLDER} ..."]
                continue
            message_lines[entry_index] = [self._exception_line(exc)]
            if self._is_exception_group(exc):
                for child in self._exception_group_leaves(exc):
                    message_lines[entry_index].append(
                        self._truncate_text(
                            "  exception group member: " + self._exception_line(child),
                            self.max_frame_chars,
                        )
                    )
                    for note in self._exception_notes(child):
                        message_lines[entry_index].append(
                            self._truncate_text("  " + note, self.max_frame_chars)
                        )
            message_lines[entry_index].extend(self._exception_notes(exc))

        root_exc = entries[-1][0]
        root_line = self._truncate_text(
            "Root exception: " + self._exception_line(root_exc, exc_type),
            self.max_frame_chars,
        )
        if entries[-1][0] is None:
            root_line = "Root exception: " + self.marker

        separators = {
            "cause": "The above exception was the direct cause of the following exception:",
            "context": "During handling of the above exception, another exception occurred:",
        }

        nonframe_chunks: list[str] = []
        for entry_index, entry in enumerate(entries_out):
            if entry_index > 0:
                relation = entries_out[entry_index - 1][2]
                separator = separators.get(relation, "Exception chain continuation:")
                nonframe_chunks.append(self._truncate_text(separator, self.max_frame_chars))
            nonframe_chunks.extend(message_lines[entry_index])
        nonframe_chunks.append(root_line)

        nonframe_bytes = self._byte_length("\n".join(nonframe_chunks))
        reserve = self._byte_length(TRUNCATED_PLACEHOLDER) * (len(entries_out) + 2) + 4
        remaining = self.max_total_bytes - nonframe_bytes - reserve

        if remaining <= 0:
            minimal = f"{self._exception_name(entries[0][0], exc_type)}: {self.marker}\n{root_line}"
            result = self._truncate_bytes(minimal, self.max_total_bytes)
            return result.splitlines() if as_array else result

        output: list[str] = []
        frame_truncated = len(flat_frames) > self.max_frames
        budget_exhausted = False
        for entry_index, entry in enumerate(entries_out):
            if entry_index > 0:
                relation = entries_out[entry_index - 1][2]
                separator = separators.get(relation, "Exception chain continuation:")
                output.append(self._truncate_text(separator, self.max_frame_chars))

            frames = frames_by_entry[entry_index]
            rendered_any = False
            for frame in frames:
                if (entry_index, frame) not in selected_frames:
                    continue
                if budget_exhausted:
                    continue
                block = self._render_frame(frame)
                header = "Traceback (most recent call last):"
                header_bytes = 0 if rendered_any else self._byte_length(header) + 1
                block_bytes = self._byte_length(block) + 1 + header_bytes
                if block_bytes > remaining:
                    budget_exhausted = True
                    continue
                if not rendered_any:
                    output.append(header)
                    rendered_any = True
                output.append(block)
                remaining -= block_bytes

            if frames and not rendered_any:
                output.append(f"... {TRUNCATED_PLACEHOLDER} ...")
            elif frames and (frame_truncated or budget_exhausted):
                output.append(f"... {TRUNCATED_PLACEHOLDER} ...")

            output.extend(message_lines[entry_index])

        output.append(root_line)
        result = "\n".join(output)
        if self._byte_length(result) > self.max_total_bytes:
            result = self._truncate_bytes(result, self.max_total_bytes)
        return result.splitlines() if as_array else result

    def format_exception_text(self, text: str, *, as_array: bool = False) -> str | list[str]:
        """Sanitize previously formatted exception text (for example ``record.exc_text``)."""
        return self.format_stack(text, as_array=as_array)

    def format_stack(  # pylint: disable=too-many-locals,too-many-branches
        self, stack_info: str, *, as_array: bool = False
    ) -> str | list[str]:
        """Sanitize stack information and apply line/frame/byte limits."""
        if type(stack_info) is not str:
            result = f"<{self._safe_type_name(stack_info)} {self.marker}>"
            return [result] if as_array else result

        sanitized = self.sanitize_text(stack_info)
        lines = sanitized.splitlines()
        frame_starts = [
            index
            for index, line in enumerate(lines)
            if line.lstrip().startswith(('File "', "File '"))
        ]

        if not frame_starts:
            limited_lines = [
                self._truncate_text(line, self.max_frame_chars)
                for line in lines[: self.max_frames * 8]
            ]
            result = self._truncate_bytes("\n".join(limited_lines), self.max_total_bytes)
            return result.splitlines() if as_array else result

        prefix = lines[: frame_starts[0]]
        blocks: list[list[str]] = []
        starts = frame_starts + [len(lines)]
        for index in range(len(frame_starts)):
            blocks.append(lines[starts[index] : starts[index + 1]])

        selected_blocks = blocks
        omitted = False
        if len(blocks) > self.max_frames:
            keep_head = self.max_frames // 2
            keep_tail = self.max_frames - keep_head
            if keep_tail:
                selected_blocks = blocks[:keep_head] + blocks[-keep_tail:]
            else:
                selected_blocks = blocks[:keep_head]
            omitted = True

        rendered: list[str] = []
        rendered.extend(self._truncate_text(line, self.max_frame_chars) for line in prefix)
        for block_index, block in enumerate(selected_blocks):
            if omitted and block_index == len(selected_blocks) - 1:
                rendered.append(f"... {TRUNCATED_PLACEHOLDER} ...")
            rendered.extend(self._truncate_text(line, self.max_frame_chars) for line in block)

        result = self._truncate_bytes("\n".join(rendered), self.max_total_bytes)
        return result.splitlines() if as_array else result


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
        sanitize_exceptions: bool = False,
        exception_sanitizer: ExceptionSanitizer | None = None,
        redact_patterns: Sequence[str | Pattern[str]] | None = None,
        sensitive_key_patterns: Sequence[str | Pattern[str]] | None = None,
        exception_max_frames: int = 50,
        exception_max_frame_chars: int = 4096,
        exception_max_total_bytes: int = 32768,
        exception_capture_locals: bool = True,
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
            sanitize_exceptions: explicitly enable bounded exception redaction. When
                disabled the standard library's existing traceback formatting is used.
            exception_sanitizer: an optional preconfigured :class:`ExceptionSanitizer`.
                Supplying one enables sanitization and takes precedence over the
                individual sanitizer options.
            redact_patterns: optional regular expressions (strings or compiled patterns).
                Every match in exception messages, frame locals, source lines, and
                `stack_info` is replaced with a fixed marker.
            sensitive_key_patterns: optional additional regular expressions identifying
                sensitive mapping/local variable names.
            exception_max_frames: maximum number of traceback frames to render.
            exception_max_frame_chars: maximum character length of one rendered frame.
            exception_max_total_bytes: maximum UTF-8 byte length of sanitized exception
                or stack text. Exception type and root exception information are retained.
            exception_capture_locals: include sanitized frame locals. If false, only
                frame location/source information is included.

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
        self.sanitize_exceptions = sanitize_exceptions or exception_sanitizer is not None
        self.exception_sanitizer: ExceptionSanitizer | None = exception_sanitizer
        if self.sanitize_exceptions and self.exception_sanitizer is None:
            self.exception_sanitizer = ExceptionSanitizer(
                redact_patterns=redact_patterns,
                sensitive_key_patterns=sensitive_key_patterns,
                max_frames=exception_max_frames,
                max_frame_chars=exception_max_frame_chars,
                max_total_bytes=exception_max_total_bytes,
                capture_locals=exception_capture_locals,
            )
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

        caller_exc_info = bool(message_dict.get("exc_info"))
        caller_stack_info = bool(message_dict.get("stack_info"))

        # only format time if needed
        if "asctime" in self._required_fields:
            record.asctime = self.formatTime(record, self.datefmt)

        # Display formatted exception, but allow overriding it in the
        # user-supplied dict.
        if record.exc_info and not message_dict.get("exc_info"):
            message_dict["exc_info"] = self.formatException(record.exc_info)
        if not message_dict.get("exc_info") and record.exc_text:
            exc_text = record.exc_text
            if self.sanitize_exceptions and self.exception_sanitizer is not None:
                exc_text = self.exception_sanitizer.format_exception_text(
                    exc_text, as_array=self.exc_info_as_array
                )
            else:
                exc_text = exc_text.splitlines() if self.exc_info_as_array else exc_text
            message_dict["exc_info"] = exc_text

        # Display formatted record of stack frames
        # default format is a string returned from :func:`traceback.print_stack`
        if record.stack_info and not message_dict.get("stack_info"):
            message_dict["stack_info"] = self.formatStack(record.stack_info)

        if self.sanitize_exceptions and self.exception_sanitizer is not None:
            if caller_exc_info:
                message_dict["exc_info"] = self._sanitize_supplied_output(
                    message_dict["exc_info"], as_array=self.exc_info_as_array
                )
            if caller_stack_info:
                message_dict["stack_info"] = self._sanitize_supplied_stack(
                    message_dict["stack_info"], as_array=self.stack_info_as_array
                )

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
        if self.sanitize_exceptions and self.exception_sanitizer is not None:
            return self.exception_sanitizer.format_exception(ei, as_array=self.exc_info_as_array)
        exception_info_str = super().formatException(ei)
        return exception_info_str.splitlines() if self.exc_info_as_array else exception_info_str

    def formatStack(self, stack_info) -> str | list[str]:  # type: ignore[override]
        """Format and return the specified stack information.

        If stack_info_as_array is set to True, This method returns an array of strings.
        """
        if self.sanitize_exceptions and self.exception_sanitizer is not None:
            return self.exception_sanitizer.format_stack(
                stack_info, as_array=self.stack_info_as_array
            )
        stack_info_str = super().formatStack(stack_info)
        return stack_info_str.splitlines() if self.stack_info_as_array else stack_info_str

    def _sanitize_supplied_output(
        self, value: Any, *, as_array: bool
    ) -> str | list[str] | tuple[str, ...]:
        if self.exception_sanitizer is None:
            return str(value)  # type: ignore[unreachable]
        if isinstance(value, str):
            return self.exception_sanitizer.format_exception_text(value, as_array=as_array)
        if isinstance(value, (list, tuple)) and all(isinstance(line, str) for line in value):
            result = self.exception_sanitizer.format_exception_text("\n".join(value), as_array=True)
            if isinstance(result, str):
                result = result.splitlines()
            return tuple(result) if isinstance(value, tuple) else result
        return self.exception_sanitizer.marker

    def _sanitize_supplied_stack(
        self, value: Any, *, as_array: bool
    ) -> str | list[str] | tuple[str, ...]:
        if self.exception_sanitizer is None:
            return str(value)  # type: ignore[unreachable]
        if isinstance(value, str):
            return self.exception_sanitizer.format_stack(value, as_array=as_array)
        if isinstance(value, (list, tuple)) and all(isinstance(line, str) for line in value):
            result = self.exception_sanitizer.format_stack("\n".join(value), as_array=True)
            if isinstance(result, str):
                result = result.splitlines()
            return tuple(result) if isinstance(value, tuple) else result
        return self.exception_sanitizer.marker
