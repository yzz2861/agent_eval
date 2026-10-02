# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
A JSON renderer that never exceeds a fixed output size.

Unlike rendering the whole event dict and truncating the resulting string,
the renderer in this module builds the JSON document directly into a
fixed-size byte buffer.  Fields are kept in priority order, strings are
shortened and low-priority fields are omitted while the result always stays
syntactically valid JSON.
"""

from __future__ import annotations

import math

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from .typing import EventDict, WrappedLogger


__all__ = ["BudgetedJSONRenderer"]


_TRUNCATED_KEY = "_truncated"
_TRUNCATED_NOTE = "truncated"
_ERROR_NOTE = "encoding error"
_ELLIPSIS = b"\xe2\x80\xa6"  # UTF-8 encoding of the horizontal ellipsis
_ASCII_ELLIPSIS = b"..."

# Fields are rendered in this order by default (highest priority first),
# followed by any remaining keys in their original insertion order.
_DEFAULT_PRIORITY: tuple[str, ...] = (
    "event",
    "level",
    "level_name",
    "logger",
    "logger_name",
    "timestamp",
    "time",
    "exception",
)

_ESCAPES = {
    ord('"'): b'\\"',
    ord("\\"): b"\\\\",
    ord("\b"): b"\\b",
    ord("\f"): b"\\f",
    ord("\n"): b"\\n",
    ord("\r"): b"\\r",
    ord("\t"): b"\\t",
}


def _utf8_safe_prefix(data: bytes, n: int) -> bytes:
    """
    Return the longest prefix of *data* that fits into *n* bytes and ends on
    a UTF-8 boundary.  The result may be empty.
    """
    if n >= len(data):
        return data
    if n <= 0:
        return b""
    cut = n
    while cut > 0 and data[cut] & 0xC0 == 0x80:
        cut -= 1
    if data[cut] < 0x80:
        return data[:cut]
    if data[cut] >= 0xF0:
        length = 4
    elif data[cut] >= 0xE0:
        length = 3
    else:
        length = 2
    if n - cut >= length:
        return data[:n]
    return data[:cut]


def _is_balanced(data: bytes) -> bool:
    """
    Check that *data* is a syntactically complete JSON value with respect to
    to brackets, strings and escapes.  Used to discard fragments that could
    not be closed inside the budget.
    """
    stack: list[int] = []
    index = 0
    length = len(data)
    while index < length:
        char = data[index]
        if char == 0x22:  # double quote
            index += 1
            while index < length:
                if data[index] == 0x5C:  # backslash
                    index += 2
                    continue
                if data[index] == 0x22:
                    break
                index += 1
            else:
                return False
        elif char == 0x7B or char == 0x5B:  # { or [
            stack.append(char)
        elif char == 0x7D:  # }
            if not stack or stack.pop() != 0x7B:
                return False
        elif char == 0x5D:  # ]
            if not stack or stack.pop() != 0x5B:
                return False
        index += 1
    return not stack


def _needs_escape(code: int, ensure_ascii: bool) -> bool:
    if code < 0x20 or code in _ESCAPES:
        return True
    if 0xD800 <= code <= 0xDFFF:
        # A lone surrogate cannot appear verbatim in valid JSON.
        return True
    return ensure_ascii and code >= 0x7F


def _escape_char(code: int) -> bytes:
    if code in _ESCAPES:
        return _ESCAPES[code]
    if code <= 0xFFFF:
        return b"\\u%04x" % code
    code -= 0x10000
    high = 0xD800 + (code >> 10)
    low = 0xDC00 + (code & 0x3FF)
    return b"\\u%04x\\u%04x" % (high, low)


def _iter_string_pieces(
    value: str, ensure_ascii: bool
) -> Iterable[tuple[bool, bytes]]:
    """
    Yield (is_raw, bytes) pieces for *value*.

    Raw pieces are safe to embed verbatim; non-raw pieces are pre-built JSON
    escape sequences.  Long runs are chunked so that no temporary grows with
    the size of *value*.
    """
    length = len(value)
    index = 0
    while index < length:
        start = index
        while index < length and not _needs_escape(
            ord(value[index]), ensure_ascii
        ):
            index += 1
        while start != index:
            end = min(index, start + 4096)
            yield True, value[start:end].encode("utf-8")
            start = end
        if index < length:
            yield False, _escape_char(ord(value[index]))
            index += 1


class _Writer:
    """
    Append-only byte buffer with a hard byte budget.

    Every append is checked against the remaining budget before it touches
    the buffer, so a writer can never exceed its budget.
    """

    __slots__ = ("buf", "budget", "truncated")

    def __init__(self, budget: int) -> None:
        self.buf = bytearray()
        self.budget = budget
        self.truncated = False

    @property
    def remaining(self) -> int:
        return self.budget - len(self.buf)

    def put(self, data: bytes) -> bool:
        if len(data) > self.remaining:
            self.truncated = True
            return False
        self.buf += data
        return True

    def write_string(self, value: str, *, ensure_ascii: bool) -> bool:
        """
        Write a JSON string literal, shortening *value* when necessary.

        Returns True when the whole string fits, False when it had to be
        shortened.  When not even an empty, shortened string fits, nothing is
        written and False is returned.
        """
        start = len(self.buf)
        if self.remaining < 2:
            self.truncated = True
            return False
        self.buf += b'"'
        ellipsis = _ASCII_ELLIPSIS if ensure_ascii else _ELLIPSIS

        # Endpoints of fully appended, indivisible tokens (escape sequences
        # and verbatim runs), relative to the start of this string.
        token_ends: list[int] = [1]

        for is_raw, chunk in _iter_string_pieces(value, ensure_ascii):
            if is_raw:
                if len(chunk) <= self.remaining - 1 and not self.truncated:
                    self.buf += chunk
                    token_ends[-1] = len(self.buf)
                    continue
                return self._truncate_string(
                    start, token_ends, chunk, ellipsis
                )

            if len(chunk) <= self.remaining - 1:
                self.buf += chunk
                token_ends.append(len(self.buf))
                continue

            # A multi-byte escape sequence must never be split; earlier
            # content has to make room for the truncation suffix.
            return self._truncate_string(start, token_ends, None, ellipsis)

        if self.remaining >= 1:
            self.buf += b'"'
            return True
        return self._truncate_string(start, token_ends, None, ellipsis)

    def _truncate_string(
        self,
        start: int,
        token_ends: list[int],
        raw_chunk: bytes | None,
        ellipsis: bytes,
    ) -> bool:
        """
        Finish a string that does not fit by appending a UTF-8-safe prefix of
        *raw_chunk* (if any) and the ``…"`` suffix.

        Returns False (after rolling back the whole string) when an empty,
        shortened string cannot fit either.
        """
        while True:
            room_for_content = self.remaining - 4
            if raw_chunk is not None and room_for_content > 0:
                prefix = _utf8_safe_prefix(raw_chunk, room_for_content)
                if prefix:
                    self.buf += prefix
                    token_ends[-1] = len(self.buf)
            if self.remaining >= 4:
                self.buf += ellipsis
                self.buf += b'"'
                self.truncated = True
                return False
            if len(self.buf) > start + 1 and len(token_ends) > 1:
                end = token_ends.pop()
                del self.buf[end:]
                raw_chunk = None
                continue
            del self.buf[start:]
            self.truncated = True
            return False


def _ordered_keys(
    mapping: Mapping[str, Any],
    priority: Sequence[str],
    *,
    skip: str | None = None,
) -> list[str]:
    """
    Return the keys of *mapping* ordered by *priority*, then insertion order.
    """
    ordered: list[str] = []
    seen: set[Any] = set()
    for key in priority:
        if key in mapping and key not in seen and key != skip:
            ordered.append(key)
            seen.add(key)
    for key in mapping:
        if key not in seen and key != skip:
            ordered.append(key)
    return ordered


def _default_fallback(obj: Any) -> Any:
    """
    Serialize custom datatypes, mirroring structlog.processors' fallback.
    """
    from .threadlocal import _ThreadLocalDictWrapper

    if isinstance(obj, _ThreadLocalDictWrapper):
        return obj._dict

    try:
        return obj.__structlog__()
    except AttributeError:
        return repr(obj)


def _encode_value(
    writer: _Writer,
    value: Any,
    *,
    priority: Sequence[str],
    fallback: Callable[[Any], Any],
    ensure_ascii: bool,
    seen: set[int],
) -> bool:
    """
    Encode *value* into *writer*, returning True when nothing was dropped.
    """
    if value is None:
        return writer.put(b"null")
    if value is True:
        return writer.put(b"true")
    if value is False:
        return writer.put(b"false")

    if isinstance(value, str):
        return writer.write_string(value, ensure_ascii=ensure_ascii)

    if isinstance(value, int):
        # Avoid rendering huge integers that cannot possibly fit.
        if value.bit_length() > 3 * writer.remaining + 1:
            writer.truncated = True
            return False
        return writer.put(repr(value).encode("ascii"))

    if isinstance(value, float):
        if not math.isfinite(value):
            # NaN/Infinity are not valid JSON; null is the smallest safe
            # stand-in.
            if not writer.put(b"null"):
                return False
            writer.truncated = True
            return False
        return writer.put(repr(value).encode("ascii"))

    if isinstance(value, Mapping):
        return _encode_fields(
            writer,
            value,
            priority=priority,
            fallback=fallback,
            ensure_ascii=ensure_ascii,
            seen=seen,
        )

    if isinstance(value, (list, tuple)):
        return _encode_array(
            writer,
            value,
            priority=priority,
            fallback=fallback,
            ensure_ascii=ensure_ascii,
            seen=seen,
        )

    return _encode_fallback(
        writer,
        value,
        priority=priority,
        fallback=fallback,
        ensure_ascii=ensure_ascii,
        seen=seen,
    )


def _encode_fallback(
    writer: _Writer,
    value: Any,
    *,
    priority: Sequence[str],
    fallback: Callable[[Any], Any],
    ensure_ascii: bool,
    seen: set[int],
) -> bool:
    converted = fallback(value)
    if converted is value:
        converted = repr(value)
    if isinstance(converted, str):
        return writer.write_string(converted, ensure_ascii=ensure_ascii)
    return _encode_value(
        writer,
        converted,
        priority=priority,
        fallback=fallback,
        ensure_ascii=ensure_ascii,
        seen=seen,
    )


def _encode_fields(
    writer: _Writer,
    mapping: Mapping[str, Any],
    *,
    priority: Sequence[str],
    fallback: Callable[[Any], Any],
    ensure_ascii: bool,
    seen: set[int],
    skip: str | None = None,
) -> bool:
    if not writer.put(b"{"):
        return False
    complete = _encode_fields_body(
        writer,
        mapping,
        priority=priority,
        fallback=fallback,
        ensure_ascii=ensure_ascii,
        seen=seen,
        skip=skip,
    )
    if writer.buf.endswith(b","):
        del writer.buf[-1]
    if not writer.put(b"}"):
        complete = False
    return complete


def _encode_fields_body(
    writer: _Writer,
    mapping: Mapping[str, Any],
    *,
    priority: Sequence[str],
    fallback: Callable[[Any], Any],
    ensure_ascii: bool,
    seen: set[int],
    skip: str | None = None,
) -> bool:
    complete = True
    identity = id(mapping)
    recursive = identity in seen
    seen.add(identity)

    if recursive:
        # Cyclic structures cannot be represented in JSON; emit a marker
        # instead of recursing forever.
        writer.put(b'"$ref":"cycle"')
        complete = False
    else:
        first = True
        for key in _ordered_keys(mapping, priority, skip=skip):
            value = mapping[key]
            prefix = b"" if first else b","
            # Reserve a colon and the enclosing object's closing brace.
            key_writer = _Writer(writer.remaining - 2)
            key_complete = key_writer.write_string(
                str(key), ensure_ascii=ensure_ascii
            )
            key_bytes = bytes(key_writer.buf)
            if not key_complete:
                complete = False
                continue
            value_budget = (
                writer.remaining - len(prefix) - len(key_bytes) - 1 - 1
            )
            value_writer = _Writer(value_budget)
            value_complete = _encode_value(
                value_writer,
                value,
                priority=priority,
                fallback=fallback,
                ensure_ascii=ensure_ascii,
                seen=seen,
            )
            value_bytes = bytes(value_writer.buf)
            if not value_bytes or not _is_balanced(value_bytes):
                complete = False
                continue
            entry = prefix + key_bytes + b":" + value_bytes
            if len(entry) > writer.remaining - 1:
                complete = False
                continue
            writer.buf += entry
            if not value_complete:
                complete = False
            first = False

    if not recursive:
        seen.discard(identity)
    return complete and not writer.truncated


def _encode_array(
    writer: _Writer,
    sequence: Sequence[Any],
    *,
    priority: Sequence[str],
    fallback: Callable[[Any], Any],
    ensure_ascii: bool,
    seen: set[int],
) -> bool:
    complete = True
    identity = id(sequence)
    recursive = identity in seen
    seen.add(identity)
    if not writer.put(b"["):
        if not recursive:
            seen.discard(identity)
        return False

    if recursive:
        writer.put(b'{"$ref":"cycle"}')
        complete = False
    else:
        first = True
        for value in sequence:
            prefix = b"" if first else b","
            item_writer = _Writer(writer.remaining - len(prefix) - 1)
            item_complete = _encode_value(
                item_writer,
                value,
                priority=priority,
                fallback=fallback,
                ensure_ascii=ensure_ascii,
                seen=seen,
            )
            item_bytes = bytes(item_writer.buf)
            if not item_bytes or not _is_balanced(item_bytes):
                complete = False
                continue
            entry = prefix + item_bytes
            if len(entry) > writer.remaining - 1:
                complete = False
                continue
            writer.buf += entry
            if not item_complete:
                complete = False
            first = False

    if writer.buf.endswith(b","):
        del writer.buf[-1]
    if not writer.put(b"]"):
        complete = False
    if not recursive:
        seen.discard(identity)
    return complete and not writer.truncated


def _failure_record(
    budget: int, note: str, truncated_key: str, *, ensure_ascii: bool
) -> str:
    for key in (truncated_key, _TRUNCATED_KEY):
        writer = _Writer(budget)
        if writer.put(b"{") and writer.write_string(
            key, ensure_ascii=ensure_ascii
        ):
            if writer.put(b":") and writer.write_string(
                note, ensure_ascii=ensure_ascii
            ) and writer.put(b"}"):
                return bytes(writer.buf).decode("utf-8")
    raise AssertionError("budget is too small for the failure record")


class BudgetedJSONRenderer:
    """
    Render an event dict as compact JSON that never exceeds a byte budget.

    The document is built directly inside the budget instead of rendering the
    full event first and then cutting it.  When the event does not fit,
    fields are kept in priority order, nested containers are reduced and long
    strings are shortened with an ellipsis.  Dropped or shortened content is
    reported through a truncation note field.

    Output is valid UTF-8 JSON and its encoded length never exceeds
    *max_bytes*.  The original event dict is never modified.

    Args:
        max_bytes: Upper bound for the size of the rendered document measured
            in UTF-8 bytes.

        priority: Field names in descending priority.  Named fields are
            rendered first, followed by all other fields in their original
            insertion order.  The truncation note field is always rendered
            first when present.

        truncated_key: Name of the field that carries the truncation note.

        fallback: Called for values the renderer does not understand, like
            the *default* argument of :func:`json.dumps`.  Defaults to the
            same ``__structlog__`` / ``repr()`` behavior as
            :class:`~structlog.processors.JSONRenderer`.

        ensure_ascii: Escape all non-ASCII characters when true (the default
            of :func:`json.dumps`).  When false, UTF-8 characters such as
            Chinese text are emitted verbatim, which usually saves budget.

    Raises:
        ValueError: If *max_bytes* is smaller than the minimum failure
            record, since then even the guaranteed fallback output could not
            be produced.

    .. versionadded:: 26.2.0
    """

    def __init__(
        self,
        max_bytes: int,
        priority: Sequence[str] = _DEFAULT_PRIORITY,
        *,
        truncated_key: str = _TRUNCATED_KEY,
        fallback: Callable[[Any], Any] | None = None,
        ensure_ascii: bool = False,
    ) -> None:
        self._priority = tuple(priority)
        self._truncated_key = truncated_key
        self._fallback = fallback or _default_fallback
        self._ensure_ascii = ensure_ascii
        self._max_bytes = int(max_bytes)

        # The smallest guaranteed output: a one-field truncation record.
        minimum = len(
            _failure_record(
                10**9,
                _ERROR_NOTE,
                truncated_key,
                ensure_ascii=ensure_ascii,
            ).encode("utf-8")
        )
        self.MIN_MAX_BYTES = minimum
        if self._max_bytes < minimum:
            msg = (
                "max_bytes must be at least "
                f"{minimum} to hold the minimum failure record, "
                f"got {max_bytes!r}."
            )
            raise ValueError(msg)

    def __call__(
        self, logger: WrappedLogger, name: str, event_dict: EventDict
    ) -> str:
        try:
            return self._render(event_dict)
        except Exception:
            return _failure_record(
                self._max_bytes,
                _ERROR_NOTE,
                self._truncated_key,
                ensure_ascii=self._ensure_ascii,
            )

    def _render(self, event: Any) -> str:
        budget = self._max_bytes
        common = dict(
            priority=self._priority,
            fallback=self._fallback,
            ensure_ascii=self._ensure_ascii,
        )

        if isinstance(event, Mapping):
            note_key = self._truncated_key

            first = _Writer(budget)
            complete = _encode_fields(
                first,
                event,
                skip=None,
                seen=set(),
                **common,
            )
            if complete and not first.truncated:
                return bytes(first.buf).decode("utf-8")

            # Rebuild with the truncation note as the first field.
            writer = _Writer(budget)
            self._open_with_note(writer, note_key, _TRUNCATED_NOTE)
            _encode_fields_body(
                writer,
                event,
                skip=note_key,
                seen=set(),
                **common,
            )
            if writer.buf.endswith(b","):
                del writer.buf[-1]
            if not writer.put(b"}") and len(writer.buf) == 0:
                return _failure_record(
                    budget,
                    _TRUNCATED_NOTE,
                    note_key,
                    ensure_ascii=common["ensure_ascii"],
                )
            return bytes(writer.buf).decode("utf-8")

        writer = _Writer(budget)
        _encode_value(writer, event, seen=set(), **common)
        raw = bytes(writer.buf)
        if raw and _is_balanced(raw):
            # The value could be shortened on its own; a bare, valid JSON
            # scalar is acceptable output without an explanatory object.
            return raw.decode("utf-8")

        # Nothing renderable on its own: emit the minimum failure record.
        return _failure_record(
            budget,
            _TRUNCATED_NOTE,
            self._truncated_key,
            ensure_ascii=common["ensure_ascii"],
        )

    def _open_with_note(self, writer: _Writer, key: str, note: str) -> None:
        """
        Write ``{"key":"note"`` into *writer*, shortening *note* as needed.

        At least one trailing byte remains for the closing brace.
        """
        ensure_ascii = self._ensure_ascii
        if not writer.put(b"{"):
            return
        # Reserve a colon and the final brace.
        key_writer = _Writer(writer.remaining - 2)
        if not key_writer.write_string(key, ensure_ascii=ensure_ascii):
            return
        writer.buf += bytes(key_writer.buf)
        if not writer.put(b":"):
            return
        # The note string carries its own quotes; reserve the closing brace.
        note_writer = _Writer(writer.remaining - 1)
        note_writer.write_string(note, ensure_ascii=ensure_ascii)
        writer.buf += bytes(note_writer.buf)
        if writer.remaining > 1:
            writer.buf += b","
