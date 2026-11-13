"""
   The MIT License (MIT)

   Copyright (C) 2026 Joe Testa (jtesta@positronsecurity.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import csv
import io
import json
import re

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class ResultEncoder:
    '''Unified encoding layer for audit results.

    All output formats (JSON, CSV, terminal text) are encoded from the same
    structured result (see ssh_audit.build_struct()); no format re-parses the
    banner or any other raw protocol data on its own.

    Encoding rules:

      * JSON: raw Unicode is preserved (ensure_ascii=False), but NUL
        characters and unpaired surrogates are rejected with ValueError.

      * CSV: fields are quoted per RFC 4180 (via the csv module), and values
        beginning with one of '=', '+', '-', '@' are prefixed with an
        apostrophe to prevent spreadsheet formula injection.  To recover the
        original value, strip one leading apostrophe when the character after
        it is one of those four.

      * Terminal: C0/C1 control characters (except newline, which carries the
        line structure), DEL, unpaired surrogates, and Unicode bidi/format
        characters are rendered as visible, reversible escape sequences
        (backslash-t, backslash-r, backslash-xNN, backslash-uXXXX).

    All formats redact sensitive fields (private keys, passwords, secrets,
    tokens, credentials, raw handshake/packet data) and truncate overlong
    fields with a visible marker.'''

    MAX_FIELD_LENGTH = 2048
    TRUNCATION_MARKER = '...[truncated]'
    REDACTED_VALUE = '[REDACTED]'

    # Keys (anywhere in the structure) whose values must never appear in a report.
    SENSITIVE_KEY_RX = re.compile(r'private[_-]?key|password|passwd|secret|token|credential|handshake|raw[_-]?packet|kexinit|payload', re.IGNORECASE)

    # Spreadsheet formula prefixes that must be neutralized in CSV output.
    FORMULA_PREFIXES = ('=', '+', '-', '@')
    FORMULA_GUARD = "'"

    # Unicode bidi / zero-width format characters that can visually corrupt terminal output (e.g.: U+202E RIGHT-TO-LEFT OVERRIDE).
    BIDI_FORMAT_CHARS = frozenset(
        [0x00ad, 0x061c, 0x200e, 0x200f, 0xfeff]
        + list(range(0x202a, 0x202f))
        + list(range(0x2066, 0x206a))
    )

    @classmethod
    def truncate(cls, text: str, max_length: Optional[int] = None) -> str:
        '''Truncates an overlong string and appends a visible marker.'''
        limit = cls.MAX_FIELD_LENGTH if max_length is None else max_length
        if len(text) <= limit:
            return text
        return text[:limit] + cls.TRUNCATION_MARKER

    @classmethod
    def sanitize_struct(cls, value: Any) -> Any:
        '''Returns a sanitized copy of a structured result: values under sensitive keys are redacted, and overlong strings are truncated and marked.'''
        if isinstance(value, dict):
            sanitized = {}
            for k, v in value.items():
                if cls.SENSITIVE_KEY_RX.search(str(k)) is not None:
                    sanitized[k] = cls.REDACTED_VALUE
                else:
                    sanitized[k] = cls.sanitize_struct(v)
            return sanitized
        if isinstance(value, (list, tuple)):
            return [cls.sanitize_struct(item) for item in value]
        if isinstance(value, str):
            return cls.truncate(value)
        return value

    @classmethod
    def validate_json_safe(cls, value: Any, path: str = '$') -> None:
        '''Raises ValueError if any string in the structure contains a NUL character or an unpaired surrogate.'''
        if isinstance(value, str):
            for ch in value:
                code = ord(ch)
                if code == 0:
                    raise ValueError('NUL character is not allowed in JSON output (at %s)' % path)
                if 0xd800 <= code <= 0xdfff:
                    raise ValueError('unpaired surrogate U+%04X is not allowed in JSON output (at %s)' % (code, path))
        elif isinstance(value, dict):
            for k, v in value.items():
                cls.validate_json_safe(str(k), path)
                cls.validate_json_safe(v, '%s.%s' % (path, k))
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                cls.validate_json_safe(item, '%s[%d]' % (path, i))

    @classmethod
    def to_json(cls, res: Any, indent: Optional[int] = None, sort_keys: bool = True) -> str:
        '''Encodes a structured result as JSON.  Raw Unicode is preserved; NUL characters and unpaired surrogates are rejected.'''
        sanitized = cls.sanitize_struct(res)
        cls.validate_json_safe(sanitized)
        return json.dumps(sanitized, indent=indent, sort_keys=sort_keys, ensure_ascii=False)

    @classmethod
    def escape_terminal(cls, text: str) -> str:
        '''Renders control characters, unpaired surrogates, and Unicode bidi/format characters as visible escape sequences.  Newlines are preserved, since they carry the line structure of the output.'''
        out = []
        for ch in text:
            code = ord(ch)
            if ch == '\n':
                out.append(ch)
            elif ch == '\t':
                out.append('\\t')
            elif ch == '\r':
                out.append('\\r')
            elif code < 0x20 or code == 0x7f or 0x80 <= code <= 0x9f:
                out.append('\\x%02x' % code)
            elif code in cls.BIDI_FORMAT_CHARS or 0xd800 <= code <= 0xdfff:
                out.append('\\u%04x' % code)
            else:
                out.append(ch)
        return ''.join(out)

    @classmethod
    def csv_safe_field(cls, value: str) -> str:
        '''Prefixes a leading apostrophe to values that start with a spreadsheet formula prefix ('=', '+', '-', '@').  Reversible: strip one leading apostrophe when the following character is a formula prefix.'''
        if len(value) > 0 and value.startswith(cls.FORMULA_PREFIXES):
            return cls.FORMULA_GUARD + value
        return value

    @classmethod
    def _scalar_to_text(cls, value: Any) -> str:
        if value is None:
            return ''
        if isinstance(value, bool):
            return 'true' if value else 'false'
        return str(value)

    @classmethod
    def flatten_struct(cls, value: Any, path: str = '') -> Iterable[Tuple[str, Any]]:
        '''Flattens a structured result into (field_path, value) pairs, preserving the structure field order.  Empty containers yield a row with an empty value so that downstream consumers can distinguish present-but-empty from missing fields.'''
        if isinstance(value, dict):
            if len(value) == 0:
                yield (path, '')
            for k, v in value.items():
                child_path = '%s.%s' % (path, k) if len(path) > 0 else str(k)
                yield from cls.flatten_struct(v, child_path)
        elif isinstance(value, (list, tuple)):
            if len(value) == 0:
                yield (path, '')
            for i, item in enumerate(value):
                yield from cls.flatten_struct(item, '%s[%d]' % (path, i))
        else:
            yield (path, value)

    @classmethod
    def to_csv(cls, res: Any) -> str:
        '''Encodes a structured result as CSV (RFC 4180 quoting, CRLF line endings), with spreadsheet formula-injection protection on every field.'''
        sanitized = cls.sanitize_struct(res)
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator='\r\n')
        writer.writerow(['field', 'value'])
        for path, value in cls.flatten_struct(sanitized):
            writer.writerow([cls.csv_safe_field(path), cls.csv_safe_field(cls._scalar_to_text(value))])
        return buf.getvalue()
