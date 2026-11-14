"""
requests._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are consumed internally by Requests
which depend on extremely few external helpers (such as compat)
"""

import re

from .compat import builtin_str

_VALID_HEADER_NAME_RE_BYTE = re.compile(rb"^[^:\s][^:\r\n]*\Z")
_VALID_HEADER_NAME_RE_STR = re.compile(r"^[^:\s][^:\r\n]*\Z")
_VALID_HEADER_VALUE_RE_BYTE = re.compile(rb"^\S[^\r\n]*\Z|^\Z")
_VALID_HEADER_VALUE_RE_STR = re.compile(r"^\S[^\r\n]*\Z|^\Z")

_HEADER_VALIDATORS_STR = (_VALID_HEADER_NAME_RE_STR, _VALID_HEADER_VALUE_RE_STR)
_HEADER_VALIDATORS_BYTE = (_VALID_HEADER_NAME_RE_BYTE, _VALID_HEADER_VALUE_RE_BYTE)
HEADER_VALIDATORS = {
    bytes: _HEADER_VALIDATORS_BYTE,
    str: _HEADER_VALIDATORS_STR,
}

# Characters that may never appear verbatim in a request field that is placed
# on the wire: the NUL byte, the other ASCII control characters and DEL.
# CR and LF are part of this range, so a single check covers request smuggling
# via bare carriage returns and line feeds.
_CONTROL_CHAR_RE_STR = re.compile(r"[\x00-\x1f\x7f]")
_CONTROL_CHAR_RE_BYTE = re.compile(rb"[\x00-\x1f\x7f]")


def contains_control_characters(value: str | bytes) -> bool:
    """Return ``True`` if ``value`` contains a bare NUL, CR, LF, tab or any
    other ASCII control character (including DEL).

    Percent-encoded sequences such as ``%0d`` are left untouched: only raw,
    unencoded control characters are considered dangerous.
    """
    if isinstance(value, bytes):
        return _CONTROL_CHAR_RE_BYTE.search(value) is not None
    return _CONTROL_CHAR_RE_STR.search(value) is not None


def is_valid_method_token(method: str) -> bool:
    """Validate an HTTP request token (method) before it is sent.

    HTTP methods are ``token`` values per RFC 9110 and therefore must not
    contain whitespace or control characters.
    """
    if not isinstance(method, str) or not method:
        return False
    if contains_control_characters(method):
        return False
    return all(ch != " " for ch in method)


def to_native_string(string: str | bytes, encoding: str = "ascii") -> str:
    """Given a string object, regardless of type, returns a representation of
    that string in the native string type, encoding and decoding where
    necessary. This assumes ASCII unless told otherwise.
    """
    if isinstance(string, builtin_str):
        out = string
    else:
        out = string.decode(encoding)

    return out


def unicode_is_ascii(u_string: str) -> bool:
    """Determine if unicode string only contains ASCII characters.

    :param str u_string: unicode string to check. Must be unicode
        and not Python 2 `str`.
    :rtype: bool
    """
    assert isinstance(u_string, str)
    try:
        u_string.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False
