from __future__ import annotations

from secure._internal.constants import HEADER_NAME_RE

# Stable rule identifiers used in error messages. Exceptions raised by this
# module contain only the header name and the rule id; header values are never
# echoed back (they may contain attacker-controlled input such as CRLF).
RULE_HEADER_NAME = "SEC-HDR-NAME"
RULE_HEADER_VALUE = "SEC-HDR-VALUE"
RULE_HEADER_ENCODING = "SEC-HDR-ENCODING"
RULE_HEADER_SET = "SEC-HDR-SET"

_HORIZONTAL_TAB = 0x09
_C0_CONTROL_MAX = 0x1F
_DELETE = 0x7F
_C1_CONTROL_MIN = 0x80
_C1_CONTROL_MAX = 0x9F


def _is_forbidden_value_char(char: str) -> bool:
    """
    Return True for characters that can break HTTP field boundaries.

    Forbidden: C0 controls (including CR, LF, NUL) except horizontal tab,
    DEL, and the C1 control range. Everything else (visible ASCII, internal
    spaces, latin-1 supplement letters, and non-latin-1 text such as CJK
    display names) is syntactically acceptable at this layer.
    """
    codepoint = ord(char)
    if codepoint == _HORIZONTAL_TAB:
        return False
    return codepoint <= _C0_CONTROL_MAX or codepoint == _DELETE or _C1_CONTROL_MIN <= codepoint <= _C1_CONTROL_MAX


def validate_header_name(name: str, *, what: str = "header name") -> str:
    """
    Validate an HTTP header field-name as an RFC 9110 token.

    Args:
        name: Raw header name.
        what: Description of the name (used for error messages).

    Returns:
        The stripped header name.

    Raises:
        ValueError: If the name is not a valid token. The message contains
            only the (repr-escaped) name and a rule id.
    """
    stripped = name.strip()
    if not HEADER_NAME_RE.match(stripped):
        raise ValueError(f"Invalid {what} {stripped!r} (rule {RULE_HEADER_NAME}): must be an RFC 9110 token")
    return stripped


def validate_header_value(value: str, *, header_name: str) -> str:
    """
    Validate an HTTP header field-value against field-boundary attacks.

    Rejects CR, LF, NUL, and other control characters (C0 except tab, DEL,
    and C1). Allows visible ASCII, internal spaces/tabs, latin-1 supplement
    characters, and non-latin-1 text.

    Args:
        value: Raw header value.
        header_name: Name of the header (used for error messages).

    Returns:
        The value unchanged.

    Raises:
        ValueError: If a forbidden control character is present. The message
            contains only the header name and a rule id, never the value.
    """
    for char in value:
        if _is_forbidden_value_char(char):
            raise ValueError(
                f"Invalid value for header {header_name!r} (rule {RULE_HEADER_VALUE}): forbidden control character"
            )
    return value


def validate_header_value_encoding(value: str, *, header_name: str) -> str:
    """
    Validate that a header value is encodable for the HTTP wire (latin-1).

    Both WSGI (PEP 3333 string headers) and ASGI (bytes headers) transport
    header values as latin-1, so this shared check keeps the accept/reject
    outcome identical across the two middleware paths.

    Args:
        value: Header value (already syntax-validated).
        header_name: Name of the header (used for error messages).

    Returns:
        The value unchanged.

    Raises:
        ValueError: If the value is not latin-1 encodable. The message
            contains only the header name and a rule id, never the value.
    """
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError(
            f"Invalid value for header {header_name!r} (rule {RULE_HEADER_ENCODING}): not encodable as latin-1"
        ) from None
    return value


def validate_wire_header(name: str, value: str) -> tuple[str, str]:
    """
    Validate a ``(name, value)`` pair for emission on the HTTP wire.

    Applies the shared name token check, the value control-character check,
    and the latin-1 encodability check so that WSGI and ASGI emission reach
    the same accept/reject conclusion for the same logical header list.

    Returns:
        The ``(stripped_name, value)`` pair.

    Raises:
        ValueError: If the pair is invalid (name and rule id only).
    """
    checked_name = validate_header_name(name)
    checked_value = validate_header_value(value, header_name=checked_name)
    validate_header_value_encoding(checked_value, header_name=checked_name)
    return checked_name, checked_value


def normalize_header_value(value: str, *, what: str = "header value") -> str:
    """
    Trim whitespace and reject control characters in header strings.

    Args:
        value: Raw header string.
        what: Description of the value (used for error messages).

    Returns:
        The stripped string without CR/LF or other control characters.

    Raises:
        ValueError: If CR, LF, NUL, or other field-boundary-breaking control
            characters are present. The message contains a rule id and never
            echoes the offending value.
    """
    stripped = value.strip()
    try:
        validate_header_value(stripped, header_name=what)
    except ValueError:
        raise ValueError(f"{what} must not contain CR/LF or control characters (rule {RULE_HEADER_VALUE})") from None
    return stripped
