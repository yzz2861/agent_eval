from __future__ import annotations

import json as _json
import math as _math
import typing as t


class _CompactJSON:
    """Wrapper around json module that strips whitespace."""

    @staticmethod
    def loads(payload: str | bytes) -> t.Any:
        return _json.loads(payload)

    @staticmethod
    def dumps(obj: t.Any, **kwargs: t.Any) -> str:
        kwargs.setdefault("ensure_ascii", False)
        kwargs.setdefault("separators", (",", ":"))
        return _json.dumps(obj, **kwargs)


# RFC 8785 declares the input number domain to be IEEE 754 double
# precision. Integers with a magnitude beyond 2**53 are not guaranteed
# to be exactly representable in that domain, so they are rejected
# rather than silently rounded.
_MAX_SAFE_INT = 2**53

_JCS_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _jcs_encode_string(value: str) -> str:
    """Escape a string as required by RFC 8785, section 3.2.2.2. Only
    the mandatory two-character escapes and `\\u00xx` for other
    control characters are used, everything else is emitted literally.
    """
    chunks = ['"']

    for char in value:
        code = ord(char)
        escape = _JCS_ESCAPES.get(code)

        if escape is not None:
            chunks.append(escape)
        elif code < 0x20:
            chunks.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("RFC 8785: lone surrogate code points are not valid input")
        else:
            chunks.append(char)

    chunks.append('"')
    return "".join(chunks)


def _jcs_encode_float(value: float) -> str:
    """Format a float using the ECMAScript `Number::toString`
    algorithm required by RFC 8785, section 3.2.2.3. `repr` already
    produces the shortest round-trip digits, only the notation differs.
    """
    if not _math.isfinite(value):
        raise ValueError("RFC 8785: non-finite numbers are not valid input")

    if value == 0:
        # Also normalizes negative zero.
        return "0"

    sign = ""

    if value < 0:
        sign = "-"
        value = -value

    mantissa, _, exponent = repr(value).partition("e")
    exp = int(exponent) if exponent else 0
    int_part, _, frac_part = mantissa.partition(".")
    digits = (int_part + frac_part).lstrip("0")
    # value == int(digits) * 10 ** (n - k), where n is the ECMAScript
    # decimal exponent and k is the digit count after stripping
    # insignificant trailing zeros.
    n = exp - len(frac_part) + len(digits)
    digits = digits.rstrip("0")
    k = len(digits)

    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        out = f"0.{'0' * -n}{digits}"
    else:
        if k == 1:
            out = digits
        else:
            out = f"{digits[0]}.{digits[1:]}"

        e = n - 1
        out += f"e+{e}" if e >= 0 else f"e-{abs(e)}"

    return sign + out


def _jcs_utf16_sort_key(key: str) -> bytes:
    """Sort object keys by their UTF-16 code units, as required by RFC
    8785, section 3.2.3. This differs from code point order for
    supplementary plane characters.
    """
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError:
        raise ValueError(
            "RFC 8785: lone surrogate code points are not valid input"
        ) from None


def _jcs_sort_key_checked(key: t.Any) -> bytes:
    if not isinstance(key, str):
        raise TypeError(
            f"RFC 8785: object keys must be strings, got {type(key).__name__}"
        )

    return _jcs_utf16_sort_key(key)


def _jcs_serialize(value: t.Any) -> str:
    if value is None:
        return "null"

    if value is True:
        return "true"

    if value is False:
        return "false"

    if isinstance(value, str):
        return _jcs_encode_string(value)

    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise ValueError(
                "RFC 8785: integers must be within the exactly"
                f" representable range ±2**53, got {value}"
            )

        return str(value)

    if isinstance(value, float):
        return _jcs_encode_float(value)

    if isinstance(value, (list, tuple)):
        return f"[{','.join(_jcs_serialize(item) for item in value)}]"

    if isinstance(value, dict):
        items = []

        for key in sorted(value, key=_jcs_sort_key_checked):
            items.append(f"{_jcs_encode_string(key)}:{_jcs_serialize(value[key])}")

        return f"{{{','.join(items)}}}"

    raise TypeError(
        f"RFC 8785: object of type {type(value).__name__} is not serializable"
    )


def _jcs_no_duplicates(pairs: list[tuple[str, t.Any]]) -> dict[str, t.Any]:
    obj: dict[str, t.Any] = {}

    for key, value in pairs:
        if key in obj:
            raise ValueError(f"RFC 8785: duplicate object key {key!r}")

        obj[key] = value

    return obj


def _jcs_reject_constant(value: str) -> t.NoReturn:
    raise ValueError(f"RFC 8785: {value!r} is not valid JSON")


class RFC8785JSON:
    """JSON serializer implementing the JSON Canonicalization Scheme
    (JCS) from :rfc:`8785`. Produces a deterministic output that is
    suitable for signing and comparing across platforms and languages:
    object keys are sorted by UTF-16 code units, numbers use the
    ECMAScript `Number::toString` representation, and only the
    mandatory string escapes are used.

    Input is restricted to the domain declared by the RFC. Non-finite
    numbers, lone surrogates, integers outside ±2**53, and non-string
    object keys are rejected. `loads` rejects duplicate object keys
    and non-JSON constants such as `NaN`.

    Pass it as the `serializer` argument to
    :class:`~itsdangerous.serializer.Serializer`::

        serializer = Serializer("secret", serializer=RFC8785JSON)
    """

    @staticmethod
    def loads(payload: str | bytes) -> t.Any:
        return _json.loads(
            payload,
            object_pairs_hook=_jcs_no_duplicates,
            parse_constant=_jcs_reject_constant,
        )

    @staticmethod
    def dumps(obj: t.Any) -> str:
        return _jcs_serialize(obj)
