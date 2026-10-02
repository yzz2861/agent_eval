from __future__ import annotations

import json as _json
import math
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


def _ecma_number_to_string(value: float) -> str:
    """Serialize a finite double per RFC 8785 section 4.2.3.

    Python's ``repr`` already produces the shortest decimal that rounds
    back to the same IEEE 754 double (the ECMAScript ``Number::toString``
    "shortest representation" requirement). The mantissa is re-parsed
    and the exponent formatted with ECMAScript conventions: scientific
    notation is used when ``e <= -7`` or ``e >= 21``.
    """
    # Negative zero is serialized as zero.
    if value == 0.0:
        return "0"

    negative = value < 0.0
    raw = repr(abs(value))

    if "e" in raw:
        mantissa, exp_text = raw.split("e", 1)
        repr_exp = int(exp_text)
    else:
        mantissa = raw
        repr_exp = 0

    if "." in mantissa:
        int_part, frac_part = mantissa.split(".", 1)
    else:
        int_part, frac_part = mantissa, ""

    all_digits = int_part + frac_part
    # Position of the decimal point after applying the repr exponent.
    point = len(int_part) + repr_exp
    first = len(all_digits) - len(all_digits.lstrip("0"))
    # Decimal exponent relative to the first significant digit.
    exp = point - first - 1
    digits = all_digits[first:].rstrip("0")

    if exp >= 21 or exp <= -7:
        if len(digits) > 1:
            out = f"{digits[0]}.{digits[1:]}e{exp:+d}"
        else:
            out = f"{digits[0]}e{exp:+d}"
    elif exp < 0:
        # Decimal point is before the first significant digit.
        out = "0." + "0" * (-exp - 1) + digits
    elif exp + 1 >= len(digits):
        out = digits + "0" * (exp + 1 - len(digits))
    else:
        out = f"{digits[: exp + 1]}.{digits[exp + 1 :]}"

    if negative:
        out = "-" + out

    return out


_BACKSLASH = chr(0x5C)
_ESCAPE_MAP = {
    chr(0x08): _BACKSLASH + "b",  # backspace
    chr(0x0C): _BACKSLASH + "f",  # form feed
    chr(0x0A): _BACKSLASH + "n",  # line feed
    chr(0x0D): _BACKSLASH + "r",  # carriage return
    chr(0x09): _BACKSLASH + "t",  # tab
    chr(0x22): _BACKSLASH + chr(0x22),  # quotation mark
    chr(0x5C): _BACKSLASH * 2,  # reverse solidus
}


def _serialize_string(value: str) -> str:
    parts: list[str] = ['"']

    for ch in value:
        code = ord(ch)
        escaped = _ESCAPE_MAP.get(ch)

        if escaped is not None:
            parts.append(escaped)
        elif code <= 0x1F:
            parts.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError(
                "Canonical JSON cannot serialize strings containing lone"
                " UTF-16 surrogate characters."
            )
        else:
            parts.append(ch)

    parts.append('"')
    return "".join(parts)


def _utf16_key(key: str) -> bytes:
    """UTF-16BE code units, which sort identically to the UTF-16 code
    unit sequence required by RFC 8785 section 4.2.1."""
    try:
        return key.encode("utf-16-be")
    except UnicodeEncodeError as e:
        raise ValueError(
            "Canonical JSON object keys must not contain lone UTF-16"
            " surrogate characters."
        ) from e


def _check_number_domain(value: int) -> None:
    # The declared numeric domain is ECMAScript's IEEE 754 double set.
    # Integers outside it must not be silently rounded.
    try:
        as_float = float(value)
    except OverflowError as e:
        raise ValueError(
            f"Integer {value} is outside the IEEE 754 double range."
        ) from e

    if not math.isfinite(as_float) or int(as_float) != value:
        raise ValueError(
            f"Integer {value} cannot be represented exactly as an IEEE"
            " 754 double; refusing to round it."
        )


class CanonicalJSONSerializer:
    """JSON serializer implementing RFC 8785 (JSON Canonicalization
    Scheme).

    The canonical form sorts object members by UTF-16 code unit,
    serializes numbers as ECMAScript ``Number`` values (including
    negative zero as ``0``), escapes strings per section 4.2.2 and has
    no insignificant whitespace. It produces the same bytes for every
    conforming implementation regardless of language, so signatures
    computed over its output are interoperable.

    Non-finite numbers, integers outside the IEEE 754 double domain,
    and lone UTF-16 surrogate characters are rejected instead of
    producing ambiguous output.

    Pass the class (or an instance) as the ``serializer`` argument of
    :class:`~itsdangerous.serializer.Serializer`::

        from itsdangerous import CanonicalJSONSerializer, Serializer

        s = Serializer("secret-key", serializer=CanonicalJSONSerializer)

    .. versionadded:: 2.3.0
    """

    @staticmethod
    def loads(payload: str | bytes | bytearray) -> t.Any:
        """Parse JSON, explicitly rejecting duplicate object keys."""

        def object_hook(pairs: list[tuple[str, t.Any]]) -> dict[str, t.Any]:
            result: dict[str, t.Any] = {}

            for key, value in pairs:
                if key in result:
                    raise ValueError(
                        f"Duplicate JSON object key {key!r} is not allowed."
                    )

                result[key] = value

            return result

        def reject_constant(value: str) -> t.Any:
            raise ValueError(f"Non-finite JSON number {value} is not allowed.")

        result = _json.loads(
            payload, object_pairs_hook=object_hook, parse_constant=reject_constant
        )
        _validate_loaded(result)
        return result

    @staticmethod
    def dumps(obj: t.Any, **kwargs: t.Any) -> str:
        """Serialize to the canonical RFC 8785 form."""
        if kwargs:
            raise TypeError(
                "Canonical JSON serialization does not accept options: "
                f"{', '.join(sorted(kwargs))}"
            )

        return _canonical_serialize(obj, set())


def _canonical_serialize(obj: t.Any, seen: set[int]) -> str:
    if obj is None:
        return "null"

    if obj is True:
        return "true"

    if obj is False:
        return "false"

    if isinstance(obj, str):
        return _serialize_string(obj)

    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise ValueError("Canonical JSON cannot serialize non-finite numbers.")

        return _ecma_number_to_string(obj)

    if isinstance(obj, int):
        _check_number_domain(obj)
        return str(obj)

    if isinstance(obj, t.Mapping):
        obj_id = id(obj)

        if obj_id in seen:
            raise ValueError("Circular reference detected.")

        seen.add(obj_id)

        try:
            entries = []

            for key, value in obj.items():
                if not isinstance(key, str):
                    raise TypeError(
                        "Canonical JSON object keys must be strings, got"
                        f" {type(key).__name__}."
                    )

                entries.append((_utf16_key(key), key, value))

            entries.sort(key=lambda item: item[0])
            parts = ["{"]
            first = True

            for _, key, value in entries:
                if not first:
                    parts.append(",")

                first = False
                parts.append(_serialize_string(key))
                parts.append(":")
                parts.append(_canonical_serialize(value, seen))

            parts.append("}")
        finally:
            seen.discard(obj_id)

        return "".join(parts)

    if isinstance(obj, (list, tuple)):
        obj_id = id(obj)

        if obj_id in seen:
            raise ValueError("Circular reference detected.")

        seen.add(obj_id)

        try:
            items = [_canonical_serialize(item, seen) for item in obj]
        finally:
            seen.discard(obj_id)

        return "[" + ",".join(items) + "]"

    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _validate_loaded(obj: t.Any) -> None:
    """Reject lone surrogates that may come from surrogate-escaped JSON."""
    if isinstance(obj, str):
        for ch in obj:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise ValueError(
                    "Canonical JSON cannot deserialize strings containing"
                    " lone UTF-16 surrogate characters."
                )
    elif isinstance(obj, t.Mapping):
        for key, value in obj.items():
            _validate_loaded(key)
            _validate_loaded(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_loaded(item)
