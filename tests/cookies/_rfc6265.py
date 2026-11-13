"""Minimal RFC 6265bis ``Set-Cookie`` parser used to verify serialized output.

The stdlib ``http.cookies`` module predates RFC 6265: it silently discards
cookies carrying modern attributes such as ``Partitioned`` and rejects
non-ASCII values. This helper implements the attribute-collection rules from
RFC 6265bis section 5.3 so tests can assert the exact attribute set a
standards-compliant user agent would observe.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedSetCookie:
    name: str
    value: str
    attributes: dict[str, str | bool] = field(default_factory=dict)

    def attribute_names(self) -> set[str]:
        return set(self.attributes)

    def has(self, attribute: str) -> bool:
        return attribute.lower() in self.attributes


_BOOLEAN_ATTRIBUTES = frozenset({"secure", "httponly", "partitioned"})


def parse_set_cookie(header_value: str) -> ParsedSetCookie:
    """Parse a serialized ``Set-Cookie`` header value per RFC 6265bis grammar."""
    pieces = [piece.strip() for piece in header_value.split(";")]
    if not pieces or not pieces[0] or "=" not in pieces[0]:
        raise ValueError("Set-Cookie header must start with name=value")

    name, value = pieces[0].split("=", 1)
    parsed = ParsedSetCookie(name=name, value=value)

    for piece in pieces[1:]:
        if not piece:
            raise ValueError("empty cookie attribute")
        if "=" in piece:
            attr_name, attr_value = piece.split("=", 1)
            key = attr_name.strip().lower()
            if key in _BOOLEAN_ATTRIBUTES:
                raise ValueError(f"attribute {attr_name!r} must not carry a value")
            parsed.attributes[key] = attr_value.strip()
        else:
            key = piece.lower()
            if key not in _BOOLEAN_ATTRIBUTES:
                raise ValueError(f"unknown valueless cookie attribute {piece!r}")
            parsed.attributes[key] = True

    return parsed
