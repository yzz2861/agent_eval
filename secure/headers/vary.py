# Security header recommendations and information from the MDN Web Docs.
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
#
# Vary by Mozilla Contributors is licensed under CC-BY-SA 2.5.
# https://developer.mozilla.org/en-US/docs/MDN/Community/Roles_teams#contributor
# https://creativecommons.org/licenses/by-sa/2.5/

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import ClassVar

from secure.headers._validation import normalize_header_value
from secure.headers.base_header import BaseHeader, HeaderDefaultValue, HeaderName

_FIELD_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def split_vary_value(value: str) -> list[str]:
    """Split a ``Vary`` header value into field names, preserving token spelling."""
    cleaned = normalize_header_value(value, what="Vary value")
    if not cleaned:
        return []

    fields: list[str] = []
    for raw in cleaned.split(","):
        raw_field = raw.strip()
        if not raw_field:
            continue
        if raw_field == "*":
            fields.append("*")
            continue
        if not _FIELD_NAME_RE.match(raw_field):
            raise ValueError(f"Invalid Vary field name {raw_field!r}")
        fields.append(raw_field)
    return fields


@dataclass
class Vary(BaseHeader):
    """
    Fluent builder for the `Vary` HTTP response header.

    Default header value: `Accept-Encoding`

    Notes:
        * Field names are case-insensitive for response-cache matching. This
          builder de-duplicates them case-insensitively while keeping the first
          spelling it was given.
        * ``*`` means the response cannot be reused without revalidation. When
          present, it is emitted on its own because additional field names have
          no effect.
        * ``merge()`` adds field names from an existing header value instead of
          replacing them, which is useful when a framework already added
          ``Accept-Encoding``.

    Resources:
        - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
    """

    header_name: str = field(init=False, default=HeaderName.VARY.value, repr=False)

    _fields: list[str] = field(default_factory=list)
    _raw_value: str | None = None
    _default_value: str = field(init=False, default=HeaderDefaultValue.VARY.value, repr=False)

    _CANONICAL_ORDER: ClassVar[tuple[str, ...]] = (
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Cookie",
        "Origin",
        "User-Agent",
    )

    @property
    def header_value(self) -> str:
        """Return the current `Vary` header value, or the default if unset."""
        if self._raw_value is not None:
            return self._raw_value

        if not self._fields:
            return self._default_value

        if "*" in self._fields:
            return "*"

        canonical: list[str] = []
        known_lc = {name.lower() for name in self._CANONICAL_ORDER}
        by_lc = {name.lower(): name for name in self._fields}

        canonical.extend(name for name in self._CANONICAL_ORDER if name.lower() in by_lc)
        canonical.extend(by_lc[name] for name in sorted((n for n in by_lc if n not in known_lc), key=str.lower))

        return ", ".join(canonical)

    def _ensure_field_mode(self) -> None:
        if self._raw_value is not None:
            self._raw_value = None

    def _add_field(self, field_name: str) -> None:
        self._ensure_field_mode()
        raw_field = field_name.strip()
        if not raw_field:
            raise ValueError("Vary field name must not be empty")
        if raw_field != "*" and not _FIELD_NAME_RE.match(raw_field):
            raise ValueError(f"Invalid Vary field name {raw_field!r}")

        if "*" in self._fields:
            return
        if raw_field == "*":
            self._fields[:] = ["*"]
            return

        lowered = raw_field.lower()
        if any(existing.lower() == lowered for existing in self._fields):
            return
        self._fields.append(raw_field)

    # -------------------------------------------------------------------------
    # Builder API
    # -------------------------------------------------------------------------

    def add(self, *field_names: str) -> Vary:
        """Add one or more field names, each of which may be comma-separated."""
        for field_name in field_names:
            for token in split_vary_value(field_name):
                self._add_field(token)
        return self

    def field(self, *field_names: str) -> Vary:
        """Alias for :meth:`add`."""
        return self.add(*field_names)

    def custom(self, *field_names: str) -> Vary:
        """Alias for :meth:`add`, provided for parity with other builders."""
        return self.add(*field_names)

    def accept(self) -> Vary:
        """Vary on the ``Accept`` request header."""
        return self.add("Accept")

    def accept_encoding(self) -> Vary:
        """Vary on the ``Accept-Encoding`` request header."""
        return self.add("Accept-Encoding")

    def accept_language(self) -> Vary:
        """Vary on the ``Accept-Language`` request header."""
        return self.add("Accept-Language")

    def authorization(self) -> Vary:
        """Vary on the ``Authorization`` request header."""
        return self.add("Authorization")

    def cookie(self) -> Vary:
        """Vary on the ``Cookie`` request header."""
        return self.add("Cookie")

    def origin(self) -> Vary:
        """Vary on the ``Origin`` request header."""
        return self.add("Origin")

    def user_agent(self) -> Vary:
        """Vary on the ``User-Agent`` request header."""
        return self.add("User-Agent")

    def any(self) -> Vary:
        """Use ``*``, making a stored response unusable without revalidation."""
        return self.add("*")

    def merge(self, value: str | Vary | None) -> Vary:
        """Merge field names from an existing value (or another builder)."""
        if value is None:
            return self
        source = value.header_value if isinstance(value, Vary) else value
        for token in split_vary_value(source):
            self._add_field(token)
        return self

    def merge_header(self, value: str | None) -> Vary:
        """Alias for :meth:`merge`."""
        return self.merge(value)

    def value(self, value: str) -> Vary:
        """Set an explicit header value, replacing all configured fields."""
        cleaned = normalize_header_value(value, what="Vary value")
        if not cleaned:
            raise ValueError("Vary value must not be empty")
        fields = split_vary_value(cleaned)
        self._raw_value = ", ".join(fields)
        self._fields.clear()
        return self

    def set(self, value: str) -> Vary:
        """Alias for :meth:`value`."""
        return self.value(value)

    def clear(self) -> Vary:
        """Clear all fields and return to the library default."""
        self._raw_value = None
        self._fields.clear()
        return self

    @classmethod
    def parse(cls, value: str) -> Vary:
        """Create a builder from an existing ``Vary`` header value."""
        builder = cls()
        if value and value.strip():
            builder._raw_value = None
            for token in split_vary_value(value):
                builder._add_field(token)
        return builder

    @classmethod
    def from_value(cls, value: str) -> Vary:
        """Alias for :meth:`parse`."""
        return cls.parse(value)


def merge_vary_values(values: list[str], additions: list[str]) -> str:
    """
    Merge all existing ``Vary`` values with additional field names.

    Existing values are preserved in the order supplied. Duplicate field names
    are removed case-insensitively, and ``*`` dominates the result.
    """
    merged = Vary()
    for value in values:
        for token in split_vary_value(value):
            merged._add_field(token)
    for value in additions:
        for token in split_vary_value(value):
            merged._add_field(token)

    if not merged._fields:
        return ""
    return merged.header_value
