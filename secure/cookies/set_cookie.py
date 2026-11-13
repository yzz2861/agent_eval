# Security recommendations and syntax from the MDN Web Docs and RFC 6265bis.
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie
# https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

from __future__ import annotations

from datetime import datetime
from email.utils import format_datetime
from enum import Enum
import re
from typing import TYPE_CHECKING

from secure._internal.emit import set_headers_async, set_headers_sync

if TYPE_CHECKING:
    from secure._internal.types import HeaderItems, ResponseProtocol

# Unicode codepoint boundaries used by the RFC 6265bis grammar.
_CONTROL_CHAR_MAX = 0x1F  # C0 control characters (0x00-0x1F)
_DEL = 0x7F
_ASCII_MAX = 0x7F

# RFC 6265bis cookie-name: an RFC 7230 token (visible ASCII excluding separators).
_COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# RFC 6265bis cookie-value characters that never need quoting.
_COOKIE_VALUE_ALLOWED_RE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$")

# Path / Domain are cookie-av values: no CTLs, whitespace or semicolons (Domain also bans commas).
_PATH_DOMAIN_FORBIDDEN_RE = re.compile(r"[\x00-\x20\x7f;]")
_DOMAIN_FORBIDDEN_RE = re.compile(r"[\x00-\x20\x7f;,]")

# Widely-implemented browser limit for the combined name=value payload (RFC 6265bis minimum).
MAX_COOKIE_PAYLOAD_BYTES = 4096

HOST_PREFIX = "__Host-"
SECURE_PREFIX = "__Secure-"


class SameSite(str, Enum):
    """
    Enumeration of the ``SameSite`` cookie attribute values.

    ``None`` requires the cookie to also carry ``Secure``; the builder enforces
    this at construction time.
    """

    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"

    @classmethod
    def coerce(cls, value: SameSite | str) -> SameSite:
        """Resolve a :class:`SameSite` member from an enum member or a case-insensitive string."""
        if isinstance(value, SameSite):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            for member in cls:
                if member.value.lower() == normalized:
                    return member
        raise ValueError("SameSite must be one of 'Strict', 'Lax' or 'None' (got an unsupported value)")


def _contains_control_characters(value: str) -> bool:
    return any(ord(char) <= _CONTROL_CHAR_MAX or ord(char) == _DEL for char in value)


def _validate_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError("cookie name must be a non-empty string")
    if _contains_control_characters(name) or not _COOKIE_NAME_RE.fullmatch(name):
        raise ValueError(
            "cookie name must be an RFC 7230 token (visible ASCII without separators or control characters)"
        )
    return name


def _validate_value(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("cookie value must be a string")
    if _contains_control_characters(value):
        raise ValueError("cookie value must not contain control characters")
    if not _COOKIE_VALUE_ALLOWED_RE.fullmatch(value):
        # Non-ASCII (e.g. Chinese) text is allowed as UTF-8; only structural ASCII
        # characters that break cookie/HTTP parsing are rejected.
        for char in value:
            codepoint = ord(char)
            if codepoint <= _ASCII_MAX and not _COOKIE_VALUE_ALLOWED_RE.fullmatch(char):
                raise ValueError(
                    "cookie value contains a disallowed ASCII character "
                    "(whitespace, double quote, comma, semicolon or backslash)"
                )
    return value


def _validate_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ValueError("cookie Path must be a non-empty string")
    if _PATH_DOMAIN_FORBIDDEN_RE.search(path):
        raise ValueError("cookie Path must not contain control characters, whitespace or ';'")
    return path


def _validate_domain(domain: str) -> str:
    if not isinstance(domain, str) or not domain:
        raise ValueError("cookie Domain must be a non-empty string")
    if _DOMAIN_FORBIDDEN_RE.search(domain):
        raise ValueError("cookie Domain must not contain control characters, whitespace, ';' or ','")
    return domain


class SetCookie:
    """
    Explicit, validated builder for a single ``Set-Cookie`` response header.

    Every combination that browsers silently reject is refused at construction
    time, so a built object always serializes to a safe header string:

    * ``__Host-`` cookies must not set ``Domain``, must use ``Path=/`` and must
      carry ``Secure``.
    * ``__Secure-`` cookies must carry ``Secure``.
    * ``SameSite=None`` requires ``Secure``.
    * ``Partitioned`` requires ``Secure``.
    * ``Max-Age`` and ``Expires`` are mutually exclusive.

    The cookie value is treated as sensitive: it is never included in exception
    messages or :meth:`__repr__`.

    Example
    -------
    >>> cookie = SetCookie(
    ...     "__Host-session",
    ...     "token",
    ...     path="/",
    ...     secure=True,
    ...     http_only=True,
    ...     same_site=SameSite.STRICT,
    ... )
    >>> cookie.header_name
    'Set-Cookie'
    >>> cookie.header_value
    '__Host-session=token; Path=/; Secure; HttpOnly; SameSite=Strict'
    """

    header_name: str = "Set-Cookie"

    def __init__(  # noqa: PLR0913
        self,
        name: str,
        value: str = "",
        *,
        path: str | None = None,
        domain: str | None = None,
        max_age: int | None = None,
        expires: datetime | None = None,
        same_site: SameSite | str | None = None,
        secure: bool = False,
        http_only: bool = False,
        partitioned: bool = False,
    ) -> None:
        self._name = _validate_name(name)
        self._value = _validate_value(value)
        self._path = _validate_path(path) if path is not None else None
        self._domain = _validate_domain(domain) if domain is not None else None
        self._max_age = self._validate_max_age(max_age)
        self._expires = self._validate_expires(expires)
        self._same_site = SameSite.coerce(same_site) if same_site is not None else None
        self._secure = bool(secure)
        self._http_only = bool(http_only)
        self._partitioned = bool(partitioned)
        self._validate_combinations()
        self._validate_payload_length()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_max_age(max_age: int | None) -> int | None:
        if max_age is None:
            return None
        if isinstance(max_age, bool) or not isinstance(max_age, int):
            raise TypeError("cookie Max-Age must be an integer number of seconds")
        if max_age < 0:
            raise ValueError("cookie Max-Age must be a non-negative integer")
        return max_age

    @staticmethod
    def _validate_expires(expires: datetime | None) -> datetime | None:
        if expires is None:
            return None
        if not isinstance(expires, datetime):
            raise TypeError("cookie Expires must be a datetime.datetime instance")
        if expires.tzinfo is None or expires.utcoffset() is None:
            raise ValueError("cookie Expires must be a timezone-aware datetime")
        return expires

    def _validate_combinations(self) -> None:
        if self._max_age is not None and self._expires is not None:
            raise ValueError(f"cookie {self._name!r}: Max-Age and Expires are mutually exclusive; set only one")

        if self._name.startswith(HOST_PREFIX):
            if self._domain is not None:
                raise ValueError(f"cookie {self._name!r}: __Host- prefix forbids the Domain attribute")
            if self._path != "/":
                raise ValueError(f"cookie {self._name!r}: __Host- prefix requires Path=/")
            if not self._secure:
                raise ValueError(f"cookie {self._name!r}: __Host- prefix requires the Secure attribute")
        elif self._name.startswith(SECURE_PREFIX) and not self._secure:
            raise ValueError(f"cookie {self._name!r}: __Secure- prefix requires the Secure attribute")

        if self._same_site is SameSite.NONE and not self._secure:
            raise ValueError(f"cookie {self._name!r}: SameSite=None requires the Secure attribute")

        if self._partitioned and not self._secure:
            raise ValueError(f"cookie {self._name!r}: Partitioned requires the Secure attribute")

    def _validate_payload_length(self) -> None:
        payload = f"{self._name}={self._value}".encode()
        if len(payload) > MAX_COOKIE_PAYLOAD_BYTES:
            raise ValueError(
                f"cookie {self._name!r}: name=value payload exceeds "
                f"{MAX_COOKIE_PAYLOAD_BYTES} bytes when encoded as UTF-8"
            )

    # ------------------------------------------------------------------
    # Read-only attributes
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        """Return the cookie name."""
        return self._name

    @property
    def path(self) -> str | None:
        """Return the validated ``Path`` attribute, or ``None`` when unset."""
        return self._path

    @property
    def domain(self) -> str | None:
        """Return the validated ``Domain`` attribute, or ``None`` when unset."""
        return self._domain

    @property
    def max_age(self) -> int | None:
        """Return the ``Max-Age`` seconds, or ``None`` when unset."""
        return self._max_age

    @property
    def expires(self) -> datetime | None:
        """Return the timezone-aware ``Expires`` datetime, or ``None`` when unset."""
        return self._expires

    @property
    def same_site(self) -> SameSite | None:
        """Return the :class:`SameSite` member, or ``None`` when unset."""
        return self._same_site

    @property
    def secure(self) -> bool:
        """Return whether the ``Secure`` attribute is enabled."""
        return self._secure

    @property
    def http_only(self) -> bool:
        """Return whether the ``HttpOnly`` attribute is enabled."""
        return self._http_only

    @property
    def partitioned(self) -> bool:
        """Return whether the ``Partitioned`` attribute is enabled."""
        return self._partitioned

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @property
    def header_value(self) -> str:
        """Return the fully serialized ``Set-Cookie`` header value."""
        parts = [f"{self._name}={self._value}"]
        if self._expires is not None:
            parts.append(f"Expires={format_datetime(self._expires, usegmt=True)}")
        if self._max_age is not None:
            parts.append(f"Max-Age={self._max_age}")
        if self._domain is not None:
            parts.append(f"Domain={self._domain}")
        if self._path is not None:
            parts.append(f"Path={self._path}")
        if self._secure:
            parts.append("Secure")
        if self._http_only:
            parts.append("HttpOnly")
        if self._same_site is not None:
            parts.append(f"SameSite={self._same_site.value}")
        if self._partitioned:
            parts.append("Partitioned")
        return "; ".join(parts)

    def header_items(self) -> HeaderItems:
        """Return the builder as a single immutable ``(name, value)`` header pair."""
        return ((self.header_name, self.header_value),)

    def __str__(self) -> str:
        """Return the serialized header value (including the sensitive cookie value)."""
        return self.header_value

    def __repr__(self) -> str:
        """Return a debug representation that never echoes the sensitive cookie value."""
        return (
            f"SetCookie(name={self._name!r}, value=<redacted>, path={self._path!r}, "
            f"domain={self._domain!r}, max_age={self._max_age!r}, expires={self._expires!r}, "
            f"same_site={self._same_site!r}, secure={self._secure}, http_only={self._http_only}, "
            f"partitioned={self._partitioned})"
        )

    # ------------------------------------------------------------------
    # Response emission
    # ------------------------------------------------------------------

    def set_on(self, response: ResponseProtocol) -> None:
        """
        Append this ``Set-Cookie`` header to a synchronous response object.

        Supports the same response interfaces as :meth:`secure.Secure.set_headers`
        (``set_header`` or a ``headers`` container/mapping). Multiple cookies can
        be emitted when the container keeps repeated ``Set-Cookie`` fields.
        """
        set_headers_sync(response, self.header_items())

    async def set_on_async(self, response: ResponseProtocol) -> None:
        """Async counterpart of :meth:`set_on` for async response objects."""
        await set_headers_async(response, self.header_items())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SetCookie):
            return NotImplemented
        return self.header_value == other.header_value

    def __hash__(self) -> int:
        return hash(self.header_value)
