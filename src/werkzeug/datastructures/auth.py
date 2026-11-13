from __future__ import annotations

import base64
import binascii
import collections.abc as cabc
import typing as t
from enum import Enum

from ..http import DEFAULT_MAX_HEADER_LENGTH
from ..http import DEFAULT_MAX_PARAM_LENGTH
from ..http import dump_header
from ..http import HeaderParseError
from ..http import HeaderParseErrorReason
from ..http import is_valid_token
from ..http import parse_dict_header
from ..http import parse_strict_dict_header
from ..http import parse_strict_header_scheme
from ..http import quote_header_value
from .structures import CallbackDict


class AuthorizationParseErrorReason(Enum):
    """Stable reason codes returned when an ``Authorization`` header is
    rejected by the strict parser.

    Only the reason is exposed; no base64 content, token or parameter value is
    ever included in the exception.

    .. versionadded:: 3.2
    """

    EMPTY = HeaderParseErrorReason.EMPTY.value
    LENGTH = HeaderParseErrorReason.LENGTH.value
    OBS_FOLD = HeaderParseErrorReason.OBS_FOLD.value
    NUL = HeaderParseErrorReason.NUL.value
    CONTROL_CHAR = HeaderParseErrorReason.CONTROL_CHAR.value
    SCHEME = HeaderParseErrorReason.SCHEME.value
    MISSING_CREDENTIALS = HeaderParseErrorReason.MISSING_CREDENTIALS.value
    MULTIPLE_SCHEMES = HeaderParseErrorReason.MULTIPLE_SCHEMES.value
    PARAMETER_KEY = HeaderParseErrorReason.PARAMETER_KEY.value
    DUPLICATE_PARAMETER = HeaderParseErrorReason.DUPLICATE_PARAMETER.value
    EMPTY_PARAMETER = HeaderParseErrorReason.EMPTY_PARAMETER.value
    BARE_PARAMETER = HeaderParseErrorReason.BARE_PARAMETER.value
    QUOTED_STRING = HeaderParseErrorReason.QUOTED_STRING.value
    PARAMETER_LENGTH = HeaderParseErrorReason.PARAMETER_LENGTH.value
    TOKEN = HeaderParseErrorReason.TOKEN.value
    BASIC_BASE64 = "basic_base64"
    """The Basic credentials were not valid canonical base64."""

    BASIC_ENCODING = "basic_encoding"
    """The decoded Basic credentials were not valid UTF-8."""

    BASIC_COLON = "basic_colon"
    """The decoded Basic credentials did not contain exactly one ``:``."""


class AuthorizationParseError(ValueError):
    """Raised by :meth:`Authorization.from_header_strict` when the header is
    rejected.

    The :attr:`reason` attribute is a stable
    :class:`AuthorizationParseErrorReason` member suitable for metrics and
    logging. The message contains only that reason string, never the header
    value or any credential material.

    .. versionadded:: 3.2
    """

    def __init__(self, reason: AuthorizationParseErrorReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def _strict_reason(error: HeaderParseError) -> AuthorizationParseErrorReason:
    """Map an HTTP-level parse error to an auth-level reason with the same
    stable code."""
    return AuthorizationParseErrorReason(error.reason.value)


def _parse_strict_basic(token: str, max_param_length: int) -> dict[str, str]:
    """Decode and validate the credentials portion of a Basic header.

    The token must be canonical base64 of UTF-8 text containing exactly one
    ``:``. Username and password are returned verbatim with no whitespace
    stripping or other normalization.
    """
    if len(token) > max_param_length:
        raise AuthorizationParseError(AuthorizationParseErrorReason.PARAMETER_LENGTH)

    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        raise AuthorizationParseError(
            AuthorizationParseErrorReason.BASIC_BASE64
        ) from None

    # Re-encoding canonical base64 must reproduce the token; this rejects
    # non-canonical encodings such as missing padding or extra line bits.
    if base64.b64encode(raw).decode("ascii") != token:
        raise AuthorizationParseError(AuthorizationParseErrorReason.BASIC_BASE64)

    try:
        credentials = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise AuthorizationParseError(
            AuthorizationParseErrorReason.BASIC_ENCODING
        ) from None

    # The base64 wrapper can hide characters rejected on the raw header, so
    # apply the same character rules to the decoded credentials.
    if "\n" in credentials or "\r" in credentials:
        raise AuthorizationParseError(AuthorizationParseErrorReason.OBS_FOLD)

    if "\x00" in credentials:
        raise AuthorizationParseError(AuthorizationParseErrorReason.NUL)

    if any(
        (ord(char) < 0x20 and char != "\t") or ord(char) == 0x7F for char in credentials
    ):
        raise AuthorizationParseError(AuthorizationParseErrorReason.CONTROL_CHAR)

    separator = credentials.find(":")

    if separator == -1 or credentials.find(":", separator + 1) != -1:
        raise AuthorizationParseError(AuthorizationParseErrorReason.BASIC_COLON)

    username = credentials[:separator]
    password = credentials[separator + 1 :]

    if not username or not password:
        raise AuthorizationParseError(AuthorizationParseErrorReason.EMPTY_PARAMETER)

    return {"username": username, "password": password}


class Authorization:
    """A parsed ``Authorization`` header.

    :attr:`.Request.authorization` returns an instance if the header is set.

    An instance can be used with the test :class:`.Client` request methods' ``auth``
    parameter to send the header in test requests.

    Depending on the auth scheme, either :attr:`parameters` or :attr:`token` will be
    set. The ``Basic`` scheme's token is decoded into the ``username`` and ``password``
    parameters.

    .. versionchanged:: 3.2
        Get/set/delete ``auth["key"]`` and ``auth.key``, along with
        ``"key" in auth`` and ``auth.get("key")``, are deprecated and will
        be removed in Werkzeug 4.0. Use ``parameters`` directly instead.

    .. versionchanged:: 2.3
        The ``token`` parameter and attribute was added to support auth schemes
        that use a token instead of parameters, such as ``Bearer``.

    .. versionchanged:: 2.3
        The object is no longer a ``dict``.

    .. versionchanged:: 0.5
        The object is an immutable dict.
    """

    def __init__(
        self,
        auth_type: str,
        data: dict[str, str | None] | None = None,
        token: str | None = None,
    ) -> None:
        self.type = auth_type
        """The authorization scheme, like ``basic``, ``digest``, or ``bearer``."""

        if data is None:
            data = {}

        self.parameters = data
        """A dict of parameters parsed from the header. Either this or :attr:`token`
        will have a value for a given scheme.
        """

        self.token = token
        """A token parsed from the header. Either this or :attr:`parameters` will have a
        value for a given scheme.

        .. versionadded:: 2.3
        """

    @property
    def username(self) -> str | None:
        """The ``username`` key from :attr:`parameters`. A shortcut for
        ``Basic`` auth.
        """
        return self.parameters.get("username")

    @property
    def password(self) -> str | None:
        """The ``password`` key from :attr:`parameters`. A shortcut for
        ``Basic`` auth.
        """
        return self.parameters.get("password")

    def __getattr__(self, name: str) -> str | None:
        import warnings

        warnings.warn(
            f"'auth.{name}' is deprecated and will be removed in Werkzeug 4.0."
            f" Use 'auth.parameters[\"{name}\"]' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parameters.get(name)

    def __getitem__(self, name: str) -> str | None:
        import warnings

        warnings.warn(
            "'auth[key]' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'auth.parameters[key]' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parameters.get(name)

    def get(self, key: str, default: str | None = None) -> str | None:
        import warnings

        warnings.warn(
            "'auth.get(key)' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'auth.parameters.get(key)' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parameters.get(key, default)

    def __contains__(self, key: str) -> bool:
        import warnings

        warnings.warn(
            "'key in auth' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'key in auth.parameters' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return key in self.parameters

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Authorization):
            return NotImplemented

        return (
            other.type == self.type
            and other.token == self.token
            and other.parameters == self.parameters
        )

    @classmethod
    def from_header(cls, value: str | None) -> t.Self | None:
        """Parse an ``Authorization`` header value and create an instance of
        this class, or ``None`` if the value is empty.

        :param value: The header value to parse.

        .. versionadded:: 2.3
        """
        if not value:
            return None

        scheme, _, rest = value.partition(" ")
        scheme = scheme.lower()
        rest = rest.strip(" \t")

        if scheme == "basic":
            try:
                username, _, password = (
                    base64.b64decode(rest, validate=True).decode().partition(":")
                )
            except (binascii.Error, UnicodeError):
                return None

            return cls(scheme, {"username": username, "password": password})

        if "=" in rest.rstrip("="):
            # = that is not trailing, this is parameters.
            return cls(scheme, parse_dict_header(rest), None)

        # No = or only trailing =, this is a token.
        return cls(scheme, None, rest)

    @classmethod
    def from_header_strict(
        cls,
        value: str | None,
        *,
        max_length: int = DEFAULT_MAX_HEADER_LENGTH,
        max_param_length: int = DEFAULT_MAX_PARAM_LENGTH,
    ) -> t.Self:
        """Parse an ``Authorization`` header value using the strict profile.

        The lenient :meth:`from_header` keeps historical compatibility; this
        method is opt-in and applies deterministic rules so that every layer
        of the application arrives at the same interpretation of the
        credentials.

        The auth scheme token and the overall length are validated before any
        scheme-specific parsing. Failures raise
        :class:`AuthorizationParseError` carrying a stable
        :class:`AuthorizationParseErrorReason`; the header value itself is
        never included in the exception.

        ``Basic``
            The credentials must be canonical, correctly padded base64 of
            UTF-8 text containing exactly one ``:`` separator. The username
            and password are kept verbatim, including any internal
            whitespace; no whitespace is stripped and no surrogate or control
            character is accepted.

        ``Digest``
            Parameter names are matched case-insensitively and lowercased.
            Duplicate parameter names, bare keys, empty values and unclosed
            or badly escaped quoted strings are rejected.

        ``Bearer``
            Exactly one RFC 9110 ``token`` must follow the scheme; any
            parameter, space or extra scheme is rejected.

        Any other scheme follows the same token or strict parameter rules.
        Obsolete line folding, NUL characters, bare control characters,
        overlong values and a second auth scheme mixed into the header always
        cause an error instead of being silently truncated.

        :param value: The header value to parse.
        :param max_length: Maximum accepted length of the complete header.
        :param max_param_length: Maximum accepted length of one parameter.

        .. versionadded:: 3.2
        """
        if not value:
            raise AuthorizationParseError(AuthorizationParseErrorReason.EMPTY)

        try:
            scheme, rest = parse_strict_header_scheme(value, max_length=max_length)
        except HeaderParseError as error:
            raise AuthorizationParseError(_strict_reason(error)) from None

        if scheme == "basic":
            return cls(
                scheme,
                _parse_strict_basic(rest, max_param_length),
            )

        if scheme == "bearer":
            if any(char in " \t" for char in rest):
                raise AuthorizationParseError(
                    AuthorizationParseErrorReason.MULTIPLE_SCHEMES
                )

            if not is_valid_token(rest):
                raise AuthorizationParseError(AuthorizationParseErrorReason.TOKEN)

            return cls(scheme, None, rest)

        if scheme == "digest" or "=" in rest:
            try:
                parameters = parse_strict_dict_header(
                    rest,
                    max_length=max_length,
                    max_param_length=max_param_length,
                )
            except HeaderParseError as error:
                raise AuthorizationParseError(_strict_reason(error)) from None

            return cls(scheme, parameters)

        if not is_valid_token(rest):
            raise AuthorizationParseError(AuthorizationParseErrorReason.TOKEN)

        return cls(scheme, None, rest)

    def to_header(self) -> str:
        """Convert to an ``Authorization`` header value.

        .. versionadded:: 2.0
        """
        if self.type == "basic":
            value = base64.b64encode(
                f"{self.username}:{self.password}".encode()
            ).decode("ascii")
            return f"Basic {value}"

        if self.token is not None:
            return f"{self.type.title()} {self.token}"

        return f"{self.type.title()} {dump_header(self.parameters)}"

    def __str__(self) -> str:
        return self.to_header()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.to_header()}>"


class WWWAuthenticate:
    """A parsed ``WWW-Authenticate`` header.

    Set :attr:`.Response.www_authenticate` to an instance or list of instances to set
    the header. Modifying the instance will update the header.

    Depending on the auth scheme, either :attr:`parameters` or :attr:`token` should be
    set. The ``Basic`` scheme will encode ``username`` and ``password`` parameters to a
    token.

    .. versionchanged:: 3.2
        Considered ``False`` if ``type`` is the empty string.

    .. versionchanged:: 3.2
        Get/set/delete ``auth["key"]`` and ``auth.key``, along with
        ``"key" in auth`` and ``auth.get("key")``, are deprecated and will
        be removed in Werkzeug 4.0. Use ``parameters`` directly instead.

    .. versionchanged:: 2.3
        The ``token`` parameter and attribute was added to support auth schemes
        that use a token instead of parameters, such as ``Bearer``.

    .. versionchanged:: 2.3
        The object is no longer a ``dict``.

    .. versionchanged:: 2.3
        The ``on_update`` parameter was removed.
    """

    def __init__(
        self,
        auth_type: str = "",
        values: dict[str, str | None] | None = None,
        token: str | None = None,
    ):
        self._type = auth_type.lower()
        self._parameters: dict[str, str | None] = CallbackDict(
            values, lambda _: self._trigger_on_update()
        )
        self._token = token
        self._on_update: cabc.Callable[[WWWAuthenticate], None] | None = None

    def _trigger_on_update(self) -> None:
        if self._on_update is not None:
            self._on_update(self)

    @property
    def type(self) -> str:
        """The authorization scheme, like ``basic``, ``digest``, or ``bearer``."""
        return self._type

    @type.setter
    def type(self, value: str) -> None:
        self._type = value
        self._trigger_on_update()

    @property
    def parameters(self) -> dict[str, str | None]:
        """A dict of parameters for the header. Only one of this or :attr:`token` should
        have a value for a given scheme.
        """
        return self._parameters

    @parameters.setter
    def parameters(self, value: dict[str, str]) -> None:
        self._parameters = CallbackDict(value, lambda _: self._trigger_on_update())
        self._trigger_on_update()

    @property
    def token(self) -> str | None:
        """A dict of parameters for the header. Only one of this or :attr:`token` should
        have a value for a given scheme.
        """
        return self._token

    @token.setter
    def token(self, value: str | None) -> None:
        """A token for the header. Only one of this or :attr:`parameters` should have a
        value for a given scheme.

        .. versionadded:: 2.3
        """
        self._token = value
        self._trigger_on_update()

    def __getitem__(self, key: str) -> str | None:
        import warnings

        warnings.warn(
            "'auth[key]' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'auth.parameters[key]' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parameters.get(key)

    def __setitem__(self, key: str, value: str | None) -> None:
        import warnings

        warnings.warn(
            "'auth[key] = value' is deprecated and will be removed in"
            " Werkzeug 4.0. Use 'auth.parameters[key] = value' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if value is None:
            if key in self.parameters:
                del self.parameters[key]
        else:
            self.parameters[key] = value

        self._trigger_on_update()

    def __delitem__(self, key: str) -> None:
        import warnings

        warnings.warn(
            "'del auth[key]' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'del auth.parameters[key]' instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        if key in self.parameters:
            del self.parameters[key]
            self._trigger_on_update()

    def __getattr__(self, name: str) -> str | None:
        import warnings

        warnings.warn(
            f"'auth.{name}' is deprecated and will be removed in Werkzeug 4.0."
            f" Use 'auth.parameters[\"{name}\"]' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self[name]

    def __setattr__(self, name: str, value: str | None) -> None:
        if name in {
            "type",
            "_type",
            "parameters",
            "_parameters",
            "token",
            "_token",
            "_on_update",
        }:
            super().__setattr__(name, value)
        else:
            import warnings

            warnings.warn(
                f"'auth.{name} = value' is deprecated and will be removed in"
                f" Werkzeug 4.0. Use 'auth.parameters[\"{name}\"] = value' instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            self[name] = value

    def __delattr__(self, name: str) -> None:
        import warnings

        warnings.warn(
            f"'del auth.{name}' is deprecated and will be removed in Werkzeug 4.0."
            f" Use 'del auth.parameters[\"{name}\"]' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        del self[name]

    def __contains__(self, key: str) -> bool:
        import warnings

        warnings.warn(
            "'key in auth' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'key in auth.parameters' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return key in self.parameters

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, WWWAuthenticate):
            return NotImplemented

        return (
            other.type == self.type
            and other.token == self.token
            and other.parameters == self.parameters
        )

    def get(self, key: str, default: str | None = None) -> str | None:
        import warnings

        warnings.warn(
            "'auth.get(key)' is deprecated and will be removed in Werkzeug 4.0."
            " Use 'auth.parameters.get(key)' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parameters.get(key, default)

    @classmethod
    def from_header(cls, value: str | None) -> t.Self:
        """Parse a ``WWW-Authenticate`` header value and create an instance of
        this class.

        :param value: The header value to parse.

        .. versionchanged:: 3.2
            Return an empty instance instead of ``None`` if the value is empty.

        .. versionadded:: 2.3
        """
        if not value:
            return cls()

        scheme, _, rest = value.partition(" ")
        scheme = scheme.lower()
        rest = rest.strip(" \t")

        if "=" in rest.rstrip("="):
            # = that is not trailing, this is parameters.
            return cls(scheme, parse_dict_header(rest))

        # No = or only trailing =, this is a token or empty.
        if rest:
            return cls(scheme, token=rest)

        return cls(scheme)

    def to_header(self) -> str:
        """Convert to a ``WWW-Authenticate`` header value.

        .. versionchanged:: 3.2
            Return the empty string if the instance is empty.
        """
        if not self:
            return ""

        if self.token is not None:
            return f"{self.type.title()} {self.token}"

        if not self.parameters:
            return self.type.title()

        if self.type == "digest":
            items = []

            for key, value in self.parameters.items():
                if key in {"realm", "domain", "nonce", "opaque", "qop"}:
                    value = quote_header_value(value, allow_token=False)
                else:
                    value = quote_header_value(value)

                items.append(f"{key}={value}")

            return f"Digest {', '.join(items)}"

        return f"{self.type.title()} {dump_header(self.parameters)}"

    def __bool__(self) -> bool:
        return self._type != ""

    def __str__(self) -> str:
        return self.to_header()

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.to_header()}>"
