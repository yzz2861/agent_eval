from __future__ import annotations

import base64
import binascii
import collections.abc as cabc
import typing as t
from decimal import Decimal

__all__ = [
    "Dictionary",
    "InnerList",
    "Item",
    "Parameters",
    "StructuredFieldParseError",
    "StructuredFieldSerializeError",
    "Token",
    "is_inner_list",
    "is_item",
    "parse_dictionary",
    "parse_item",
    "parse_list",
    "serialize_dictionary",
    "serialize_item",
    "serialize_list",
]


class Token(str):
    """An RFC 8941 ``token`` bare item.

    This is a :class:`str` subclass so it compares and formats like a string,
    while allowing serializers to distinguish a token from a quoted string.
    ``"foo"`` is a string, ``Token("foo")`` serializes as ``foo``.

    .. versionadded:: 3.2
    """


Parameters = t.Mapping[str, "BareItem"]
BareItem = int | Decimal | str | Token | bytes | bool
# An item is a ``(bare_value, parameters)`` tuple.
Item = tuple[BareItem, t.Mapping[str, BareItem]]
# An inner list is a ``(members, parameters)`` tuple.
InnerList = tuple[t.Sequence[Item], t.Mapping[str, BareItem]]
ListMember = Item | InnerList
DictValue = Item | InnerList
Dictionary = t.Mapping[str, DictValue]

_SF_INTEGER_MAX = 999_999_999_999_999

_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGIT = frozenset("0123456789")
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_KEY_CHARS = frozenset(
    "*-_.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class StructuredFieldParseError(ValueError):
    """Raised when a value is not valid per `RFC 8941`_.

    :attr:`position` is the zero-based index into the header value where the
    error occurred. It is the end of the value when the error is unexpected
    end of input.

    .. versionadded:: 3.2

    .. _RFC 8941: https://httpwg.org/specs/rfc8941.html
    """

    def __init__(self, message: str, position: int) -> None:
        self.message = message
        self.position = position
        super().__init__(f"{message} at position {position}")


class StructuredFieldSerializeError(TypeError):
    """Raised when a Python value cannot be serialized per `RFC 8941`_.

    .. versionadded:: 3.2

    .. _RFC 8941: https://httpwg.org/specs/rfc8941.html
    """


class _Parser:
    def __init__(self, value: str) -> None:
        self.value = value
        self.pos = 0
        self.length = len(value)

    def error(self, message: str) -> t.NoReturn:
        raise StructuredFieldParseError(message, self.pos)

    def peek(self) -> str:
        if self.pos >= self.length:
            self.error("Unexpected end of input")

        return self.value[self.pos]

    def consume(self) -> str:
        if self.pos >= self.length:
            self.error("Unexpected end of input")

        char = self.value[self.pos]
        self.pos += 1
        return char

    def expect(self, char: str) -> None:
        if self.peek() != char:
            self.error(f"Expected {char!r}")

        self.pos += 1

    def skip_sp(self) -> None:
        while self.pos < self.length and self.value[self.pos] == " ":
            self.pos += 1

    def skip_ows(self) -> None:
        while self.pos < self.length and self.value[self.pos] in " \t":
            self.pos += 1

    def parse_list(self) -> list[ListMember]:
        self.skip_ows()

        if self.pos == self.length:
            return []

        members: list[ListMember] = []

        while True:
            if self.peek() == "(":
                members.append(self.parse_inner_list())
            else:
                members.append(self.parse_item())

            self.skip_ows()

            if self.pos == self.length:
                return members

            self.expect(",")

            if self.consume() != " ":
                self.error("Expected a space after ',' in a list")

            self.skip_ows()

            if self.pos == self.length:
                self.error("Unexpected end of list member")

    def parse_dictionary(self) -> dict[str, DictValue]:
        self.skip_ows()

        if self.pos == self.length:
            return {}

        result: dict[str, DictValue] = {}

        while True:
            key = self.parse_key()

            if key in result:
                self.error(f"Duplicate dictionary key {key!r}")

            if self.pos < self.length and self.value[self.pos] == "=":
                self.pos += 1

                if self.peek() == "(":
                    member: DictValue = self.parse_inner_list()
                else:
                    member = self.parse_item()
            else:
                # A member with no value is equivalent to a boolean true item
                # with no parameters. Per the grammar, parameters may only
                # appear after an explicit ``=`` here.
                member = (True, {})
                self.skip_ows()

            result[key] = member
            self.skip_ows()

            if self.pos == self.length:
                return result

            self.expect(",")

            if self.consume() != " ":
                self.error("Expected a space after ',' in a dictionary")

            self.skip_ows()

            if self.pos == self.length:
                self.error("Unexpected end of dictionary member")

    def parse_inner_list(self) -> InnerList:
        self.expect("(")
        members: list[Item] = []

        while True:
            self.skip_sp()

            if self.pos >= self.length:
                self.error("Unterminated inner list")

            if self.value[self.pos] == ")":
                self.pos += 1
                return members, self.parse_parameters()

            members.append(self.parse_item())

            if self.pos >= self.length:
                self.error("Unterminated inner list")

            if self.value[self.pos] not in " )":
                self.error("Expected ' ' or ')' in inner list")

    def parse_item(self) -> Item:
        return self.parse_bare_item(), self.parse_parameters()

    def parse_parameters(self) -> dict[str, BareItem]:
        parameters: dict[str, BareItem] = {}

        while self.pos < self.length and self.value[self.pos] == ";":
            self.pos += 1
            self.skip_sp()
            key = self.parse_key()

            if key in parameters:
                self.error(f"Duplicate parameter key {key!r}")

            if self.pos < self.length and self.value[self.pos] == "=":
                self.pos += 1
                parameters[key] = self.parse_bare_item()
            else:
                parameters[key] = True

        return parameters

    def parse_key(self) -> str:
        char = self.peek()

        if char != "*" and char not in _ALPHA:
            self.error("Expected a key to start with '*' or a letter")

        start = self.pos
        self.pos += 1

        while self.pos < self.length and self.value[self.pos] in _KEY_CHARS:
            self.pos += 1

        return self.value[start : self.pos]

    def parse_bare_item(self) -> BareItem:
        char = self.peek()

        if char in _DIGIT or char == "-":
            start = self.pos

            if char == "-":
                self.pos += 1

                if self.pos >= self.length or self.value[self.pos] not in _DIGIT:
                    self.error("Expected a digit after '-' in number")

            return self.parse_number(start)

        if char == '"':
            return self.parse_string()

        if char in _ALPHA or char == "*":
            return self.parse_token()

        if char == "?":
            self.pos += 1
            char = self.consume()

            if char == "1":
                return True

            if char == "0":
                return False

            self.error("Expected '1' or '0' in boolean")

        if char == ":":
            return self.parse_byte_sequence()

        if char == "(":
            self.error("Unexpected inner list as bare item")

        self.error("Invalid bare item")

    def parse_number(self, start: int) -> int | Decimal:
        is_decimal = False
        integer_count = 0

        while self.pos < self.length:
            char = self.value[self.pos]

            if char in _DIGIT:
                self.pos += 1

                if not is_decimal:
                    integer_count += 1

                continue

            if char == "." and not is_decimal:
                is_decimal = True
                fraction_start = self.pos + 1
                self.pos += 1
                continue

            break

        number = self.value[start : self.pos]

        if not is_decimal:
            value = int(number)

            if not -_SF_INTEGER_MAX <= value <= _SF_INTEGER_MAX:
                self.error("Integer out of range")

            return value

        if integer_count > 12:
            self.error("Decimal integer part out of range")

        fraction_count = self.pos - fraction_start

        if fraction_count > 3 or number[-1] == ".":
            self.error("Decimal must have 1 to 3 fractional digits")

        return Decimal(number)

    def parse_string(self) -> str:
        self.expect('"')
        output: list[str] = []

        while True:
            char = self.consume()

            if char == "\\":
                char = self.consume()

                if char not in '"\\':
                    self.error("Invalid string escape")

                output.append(char)
            elif char == '"':
                return "".join(output)
            elif ord(char) < 0x20 or ord(char) > 0x7E:
                self.error("Strings can only contain printable ASCII characters")
            else:
                output.append(char)

    def parse_token(self) -> Token:
        start = self.pos
        self.pos += 1

        while self.pos < self.length and self.value[self.pos] in _TOKEN_CHARS:
            self.pos += 1

        return Token(self.value[start : self.pos])

    def parse_byte_sequence(self) -> bytes:
        self.expect(":")
        end = self.value.find(":", self.pos)

        if end == -1:
            self.pos = self.length
            self.error("Unterminated byte sequence")

        encoded = self.value[self.pos : end]
        self.pos = end + 1

        if not encoded:
            self.error("Empty byte sequence")

        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as e:
            self.error(f"Invalid byte sequence: {e}")


def is_item(value: object) -> t.TypeGuard[Item]:
    return (
        isinstance(value, tuple)
        and len(value) == 2
        and not isinstance(value[0], (list, tuple))
        and isinstance(value[1], cabc.Mapping)
    )


def is_inner_list(value: object) -> t.TypeGuard[InnerList]:
    return (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], cabc.Sequence)
        and not isinstance(value[0], (str, bytes))
        and isinstance(value[1], cabc.Mapping)
    )


def _serialize_key(key: object) -> str:
    if not isinstance(key, str):
        raise StructuredFieldSerializeError(
            f"Expected a string key, got {type(key).__name__}."
        )

    if (
        not key
        or (key[0] not in _ALPHA and key[0] != "*")
        or any(char not in _KEY_CHARS for char in key[1:])
    ):
        raise StructuredFieldSerializeError(f"Invalid structured field key {key!r}.")

    return key


def _serialize_integer(value: int) -> str:
    if not -_SF_INTEGER_MAX <= value <= _SF_INTEGER_MAX:
        raise StructuredFieldSerializeError(
            f"Integer {value} is out of the valid range."
        )

    return str(value)


def _serialize_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise StructuredFieldSerializeError("Decimal value must be finite.")

    if value == 0:
        value = Decimal(0)

    _sign, digits, exponent = value.as_tuple()
    digit_count = len(digits)

    if exponent >= 0:
        integer_count = digit_count + exponent
        fraction_count = 0
    else:
        integer_count = digit_count + exponent
        fraction_count = -exponent

    if fraction_count > 3:
        raise StructuredFieldSerializeError(
            f"Decimal {value} has more than 3 fractional digits."
        )

    if integer_count > 12:
        raise StructuredFieldSerializeError(
            f"Decimal {value} is out of the valid range."
        )

    if fraction_count == 0:
        return f"{value:.1f}"

    return format(value, f".{fraction_count}f")


def _serialize_bare_item(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"

    if isinstance(value, int):
        return _serialize_integer(value)

    if isinstance(value, Decimal):
        return _serialize_decimal(value)

    if isinstance(value, float):
        raise StructuredFieldSerializeError(
            "float values are not supported; use decimal.Decimal for decimals"
            " or int for integers."
        )

    if isinstance(value, Token):
        token = str(value)

        if (
            not token
            or (token[0] not in _ALPHA and token[0] != "*")
            or any(char not in _TOKEN_CHARS for char in token[1:])
        ):
            raise StructuredFieldSerializeError(f"Invalid token {token!r}.")

        return token

    if isinstance(value, str):
        chars = ['"']

        for char in value:
            code = ord(char)

            if code < 0x20 or code > 0x7E:
                raise StructuredFieldSerializeError(
                    "Strings can only contain printable ASCII characters."
                )

            if char in '"\\':
                chars.append("\\")

            chars.append(char)

        chars.append('"')
        return "".join(chars)

    if isinstance(value, bytes):
        return f":{base64.b64encode(value).decode('ascii')}:"

    raise StructuredFieldSerializeError(
        f"Cannot serialize {type(value).__name__} as a structured field item."
    )


def _serialize_parameters(parameters: object) -> str:
    if not isinstance(parameters, cabc.Mapping):
        raise StructuredFieldSerializeError("Parameters must be a mapping.")

    output = []

    for key, value in parameters.items():
        key = _serialize_key(key)

        output.append(f"{key}={_serialize_bare_item(value)}")

    return "".join(f"; {part}" for part in output)


def _serialize_item(item: Item | BareItem) -> str:
    if is_item(item):
        value, parameters = item
        return _serialize_bare_item(value) + _serialize_parameters(parameters)

    return _serialize_bare_item(item)  # type: ignore[arg-type]


def _serialize_inner_list(inner_list: InnerList) -> str:
    members, parameters = inner_list
    output = ["("]

    for index, member in enumerate(members):
        if index:
            output.append(" ")

        output.append(_serialize_item(member))

    output.append(")")
    output.append(_serialize_parameters(parameters))
    return "".join(output)


def _serialize_member(member: ListMember | BareItem) -> str:
    if is_inner_list(member):
        return _serialize_inner_list(member)

    if is_item(member):
        return _serialize_item(member)

    return _serialize_bare_item(member)  # type: ignore[arg-type]


def parse_item(value: str) -> Item:
    """Parse an RFC 8941 structured field :rfc:`item <8941#item>`.

    An item is returned as a ``(value, parameters)`` tuple. ``value`` is an
    :class:`int`, :class:`~decimal.Decimal`, :class:`str`, :class:`Token`,
    :class:`bytes`, or :class:`bool`. ``parameters`` is a mapping of parameter
    keys to bare items, in the order they appeared.

    :param value: The header value to parse.
    :raises StructuredFieldParseError: If the value is not a valid item.

    .. versionadded:: 3.2
    """
    parser = _Parser(value)
    parser.skip_ows()
    result = parser.parse_item()
    parser.skip_ows()

    if parser.pos != parser.length:
        parser.error("Unexpected trailing characters")

    return result


def parse_list(value: str) -> list[ListMember]:
    """Parse an RFC 8941 structured field :rfc:`list <8941#list>`.

    Members are :func:`parse_item` results (``(value, parameters)`` tuples)
    or inner lists. An inner list is a ``(members, parameters)`` tuple where
    ``members`` is a list of item tuples.

    An empty header value parses to an empty list.

    :param value: The header value to parse.
    :raises StructuredFieldParseError: If the value is not a valid list.

    .. versionadded:: 3.2
    """
    parser = _Parser(value)
    result = parser.parse_list()

    if parser.pos != parser.length:
        parser.error("Unexpected trailing characters")

    return result


def parse_dictionary(value: str) -> dict[str, DictValue]:
    """Parse an RFC 8941 structured field :rfc:`dictionary <8941#dictionary>`.

    Values are item tuples or inner list tuples. A member with no value, such
    as ``foo``, parses to the boolean ``true`` item ``(True, {})``. Duplicate
    dictionary keys and duplicate parameter keys are parse errors.

    An empty header value parses to an empty dictionary.

    :param value: The header value to parse.
    :raises StructuredFieldParseError: If the value is not a valid dictionary.

    .. versionadded:: 3.2
    """
    parser = _Parser(value)
    result = parser.parse_dictionary()

    if parser.pos != parser.length:
        parser.error("Unexpected trailing characters")

    return result


def serialize_item(item: Item | BareItem) -> str:
    """Serialize an RFC 8941 structured field :rfc:`item <8941#item>`.

    An item may be a bare value or a ``(value, parameters)`` tuple produced by
    :func:`parse_item`. Decimals must be :class:`~decimal.Decimal` so that they
    are not confused with integers or lossy floats.

    :param item: The bare value or item tuple to serialize.
    :raises StructuredFieldSerializeError: If the value cannot be serialized.

    .. versionadded:: 3.2
    """
    return _serialize_item(item)


def serialize_list(members: cabc.Iterable[ListMember | BareItem]) -> str:
    """Serialize an RFC 8941 structured field :rfc:`list <8941#list>`.

    Each member may be a bare value, an item tuple, or an inner list tuple.
    Members are serialized in iteration order.

    :param members: The list members to serialize.
    :raises StructuredFieldSerializeError: If a member cannot be serialized.

    .. versionadded:: 3.2
    """
    return ", ".join(_serialize_member(member) for member in members)


def serialize_dictionary(members: cabc.Mapping[str, t.Any]) -> str:
    """Serialize an RFC 8941 structured field :rfc:`dictionary <8941#dictionary>`.

    Values may be item tuples, inner list tuples, or bare values. The boolean
    ``True`` is serialized as a bare key. Keys and members are serialized in
    insertion order.

    :param members: The dictionary members to serialize.
    :raises StructuredFieldSerializeError: If a member cannot be serialized.

    .. versionadded:: 3.2
    """
    output = []

    for key, value in members.items():
        key = _serialize_key(key)

        if value is True:
            output.append(key)
        elif is_inner_list(value) or is_item(value):
            output.append(f"{key}={_serialize_member(value)}")
        else:
            output.append(f"{key}={_serialize_bare_item(value)}")

    return ", ".join(output)
