from __future__ import annotations

import collections.abc as cabc
import dataclasses
import re
import typing as t
from base64 import b64decode
from base64 import b64encode
from decimal import Decimal

BareItem = bool | int | str | bytes | Decimal

MAX_INTEGER = 999_999_999_999_999
MIN_INTEGER = -MAX_INTEGER
MAX_DECIMAL = Decimal("999999999999.999")
MIN_DECIMAL = -MAX_DECIMAL


class StructuredFieldError(ValueError):
    """A structured field is syntactically invalid or cannot be serialized."""

    def __init__(
        self, message: str, position: int | None = None, field: int | None = None
    ) -> None:
        self.position = position
        self.field = field

        if field is not None and position is not None:
            message = f"field {field}, position {position}: {message}"
        elif position is not None:
            message = f"position {position}: {message}"

        super().__init__(message)


class Token(str):
    """An RFC 8941 token. Unlike a regular string, it serializes unquoted."""


_BARE_ITEM_TYPES = (bool, int, str, bytes, Decimal)


@dataclasses.dataclass(frozen=True, eq=False)
class Item:
    """An RFC 8941 item: a bare value and its ordered parameters."""

    value: BareItem
    parameters: Parameters = ()

    def __init__(
        self,
        value: ItemValue,
        parameters: cabc.Mapping[str, t.Any] | None = None,
    ) -> None:
        if isinstance(value, Item):
            if parameters:
                raise TypeError("Cannot pass parameters when value is an Item.")

            bare_value = value.value
            item_parameters = value.parameters
        else:
            bare_value = value
            item_parameters = _normalize_parameters(parameters)

        if not isinstance(bare_value, _BARE_ITEM_TYPES):
            raise TypeError(
                "Item value must be bool, int, Decimal, str, Token, or bytes."
            )

        object.__setattr__(self, "value", bare_value)
        object.__setattr__(self, "parameters", item_parameters)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Item):
            return False

        if type(self.value) is not type(other.value):
            return False

        if isinstance(self.value, Decimal):
            values_equal = self.value.as_tuple() == other.value.as_tuple()
        else:
            values_equal = self.value == other.value

        return values_equal and self.parameters == other.parameters

    def __hash__(self) -> int:
        return hash(("item", type(self.value), self.value, self.parameters))


@dataclasses.dataclass(frozen=True, eq=False)
class InnerList:
    """An RFC 8941 inner list: an ordered list of items and its parameters."""

    items: tuple[Item, ...]
    parameters: Parameters = ()

    def __init__(
        self,
        items: cabc.Iterable[t.Any],
        parameters: cabc.Mapping[str, t.Any] | None = None,
    ) -> None:
        object.__setattr__(self, "items", tuple(coerce_item(item) for item in items))
        object.__setattr__(self, "parameters", _normalize_parameters(parameters))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, InnerList)
            and self.items == other.items
            and self.parameters == other.parameters
        )

    def __hash__(self) -> int:
        return hash(("inner-list", self.items, self.parameters))


Parameters = tuple[tuple[str, Item | InnerList], ...]
ItemValue = BareItem | Item
MemberValue = ItemValue | InnerList
StructuredList = list[Item | InnerList]
StructuredDictionary = dict[str, Item | InnerList]


def coerce_item(value: t.Any) -> Item:
    """Wrap and validate a bare item or return an existing item."""
    if isinstance(value, Item):
        return value

    if isinstance(value, InnerList):
        raise TypeError("An inner list cannot be used as an item value.")

    return Item(value)


def _normalize_parameters(
    parameters: cabc.Mapping[str, t.Any] | None,
) -> Parameters:
    if parameters is None:
        return ()

    if not isinstance(parameters, cabc.Mapping):
        raise TypeError("Parameters must be a mapping.")

    result = []

    for key, value in parameters.items():
        key = str(key)

        if _key_re.fullmatch(key) is None:
            raise StructuredFieldError("Invalid parameter key.")

        if isinstance(value, InnerList):
            parameter_value: Item | InnerList = value
        else:
            parameter_value = coerce_item(value)

        result.append((key, parameter_value))

    return tuple(result)


_token_re = re.compile(r"[!#$%&'*+\-.^_`|~A-Za-z][!#$%&'*+\-.^_`|~A-Za-z0-9:]*")
_key_re = re.compile(r"[a-z*][a-z0-9_.*-]*")


class _Parser:
    def __init__(self, value: str, field: int | None = None) -> None:
        if not isinstance(value, str):
            raise StructuredFieldError("Value must be a string.")

        self.value = value
        self.pos = 0
        self.field = field
        self.key_positions: dict[str, int] = {}

    def fail(self, message: str, position: int | None = None) -> t.NoReturn:
        raise StructuredFieldError(
            message, self.pos if position is None else position, self.field
        )

    def at_end(self) -> bool:
        return self.pos == len(self.value)

    def peek(self) -> str:
        return self.value[self.pos]

    def consume_sp(self) -> None:
        while self.pos < len(self.value) and self.value[self.pos] == " ":
            self.pos += 1

    def consume_ows(self) -> None:
        while self.pos < len(self.value) and self.value[self.pos] in " \t":
            self.pos += 1

    def expect_end(self) -> None:
        self.consume_sp()

        if not self.at_end():
            self.fail("Expected end of structured field.")

    def parse_item(self, stop_before_sp: bool = False) -> Item:
        value = self.parse_bare_item()
        parameters = self.parse_parameters(stop_before_sp)
        return Item(value, dict(parameters))

    def parse_bare_item(self) -> BareItem:
        if self.at_end():
            self.fail("Expected item.")

        char = self.peek()

        if char == '"':
            return self.parse_string()

        if char in "-0123456789":
            return self.parse_number()

        if _token_re.match(self.value, self.pos) is not None:
            return self.parse_token()

        if char == ":":
            return self.parse_byte_sequence()

        if char == "?":
            return self.parse_boolean()

        self.fail("Expected bare item.")

    def parse_number(self) -> int | Decimal:
        start = self.pos

        if self.peek() == "-":
            self.pos += 1

        integer_start = self.pos

        while (
            self.pos < len(self.value)
            and self.value[self.pos].isascii()
            and self.value[self.pos].isdigit()
        ):
            self.pos += 1

        integer_digits = self.pos - integer_start

        if integer_digits == 0 or integer_digits > 15:
            self.fail("Expected integer digits.", start)

        is_decimal = False

        if self.pos < len(self.value) and self.value[self.pos] == ".":
            is_decimal = True
            decimal_position = self.pos
            self.pos += 1
            fraction_start = self.pos

            while (
                self.pos < len(self.value)
                and self.value[self.pos].isascii()
                and self.value[self.pos].isdigit()
            ):
                self.pos += 1

            fraction_digits = self.pos - fraction_start

            if fraction_digits == 0 or fraction_digits > 3 or integer_digits > 12:
                self.fail("Invalid decimal.", decimal_position)

        text = self.value[start : self.pos]

        if is_decimal:
            result = Decimal(text)

            if not MIN_DECIMAL <= result <= MAX_DECIMAL:
                self.fail("Decimal is outside the allowed range.", start)

            return result

        result = int(text)

        if not MIN_INTEGER <= result <= MAX_INTEGER:
            self.fail("Integer is outside the allowed range.", start)

        return result

    def parse_string(self) -> str:
        start = self.pos
        self.pos += 1
        result = []

        while True:
            if self.at_end():
                self.fail("Unclosed string.", start)

            char = self.peek()

            if ord(char) < 0x20 or ord(char) >= 0x7F:
                self.fail("Strings must contain ASCII VCHAR or SP.")

            if char == '"':
                self.pos += 1
                return "".join(result)

            if char == "\\":
                self.pos += 1

                if self.at_end():
                    self.fail("Unclosed string escape.", start)

                escaped = self.peek()

                if escaped not in {'"', "\\"}:
                    self.fail("Invalid string escape.")

                result.append(escaped)
                self.pos += 1
                continue

            result.append(char)
            self.pos += 1

    def parse_token(self) -> Token:
        match = _token_re.match(self.value, self.pos)

        if match is None or match.start() != self.pos:
            self.fail("Expected token.")

        self.pos = match.end()
        return Token(match.group(0))

    def parse_byte_sequence(self) -> bytes:
        start = self.pos
        end = self.value.find(":", start + 1)

        if end == -1:
            self.fail("Unclosed byte sequence.", start)

        encoded = self.value[start + 1 : end]

        if not re.fullmatch(r"[A-Za-z0-9+/]*(?:={1,2})?", encoded):
            self.fail("Invalid byte sequence.", start)

        padding = len(encoded) - len(encoded.rstrip("="))

        if padding > 2 or len(encoded) % 4 != 0:
            self.fail("Invalid byte sequence padding.", start)

        if padding and len(b64decode(encoded, validate=True)) % 3 != 3 - padding:
            self.fail("Invalid byte sequence padding.", start)

        try:
            result = b64decode(encoded, validate=True)
        except Exception as exc:
            raise StructuredFieldError(
                "Invalid byte sequence.", start, self.field
            ) from exc

        self.pos = end + 1
        return result

    def parse_boolean(self) -> bool:
        start = self.pos
        self.pos += 1

        if self.at_end() or self.peek() not in "01":
            self.fail("Expected boolean.", start)

        result = self.peek() == "1"
        self.pos += 1
        return result

    def _parse_inner_list_body(self) -> tuple[Item, ...]:
        start = self.pos
        self.pos += 1
        items: list[Item] = []

        while True:
            self.consume_sp()

            if self.at_end():
                self.fail("Unclosed inner list.", start)

            if self.peek() == ")":
                self.pos += 1
                return tuple(items)

            items.append(self.parse_item(stop_before_sp=True))

            if self.at_end():
                self.fail("Unclosed inner list.", start)

            if self.peek() not in " )":
                self.fail("Expected SP or ')' after inner list item.")

    def parse_parameters(self, stop_before_sp: bool = False) -> Parameters:
        result: dict[str, Item | InnerList] = {}

        while not self.at_end() and self.peek() == ";":
            if stop_before_sp and self.value[self.pos - 1] == " ":
                break

            self.pos += 1
            self.consume_sp()
            key = self.parse_key()

            if key in result:
                self.fail(f"Duplicate parameter {key!r}.")

            if self.at_end() or self.peek() != "=":
                self.fail("Expected '=' after parameter name.")

            self.pos += 1

            if not self.at_end() and self.peek() == "(":
                result[key] = self.parse_inner_list()
            else:
                result[key] = self.parse_item()

        return tuple(result.items())

    def parse_key(self) -> str:
        match = _key_re.match(self.value, self.pos)

        if match is None or match.start() != self.pos:
            self.fail("Expected key.")

        self.pos = match.end()
        return match.group(0)

    def parse_inner_list(self) -> InnerList:
        items = self._parse_inner_list_body()
        parameters = self.parse_parameters()
        return InnerList(items, dict(parameters))

    def parse_list(self) -> StructuredList:
        result: StructuredList = []
        self.consume_ows()

        if self.at_end():
            return result

        while True:
            self.consume_ows()

            if self.peek() == "(":
                member: Item | InnerList = self.parse_inner_list()
            else:
                member = self.parse_item()

            result.append(member)
            self.consume_ows()

            if self.at_end():
                return result

            if self.peek() != ",":
                self.fail("Expected ',' between list members.")

            self.pos += 1
            self.consume_ows()

            if self.at_end():
                self.fail("Expected list member after ','.")

    def parse_dictionary(self) -> StructuredDictionary:
        result: StructuredDictionary = {}
        self.consume_ows()
        self.key_positions = {}

        if self.at_end():
            return result

        while True:
            self.consume_ows()

            key_start = self.pos
            key = self.parse_key()
            self.key_positions[key] = key_start

            if key in result:
                self.fail(f"Duplicate dictionary key {key!r}.")

            key_parameters = self.parse_parameters()

            if not self.at_end() and self.peek() == "=":
                self.pos += 1

                if not self.at_end() and self.peek() == "(":
                    member = self._with_key_parameters(
                        self.parse_inner_list(), key_parameters
                    )
                else:
                    member = self._with_key_parameters(
                        self.parse_item(), key_parameters
                    )
            else:
                member = Item(True, dict(key_parameters))

            result[key] = member
            self.consume_ows()

            if self.at_end():
                return result

            if self.peek() != ",":
                self.fail("Expected ',' between dictionary members.")

            self.pos += 1
            self.consume_ows()

            if self.at_end():
                self.fail("Expected dictionary member after ','.")

    def _with_key_parameters(
        self, member: Item | InnerList, parameters: Parameters
    ) -> Item | InnerList:
        if not parameters:
            return member

        existing = {key for key, _ in member.parameters}

        for key, _ in parameters:
            if key in existing:
                self.fail(f"Duplicate parameter {key!r}.")

        merged = parameters + member.parameters

        if isinstance(member, Item):
            return Item(member.value, dict(merged))

        return InnerList(member.items, dict(merged))


def parse_item(value: str, field: int | None = None) -> Item:
    """Parse an RFC 8941 item field."""
    parser = _Parser(value, field)
    item = parser.parse_item()
    parser.expect_end()
    return item


def parse_list(value: str, field: int | None = None) -> StructuredList:
    """Parse an RFC 8941 list field."""
    parser = _Parser(value, field)
    result = parser.parse_list()
    parser.expect_end()
    return result


def parse_dictionary(
    value: str,
    field: int | None = None,
) -> StructuredDictionary:
    """Parse an RFC 8941 dictionary field."""
    return _parse_dictionary(value, field)


def _parse_dictionary(
    value: str,
    field: int | None = None,
    key_positions: dict[str, int] | None = None,
) -> StructuredDictionary:
    parser = _Parser(value, field)
    result = parser.parse_dictionary()
    parser.expect_end()

    if key_positions is not None:
        key_positions.update(parser.key_positions)

    return result


def _dump_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise StructuredFieldError("Decimal must be finite.")

    text = format(value, "f")
    negative = text.startswith("-")

    if negative:
        text = text[1:]

    integer_text, dot, fraction_text = text.partition(".")
    integer_text = integer_text.lstrip("0") or "0"

    if fraction_text and len(fraction_text) > 3:
        raise StructuredFieldError("Decimals may have at most three fractional digits.")

    if not dot:
        fraction_text = "0"

    if len(integer_text) > 12:
        raise StructuredFieldError("Decimal is outside the allowed range.")

    result = f"{integer_text}.{fraction_text}"
    result_decimal = Decimal(("-" if negative else "") + result)

    if not MIN_DECIMAL <= result_decimal <= MAX_DECIMAL:
        raise StructuredFieldError("Decimal is outside the allowed range.")

    return ("-" if negative else "") + result


def _dump_bare_item(value: BareItem) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"

    if isinstance(value, int):
        if not MIN_INTEGER <= value <= MAX_INTEGER:
            raise StructuredFieldError("Integer is outside the allowed range.")

        return str(value)

    if isinstance(value, Decimal):
        return _dump_decimal(value)

    if isinstance(value, Token):
        if _token_re.fullmatch(value) is None:
            raise StructuredFieldError("Invalid token.")

        return value

    if isinstance(value, str):
        if any(ord(char) < 0x20 or ord(char) >= 0x7F for char in value):
            raise StructuredFieldError("Strings must contain ASCII VCHAR or SP.")

        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    if isinstance(value, bytes):
        return f":{b64encode(value).decode('ascii')}:"

    raise StructuredFieldError("Unsupported item type.")


def _dump_parameters(parameters: Parameters) -> str:
    result = []

    for key, value in parameters:
        result.append(";")
        result.append(key)
        result.append("=")

        if isinstance(value, InnerList):
            result.append(_dump_inner_list(value))
        else:
            result.append(_dump_item(value))

    return "".join(result)


def _dump_item(item: t.Any) -> str:
    item = coerce_item(item)
    return _dump_bare_item(item.value) + _dump_parameters(item.parameters)


def _dump_inner_list(inner_list: InnerList) -> str:
    items = " ".join(_dump_item(item) for item in inner_list.items)
    return f"({items}){_dump_parameters(inner_list.parameters)}"


def dump_item(item: t.Any) -> str:
    """Serialize an RFC 8941 item field to canonical form."""
    return _dump_item(item)


def dump_list(items: cabc.Iterable[t.Any]) -> str:
    """Serialize an RFC 8941 list field to canonical form."""
    result = []

    for item in items:
        if isinstance(item, InnerList):
            result.append(_dump_inner_list(item))
        else:
            result.append(_dump_item(item))

    return ", ".join(result)


def dump_dictionary(items: cabc.Mapping[str, t.Any]) -> str:
    """Serialize an RFC 8941 dictionary field to canonical form."""
    result = []

    for key, value in items.items():
        if _key_re.fullmatch(key) is None:
            raise StructuredFieldError("Invalid dictionary key.")

        if isinstance(value, InnerList):
            result.append(f"{key}={_dump_inner_list(value)}")
            continue

        item = coerce_item(value)

        if item.value is True and not item.parameters:
            result.append(key)
        else:
            result.append(f"{key}={_dump_item(item)}")

    return ", ".join(result)
