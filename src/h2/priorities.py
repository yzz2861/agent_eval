"""
RFC 9218 extensible HTTP prioritization helpers.
"""
from __future__ import annotations

import base64

from hyperframe.frame import ExtensionFrame

from .exceptions import ProtocolError

PRIORITY_UPDATE_FRAME_TYPE = 0x10
MINIMUM_URGENCY = 0
MAXIMUM_URGENCY = 7
DEFAULT_URGENCY = 3


class PriorityUpdateFrame(ExtensionFrame):
    type = PRIORITY_UPDATE_FRAME_TYPE

    def __init__(self, prioritized_stream_id: int, priority_field_value: bytes) -> None:
        super().__init__(type=PRIORITY_UPDATE_FRAME_TYPE, stream_id=0)
        self.prioritized_stream_id = prioritized_stream_id
        self.priority_field_value = priority_field_value

    def serialize_body(self) -> bytes:
        body = self.prioritized_stream_id.to_bytes(4, "big") + self.priority_field_value
        self.body = body
        self.body_len = len(body)
        return body

    def serialize(self) -> bytes:
        body = self.serialize_body()
        header = (
            self.body_len.to_bytes(3, "big")
            + bytes([self.type, self.flag_byte])
            + self.stream_id.to_bytes(4, "big")
        )
        return header + body


class _StructuredFieldParser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def parse_dictionary(self) -> dict[bytes, object]:
        result: dict[bytes, object] = {}
        self._skip_ows()
        if self.pos != len(self.data):
            self._parse_member(result)
            while True:
                self._skip_ows()
                if self.pos == len(self.data):
                    return result
                self._consume(b",")
                self._skip_ows()
                if self.pos == len(self.data) or self.data[self.pos:self.pos + 1] == b",":
                    self._error()
                self._parse_member(result)
        self._skip_ows()
        self._expect_end()
        return result

    def _parse_member(self, result: dict[bytes, object]) -> None:
        key = self._parse_key()
        value: object = True
        if self._peek() == ord("="):
            self.pos += 1
            value = self._parse_item_or_inner_list()
        else:
            value = (value, self._parse_parameters())
        if key in result:
            self._error()
        result[key] = value

    def _parse_item_or_inner_list(self) -> object:
        if self._peek() == ord("("):
            return self._parse_inner_list()
        return self._parse_item()

    def _parse_item(self) -> tuple[object, dict[bytes, object]]:
        value = self._parse_bare_item()
        return value, self._parse_parameters()

    def _parse_inner_list(self) -> tuple[list[tuple[object, dict[bytes, object]]], dict[bytes, object]]:
        self.pos += 1
        items: list[tuple[object, dict[bytes, object]]] = []
        while True:
            if self._peek() == ord(")"):
                self.pos += 1
                return items, self._parse_parameters()
            if items:
                self._require_sp()
            else:
                self._skip_sp()
            items.append(self._parse_item())

    def _parse_bare_item(self) -> object:
        char = self._peek()
        if char in (ord("-"), ord("0")) or ord("1") <= char <= ord("9"):
            return self._parse_number()
        if char == ord('"'):
            return self._parse_string()
        if char == ord("?"):
            return self._parse_boolean()
        if char == ord(":"):
            return self._parse_byte_sequence()
        if self._is_alpha(char) or char == ord("*"):
            return self._parse_token()
        self._error()

    def _parse_number(self) -> int | float:
        start = self.pos
        decimal = False
        if self._peek() == ord("-"):
            self.pos += 1
        if not ord("0") <= self._peek() <= ord("9"):
            self._error()
        integer_digits = 0
        while ord("0") <= self._peek() <= ord("9"):
            integer_digits += 1
            self.pos += 1
        if self._peek() == ord("."):
            decimal = True
            self.pos += 1
            fraction_start = self.pos
            while ord("0") <= self._peek() <= ord("9"):
                self.pos += 1
            fraction_digits = self.pos - fraction_start
            if not 1 <= fraction_digits <= 3:
                self._error()
        text = self.data[start:self.pos].decode("ascii")
        if (decimal and integer_digits > 9) or (not decimal and integer_digits > 15):
            self._error()
        try:
            return float(text) if decimal else int(text)
        except ValueError:  # pragma: no cover
            self._error()

    def _parse_string(self) -> bytes:
        self.pos += 1
        result = bytearray()
        while True:
            char = self._peek()
            if char == ord('"'):
                self.pos += 1
                return bytes(result)
            if char < 0:
                self._error()
            if char < 0x20 or char > 0x7E:
                self._error()
            if char == ord("\\"):
                self.pos += 1
                escaped = self._peek()
                if escaped not in (ord('"'), ord("\\")):
                    self._error()
                result.append(escaped)
            else:
                result.append(char)
            self.pos += 1

    def _parse_boolean(self) -> bool:
        self.pos += 1
        value = self._peek()
        if value not in (ord("0"), ord("1")):
            self._error()
        self.pos += 1
        return value == ord("1")

    def _parse_byte_sequence(self) -> bytes:
        self.pos += 1
        start = self.pos
        while True:
            char = self._peek()
            if char == ord(":"):
                break
            if not self._is_b64(char):
                self._error()
            self.pos += 1
        value = self.data[start:self.pos]
        self.pos += 1
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as e:
            raise ProtocolError("Invalid byte sequence") from e

    def _parse_token(self) -> bytes:
        start = self.pos
        while self._is_token_char(self._peek()):
            self.pos += 1
        if self.pos == start:
            self._error()
        return self.data[start:self.pos]

    def _parse_key(self) -> bytes:
        start = self.pos
        if not (self._is_lower_alpha(self._peek()) or self._peek() == ord("*")):
            self._error()
        while self._is_key_char(self._peek()):
            self.pos += 1
        return self.data[start:self.pos]

    def _parse_parameters(self) -> dict[bytes, object]:
        result: dict[bytes, object] = {}
        while self._peek() == ord(";"):
            self.pos += 1
            self._skip_sp()
            key = self._parse_key()
            value: object = True
            if self._peek() == ord("="):
                self.pos += 1
            value, _ = self._parse_item()
            if key in result:
                self._error()
            result[key] = value
        return result

    def _skip_ows(self) -> None:
        while self._peek() in (0x20, 0x09):
            self.pos += 1

    def _skip_sp(self) -> None:
        while self._peek() == 0x20:
            self.pos += 1

    def _require_sp(self) -> None:
        if self._peek() != 0x20:
            self._error()
        self._skip_sp()

    def _consume(self, expected: bytes) -> None:
        if self.pos + len(expected) > len(self.data) or self.data[self.pos:self.pos + len(expected)] != expected:
            self._error()
        self.pos += len(expected)

    def _expect_end(self) -> None:
        if self.pos != len(self.data):
            self._error()

    def _peek(self) -> int:
        if self.pos >= len(self.data):
            return -1
        return self.data[self.pos]

    def _error(self) -> None:
        msg = "Invalid structured field value"
        raise ProtocolError(msg)

    @staticmethod
    def _is_alpha(char: int) -> bool:
        return ord("a") <= char <= ord("z") or ord("A") <= char <= ord("Z")

    @staticmethod
    def _is_lower_alpha(char: int) -> bool:
        return ord("a") <= char <= ord("z")

    @staticmethod
    def _is_key_char(char: int) -> bool:
        if char < 0:
            return False
        return (
            ord("a") <= char <= ord("z")
            or ord("0") <= char <= ord("9")
            or chr(char) in "_-.*"
        )

    @staticmethod
    def _is_token_char(char: int) -> bool:
        if char < 0:
            return False
        if (
            ord("a") <= char <= ord("z")
            or ord("A") <= char <= ord("Z")
            or ord("0") <= char <= ord("9")
        ):
            return True
        return chr(char) in "!#$%&'*+-.^_`|~"

    @staticmethod
    def _is_b64(char: int) -> bool:
        if char < 0:
            return False
        return (
            ord("a") <= char <= ord("z")
            or ord("A") <= char <= ord("Z")
            or ord("0") <= char <= ord("9")
            or chr(char) in "+/="
        )


def parse_priority_field_value(
    data: bytes,
) -> tuple[int | None, bool | None, dict[bytes, object], bytes]:
    if not isinstance(data, bytes):
        msg = "Invalid structured field value"
        raise ProtocolError(msg)
    try:
        members = _StructuredFieldParser(data).parse_dictionary() if data else {}
    except (ValueError, UnicodeError) as e:
        msg = "Invalid structured field value"
        raise ProtocolError(msg) from e
    urgency = members.pop(b"u", None)
    incremental = members.pop(b"i", None)
    if urgency is not None and (
        not isinstance(urgency, tuple)
        or type(urgency[0]) is not int
        or not MINIMUM_URGENCY <= urgency[0] <= MAXIMUM_URGENCY
    ):
        msg = "Invalid urgency"
        raise ProtocolError(msg)
    if incremental is not None and (
        not isinstance(incremental, tuple)
        or not isinstance(incremental[0], bool)
    ):
        msg = "Invalid incremental parameter"
        raise ProtocolError(msg)
    if incremental is not None and isinstance(incremental, tuple) and incremental[1]:
        msg = "Invalid incremental parameter"
        raise ProtocolError(msg)
    urgency_value = urgency[0] if isinstance(urgency, tuple) else None
    incremental_value = incremental[0] if isinstance(incremental, tuple) else None
    return urgency_value, incremental_value, members, data


def serialize_priority_field_value(
    urgency: int = DEFAULT_URGENCY,
    incremental: bool = False,
    extensions: bytes | None = None,
) -> bytes:
    if type(urgency) is not int or not MINIMUM_URGENCY <= urgency <= MAXIMUM_URGENCY:
        msg = "Urgency must be between 0 and 7"
        raise ValueError(msg)
    if not isinstance(incremental, bool):
        msg = "Incremental must be a boolean"
        raise ValueError(msg)
    result = f"u={urgency}".encode("ascii")
    if incremental:
        result += b",i"
    if extensions is not None:
        if not isinstance(extensions, bytes) or not extensions:
            msg = "Extensions must be a non-empty structured field fragment"
            raise ValueError(msg)
        leading_or_trailing = (
            extensions[:1] in (b",", b" ", b"\t")
            or extensions[-1:] in (b",", b" ", b"\t")
        )
        if leading_or_trailing:
            msg = "Extensions must not include surrounding delimiters"
            raise ValueError(msg)
        result += b"," + extensions
    parse_priority_field_value(result)
    return result
