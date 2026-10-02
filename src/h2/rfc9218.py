"""RFC 9218 extensible HTTP/2 prioritization support."""
from __future__ import annotations

import struct
from collections.abc import Mapping
from typing import Any

from hyperframe.frame import ExtensionFrame

from .exceptions import FrameDataMissingError, ProtocolError

PRIORITY_UPDATE_FRAME_TYPE = 0x10


class PriorityUpdateFrame(ExtensionFrame):
    """A PRIORITY_UPDATE frame carried on stream zero."""

    type = PRIORITY_UPDATE_FRAME_TYPE

    def __init__(self, stream_id: int = 0) -> None:
        super().__init__(PRIORITY_UPDATE_FRAME_TYPE, stream_id)
        self.prioritized_stream_id = 0
        self.priority_field_value = b""

    @classmethod
    def create(cls, prioritized_stream_id: int, priority_field_value: bytes) -> PriorityUpdateFrame:
        frame = cls(0)
        frame.body = struct.pack(">I", prioritized_stream_id) + priority_field_value
        frame.body_len = len(frame.body)
        frame.prioritized_stream_id = prioritized_stream_id
        frame.priority_field_value = priority_field_value
        return frame

    def parse_body(self, data: memoryview) -> None:
        super().parse_body(data)
        self.prioritized_stream_id = 0
        self.priority_field_value = b""


class _Parser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def parse_dict(self) -> tuple[int, bool, dict[bytes, bytes]]:
        urgency: int | None = None
        incremental = False
        extensions: dict[bytes, bytes] = {}
        seen: set[bytes] = set()
        for key, raw_value, raw_member, shorthand in split_dictionary(self.data):
            if key in seen:
                raise ProtocolError("Duplicate structured field key")
            seen.add(key)
            value, parameters = self.parse_member(raw_value, shorthand)
            if key == b"u":
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ProtocolError("Priority urgency must be an integer")
                urgency = value
                incremental = parameters.get(b"i", incremental)
            elif key == b"i":
                if not isinstance(value, bool):
                    raise ProtocolError("Priority incremental parameter must be a boolean")
                incremental = value
            else:
                if shorthand:
                    extensions[key] = b"?1" + raw_member[len(key):].lstrip(b" ")
                else:
                    extensions[key] = raw_value

        urgency = 3 if urgency is None else urgency
        if not 0 <= urgency <= 7:
            raise ProtocolError(f"Priority urgency must be between 0 and 7, not {urgency}")
        return urgency, bool(incremental), extensions

    def parse_member(self, raw_value: bytes, shorthand: bool) -> tuple[Any, dict[bytes, Any]]:
        if shorthand:
            parser = _Parser(raw_value)
            return True, parser.parse_parameters()
        if not raw_value:
            parser = _Parser(raw_value)
            return True, parser.parse_parameters()
        parser = _Parser(raw_value)
        value = parser.parse_bare_item()
        parameters = parser.parse_parameters(raw_value.endswith(b")"))
        parser.skip_ows()
        if parser.position != len(raw_value):
            raise ProtocolError("Invalid structured field dictionary member")
        return value, parameters

    def parse_parameters(self, inside_list: bool = False) -> dict[bytes, Any]:
        result: dict[bytes, Any] = {}
        while self.at(b";"):
            if self.parameter_terminates_inner_list():
                break
            self.position += 1
            self.skip_sp()
            key = self.parse_key()
            value: Any = True
            if self.at(b"="):
                self.position += 1
                value = self.parse_bare_item()
            if key in result:
                raise ProtocolError("Duplicate structured field parameter")
            result[key] = value
        return result

    def parameter_terminates_inner_list(self) -> bool:
        """Return whether this semicolon belongs to the enclosing list item."""
        depth = 0
        quoted = False
        escaped = False
        for byte in self.data[self.position:]:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == ord("\\"):
                    escaped = True
                elif byte == ord('"'):
                    quoted = False
            elif byte == ord('"'):
                quoted = True
            elif byte == ord("("):
                depth += 1
            elif byte == ord(")"):
                if depth == 0:
                    return True
                depth -= 1
            elif byte == ord(",") and depth == 0:
                return False
        return False

    def parse_bare_item(self) -> Any:
        self.skip_sp()
        if self.position >= len(self.data):
            raise ProtocolError("Missing structured field value")
        byte = self.data[self.position]
        if byte in b"-0123456789":
            return self.parse_number()
        if byte == ord("?"):
            return self.parse_boolean()
        if byte == ord('"'):
            return self.parse_quoted_string()
        if byte == ord(":"):
            return self.parse_byte_sequence()
        if byte == ord("("):
            return self.parse_inner_list()
        if self.is_alpha(byte) or byte == ord("*"):
            return self.parse_token()
        raise ProtocolError("Invalid structured field value")

    def parse_number(self) -> int | float:
        start = self.position
        if self.at(b"-"):
            self.position += 1
        digits_start = self.position
        while self.position < len(self.data) and self.is_digit(self.data[self.position]):
            self.position += 1
        integer_digits = self.position - digits_start
        if integer_digits == 0 or integer_digits > 15:
            raise ProtocolError("Invalid structured field integer")
        if integer_digits > 1 and self.data[digits_start] == ord("0"):
            raise ProtocolError("Structured field integer has a leading zero")
        decimal = False
        if self.at(b"."):
            decimal = True
            self.position += 1
            fraction_start = self.position
            while self.position < len(self.data) and self.is_digit(self.data[self.position]):
                self.position += 1
            fraction_digits = self.position - fraction_start
            if not 1 <= fraction_digits <= 3 or integer_digits > 12:
                raise ProtocolError("Invalid structured field decimal")
        elif abs(int(self.data[start:self.position])) > 999_999_999_999_999:
            raise ProtocolError("Structured field integer is out of range")
        raw = self.data[start:self.position]
        return float(raw) if decimal else int(raw)

    def parse_boolean(self) -> bool:
        self.position += 1
        if self.position >= len(self.data) or self.data[self.position] not in b"01":
            raise ProtocolError("Invalid structured field boolean")
        value = self.data[self.position] == ord("1")
        self.position += 1
        return value

    def parse_quoted_string(self) -> bytes:
        start = self.position
        self.position += 1
        escaped = False
        while self.position < len(self.data):
            byte = self.data[self.position]
            if byte < 0x20 or byte == 0x7F:
                raise ProtocolError("Invalid control character in structured field string")
            if escaped:
                if byte not in (ord('"'), ord("\\")):
                    raise ProtocolError("Invalid structured field escape")
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                self.position += 1
                return self.data[start:self.position]
            self.position += 1
        raise ProtocolError("Unterminated structured field string")

    def parse_byte_sequence(self) -> bytes:
        start = self.position
        end = self.data.find(b":", start + 1)
        if end == -1:
            raise ProtocolError("Unterminated structured field byte sequence")
        value = self.data[start + 1:end]
        allowed = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        if any(byte not in allowed for byte in value):
            raise ProtocolError("Invalid structured field byte sequence")
        self.position = end + 1
        return self.data[start:self.position]

    def parse_token(self) -> bytes:
        start = self.position
        self.position += 1
        while self.position < len(self.data) and self.is_token_character(self.data[self.position]):
            self.position += 1
        return self.data[start:self.position]

    def parse_inner_list(self) -> list[Any]:
        self.position += 1
        values: list[Any] = []
        while True:
            self.skip_sp()
            if self.at(b")"):
                self.position += 1
                self.parse_parameters()
                return values
            if values:
                self.skip_sp()
            values.append(self.parse_bare_item())
            self.parse_parameters(inside_list=True)

    def parse_key(self) -> bytes:
        start = self.position
        if self.position >= len(self.data) or not (self.is_alpha(self.data[self.position]) or self.data[self.position] == ord("*")):
            raise ProtocolError("Invalid structured field key")
        self.position += 1
        while self.position < len(self.data) and self.is_key_character(self.data[self.position]):
            self.position += 1
        return self.data[start:self.position]

    def at(self, token: bytes) -> bool:
        return self.position < len(self.data) and self.data[self.position] == token[0]

    def skip_sp(self) -> None:
        if self.position < len(self.data) and self.data[self.position] == ord(" "):
            self.position += 1

    def skip_ows(self) -> None:
        while self.position < len(self.data) and self.data[self.position] == ord(" "):
            self.position += 1

    @staticmethod
    def is_digit(byte: int) -> bool:
        return ord("0") <= byte <= ord("9")

    @staticmethod
    def is_alpha(byte: int) -> bool:
        return ord("a") <= byte <= ord("z") or ord("A") <= byte <= ord("Z")

    @staticmethod
    def is_key_character(byte: int) -> bool:
        return _Parser.is_alpha(byte) or _Parser.is_digit(byte) or byte in b"_*-."

    @staticmethod
    def is_token_character(byte: int) -> bool:
        return byte >= 0x21 and byte != 0x7F and byte not in b'"(),;<=>?@[\\]{} '


def split_dictionary(data: bytes) -> list[tuple[bytes, bytes, bytes, bool]]:
    members: list[bytes] = []
    start = 0
    depth = 0
    quoted = False
    escaped = False
    for index, byte in enumerate(data):
        if quoted:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                quoted = False
        elif byte == ord('"'):
            quoted = True
        elif byte == ord("("):
            depth += 1
        elif byte == ord(")"):
            depth -= 1
            if depth < 0:
                raise ProtocolError("Unmatched structured field inner list")
        elif byte == ord(",") and depth == 0:
            members.append(data[start:index])
            start = index + 1
    if quoted or depth:
        raise ProtocolError("Invalid structured field dictionary")
    members.append(data[start:])

    result: list[tuple[bytes, bytes, bytes, bool]] = []
    if len(members) == 1 and not members[0].strip(b" "):
        return []
    for member in members:
        member = member.strip(b" ")
        if not member:
            raise ProtocolError("Empty structured field dictionary member")
        equal_position = member.find(b"=")
        if equal_position == -1:
            semicolon_position = member.find(b";")
            if semicolon_position == -1:
                key, rest = member, b""
            else:
                key, rest = member[:semicolon_position].strip(b" "), member[semicolon_position:].strip(b" ")
        else:
            key, rest = member[:equal_position].strip(b" "), member[equal_position + 1:].strip(b" ")
        parser = _Parser(key)
        parsed_key = parser.parse_key()
        if parser.position != len(key) or parsed_key != key:
            raise ProtocolError("Invalid structured field key")
        result.append((key, rest, member, equal_position == -1))
    return result


def parse_priority_field_value(data: bytes) -> tuple[int, bool, dict[bytes, bytes]]:
    if any(byte >= 0x80 for byte in data):
        raise ProtocolError("Structured fields must contain only ASCII data")
    return _Parser(data).parse_dict()


def parse_priority_update_frame(body: bytes | memoryview) -> tuple[int, bytes, int, bool, dict[bytes, bytes]]:
    data = bytes(body)
    if len(data) < 4:
        raise FrameDataMissingError("PRIORITY_UPDATE frame must contain a prioritized stream identifier")
    stream_id = struct.unpack(">I", data[:4])[0] & 0x7FFFFFFF
    field_value = data[4:]
    urgency, incremental, extensions = parse_priority_field_value(field_value)
    return stream_id, field_value, urgency, incremental, extensions


def serialize_priority_field_value(
    urgency: int,
    incremental: bool,
    extensions: Mapping[bytes, bytes | bool] | None = None,
) -> bytes:
    if not 0 <= urgency <= 7:
        raise ValueError(f"Priority urgency must be between 0 and 7, not {urgency}")
    if not isinstance(incremental, bool):
        raise ValueError("Priority incremental must be a bool")
    members = [f"u={urgency};i".encode() if incremental else f"u={urgency}".encode()]
    for key, value in (extensions or {}).items():
        if not isinstance(key, bytes) or not isinstance(value, (bytes, bool)):
            raise ValueError("Priority extension keys must be bytes and values must be bytes or bool")
        _Parser(key).parse_key()
        if key in (b"u", b"i"):
            raise ValueError("Priority extension parameters must not use reserved names")
        if value is True:
            members.append(key)
        elif value is False:
            members.append(key + b"=?0")
        else:
            members.append(key + b"=" + value)
    field_value = b",".join(members)
    parse_priority_field_value(field_value)
    return field_value


def build_priority_update_frame(
    prioritized_stream_id: int,
    urgency: int,
    incremental: bool,
    extensions: Mapping[bytes, bytes | bool] | None = None,
) -> PriorityUpdateFrame:
    return PriorityUpdateFrame.create(
        prioritized_stream_id,
        serialize_priority_field_value(urgency, incremental, extensions),
    )
