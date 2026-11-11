import base64
import binascii
import json
import math
import re
from typing import Any, Dict, NoReturn, Optional, Tuple

from .bytes_to_base64url import bytes_to_base64url
from .byteslike_to_bytes import byteslike_to_bytes
from .exceptions import InvalidJSONStructure
from .structs import (
    ClientDataType,
    CollectedClientData,
    TokenBinding,
    TokenBindingStatus,
)

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_MAX_JSON_DEPTH = 64
_WHITESPACE = b" \t\r\n"


class _StrictJSONParser:
    """Parse JSON from bytes while retaining exact value locations.

    The standard library parser silently keeps the last value for duplicate object
    properties. That makes the parsed value disagree with the bytes covered by the
    authenticator signature. This parser rejects duplicate properties at every depth
    and records byte spans for all object properties in the original input.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0
        self._field_ranges: Dict[str, Tuple[int, int]] = {}

    def parse(self) -> Tuple[Any, Dict[str, Tuple[int, int]]]:
        self._skip_whitespace()
        if self._pos >= len(self._data):
            self._syntax_error(None, "expected a JSON value")

        value, _, _ = self._parse_value(None, 0)

        self._skip_whitespace()
        if self._pos != len(self._data):
            detail = "trailing content after top-level value"
            if self._data[self._pos] >= 0x80:
                detail = "invalid UTF-8 after top-level value"
            self._syntax_error(None, detail)

        return value, self._field_ranges

    def _syntax_error(self, path: Optional[str], detail: str) -> NoReturn:
        if path is None:
            raise InvalidJSONStructure(
                f"Unable to decode clientDataJSON as JSON: {detail}"
            ) from None

        raise InvalidJSONStructure(
            f'Unable to decode clientDataJSON as JSON in property "{path}": {detail}'
        ) from None

    def _skip_whitespace(self) -> None:
        while self._pos < len(self._data) and self._data[self._pos] in _WHITESPACE:
            self._pos += 1

    def _parse_value(self, path: Optional[str], depth: int) -> Tuple[Any, int, int]:
        if depth > _MAX_JSON_DEPTH:
            self._syntax_error(path, "maximum JSON nesting depth exceeded")
        if self._pos >= len(self._data):
            self._syntax_error(path, "expected a JSON value")

        byte = self._data[self._pos]
        if byte == ord("{"):
            return self._parse_object(path, depth)
        if byte == ord("["):
            return self._parse_array(path, depth)
        if byte == ord('"'):
            value, start, end = self._parse_string(path)
            return value, start, end
        if byte == ord("t") or byte == ord("f") or byte == ord("n"):
            return self._parse_literal(path)
        if byte == ord("-") or ord("0") <= byte <= ord("9"):
            return self._parse_number(path)
        if byte >= 0x80:
            self._syntax_error(path, "invalid UTF-8")

        self._syntax_error(path, "expected a JSON value")

    def _parse_object(
        self, path: Optional[str], depth: int
    ) -> Tuple[Dict[str, Any], int, int]:
        start = self._pos
        self._pos += 1
        result: Dict[str, Any] = {}

        self._skip_whitespace()
        if self._pos >= len(self._data):
            self._syntax_error(path, "unterminated object")
        if self._data[self._pos] == ord("}"):
            self._pos += 1
            return result, start, self._pos

        while True:
            self._skip_whitespace()
            if self._pos >= len(self._data) or self._data[self._pos] != ord('"'):
                self._syntax_error(path, "expected an object property name")

            key, _, _ = self._parse_string(path)
            if key in result:
                location = f' in property "{path}"' if path is not None else ""
                raise InvalidJSONStructure(
                    f'clientDataJSON{location} contains duplicate property "{key}"'
                )

            self._skip_whitespace()
            if self._pos >= len(self._data) or self._data[self._pos] != ord(":"):
                self._syntax_error(
                    path, "expected a colon after an object property name"
                )
            self._pos += 1
            self._skip_whitespace()

            child_path = f"{path}.{key}" if path is not None else key
            value, value_start, value_end = self._parse_value(child_path, depth + 1)
            result[key] = value
            self._field_ranges[child_path] = (value_start, value_end)

            self._skip_whitespace()
            if self._pos >= len(self._data):
                self._syntax_error(path, "unterminated object")

            delimiter = self._data[self._pos]
            if delimiter == ord(","):
                self._pos += 1
                self._skip_whitespace()
                if self._pos < len(self._data) and self._data[self._pos] == ord("}"):
                    self._syntax_error(path, "trailing comma in object")
                continue
            if delimiter == ord("}"):
                self._pos += 1
                return result, start, self._pos

            if delimiter >= 0x80:
                self._syntax_error(path, "invalid UTF-8")
            self._syntax_error(path, "expected a comma or closing brace")

    def _parse_array(self, path: Optional[str], depth: int) -> Tuple[Any, int, int]:
        start = self._pos
        self._pos += 1
        result = []

        self._skip_whitespace()
        if self._pos >= len(self._data):
            self._syntax_error(path, "unterminated array")
        if self._data[self._pos] == ord("]"):
            self._pos += 1
            return result, start, self._pos

        while True:
            self._skip_whitespace()
            child_path = (
                f"{path}[{len(result)}]" if path is not None else f"[{len(result)}]"
            )
            value, value_start, value_end = self._parse_value(child_path, depth + 1)
            result.append(value)
            self._field_ranges[child_path] = (value_start, value_end)

            self._skip_whitespace()
            if self._pos >= len(self._data):
                self._syntax_error(path, "unterminated array")

            delimiter = self._data[self._pos]
            if delimiter == ord(","):
                self._pos += 1
                self._skip_whitespace()
                if self._pos < len(self._data) and self._data[self._pos] == ord("]"):
                    self._syntax_error(path, "trailing comma in array")
                continue
            if delimiter == ord("]"):
                self._pos += 1
                return result, start, self._pos

            if delimiter >= 0x80:
                self._syntax_error(path, "invalid UTF-8")
            self._syntax_error(path, "expected a comma or closing bracket")

    def _parse_string(self, path: Optional[str]) -> Tuple[str, int, int]:
        start = self._pos
        if self._data[self._pos] != ord('"'):
            self._syntax_error(path, "expected a string")
        self._pos += 1

        while self._pos < len(self._data):
            byte = self._data[self._pos]
            if byte == ord('"'):
                end = self._pos + 1
                raw = self._data[start:end]
                try:
                    value = json.loads(raw)
                except UnicodeDecodeError:
                    self._syntax_error(path, "invalid UTF-8 in string")
                except ValueError:
                    self._syntax_error(path, "invalid string literal")

                if not isinstance(value, str):
                    self._syntax_error(path, "invalid string literal")

                try:
                    value.encode("utf-8")
                except UnicodeEncodeError:
                    self._syntax_error(path, "invalid Unicode escape sequence")

                self._pos = end
                return value, start, end
            if byte == ord("\\"):
                self._pos += 1
                if self._pos >= len(self._data):
                    self._syntax_error(path, "unterminated string")
            elif byte < 0x20:
                self._syntax_error(path, "unescaped control character in string")
            self._pos += 1

        self._syntax_error(path, "unterminated string")

    def _parse_literal(self, path: Optional[str]) -> Tuple[Any, int, int]:
        start = self._pos
        for literal, value in ((b"true", True), (b"false", False), (b"null", None)):
            if self._data.startswith(literal, self._pos):
                self._pos += len(literal)
                return value, start, self._pos

        if self._data[self._pos] >= 0x80:
            self._syntax_error(path, "invalid UTF-8")
        self._syntax_error(path, "invalid JSON literal")

    def _parse_number(self, path: Optional[str]) -> Tuple[Any, int, int]:
        start = self._pos

        if self._data[self._pos] == ord("-"):
            self._pos += 1
            if self._pos >= len(self._data):
                self._syntax_error(path, "invalid number")

        if self._data[self._pos] == ord("0"):
            self._pos += 1
        elif ord("1") <= self._data[self._pos] <= ord("9"):
            self._pos += 1
            while self._pos < len(self._data) and ord("0") <= self._data[
                self._pos
            ] <= ord("9"):
                self._pos += 1
        else:
            self._syntax_error(path, "invalid number")

        if self._pos < len(self._data) and self._data[self._pos] == ord("."):
            self._pos += 1
            if self._pos >= len(self._data) or not (
                ord("0") <= self._data[self._pos] <= ord("9")
            ):
                self._syntax_error(path, "invalid number")
            while self._pos < len(self._data) and ord("0") <= self._data[
                self._pos
            ] <= ord("9"):
                self._pos += 1

        if self._pos < len(self._data) and self._data[self._pos] in (
            ord("e"),
            ord("E"),
        ):
            self._pos += 1
            if self._pos < len(self._data) and self._data[self._pos] in (
                ord("+"),
                ord("-"),
            ):
                self._pos += 1
            if self._pos >= len(self._data) or not (
                ord("0") <= self._data[self._pos] <= ord("9")
            ):
                self._syntax_error(path, "invalid number")
            while self._pos < len(self._data) and ord("0") <= self._data[
                self._pos
            ] <= ord("9"):
                self._pos += 1

        raw = self._data[start : self._pos]
        try:
            value = json.loads(raw)
        except ValueError:
            self._syntax_error(path, "invalid number")

        if isinstance(value, float) and not math.isfinite(value):
            self._syntax_error(path, "non-finite number")

        return value, start, self._pos


def _require_string(json_dict: Dict[str, Any], field: str) -> str:
    if field not in json_dict:
        raise InvalidJSONStructure(
            f'clientDataJSON missing required property "{field}"'
        )

    value = json_dict[field]
    if not isinstance(value, str):
        raise InvalidJSONStructure(
            f'clientDataJSON property "{field}" must be a string'
        )

    return value


def _decode_challenge(value: str) -> bytes:
    if not _BASE64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise InvalidJSONStructure(
            'clientDataJSON property "challenge" must be a canonical, unpadded Base64URL string'
        )

    padded = f"{value}{'=' * (-len(value) % 4)}"
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise InvalidJSONStructure(
            'clientDataJSON property "challenge" must be a canonical, unpadded Base64URL string'
        ) from None

    # A value can decode successfully but still have a non-canonical encoding (for
    # example, the final Base64URL character may contain unused bits). Comparing the
    # canonical re-encoding rejects those alternate byte representations.
    if bytes_to_base64url(decoded) != value:
        raise InvalidJSONStructure(
            'clientDataJSON property "challenge" must be a canonical, unpadded Base64URL string'
        )

    return decoded


def parse_client_data_json(val: bytes) -> CollectedClientData:
    """
    Break apart `response.clientDataJSON` buffer into structured data.

    This is a strict parser: duplicate object properties, trailing content,
    non-canonical Base64URL challenges, incorrect field types, and unknown enum
    values are all rejected. The returned object retains the exact input bytes and
    the byte offsets of parsed properties so callers can bind parsed values to the
    bytes covered by the authenticator signature without re-serializing JSON.
    """
    val = byteslike_to_bytes(val)

    parser = _StrictJSONParser(val)
    json_dict, field_ranges = parser.parse()

    if type(json_dict) is not dict:
        raise InvalidJSONStructure("clientDataJSON was not a dict")

    type_value = _require_string(json_dict, "type")
    challenge_value = _require_string(json_dict, "challenge")
    origin = _require_string(json_dict, "origin")

    try:
        client_data_type = ClientDataType(type_value)
    except ValueError:
        raise InvalidJSONStructure(
            'clientDataJSON property "type" has an unknown value; expected '
            '"webauthn.create" or "webauthn.get"'
        ) from None

    challenge = _decode_challenge(challenge_value)

    cross_origin: Optional[bool] = None
    if "crossOrigin" in json_dict:
        cross_origin_value = json_dict["crossOrigin"]
        if type(cross_origin_value) is not bool:
            raise InvalidJSONStructure(
                'clientDataJSON property "crossOrigin" must be a boolean'
            )
        cross_origin = cross_origin_value

    top_origin: Optional[str] = None
    if "topOrigin" in json_dict:
        top_origin_value = json_dict["topOrigin"]
        if type(top_origin_value) is not str:
            raise InvalidJSONStructure(
                'clientDataJSON property "topOrigin" must be a string'
            )
        top_origin = top_origin_value

    token_binding: Optional[TokenBinding] = None
    if "tokenBinding" in json_dict:
        token_binding_dict = json_dict["tokenBinding"]
        if type(token_binding_dict) is not dict:
            raise InvalidJSONStructure(
                'clientDataJSON property "tokenBinding" must be an object'
            )

        if "status" not in token_binding_dict:
            raise InvalidJSONStructure(
                'clientDataJSON property "tokenBinding" missing required property "status"'
            )

        status_value = token_binding_dict["status"]
        if type(status_value) is not str:
            raise InvalidJSONStructure(
                'clientDataJSON property "tokenBinding.status" must be a string'
            )

        try:
            status = TokenBindingStatus(status_value)
        except ValueError:
            raise InvalidJSONStructure(
                'clientDataJSON property "tokenBinding.status" has an unknown '
                'value; expected "present" or "supported"'
            ) from None

        token_binding_id: Optional[str] = None
        if "id" in token_binding_dict:
            id_value = token_binding_dict["id"]
            if type(id_value) is not str:
                raise InvalidJSONStructure(
                    'clientDataJSON property "tokenBinding.id" must be a string'
                )
            token_binding_id = id_value

        token_binding = TokenBinding(status=status, id=token_binding_id)

    return CollectedClientData(
        type=client_data_type,
        challenge=challenge,
        origin=origin,
        cross_origin=cross_origin,
        token_binding=token_binding,
        top_origin=top_origin,
        raw_bytes=val,
        raw_field_ranges=field_ranges,
    )
