# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""
Minimal CBOR implementation supporting a subset of functionality and types
required for FIDO 2 CTAP.

Use the :func:`encode`, :func:`decode` and :func:`decode_from` functions to encode
and decode objects to/from CBOR.
"""

from __future__ import annotations

import struct
from types import UnionType
from typing import Any, Callable, Mapping, Sequence, TypeAlias

CborType: TypeAlias = int | bool | str | bytes | Sequence[Any] | Mapping[Any, Any]

# TODO: Requires Python 3.12, replace with collections.abc.Buffer
Buffer: TypeAlias = bytes | bytearray | memoryview

# Bounds applied when decoding CBOR data. The nesting depth of arrays and maps
# is always limited (to prevent stack exhaustion from deeply nested inputs),
# while the string length limit is enforced in strict mode only.
MAX_DEPTH = 100
MAX_STRING_LENGTH = 2**20  # 1 MiB


class CborError(ValueError):
    """Error raised when decoding invalid or non-canonical CBOR data.

    The error message indicates the path to the offending value and, where
    relevant, the CBOR data type involved. It never echoes back the decoded
    payload itself.
    """


def _dump_int(data: int, mt: int = 0) -> bytes:
    if data < 0:
        mt = 1
        data = -1 - data

    mt = mt << 5
    fmt: str
    args: tuple[int, ...]
    if data <= 23:
        fmt, args = ">B", (mt | data,)
    elif data <= 0xFF:
        fmt, args = ">BB", (mt | 24, data)
    elif data <= 0xFFFF:
        fmt, args = ">BH", (mt | 25, data)
    elif data <= 0xFFFFFFFF:
        fmt, args = ">BI", (mt | 26, data)
    else:
        fmt, args = ">BQ", (mt | 27, data)
    return struct.pack(fmt, *args)


def _dump_bool(data: bool) -> bytes:
    return b"\xf5" if data else b"\xf4"


def _dump_list(data: Sequence[CborType]) -> bytes:
    return _dump_int(len(data), mt=4) + b"".join([encode(x) for x in data])


def _sort_keys(entry):
    key = entry[0]
    return key[0], len(key), key


def _dump_dict(data: Mapping[CborType, CborType]) -> bytes:
    items = [(encode(k), encode(v)) for k, v in data.items()]
    items.sort(key=_sort_keys)
    return _dump_int(len(items), mt=5) + b"".join([k + v for (k, v) in items])


def _dump_bytes(data: bytes) -> bytes:
    return _dump_int(len(data), mt=2) + data


def _dump_text(data: str) -> bytes:
    data_bytes = data.encode("utf8")
    return _dump_int(len(data_bytes), mt=3) + data_bytes


_SERIALIZERS: Sequence[tuple[type | UnionType, Callable[[Any], bytes]]] = [
    (bool, _dump_bool),
    (int, _dump_int),
    (str, _dump_text),
    (Buffer, _dump_bytes),
    (Mapping, _dump_dict),
    (Sequence, _dump_list),
]


def _key_identity(key: Any, path: str) -> tuple[str, Any]:
    """Identity of a map key, based on its CBOR data type and value.

    This ensures that values of different CBOR types are never considered
    the same key, eg. the integer 1 and the text string "1", or the
    boolean True and the integer 1.
    """
    if isinstance(key, bool):
        return ("simple", key)
    if isinstance(key, int):
        return ("int", key)
    if isinstance(key, str):
        return ("text", key)
    if isinstance(key, (bytes, bytearray, memoryview)):
        return ("bytes", bytes(key))
    raise CborError(f"Invalid map key of type {type(key).__name__!r} at {path}")


def _key_label(key: Any, index: int) -> str:
    """Label identifying a map entry in an error path.

    Integers, booleans and (truncated) short text strings are shown
    directly; other types are identified by type and position only, to
    avoid echoing back potentially sensitive binary data.
    """
    if isinstance(key, bool):
        return repr(key)
    if isinstance(key, int):
        return str(key)
    if isinstance(key, str):
        return repr(key[:16] + ("..." if len(key) > 16 else ""))
    return f"<{type(key).__name__} #{index}>"


class _Decoder:
    """CBOR decoder with configurable strictness and resource bounds."""

    def __init__(self, strict: bool, max_depth: int, max_string_length: int):
        self._strict = strict
        self._max_depth = max_depth
        self._max_string_length = max_string_length
        self._handlers: Mapping[int, Callable] = {
            0: self._load_uint,
            1: self._load_nint,
            2: self._load_bytes,
            3: self._load_text,
            4: self._load_array,
            5: self._load_map,
            7: self._load_bool,
        }

    def decode(self, data: bytes, path: str, depth: int) -> tuple[Any, bytes]:
        if depth > self._max_depth:
            raise CborError(
                f"Maximum CBOR nesting depth ({self._max_depth}) exceeded at {path}"
            )
        if not data:
            raise CborError(f"Truncated CBOR data at {path}")
        fb = data[0]
        handler = self._handlers.get(fb >> 5)
        if handler is None:
            raise CborError(f"Unsupported CBOR major type {fb >> 5} at {path}")
        return handler(fb & 0b11111, data[1:], path, depth)

    def _load_int(self, ai: int, data: bytes, path: str) -> tuple[int, bytes]:
        if ai < 24:
            return ai, data
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        size = sizes.get(ai)
        if size is None:
            raise CborError(f"Invalid additional information {ai} at {path}")
        if len(data) < size:
            raise CborError(f"Truncated CBOR data at {path}")
        value = int.from_bytes(data[:size], "big")
        if self._strict:
            # Canonical form requires the shortest possible encoding.
            minimum = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[size]
            if value < minimum:
                raise CborError(f"Non-canonical integer encoding at {path}")
        return value, data[size:]

    def _load_uint(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[int, bytes]:
        return self._load_int(ai, data, path)

    def _load_nint(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[int, bytes]:
        val, rest = self._load_int(ai, data, path)
        return -1 - val, rest

    def _load_bool(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[bool, bytes]:
        if self._strict and ai not in (20, 21):
            raise CborError(f"Unsupported simple or floating point value at {path}")
        return ai == 21, data

    def _load_bytes(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[bytes, bytes]:
        ln, data = self._load_int(ai, data, path)
        if self._strict and ln > self._max_string_length:
            raise CborError(
                f"String of length {ln} exceeds maximum "
                f"({self._max_string_length}) at {path}"
            )
        if len(data) < ln:
            raise CborError(f"Truncated CBOR data at {path}")
        return data[:ln], data[ln:]

    def _load_text(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[str, bytes]:
        enc, rest = self._load_bytes(ai, data, path, depth)
        try:
            return enc.decode("utf8"), rest
        except UnicodeDecodeError:
            raise CborError(f"Invalid UTF-8 text string at {path}") from None

    def _load_array(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[Sequence[CborType], bytes]:
        ln, data = self._load_int(ai, data, path)
        values = []
        for i in range(ln):
            val, data = self.decode(data, f"{path}[{i}]", depth + 1)
            values.append(val)
        return values, data

    def _load_map(
        self, ai: int, data: bytes, path: str, depth: int
    ) -> tuple[Mapping[CborType, CborType], bytes]:
        ln, data = self._load_int(ai, data, path)
        values = {}
        seen = set()
        for i in range(ln):
            k, data = self.decode(data, f"{path}[{i}]", depth + 1)
            if self._strict:
                identity = _key_identity(k, path)
                if identity in seen:
                    raise CborError(
                        f"Duplicate map key of type {identity[0]!r} at {path}"
                    )
                seen.add(identity)
            v, data = self.decode(data, f"{path}[{_key_label(k, i)}]", depth + 1)
            values[k] = v
        return values, data


def encode(data: CborType) -> bytes:
    """Encodes data to a CBOR byte string."""
    for k, v in _SERIALIZERS:
        if isinstance(data, k):
            return v(data)
    raise ValueError(f"Unsupported value: {data!r}")


def decode_from(
    data: bytes,
    *,
    strict: bool = False,
    max_depth: int = MAX_DEPTH,
    max_string_length: int = MAX_STRING_LENGTH,
) -> tuple[Any, bytes]:
    """Decodes a CBOR-encoded value from the start of a byte string.

    Additional data after a valid CBOR object is returned as well.

    :param data: The CBOR-encoded data to decode.
    :param strict: When True, reject non-canonical input: duplicate map
        keys, non-minimal integer encodings, non-boolean simple values,
        and byte/text strings exceeding max_string_length.
    :param max_depth: Maximum nesting depth of arrays and maps.
    :param max_string_length: Maximum length of byte and text strings,
        enforced in strict mode only.
    :return: The decoded object, and any remaining data."""
    decoder = _Decoder(strict, max_depth, max_string_length)
    return decoder.decode(data, "$", 0)


def decode(
    data: bytes,
    *,
    strict: bool = False,
    max_depth: int = MAX_DEPTH,
    max_string_length: int = MAX_STRING_LENGTH,
) -> CborType:
    """Decodes data from a CBOR-encoded byte string.

    Also validates that no extra data follows the encoded object.

    :param data: The CBOR-encoded data to decode.
    :param strict: When True, reject non-canonical input: duplicate map
        keys, non-minimal integer encodings, non-boolean simple values,
        and byte/text strings exceeding max_string_length.
    :param max_depth: Maximum nesting depth of arrays and maps.
    :param max_string_length: Maximum length of byte and text strings,
        enforced in strict mode only.
    """
    value, rest = decode_from(
        data,
        strict=strict,
        max_depth=max_depth,
        max_string_length=max_string_length,
    )
    if rest != b"":
        raise ValueError("Extraneous data")
    return value
