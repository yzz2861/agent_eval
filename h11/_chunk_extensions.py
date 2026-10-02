from typing import List, Optional, Sequence, Tuple, Union

from ._util import LocalProtocolError, bytesify

__all__ = [
    "ChunkExtension",
    "ChunkExtensions",
    "MAX_CHUNK_HEADER_SIZE",
    "normalize_chunk_extensions",
    "parse_chunk_extensions",
    "render_chunk_extensions",
]

ChunkExtension = Tuple[bytes, Optional[bytes]]
ChunkExtensions = List[ChunkExtension]
ChunkExtensionInput = Tuple[Union[bytes, str], Optional[Union[bytes, str]]]
ChunkExtensionInputs = Sequence[ChunkExtensionInput]

MAX_CHUNK_HEADER_SIZE = 8192

_TCHAR = frozenset(
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


def _chunk_extension_bytes(value: Union[bytes, bytearray, memoryview, str]) -> bytes:
    value = bytesify(value)
    if not all(
        byte == 0x09 or byte == 0x20 or 0x21 <= byte <= 0x7E or byte >= 0x80
        for byte in value
    ):
        raise LocalProtocolError("illegal character in chunk extension")
    return value


def normalize_chunk_extensions(
    extensions: Optional[ChunkExtensionInputs],
) -> ChunkExtensions:
    if extensions is None:
        return []

    normalized: ChunkExtensions = []
    for extension in extensions:
        if not isinstance(extension, tuple):
            raise LocalProtocolError("chunk extensions must be (name, value) tuples")
        try:
            name, value = extension
        except ValueError:
            raise LocalProtocolError("chunk extensions must be (name, value) pairs")
        name = _chunk_extension_bytes(name)
        if not name or any(byte not in _TCHAR for byte in name):
            raise LocalProtocolError("illegal chunk extension name")
        if value is not None:
            value = _chunk_extension_bytes(value)
        normalized.append((name, value))
    return normalized


def render_chunk_extensions(extensions: ChunkExtensions) -> bytes:
    parts = []
    for name, value in extensions:
        part = bytearray(name)
        if value is not None:
            part += b"="
            if value and all(byte in _TCHAR for byte in value):
                part += value
            else:
                part += b'"'
                for byte in value:
                    if byte in (ord('"'), ord("\\")):
                        part += b"\\"
                    part.append(byte)
                part += b'"'
        parts.append(bytes(part))
    return b";" + b";".join(parts) if parts else b""


def _is_qdtext_or_pair_char(byte: int) -> bool:
    return byte == 0x09 or byte == 0x20 or 0x21 <= byte <= 0x7E or byte >= 0x80


def parse_chunk_extensions(data: bytes) -> ChunkExtensions:
    if not data:
        return []

    extensions: ChunkExtensions = []
    position = 0
    while position < len(data):
        if data[position] != ord(";"):
            raise LocalProtocolError("illegal chunk extension")
        position += 1

        name_start = position
        while position < len(data) and data[position] in _TCHAR:
            position += 1
        if position == name_start:
            raise LocalProtocolError("illegal chunk extension name")
        name = bytes(data[name_start:position])
        value: Optional[bytes] = None

        if position < len(data) and data[position] == ord("="):
            position += 1
            if position >= len(data):
                raise LocalProtocolError("missing chunk extension value")
            if data[position] == ord('"'):
                position += 1
                decoded = bytearray()
                while position < len(data):
                    byte = data[position]
                    if byte == ord('"'):
                        position += 1
                        break
                    if byte == ord("\\"):
                        position += 1
                        if position >= len(data):
                            raise LocalProtocolError("invalid quoted chunk extension")
                        byte = data[position]
                        if not _is_qdtext_or_pair_char(byte):
                            raise LocalProtocolError("invalid quoted chunk extension")
                    elif not _is_qdtext_or_pair_char(byte):
                        raise LocalProtocolError("invalid quoted chunk extension")
                    decoded.append(byte)
                    position += 1
                else:
                    raise LocalProtocolError("unterminated quoted chunk extension")
                value = bytes(decoded)
            else:
                value_start = position
                while position < len(data) and data[position] in _TCHAR:
                    position += 1
                if position == value_start:
                    raise LocalProtocolError("illegal chunk extension value")
                value = bytes(data[value_start:position])

        extensions.append((name, value))
        if position == len(data):
            return extensions
        if all(byte in b" \t" for byte in data[position:]):
            return extensions
    return extensions
