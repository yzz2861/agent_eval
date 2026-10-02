import re
from typing import List, Optional, Sequence, Tuple

from ._abnf import chunk_ext_item
from ._util import LocalProtocolError, bytesify, validate

__all__ = [
    "ChunkExtensions",
    "normalize_chunk_extensions",
    "parse_chunk_extensions",
    "serialize_chunk_extensions",
]

ChunkExtensions = Sequence[Sequence[Optional[bytes]]]

token_re = re.compile(rb"[-!#$%&\'*+.^_`|~0-9a-zA-Z]+")
chunk_ext_item_re = re.compile(chunk_ext_item.encode("ascii"))


def normalize_chunk_extensions(
    extensions: Optional[ChunkExtensions],
) -> Tuple[Tuple[bytes, Optional[bytes]], ...]:
    if extensions is None:
        return ()
    if isinstance(extensions, (bytes, bytearray, memoryview, str)) or not isinstance(
        extensions, Sequence
    ):
        raise LocalProtocolError("chunk extensions must be a sequence of pairs")

    normalized: List[Tuple[bytes, Optional[bytes]]] = []
    for extension in extensions:
        if not isinstance(extension, Sequence) or len(extension) != 2:
            raise LocalProtocolError("chunk extensions must be (name, value) pairs")

        name, value = extension
        name = bytesify(name)
        validate(token_re, name, "illegal chunk extension name: {!r}", name)

        if value is not None:
            value = bytesify(value)

        normalized.append((name, value))

    return tuple(normalized)


def _parse_quoted_value(raw_value: bytes) -> bytes:
    value = bytearray()
    escaped = False
    for char in raw_value:
        if escaped:
            value.append(char)
            escaped = False
        elif char == 0x5C:
            escaped = True
        else:
            value.append(char)
    return bytes(value)


def parse_chunk_extensions(
    raw_extensions: Optional[bytes],
) -> Tuple[Tuple[bytes, Optional[bytes]], ...]:
    if not raw_extensions:
        return ()

    extensions: List[Tuple[bytes, Optional[bytes]]] = []
    position = 0
    while position < len(raw_extensions):
        match = chunk_ext_item_re.match(raw_extensions, position)
        if match is None or match.start() != position:
            raise LocalProtocolError(
                "illegal chunk extensions: {!r}".format(raw_extensions)
            )

        item = raw_extensions[match.start() : match.end()]
        name_and_value = item[1:].split(b"=", 1)
        name = name_and_value[0]
        if len(name_and_value) == 1:
            value = None
        else:
            value = name_and_value[1]
            if value.startswith(b'"'):
                value = _parse_quoted_value(value[1:-1])
        extensions.append((name, value))
        position = match.end()

    return tuple(extensions)


def _quote_chunk_extension_value(value: bytes) -> bytes:
    quoted = bytearray(b'"')
    for char in value:
        if char in (0x22, 0x5C):
            quoted.append(0x5C)
        elif not (
            char == 0x09
            or char == 0x20
            or 0x21 <= char <= 0x7E
            or char >= 0x80
        ):
            raise LocalProtocolError(
                "illegal chunk extension value: {!r}".format(value)
            )
        quoted.append(char)
    quoted.append(0x22)
    return bytes(quoted)


def serialize_chunk_extensions(extensions: ChunkExtensions) -> bytes:
    serialized = bytearray()
    for name, value in extensions:
        serialized += b";" + name
        if value is None:
            continue
        serialized += b"="
        if token_re.fullmatch(value):
            serialized += value
        else:
            serialized += _quote_chunk_extension_value(value)
    return bytes(serialized)
