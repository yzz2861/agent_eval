"""Budgeted decompression for compressed JWT payloads.

Every public entry point here works off a fresh, per-decode
:class:`CompressionBudget` instance. Nothing in this module keeps mutable
state between calls, so budgets can never leak across tokens, keys or
callers.

The decompressor is driven in fixed-size chunks and every budget check runs
*before* the output buffer grows, which caps peak memory at roughly one
budget window instead of the fully inflated size of a decompression bomb.
"""

from __future__ import annotations

import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from .exceptions import (
    ClaimDepthLimitExceededError,
    ClaimNodeLimitExceededError,
    CompressedPayloadSizeError,
    CompressionRatioError,
    DecodeError,
    InvalidCompressedPayloadError,
    TrailingCompressedDataError,
    TruncatedCompressedPayloadError,
    UnsupportedCompressionAlgorithmError,
)

#: JWT ``zip`` header value (RFC 1950, zlib-wrapped deflate).
ZIP_DEF: Final[str] = "DEF"
#: JWT ``zip`` header value (RFC 1951, raw deflate, no header/checksum).
ZIP_DEFLATE_RAW: Final[str] = "DEFLATE"
#: JWT ``zip`` header value (RFC 1952, gzip-wrapped deflate).
ZIP_GZIP: Final[str] = "GZIP"

#: Window sizes accepted by :func:`zlib.decompressobj`.
_WBITS_RAW_DEFLATE: Final[int] = -15
_WBITS_ZLIB: Final[int] = 15
_WBITS_GZIP: Final[int] = 31

_DEFAULT_READ_CHUNK_SIZE: Final[int] = 64 * 1024
_QUOTE: Final[int] = ord('"')
_BACKSLASH: Final[int] = ord("\\")


@dataclass(frozen=True)
class CompressionAlgorithm:
    """A decompression algorithm the decoder is allowed to use."""

    name: str
    wbits: int
    compresslevel: int = 9


#: Algorithms supported out of the box. Frozen at import time; per-decode
#: allow-listing is handled by the caller instead of mutating this mapping.
COMPRESSION_ALGORITHMS: Final[dict[str, CompressionAlgorithm]] = {
    ZIP_DEF: CompressionAlgorithm(ZIP_DEF, _WBITS_ZLIB),
    ZIP_DEFLATE_RAW: CompressionAlgorithm(ZIP_DEFLATE_RAW, _WBITS_RAW_DEFLATE),
    ZIP_GZIP: CompressionAlgorithm(ZIP_GZIP, _WBITS_GZIP),
}

#: Defaults chosen so existing, reasonably sized compressed tokens keep
#: working while a 64 KB token that expands to gigabytes is rejected long
#: before the inflated buffer is allocated.
DEFAULT_MAX_COMPRESSED_SIZE: Final[int] = 1 * 1024 * 1024
DEFAULT_MAX_DECOMPRESSED_SIZE: Final[int] = 10 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO: Final[float] = 100.0
DEFAULT_MAX_CLAIM_NODES: Final[int] = 100_000
DEFAULT_MAX_CLAIM_DEPTH: Final[int] = 100


@dataclass(frozen=True)
class CompressionBudget:
    """Per-decode resource budget for a compressed JWT payload.

    Instances are immutable, so the same budget object can be shared between
    threads and reused across calls; each decode still gets a fresh set of
    local counters and buffers.

    :param max_compressed_size: maximum accepted compressed payload size in
        bytes. Checked before any decompressor or output buffer is created.
    :param max_decompressed_size: maximum total decompressed size in bytes.
        Checked before each output buffer extension.
    :param max_compression_ratio: maximum ``decompressed / compressed``
        ratio, evaluated cumulatively while the stream is being inflated.
    :param max_claim_nodes: maximum number of JSON value nodes allowed in
        the decompressed claims.
    :param max_claim_depth: maximum nesting depth of JSON containers in the
        decompressed claims.
    :param allowed_algorithms: JWT ``zip`` header values this budget
        permits. Defaults to every built-in algorithm.
    """

    max_compressed_size: int = DEFAULT_MAX_COMPRESSED_SIZE
    max_decompressed_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO
    max_claim_nodes: int = DEFAULT_MAX_CLAIM_NODES
    max_claim_depth: int = DEFAULT_MAX_CLAIM_DEPTH
    allowed_algorithms: frozenset[str] = frozenset(COMPRESSION_ALGORITHMS)

    def __post_init__(self) -> None:
        for field_name in (
            "max_compressed_size",
            "max_decompressed_size",
            "max_claim_nodes",
            "max_claim_depth",
        ):
            if not isinstance(getattr(self, field_name), int):
                raise TypeError(f"{field_name} must be an int")
            if getattr(self, field_name) <= 0:
                raise ValueError(f"{field_name} must be positive")
        if not isinstance(self.max_compression_ratio, (int, float)):
            raise TypeError("max_compression_ratio must be a number")
        if self.max_compression_ratio < 1.0:
            raise ValueError("max_compression_ratio must be >= 1.0")
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        unknown = set(self.allowed_algorithms) - set(COMPRESSION_ALGORITHMS)
        if unknown:
            raise ValueError(f"Unknown compression algorithm(s): {sorted(unknown)}")


def get_algorithm(name: str, budget: CompressionBudget) -> CompressionAlgorithm:
    """Resolve a JWT ``zip`` header value against a per-decode budget."""
    if not isinstance(name, str):
        raise UnsupportedCompressionAlgorithmError(
            "The 'zip' header must be a string naming a compression algorithm"
        )
    if name not in budget.allowed_algorithms:
        raise UnsupportedCompressionAlgorithmError(
            "Unsupported or disallowed compression algorithm"
        )
    try:
        return COMPRESSION_ALGORITHMS[name]
    except KeyError:
        # Defensive: budgets validate their allow-list at construction time.
        raise UnsupportedCompressionAlgorithmError(
            "Unsupported compression algorithm"
        ) from None


def bounded_decompress(
    compressed: bytes,
    budget: CompressionBudget,
    *,
    algorithm: CompressionAlgorithm,
    chunk_size: int = _DEFAULT_READ_CHUNK_SIZE,
    decompressobj_factory: Callable[..., zlib.Decompress] = zlib.decompressobj,
) -> bytearray:
    """Decompress ``compressed`` while enforcing ``budget``.

    The input is fed to a single :class:`zlib.Decompress` object in fixed
    chunks (one underlying decompressor per decode, never restarted). All
    size and ratio checks happen before the output ``bytearray`` is extended,
    so a malicious stream is rejected before a large object is allocated.

    The input bytes themselves are never copied: chunks are handed to zlib as
    ``memoryview`` slices and the returned :class:`bytearray` is the only
    output allocation.
    """
    if not isinstance(compressed, bytes):
        raise TypeError("compressed payload must be bytes")

    # Checked before allocating a decompressor or any output buffer.
    if len(compressed) > budget.max_compressed_size:
        raise CompressedPayloadSizeError(
            "Compressed payload exceeds the configured compressed-size budget"
        )

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    try:
        decompressor = decompressobj_factory(wbits=algorithm.wbits)
    except zlib.error:
        raise InvalidCompressedPayloadError(
            "Could not initialize decompressor for the compressed payload"
        ) from None

    output = bytearray()
    view = memoryview(compressed)
    offset = 0
    # Cap each decompressor call's output so a single highly compressible
    # block cannot materialize a multi-megabyte buffer before the budget
    # check runs. The window is bounded by the smallest byte budget.
    output_window = min(chunk_size, budget.max_decompressed_size)
    try:
        while True:
            # 1. Drain a retained input tail from a previous max_length cap.
            if decompressor.unconsumed_tail:
                inflated = decompressor.decompress(
                    decompressor.unconsumed_tail, max_length=output_window
                )
            # 2. Offer the next fixed-size slice of the caller's bytes.
            elif offset < len(compressed):
                chunk = view[offset : offset + chunk_size]
                offset += len(chunk)
                inflated = decompressor.decompress(chunk, max_length=output_window)
            # 3. All input has been offered exactly once.
            elif not decompressor.eof:
                # No end-of-stream marker ever appeared: truncated payload.
                raise TruncatedCompressedPayloadError(
                    "Compressed payload is truncated before the end of the stream"
                )
            else:
                # Stream finished and fully drained; nothing left to do.
                break

            projected_size = len(output) + len(inflated)
            if projected_size > budget.max_decompressed_size:
                raise CompressedPayloadSizeError(
                    "Decompressed payload exceeds the configured "
                    "decompressed-size budget"
                )
            # Cumulative ratio: a bomb is detectable on the first window that
            # crosses the budget, before its output is appended.
            if projected_size > budget.max_compression_ratio * len(compressed):
                raise CompressionRatioError(
                    "Decompressed payload exceeds the configured "
                    "compression ratio budget"
                )
            output.extend(inflated)

            # zlib surfaces bytes past the end marker instead of raising.
            if decompressor.eof and decompressor.unused_data:
                raise TrailingCompressedDataError(
                    "Trailing data after the compressed payload stream"
                )

        if not decompressor.eof:
            raise TruncatedCompressedPayloadError(
                "Compressed payload is truncated before the end of the stream"
            )
        if decompressor.unused_data:
            raise TrailingCompressedDataError(
                "Trailing data after the compressed payload stream"
            )
    except zlib.error:
        raise InvalidCompressedPayloadError(
            "Compressed payload is not a valid compression stream"
        ) from None
    finally:
        view.release()

    return output


_WHITESPACE: Final[frozenset[int]] = frozenset(b" \t\r\n")
_LITERAL_PREFIXES: Final[dict[int, bytes]] = {
    ord("t"): b"true",
    ord("f"): b"false",
    ord("n"): b"null",
}


def _skip_whitespace(data: bytes, index: int) -> int:
    while index < len(data) and data[index] in _WHITESPACE:
        index += 1
    return index


def _skip_string(data: bytes, index: int) -> int:
    """Return the index just past the JSON string starting at index."""
    length = len(data)
    index += 1
    while index < length:
        current = data[index]
        if current == _QUOTE:
            return index + 1
        if current == _BACKSLASH:
            index += 2
            continue
        index += 1
    raise DecodeError("Invalid payload string: unterminated string")


def scan_claim_limits(data: bytes, budget: CompressionBudget) -> None:
    length = len(data)
    index = _skip_whitespace(data, 0)
    if index == length:
        raise DecodeError("Invalid payload string: payload is empty")
    # Stack holds the opening bracket of every unfinished container.
    container_stack: list[int] = []
    # expect describes the next token:
    #   "value"      - root value, array element, or object member value
    #   "array_open" - array just opened, element expected (or close bracket)
    #   "key"        - object member name (closing bracket also allowed)
    #   "member"     - member name after a comma (close bracket not allowed)
    #   "colon" - the ':' separator following a member name
    #   "next"  - ',' separator or a closing bracket after a value
    expect = "value"
    node_count = 0

    def count_value() -> None:
        nonlocal node_count
        node_count += 1
        if node_count > budget.max_claim_nodes:
            raise ClaimNodeLimitExceededError(
                "Payload exceeds the configured maximum number of claim nodes"
            )

    while True:
        index = _skip_whitespace(data, index)
        if index >= length:
            raise DecodeError("Invalid payload string: unexpected end of data")
        byte = data[index]
        if expect == "colon":
            if byte != ord(":"):
                raise DecodeError("Invalid payload string: expected a colon")
            index += 1
            expect = "value"
            continue
        if expect == "next":
            if byte == ord(","):
                index += 1
                expect = "member" if container_stack[-1] == ord("{") else "value"
                continue
            if byte not in (ord("}"), ord("]")):
                raise DecodeError("Invalid payload string: expected a comma")
            # Fall through to the closing-bracket handling below.
        if byte in (ord("}"), ord("]")) and expect in (
            "key",
            "next",
            "array_open",
        ):
            if not container_stack:
                raise DecodeError("Invalid payload string: unmatched closing bracket")
            opener = container_stack.pop()
            if (byte == ord("}") and opener != ord("{")) or (
                byte == ord("]") and opener != ord("[")
            ):
                raise DecodeError("Invalid payload string: mismatched brackets")
            index += 1
            if not container_stack:
                break
            expect = "next"
            continue
        if expect in ("key", "member"):
            if byte != _QUOTE:
                raise DecodeError("Invalid payload string: expected a claim name")
            index = _skip_string(data, index)
            expect = "colon"
            continue
        # expect == "value": parse a JSON value.
        if byte in (ord("{"), ord("[")):
            if len(container_stack) + 1 > budget.max_claim_depth:
                raise ClaimDepthLimitExceededError(
                    "Payload exceeds the configured maximum claim nesting depth"
                )
            container_stack.append(byte)
            index += 1
            expect = "key" if byte == ord("{") else "array_open"
            continue
        if byte == _QUOTE:
            count_value()
            index = _skip_string(data, index)
        elif byte in _LITERAL_PREFIXES:
            count_value()
            literal = _LITERAL_PREFIXES[byte]
            if not data.startswith(literal, index):
                raise DecodeError("Invalid payload string: invalid literal")
            index += len(literal)
        elif byte == ord("-") or ord("0") <= byte <= ord("9"):
            count_value()
            index += 1
            while index < length and (
                data[index] == ord("-")
                or data[index] == ord("+")
                or data[index] == ord(".")
                or data[index] == ord("e")
                or data[index] == ord("E")
                or ord("0") <= data[index] <= ord("9")
            ):
                index += 1
        else:
            raise DecodeError("Invalid payload string: unexpected character")
        if not container_stack:
            break
        expect = "next"
    trailing = _skip_whitespace(data, index)
    if trailing != length:
        raise DecodeError("Invalid payload string: trailing data")


def compress_payload(payload: bytes, algorithm: CompressionAlgorithm) -> bytes:
    """Compress an encoded JSON payload using a supported algorithm."""
    compressor = zlib.compressobj(
        algorithm.compresslevel,
        zlib.DEFLATED,
        algorithm.wbits,
    )
    return compressor.compress(payload) + compressor.flush()
