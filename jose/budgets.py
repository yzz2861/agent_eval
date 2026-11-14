import json
import math
import numbers
import zlib

from .constants import (
    JWE_MAX_COMPRESSION_RATIO,
    JWE_MAX_DECOMPRESSED_SIZE,
    JWE_MAX_JSON_CONTAINERS,
    JWE_MAX_JSON_DEPTH,
    JWE_SIZE_LIMIT,
    ZIPS,
)
from .exceptions import JWEDecompressError, JWEPayloadError, JWEPolicyError


def _require_positive_int(value, name):
    if isinstance(value, bool) or not isinstance(value, numbers.Integral):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return int(value)


def _require_positive_number(value, name):
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise TypeError(f"{name} must be a number")
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite number greater than zero")
    return value


class JWEBudget:
    """Per-call resource budget for JWE decompression and JSON parsing.

    A budget instance only holds configuration; every ``decrypt`` call keeps
    its own counters, so budget state can never leak between calls. Callers
    may tighten the defaults but may not disable a limit: every value must be
    a finite, positive number.

    Args:
        max_compact_size (int): Maximum accepted size, in bytes, of the
            compact serialized JWE string.
        max_decompressed_size (int): Maximum accepted size, in bytes, of the
            decompressed plaintext.
        max_compression_ratio (float): Maximum accepted ratio between
            decompressed and compressed bytes.
        max_json_depth (int): Maximum nesting depth of objects and arrays
            accepted by :meth:`loads`.
        max_json_containers (int): Maximum number of objects and arrays
            accepted by :meth:`loads`.
    """

    def __init__(
        self,
        max_compact_size=JWE_SIZE_LIMIT,
        max_decompressed_size=JWE_MAX_DECOMPRESSED_SIZE,
        max_compression_ratio=JWE_MAX_COMPRESSION_RATIO,
        max_json_depth=JWE_MAX_JSON_DEPTH,
        max_json_containers=JWE_MAX_JSON_CONTAINERS,
    ):
        self.max_compact_size = _require_positive_int(max_compact_size, "max_compact_size")
        self.max_decompressed_size = _require_positive_int(max_decompressed_size, "max_decompressed_size")
        self.max_compression_ratio = _require_positive_number(max_compression_ratio, "max_compression_ratio")
        self.max_json_depth = _require_positive_int(max_json_depth, "max_json_depth")
        self.max_json_containers = _require_positive_int(max_json_containers, "max_json_containers")

    def check_compact_size(self, size):
        if size > self.max_compact_size:
            raise JWEPolicyError(
                f"JWE string {size} bytes exceeds {self.max_compact_size} bytes"
            )

    def decompress(self, zip_name, compressed):
        """Stream ``compressed`` through the selected decompressor.

        The output is produced in bounded chunks and every chunk is checked
        against :attr:`max_decompressed_size` and
        :attr:`max_compression_ratio` before it is appended, so a compression
        bomb is aborted without ever materialising the full expanded payload.
        Truncated streams and trailing bytes are reported as
        :class:`JWEDecompressError`, while budget breaches raise
        :class:`JWEPolicyError`.
        """
        if zip_name is None:
            if len(compressed) > self.max_decompressed_size:
                raise JWEPolicyError(
                    f"Decompressed JWE string exceeds {self.max_decompressed_size} bytes"
                )
            return compressed

        if zip_name != ZIPS.DEF:
            # Never include the header value in the message: it is attacker
            # controlled and error output must not echo token contents.
            raise JWEDecompressError("Unsupported JWE compression algorithm")

        decompressor = zlib.decompressobj()
        remaining = memoryview(compressed)
        output = bytearray()
        chunk_size = min(64 * 1024, self.max_decompressed_size)
        compressed_len = len(compressed)
        consumed = 0

        while remaining:
            try:
                chunk = decompressor.decompress(remaining, max_length=chunk_size)
            except zlib.error as exc:
                raise JWEDecompressError("Failed to decompress JWE payload") from exc
            output.extend(chunk)

            if len(output) > self.max_decompressed_size:
                raise JWEPolicyError(
                    f"Decompressed JWE string exceeds {self.max_decompressed_size} bytes"
                )

            if decompressor.unconsumed_tail:
                # The chunk budget was exhausted before the input was:
                # everything still in unconsumed_tail is yet to be read.
                tail = decompressor.unconsumed_tail
                consumed = compressed_len - len(tail)
                remaining = memoryview(tail)
            else:
                consumed = compressed_len - len(decompressor.unused_data)
                remaining = b""

            if consumed > 0 and len(output) > self.max_compression_ratio * consumed:
                raise JWEPolicyError(
                    "Decompressed JWE string exceeds the maximum compression ratio "
                    f"of {self.max_compression_ratio:g}"
                )

            if decompressor.unused_data:
                raise JWEDecompressError("Trailing data after the compressed JWE payload")

        while True:
            try:
                flush = decompressor.flush(chunk_size)
            except zlib.error as exc:
                raise JWEDecompressError("Failed to decompress JWE payload") from exc
            output.extend(flush)
            if len(output) > self.max_decompressed_size:
                raise JWEPolicyError(
                    f"Decompressed JWE string exceeds {self.max_decompressed_size} bytes"
                )
            if not decompressor.unconsumed_tail or decompressor.eof:
                break

        if not decompressor.eof:
            raise JWEDecompressError("Truncated compressed JWE payload")

        return bytes(output)

    def loads(self, data):
        """Parse JSON ``data`` under the depth and container budget.

        A hand-rolled streaming scanner is used instead of ``json.loads`` so
        that nesting depth and container counts are enforced while parsing,
        rather than after an unbounded object graph has already been built.
        Budget breaches raise :class:`JWEPolicyError`; malformed JSON raises
        :class:`JWEPayloadError`.
        """
        if isinstance(data, memoryview):
            data = bytes(data)
        if isinstance(data, bytes):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise JWEPayloadError("JWE payload is not valid UTF-8 JSON") from exc
        elif isinstance(data, str):
            text = data
        else:
            raise TypeError("JWE JSON payload must be bytes or str")

        scanner = _BoundedJSONScanner(
            text,
            max_depth=self.max_json_depth,
            max_containers=self.max_json_containers,
        )
        try:
            value, end = scanner.parse_value(0)
        except _JSONLimitExceeded as exc:
            raise JWEPolicyError(str(exc)) from exc
        except _JSONParseFailed as exc:
            raise JWEPayloadError("JWE payload is not valid JSON") from exc

        if scanner.skip_ws(end) != len(text):
            raise JWEPayloadError("JWE payload is not valid JSON")
        return value


class _JSONLimitExceeded(Exception):
    pass


class _JSONParseFailed(Exception):
    pass


class _BoundedJSONScanner:
    """Depth/container bounded recursive-descent JSON scanner."""

    def __init__(self, text, max_depth, max_containers):
        self.text = text
        self.max_depth = max_depth
        self.max_containers = max_containers
        self.container_count = 0
        self.decoder = json.JSONDecoder()

    def skip_ws(self, index):
        while index < len(self.text) and self.text[index] in " \t\n\r":
            index += 1
        return index

    def parse_value(self, index, depth=0):
        index = self.skip_ws(index)
        if index >= len(self.text):
            raise _JSONParseFailed("unexpected end of JSON document")

        char = self.text[index]
        if char == "{":
            return self.parse_object(index, depth)
        if char == "[":
            return self.parse_array(index, depth)

        try:
            value, end = self.decoder.raw_decode(self.text, index)
        except ValueError as exc:
            raise _JSONParseFailed(str(exc)) from exc
        if isinstance(value, (dict, list)):
            raise _JSONParseFailed("unexpected container from scalar decoder")
        return value, end

    def enter_container(self, depth):
        if depth + 1 > self.max_depth:
            raise _JSONLimitExceeded(
                f"JWE JSON nesting depth exceeds the maximum of {self.max_depth}"
            )
        self.container_count += 1
        if self.container_count > self.max_containers:
            raise _JSONLimitExceeded(
                f"JWE JSON container count exceeds the maximum of {self.max_containers}"
            )

    def parse_object(self, index, depth):
        self.enter_container(depth)
        result = {}
        index = self.skip_ws(index + 1)
        if index < len(self.text) and self.text[index] == "}":
            return result, index + 1

        while True:
            index = self.skip_ws(index)
            try:
                key, key_end = self.decoder.raw_decode(self.text, index)
            except ValueError as exc:
                raise _JSONParseFailed(str(exc)) from exc
            if not isinstance(key, str):
                raise _JSONParseFailed("JSON object keys must be strings")
            index = self.skip_ws(key_end)
            if index >= len(self.text) or self.text[index] != ":":
                raise _JSONParseFailed("expected ':' after JSON object key")
            value, index = self.parse_value(index + 1, depth + 1)
            result[key] = value
            index = self.skip_ws(index)
            if index >= len(self.text):
                raise _JSONParseFailed("unterminated JSON object")
            if self.text[index] == "}":
                return result, index + 1
            if self.text[index] != ",":
                raise _JSONParseFailed("expected ',' or '}' in JSON object")
            index += 1

    def parse_array(self, index, depth):
        self.enter_container(depth)
        result = []
        index = self.skip_ws(index + 1)
        if index < len(self.text) and self.text[index] == "]":
            return result, index + 1

        while True:
            value, index = self.parse_value(index, depth + 1)
            result.append(value)
            index = self.skip_ws(index)
            if index >= len(self.text):
                raise _JSONParseFailed("unterminated JSON array")
            if self.text[index] == "]":
                return result, index + 1
            if self.text[index] != ",":
                raise _JSONParseFailed("expected ',' or ']' in JSON array")
            index += 1
