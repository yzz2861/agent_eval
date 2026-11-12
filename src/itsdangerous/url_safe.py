from __future__ import annotations

import base64
import typing as t
import zlib

from ._json import _CompactJSON
from .encoding import base64_encode
from .exc import BadData
from .exc import BadPayload
from .serializer import DecompressionBudget
from .serializer import Serializer
from .timed import TimedSerializer

#: Bytes allowed in a canonical, unpadded URL-safe base64 string.
_URLSAFE_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

#: Fixed chunk size fed to the streaming decompressor. Small enough that a
#: bomb is cut off after at most this many extra compressed bytes are read.
_DECOMPRESS_CHUNK = 1024

#: Upper bound on bytes produced by a single ``decompress`` call. Keeping it
#: small means a high-ratio bomb trips the ratio check after the first small
#: output block instead of after the decompressor emits megabytes at once.
_DECOMPRESS_OUTPUT_LIMIT = 16 * 1024


def _strict_base64_decode(payload: bytes) -> bytes:
    """Decode canonical, unpadded URL-safe base64.

    Unlike :func:`itsdangerous.encoding.base64_decode`, this rejects
    padding, whitespace, non-alphabet bytes and other non-canonical input
    instead of ignoring or repairing it. The length must already be valid
    for unpadded base64 (that is, not congruent to 1 modulo 4).
    """
    if len(payload) % 4 == 1 or any(
        char not in _URLSAFE_ALPHABET for char in payload
    ):
        raise BadPayload(
            "Could not base64 decode the payload because of an exception",
            original_error=BadData("Non-canonical or invalid URL-safe base64 data"),
        )

    padded = payload + b"=" * (-len(payload) % 4)

    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (TypeError, ValueError) as e:
        raise BadPayload(
            "Could not base64 decode the payload because of an exception",
            original_error=e,
        ) from e

    # Re-encoding must reproduce the exact unpadded input; otherwise the
    # encoding was non-canonical even if the decoder accepted it.
    if base64_encode(decoded) != payload:
        raise BadPayload(
            "Could not base64 decode the payload because of an exception",
            original_error=BadData("Non-canonical URL-safe base64 encoding"),
        )

    return decoded


def _looks_like_zlib(data: bytes) -> bool:
    """Return whether the first bytes look like the start of a zlib stream.

    The CMF byte's low nibble is the compression method, always 8 (deflate);
    the high nibble encodes the window size. JSON text can never begin with
    a byte whose low nibble is 8, since JSON starts with whitespace or one
    of ``"{}[]-tfn0-9``, none of which have that low nibble.
    """
    return len(data) >= 2 and (data[0] & 0x0F) == 0x08


def _budgeted_decompress(
    compressed: bytes, budget: DecompressionBudget
) -> bytes:
    """Stream-decompress zlib data while enforcing the budget.

    Checks run while data is still flowing through the decompressor, so a
    bomb is aborted before the full decompressed output is allocated. The
    compressed size, absolute decompressed size and decompression ratio are
    each enforced. Truncated streams, trailing garbage, bad checksums and
    nested compression are all reported as :class:`.BadPayload` without
    exposing any decompressed content in the error message.
    """
    if not compressed:
        raise BadPayload(
            "Could not zlib decompress the payload before decoding the payload"
        )

    if len(compressed) > budget.max_compressed_bytes:
        raise BadPayload("The payload exceeds the allowed compressed size")

    decompressor = zlib.decompressobj()
    output = bytearray()
    stream_error: Exception | None = None
    consumed = 0

    # The next bytes to feed. Normally these come from the input, but if the
    # output limit makes the decompressor hold data back they are re-fed from
    # ``unconsumed_tail`` instead, so no compressed bytes are skipped.
    pending = compressed

    while pending:
        chunk = pending[:_DECOMPRESS_CHUNK]
        pending = pending[_DECOMPRESS_CHUNK:]
        consumed += len(chunk)
        room = min(
            budget.max_decompressed_bytes - len(output),
            _DECOMPRESS_OUTPUT_LIMIT,
        )

        if room <= 0:
            raise BadPayload("The payload exceeds the allowed decompressed size")

        try:
            part = decompressor.decompress(chunk, room)
        except Exception as e:
            # Covers truncated streams and Adler-32 checksum failures.
            stream_error = e
            raise BadPayload(
                "Could not zlib decompress the payload before decoding the payload",
                original_error=e,
            ) from e

        output.extend(part)

        if decompressor.unconsumed_tail:
            # The fixed output block filled up. Re-feed the held-back
            # compressed tail (without counting it twice) so legitimate
            # streams drain in bounded blocks; the post-block checks below
            # still abort a bomb before it can grow past the limits.
            pending = decompressor.unconsumed_tail + pending
            consumed -= len(decompressor.unconsumed_tail)

        # Absolute cap: the output already reached it while more compressed
        # data exists, so completing the stream would exceed it for sure.
        if len(output) > budget.max_decompressed_bytes or (
            len(output) == budget.max_decompressed_bytes
            and (pending or not decompressor.eof)
        ):
            raise BadPayload("The payload exceeds the allowed decompressed size")

        # Running ratio on the bytes actually consumed so far. The first
        # output block is allowed regardless of the (still tiny) denominator,
        # since a single 16 KiB block is bounded anyway; from the second block
        # onward a bomb trips almost immediately while legitimate streams,
        # whose final ratio is within the budget, never overshoot.
        if (
            len(output) > _DECOMPRESS_OUTPUT_LIMIT
            and len(output) > budget.max_decompression_ratio * consumed
        ):
            raise BadPayload("The payload exceeds the allowed decompression ratio")

    if not decompressor.eof:
        # The stream ended without the zlib end-of-stream marker/checksum.
        raise BadPayload(
            "Could not zlib decompress the payload before decoding the payload",
            original_error=stream_error
            or EOFError("Incomplete or truncated zlib stream"),
        )

    if decompressor.unused_data:
        # Bytes were appended after a complete zlib stream.
        raise BadPayload("The compressed payload contains trailing data")

    result = bytes(output)

    if _looks_like_zlib(result):
        # Nested compression defeats the ratio/size accounting of this
        # layer and is never produced by the built-in serializer.
        raise BadPayload("Nested compressed payloads are not allowed")

    return result


class URLSafeSerializerMixin(Serializer[str]):
    """Mixed in with a regular serializer it will attempt to zlib
    compress the string to make it shorter if necessary. It will also
    base64 encode the string so that it can safely be placed in a URL.

    Decompression on loading is bounded by the :class:`DecompressionBudget`
    configured on the serializer. Signature verification always happens
    first; the budget is only applied to payloads whose signature passed.
    """

    default_serializer: t.Any = _CompactJSON

    def load_payload(
        self,
        payload: bytes,
        *args: t.Any,
        serializer: t.Any | None = None,
        **kwargs: t.Any,
    ) -> t.Any:
        budget = self.decompression_budget

        # Cheapest possible check, before any decoding work at all.
        if len(payload) > budget.max_compact_bytes:
            raise BadPayload("The payload exceeds the allowed compact size")

        decompress = False

        if payload.startswith(b"."):
            payload = payload[1:]
            decompress = True

        json = _strict_base64_decode(payload)

        if decompress:
            json = _budgeted_decompress(json, budget)

        return super().load_payload(json, *args, **kwargs)

    def dump_payload(self, obj: t.Any) -> bytes:
        json = super().dump_payload(obj)
        is_compressed = False
        compressed = zlib.compress(json)

        if len(compressed) < (len(json) - 1):
            json = compressed
            is_compressed = True

        base64d = base64_encode(json)

        if is_compressed:
            base64d = b"." + base64d

        return base64d


class URLSafeSerializer(URLSafeSerializerMixin, Serializer[str]):
    """Works like :class:`.Serializer` but dumps and loads into a URL
    safe string consisting of the upper and lowercase character of the
    alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """


class URLSafeTimedSerializer(URLSafeSerializerMixin, TimedSerializer[str]):
    """Works like :class:`.TimedSerializer` but dumps and loads into a
    URL safe string consisting of the upper and lowercase character of
    the alphabet as well as ``'_'``, ``'-'`` and ``'.'``.
    """
