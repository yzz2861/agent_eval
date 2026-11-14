# Copyright (c) 2006, Mathieu Fenniak
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * The name of the author may not be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""
Implementation of stream filters; §7.4 Filters of the PDF 2.0 specification.

§8.9.7 Inline images of the PDF 2.0 specification has abbreviations that can be
used for the names of filters in an inline image object.
"""
__author__ = "Mathieu Fenniak"
__author_email__ = "biziqe@mathieu.fenniak.net"

import binascii
import math
import os
import shutil
import struct
import subprocess
import zlib
from base64 import a85decode
from dataclasses import dataclass
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from ._codecs._codecs import LzwCodec as _LzwCodec
from ._configuration import get_configuration
from ._stream_budget import (
    StreamBudgetContext,
    StreamDecodingBudget,
    get_budget_for_stream,
)
from ._utils import (
    WHITESPACES_AS_BYTES,
    deprecation,
    logger_warning,
)
from .constants import CcittFaxDecodeParameters as CCITT
from .constants import FilterTypeAbbreviations as FTA
from .constants import FilterTypes as FT
from .constants import ImageAttributes, StreamAttributes
from .constants import LzwFilterParameters as LZW
from .errors import STREAM_TRUNCATED_PREMATURELY, DependencyError, LimitReachedError, PdfReadError, PdfStreamError
from .generic import (
    ArrayObject,
    BooleanObject,
    DictionaryObject,
    IndirectObject,
    NumberObject,
    PdfObject,
    StreamObject,
    is_null_or_none,
)

MAX_DECLARED_STREAM_LENGTH = 75_000_000  # DEPRECATED: Use pypdf.Configuration.
MAX_ARRAY_BASED_STREAM_OUTPUT_LENGTH = 75_000_000  # DEPRECATED: Use pypdf.Configuration.

JBIG2_MAX_OUTPUT_LENGTH = 75_000_000  # DEPRECATED: Use pypdf.Configuration.
LZW_MAX_OUTPUT_LENGTH = 75_000_000  # DEPRECATED: Use pypdf.Configuration.
RUN_LENGTH_MAX_OUTPUT_LENGTH = 75_000_000  # DEPRECATED: Use pypdf.Configuration.
ZLIB_MAX_OUTPUT_LENGTH = 75_000_000  # DEPRECATED: Use pypdf.Configuration.
ZLIB_MAX_RECOVERY_INPUT_LENGTH = 5_000_000  # DEPRECATED: Use pypdf.Configuration.
FLATE_MAX_COLUMNS = 250_000  # DEPRECATED: Use pypdf.Configuration.
FLATE_MAX_ROW_LENGTH = 4_000_000  # DEPRECATED: Use pypdf.Configuration.
FLATE_MAX_BUFFER_SIZE = 75_000_000  # DEPRECATED: Use pypdf.Configuration.

# Reuse cached 1-byte values in the fallback loop to avoid per-byte allocations.
_SINGLE_BYTES = tuple(bytes((i,)) for i in range(256))


def _decompress_with_limit(data: bytes) -> bytes:
    decompressor = zlib.decompressobj()
    configuration = get_configuration()
    result = decompressor.decompress(data, max_length=configuration.zlib_maximum_output_length)
    if decompressor.unconsumed_tail:
        raise LimitReachedError(
            f"Limit reached while decompressing. {len(decompressor.unconsumed_tail)} bytes remaining."
        )
    return result


def _map_zlib_error(exception: zlib.error) -> PdfStreamError:
    """Turn raw zlib failures into distinguishable stream integrity errors."""
    message = str(exception)
    if "incomplete" in message or "ended" in message or "truncated" in message:
        return PdfStreamError(f"{STREAM_TRUNCATED_PREMATURELY}: {message}")
    if "check" in message or "distance" in message or "invalid" in message:
        return PdfStreamError(f"Invalid stream checksum or compressed data: {message}")
    return PdfStreamError(f"Unable to decompress stream: {message}")


def _zlib_decompress_chunks_wbits(
    data: bytes,
    max_output_length: int,
    wbits: int,
) -> tuple[bytes, bool, bool]:
    decompressor = zlib.decompressobj(wbits)
    output = bytearray()
    remaining = max_output_length
    chunk_size = 1 << 20
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset:offset + chunk_size]
        while chunk:
            part = decompressor.decompress(chunk, max_length=remaining)
            output.extend(part)
            remaining -= len(part)
            chunk = decompressor.unconsumed_tail
            if not chunk:
                break
            if remaining <= 0:
                raise LimitReachedError(
                    "Limit reached while decompressing. "
                    f"{len(decompressor.unconsumed_tail)} bytes remaining."
                )
        if remaining <= 0 and decompressor.unconsumed_tail:
            raise LimitReachedError(
                "Limit reached while decompressing. "
                f"{len(decompressor.unconsumed_tail)} bytes remaining."
            )
    # `eof` only becomes True after the end-of-stream marker is processed,
    # which can lag behind the last decompress() call. The reliable signal that
    # the whole input belonged to this stream is non-empty `unused_data`; an
    # empty value with `eof` False means the stream was cut short.
    return bytes(output), decompressor.eof, bool(decompressor.unused_data)


def decompress_with_budget(data: bytes, budget: StreamDecodingBudget) -> bytes:
    """Decompress flate data while honoring the shared stream decoding budget.

    The output limit is derived from the *remaining* budget before decoding,
    so a compressed bomb is rejected while it is still expanding instead of
    being materialized first. Integrity failures are reported as
    :class:`PdfStreamError` so truncated streams and bad checksums are
    distinguishable from budget violations.
    """
    configuration = get_configuration()
    output_limit = min(
        configuration.zlib_maximum_output_length,
        budget.remaining_output_budget(),
    )
    budget.require_output_capacity()
    result = b""
    reached_eof = False
    had_unused_data = False
    try:
        result, reached_eof, had_unused_data = _zlib_decompress_chunks_wbits(
            data, output_limit, zlib.MAX_WBITS
        )
    except LimitReachedError:
        raise
    except zlib.error:
        # Inside a filter chain the data is often a raw deflate stream
        # without the zlib header (an earlier FlateDecode already removed
        # it). Try raw deflate, then the auto-detecting window.
        try:
            result, reached_eof, had_unused_data = _zlib_decompress_chunks_wbits(
                data, output_limit, -zlib.MAX_WBITS
            )
        except zlib.error:
            try:
                result, reached_eof, had_unused_data = _zlib_decompress_chunks_wbits(
                    data, output_limit, zlib.MAX_WBITS | 32
                )
            except zlib.error as exception:
                raise _map_zlib_error(exception) from exception
    if not reached_eof and not had_unused_data and (
        not result or get_configuration().stream_require_complete_compressed_streams
    ):
        # Either nothing usable was decoded, or strict integrity checks
        # are enabled: the missing end marker means the stream was cut
        # short. By default, complete-looking outputs without a formal
        # marker are tolerated for backward compatibility.
        raise PdfStreamError(STREAM_TRUNCATED_PREMATURELY)
    return result


def decompress(data: bytes) -> bytes:
    """
    Decompress the given data using zlib.

    Attempts to decompress the input data using zlib.
    If the decompression fails due to a zlib error, it falls back
    to using a decompression object with a larger window size.

    Please note that the output length is limited to avoid memory
    issues. If you need to process larger content streams, consider
    adapting ``pypdf.Configuration.zlib_maximum_output_length``. In case you
    are only dealing with trusted inputs and/or want to disable these
    limits, set the value to `0`.

    Args:
        data: The input data to be decompressed.

    Returns:
        The decompressed data.

    """
    try:
        return _decompress_with_limit(data)
    except zlib.error as exception:
        # First quick approach: There are known issues with faulty added bytes to the
        # tail of the encoded stream from early Adobe Distiller or Pitstop versions
        # with CR char as the default line separator (assumed by reverse engineering)
        # that breaks the decoding process in the end.
        #
        # Try first to cut off some of the tail byte by byte, but limited to not
        # iterate through too many loops and kill the performance for large streams,
        # to then allow the final fallback to run. Added this intermediate attempt,
        # because starting from the head of the stream byte by byte kills completely
        # the performance for large streams (e.g., 6 MB) with the tail-byte-issue
        # and takes ages. This solution is really fast:
        max_tail_cut_off_bytes: int = 8
        for i in range(1, min(max_tail_cut_off_bytes + 1, len(data))):
            try:
                return _decompress_with_limit(data[:-i])
            except zlib.error:
                pass

        # If still failing, then try with increased window size.
        decompressor = zlib.decompressobj(zlib.MAX_WBITS | 32)
        result = bytearray()
        configuration = get_configuration()
        remaining_limit = configuration.zlib_maximum_output_length
        data_length = len(data)
        known_errors = set()
        for index in range(data_length):
            if index >= configuration.zlib_maximum_recovery_input_length:
                raise LimitReachedError(
                    f"Recovery limit reached while decompressing. {data_length - index} bytes remaining."
                ) from exception

            chunk = _SINGLE_BYTES[data[index]]
            try:
                decompressed = decompressor.decompress(chunk, max_length=remaining_limit)
                result += decompressed
                remaining_limit -= len(decompressed)
                if remaining_limit <= 0:
                    raise LimitReachedError(
                        f"Limit reached while decompressing. {data_length - index} bytes remaining."
                    )
            except zlib.error as error:
                error_str = str(error)
                if error_str in known_errors:
                    continue
                logger_warning(error_str, source=__name__)
                known_errors.add(error_str)
        return bytes(result)


class FlateDecode:
    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | IndirectObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decode data which is flate-encoded.

        Args:
          data: Flate-encoded data.
          decode_parms: Additional decoding parameters.

        Returns:
          The flate-decoded data.

        Raises:
          PdfReadError: Unsupported parameters have been found.

        """
        if budget is None:
            str_data = decompress(data)
        else:
            str_data = decompress_with_budget(data, budget)

        if isinstance(decode_parms, dict):
            parameters = decode_parms
        else:
            if not is_null_or_none(decode_parms):
                logger_warning(
                    "Detected invalid /DecodeParms, results might be incorrect: %(value)s (type %(type_name)s)",
                    source=__name__, value=decode_parms, type_name=decode_parms.__class__.__name__,
                )
            parameters = DictionaryObject()

        predictor = parameters.get("/Predictor", 1)

        # predictor 1 == no predictor
        if predictor != 1:
            columns, colors, bits_per_component = FlateDecode._get_parameters(parameters)
            configuration = get_configuration()

            # PNG predictor can vary by row and so is the lead byte on each row
            row_length = (
                math.ceil(columns * colors * bits_per_component / 8) + 1
            )  # number of bytes
            if row_length > configuration.flate_maximum_row_length:
                raise LimitReachedError(
                    f"Row length of {row_length} exceeds defined limit of {configuration.flate_maximum_row_length}."
                )

            # TIFF prediction:
            if predictor == 2:
                row_length -= 1  # remove the predictor byte
                bpp = row_length // columns
                str_data_mut = bytearray(str_data)
                for i in range(len(str_data_mut)):
                    if i % row_length >= bpp:
                        str_data_mut[i] = (str_data_mut[i] + str_data_mut[i - bpp]) % 256
                str_data = bytes(str_data_mut)
            # PNG prediction:
            elif 10 <= predictor <= 15:
                str_data = FlateDecode._decode_png_prediction(
                    str_data, columns, row_length
                )
            else:
                raise PdfReadError(f"Unsupported flatedecode predictor {predictor!r}")
        return str_data

    @staticmethod
    def _get_parameters(parameters: DictionaryObject) -> tuple[int, int, int]:
        # For details, see table 8 of ISO 32000-2:2020.
        def get(key: str, default: int) -> int:
            _value = parameters.get(key, NumberObject(default)).get_object()
            if not isinstance(_value, int) or _value < 1:
                raise PdfReadError(f"Expected positive number for {key}, got {_value}!")
            return _value

        configuration = get_configuration()
        columns = get(key=LZW.COLUMNS, default=1)
        if columns > configuration.flate_maximum_columns:
            raise LimitReachedError(
                f"Number of columns {columns} exceeds defined limit of {configuration.flate_maximum_columns}."
            )

        colors = get(key=LZW.COLORS, default=1)
        if colors > 16:
            raise LimitReachedError(
                f"Color value {colors} exceeds limit of 16. "
                f"Please open an issue if this limits valid use cases."
            )

        bits_per_component = get(key=LZW.BITS_PER_COMPONENT, default=8)
        if bits_per_component > 16:
            raise PdfReadError(f"More than 16 bits per component are not allowed: {bits_per_component}")

        return columns, colors, bits_per_component

    @staticmethod
    def _decode_png_prediction(data: bytes, columns: int, row_length: int) -> bytes:
        # PNG prediction can vary from row to row
        if (remainder := len(data) % row_length) != 0:
            logger_warning("Image data is not rectangular. Adding padding.", source=__name__)
            data += b"\x00" * (row_length - remainder)
            assert len(data) % row_length == 0
        output = bytearray()
        previous_row_data = bytearray(row_length)
        bpp = (row_length - 1) // columns  # recomputed locally to not change params
        # Masks to add all bytes of two rows at once, without carrying over into the next byte.
        low_mask = int.from_bytes(b"\x7f" * row_length, "big")
        high_mask = int.from_bytes(b"\x80" * row_length, "big")
        for row in range(0, len(data), row_length):
            row_data = bytearray(data[row : row + row_length])
            filter_byte = row_data[0]

            if filter_byte == 0:
                # PNG None Predictor
                pass
            elif filter_byte == 1:
                # PNG Sub Predictor
                for i in range(bpp + 1, row_length):
                    row_data[i] = (row_data[i] + row_data[i - bpp]) % 256
            elif filter_byte == 2:
                # PNG Up Predictor
                current = int.from_bytes(row_data, "big")
                previous = int.from_bytes(previous_row_data, "big")
                # The low 7 bits of each byte are added without carrying into the next byte,
                # the high bit of each byte is added with XOR, dropping its carry.
                low_sum = (current & low_mask) + (previous & low_mask)
                high_bits = (current ^ previous) & high_mask
                row_data = bytearray((low_sum ^ high_bits).to_bytes(row_length, "big"))
            elif filter_byte == 3:
                # PNG Average Predictor
                for i in range(1, bpp + 1):
                    floor = previous_row_data[i] // 2
                    row_data[i] = (row_data[i] + floor) % 256
                for i in range(bpp + 1, row_length):
                    left = row_data[i - bpp]
                    floor = (left + previous_row_data[i]) // 2
                    row_data[i] = (row_data[i] + floor) % 256
            elif filter_byte == 4:
                # PNG Paeth Predictor
                for i in range(1, bpp + 1):
                    row_data[i] = (row_data[i] + previous_row_data[i]) % 256
                for i in range(bpp + 1, row_length):
                    left = row_data[i - bpp]
                    up = previous_row_data[i]
                    up_left = previous_row_data[i - bpp]

                    # The distances of p = left + up - up_left to left, up and up_left.
                    # Avoid calling abs() in this innermost loop.
                    dist_left = up - up_left
                    dist_up = left - up_left
                    dist_up_left = dist_left + dist_up
                    if dist_left < 0:
                        dist_left = -dist_left
                    if dist_up < 0:
                        dist_up = -dist_up
                    if dist_up_left < 0:
                        dist_up_left = -dist_up_left

                    if dist_left <= dist_up and dist_left <= dist_up_left:
                        paeth = left
                    elif dist_up <= dist_up_left:
                        paeth = up
                    else:
                        paeth = up_left

                    row_data[i] = (row_data[i] + paeth) % 256
            else:
                raise PdfReadError(
                    f"Unsupported PNG filter {filter_byte!r}"
                )  # pragma: no cover
            previous_row_data = row_data
            output += row_data[1:]
        return bytes(output)

    @staticmethod
    def encode(data: bytes, level: int = -1) -> bytes:
        """
        Compress the input data using zlib.

        Args:
            data: The data to be compressed.
            level: See https://docs.python.org/3/library/zlib.html#zlib.compress

        Returns:
            The compressed data.

        """
        return zlib.compress(data, level)


class ASCIIHexDecode:
    """
    The ASCIIHexDecode filter decodes data that has been encoded in ASCII
    hexadecimal form into a base-7 ASCII format.
    """

    @staticmethod
    def decode(
        data: str | bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decode an ASCII-Hex encoded data stream.

        Args:
          data: a str sequence of hexadecimal-encoded values to be
            converted into a base-7 ASCII string
          decode_parms: this filter does not use parameters.

        Returns:
          A string conversion in base-7 ASCII, where each of its values
          v is such that 0 <= ord(v) <= 127.

        Raises:
          PdfStreamError:

        """
        if isinstance(data, str):
            data = data.encode()

        # Stop at EOD
        eod = data.find(b">")
        if eod == -1:
            logger_warning(
                "missing EOD in ASCIIHexDecode, check if output is OK",
                source=__name__,
            )
            hex_data = data
        else:
            hex_data = data[:eod]

        # Remove whitespace
        hex_data = b"".join(hex_data.split())

        # Pad if odd length
        if len(hex_data) % 2 == 1:
            hex_data += b"0"

        if budget is not None:
            budget.check_output(budget.decompressed_bytes + len(hex_data) // 2)

        # The spec permits only 0-9, A-F, a-f and whitespace inside the stream.
        # Stray bytes used to surface as an uncaught binascii.Error; turn them
        # into a proper PdfStreamError instead.
        try:
            return binascii.unhexlify(hex_data)
        except binascii.Error as error:
            raise PdfStreamError(f"Invalid hexadecimal character in ASCIIHexDecode stream: {error}") from error


class RunLengthDecode:
    """
    The RunLengthDecode filter decodes data that has been encoded in a
    simple byte-oriented format based on run length.
    The encoded data is a sequence of runs, where each run consists of
    a length byte followed by 1 to 128 bytes of data. If the length byte is
    in the range 0 to 127,
    the following length + 1 (1 to 128) bytes are copied literally during
    decompression.
    If length is in the range 129 to 255, the following single byte is to be
    copied 257 − length (2 to 128) times during decompression. A length value
    of 128 denotes EOD.
    """

    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decode a run length encoded data stream.

        Args:
          data: a bytes sequence of length/data
          decode_parms: this filter does not use parameters.

        Returns:
          A bytes decompressed sequence.

        Raises:
          PdfStreamError:

        """
        output = bytearray()
        index = 0
        data_length = len(data)
        total_length = 0
        configuration = get_configuration()

        def reserve(amount: int) -> None:
            nonlocal total_length
            total_length += amount
            if total_length > configuration.run_length_maximum_output_length:
                raise LimitReachedError("Limit reached while decompressing.")
            if budget is not None and amount > budget.remaining_output_budget():
                raise LimitReachedError(
                    "Stream decoding exceeded the maximum decompressed output budget "
                    f"of {budget.maximum_decompressed_bytes} bytes."
                )

        while True:
            if index >= data_length:
                logger_warning(
                    "missing EOD in RunLengthDecode, check if output is OK", source=__name__
                )
                break  # Reached end of string without an EOD
            length = data[index]
            index += 1
            if length == 128:
                if index < data_length:
                    # We should first check, if we have an inner stream from a multi-encoded
                    # stream with a faulty trailing newline that we can decode properly.
                    # We will just ignore the last byte and raise a warning ...
                    if (index == data_length - 1) and (data[index : index + 1] == b"\n"):
                        logger_warning(
                            "Found trailing newline in stream data, check if output is OK", source=__name__
                        )
                        break
                    # Raising an exception here breaks all image extraction for this file, which might
                    # not be desirable. For this reason, indicate that the output is most likely wrong,
                    # as processing stopped after the first EOD marker. See issue #3517.
                    logger_warning(
                        "Early EOD in RunLengthDecode, check if output is OK", source=__name__
                    )
                break
            if length < 128:
                length += 1
                if index + length > data_length:
                    if budget is not None:
                        raise PdfStreamError(STREAM_TRUNCATED_PREMATURELY)
                    logger_warning(
                        "Missing EOD in RunLengthDecode, check if output is OK", source=__name__
                    )
                    output.extend(data[index:])
                    break
                reserve(length)
                output.extend(data[index : (index + length)])
                index += length
            else:  # >128
                if index >= data_length:
                    if budget is not None:
                        raise PdfStreamError(STREAM_TRUNCATED_PREMATURELY)
                    logger_warning(
                        "Missing EOD in RunLengthDecode, check if output is OK", source=__name__
                    )
                    break  # Reached end of string without the replicated byte
                length = 257 - length
                reserve(length)
                output.extend(bytes((data[index],)) * length)
                index += 1
        return bytes(output)


class LZWDecode:
    class Decoder:
        STOP = 257
        CLEARDICT = 256

        def __init__(self, data: bytes) -> None:
            self.data = data

        def decode(self) -> bytes:
            configuration = get_configuration()
            return _LzwCodec(max_output_length=configuration.lzw_maximum_output_length).decode(self.data)

    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decode an LZW encoded data stream.

        Args:
          data: ``bytes`` or ``str`` text to decode.
          decode_parms: a dictionary of parameter values.

        Returns:
          decoded data.

        """
        # decode_parms is unused here
        if budget is None:
            return LZWDecode.Decoder(data).decode()
        budget.require_output_capacity()
        configuration = get_configuration()
        maximum_output_length = min(
            configuration.lzw_maximum_output_length,
            budget.remaining_output_budget(),
        )
        return _LzwCodec(max_output_length=maximum_output_length).decode(data)


class ASCII85Decode:
    """Decodes string ASCII85-encoded data into a byte format."""

    @staticmethod
    def _decode_streaming(data: bytes, budget: StreamDecodingBudget | None) -> bytes:
        """Decode ASCII85 incrementally, charging the budget per output group.

        Each group of (up to) five input characters produces at most four
        output bytes, so the remaining output budget is checked before every
        group is materialized instead of decoding the whole stream first.
        """
        output = bytearray()
        group = bytearray()
        index = 0
        data_length = len(data)
        ended = False

        def decode_group(group_bytes: bytes, pad: int) -> None:
            if budget is not None and 4 - pad > budget.remaining_output_budget():
                raise LimitReachedError(
                    "Stream decoding exceeded the maximum decompressed output budget "
                    f"of {budget.maximum_decompressed_bytes} bytes."
                )
            if group_bytes == b"z":
                output.extend(b"\x00\x00\x00\x00")
                return
            value = 0
            for char in group_bytes:
                value = value * 85 + (char - 33)
            if value > 0xFFFFFFFF:
                raise ValueError("Ascii85 integer overflow")
            chunk = value.to_bytes(4, "big")
            output.extend(chunk[: 4 - pad] if pad else chunk)

        # Skip the optional Adobe prefix "<~".
        if data.startswith(b"<~"):
            index = 2

        while index < data_length:
            char = data[index]
            index += 1
            if char in WHITESPACES_AS_BYTES:
                continue
            if char == ord("~"):
                if index < data_length and data[index] == ord(">"):
                    index += 1
                ended = True
                break
            if char == ord("z") and not group:
                decode_group(b"z", 0)
                continue
            if not 33 <= char <= 117:
                raise ValueError(f"Invalid Ascii85 character {char!r}")
            group.append(char)
            if len(group) == 5:
                decode_group(bytes(group), 0)
                group = bytearray()

        if group:
            if len(group) == 1:
                raise ValueError("Ascii85 encoded byte groups cannot consist of a single character")
            pad = 5 - len(group)
            group.extend(b"u" * pad)
            decode_group(bytes(group), pad)
        elif not ended and index < data_length:
            raise ValueError("Ascii85 encoded byte sequences must end with b'~>'")
        return bytes(output)

    @staticmethod
    def decode(
        data: str | bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decode an Ascii85 encoded data stream.

        Args:
          data: ``bytes`` or ``str`` text to decode.
          decode_parms: this filter does not use parameters.

        Returns:
          decoded data.

        """
        if isinstance(data, str):
            data = data.encode()
        data = data.strip(WHITESPACES_AS_BYTES)
        if len(data) > 2 and data.endswith(b">"):
            data = data[:-1].rstrip(WHITESPACES_AS_BYTES) + data[-1:]
        if budget is not None:
            # The output is at most 4/5 of the (whitespace-free) input.
            expected = (len(data.rstrip(b"~>")) * 4 + 4) // 5
            budget.check_output(budget.decompressed_bytes + expected)
        try:
            if budget is None:
                return a85decode(data, adobe=True, ignorechars=WHITESPACES_AS_BYTES)
            if not data.endswith(b"~>"):
                logger_warning("Ignoring missing Ascii85 end marker.", source=__name__)
            return ASCII85Decode._decode_streaming(data, budget)
        except ValueError as error:
            if error.args[0] == "Ascii85 encoded byte sequences must end with b'~>'":
                logger_warning("Ignoring missing Ascii85 end marker.", source=__name__)
                return a85decode(data, adobe=False, ignorechars=WHITESPACES_AS_BYTES)
            raise


class DCTDecode:
    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decompresses data encoded using a DCT (discrete cosine transform)
        technique based on the JPEG standard (IS0/IEC 10918),
        reproducing image sample data that approximates the original data.

        Args:
          data: text to decode.
          decode_parms: this filter does not use parameters.

        Returns:
          decoded data.

        """
        if budget is not None:
            budget.check_output(budget.decompressed_bytes + len(data))
        return data


class JPXDecode:
    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decompresses data encoded using the wavelet-based JPEG 2000 standard,
        reproducing the original image data.

        Args:
          data: text to decode.
          decode_parms: this filter does not use parameters.

        Returns:
          decoded data.

        """
        if budget is not None:
            budget.check_output(budget.decompressed_bytes + len(data))
        return data


class BrotliDecode:
    @staticmethod
    @lru_cache(maxsize=1)
    def _check_brotli_available() -> None:
        if find_spec("brotli") is not None:
            return
        raise DependencyError("brotli is required for BrotliDecode. Install it with: pip install pypdf[brotli]")

    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Decompresses data encoded using the Brotli compression method,
        reproducing the original data.

        Announcement: https://pdfa.org/brotli-compression-coming-to-pdf/

        Specification: https://pdfa.org/download-area/publications/pdf-extension-brotli.pdf

        Args:
          data: text to decode.
          decode_parms: this filter does not use parameters.

        Returns:
          decoded data.

        Raises:
          DependencyError: If the ``brotli`` package is not installed.

        """
        BrotliDecode._check_brotli_available()
        import brotli  # noqa: PLC0415

        decompressor = brotli.Decompressor()
        configuration = get_configuration()
        maximum_output_length = configuration.brotli_maximum_output_length
        if budget is not None:
            budget.require_output_capacity()
            maximum_output_length = min(maximum_output_length, budget.remaining_output_budget())

        # TODO: Simplify once fixed upstream.
        #       https://github.com/google/brotli/issues/1396
        #       https://github.com/google/brotli/pull/1525
        output = bytearray()
        remaining = maximum_output_length
        chunk_size = 65_535
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset:offset + chunk_size]
            try:
                part = decompressor.process(chunk, output_buffer_limit=remaining)
            except brotli.error as exception:  # pragma: no cover
                raise LimitReachedError("Limit reached while decompressing.") from exception
            output.extend(part)
            remaining -= len(part)
            if remaining < 0:
                raise LimitReachedError("Limit reached while decompressing.")
        return bytes(output)

    @staticmethod
    def encode(data: bytes, **kwargs: Any) -> bytes:
        """
        Compresses data using the Brotli compression method.

        Args:
            data: The data to be compressed.

        Returns:
            The compressed data.

        Raises:
            DependencyError: If the ``brotli`` package is not installed.

        """
        BrotliDecode._check_brotli_available()
        import brotli  # noqa: PLC0415

        return bytes(brotli.compress(data))


@dataclass
class CCITTParameters:
    """§7.4.6, optional parameters for the CCITTFaxDecode filter."""

    K: int = 0
    columns: int = 1728
    rows: int = 0
    EndOfLine: bool | None = False
    EncodedByteAlign: bool | None = False
    EndOfBlock: bool | None = True
    BlackIs1: bool = False
    DamagedRowsBeforeError: int | None = 0

    @property
    def group(self) -> int:
        if self.K < 0:
            # Pure two-dimensional encoding (Group 4)
            ccitt_group = 4
        else:
            # K == 0: Pure one-dimensional encoding (Group 3, 1-D)
            # K > 0: Mixed one- and two-dimensional encoding (Group 3, 2-D)
            ccitt_group = 3
        return ccitt_group


class CCITTFaxDecode:
    """
    §7.4.6, CCITTFaxDecode filter (ISO 32000).

    Either Group 3 or Group 4 CCITT facsimile (fax) encoding.
    CCITT encoding is bit-oriented, not byte-oriented.

    §7.4.6, optional parameters for the CCITTFaxDecode filter.
    """

    # We use the `L` with standard size, thus have 4 bytes, which corresponds to an upper limit of
    # 2 ** (struct.calcsize("<L") * 8) - 1 = 2 ** (4 * 8) - 1 = 2 ** 32 - 1 = 4_294_967_295
    # https://docs.python.org/3/library/struct.html#format-characters
    _MAXIMUM_UNSIGNED_LONG = 0xFFFFFFFF

    @staticmethod
    def _get_parameters(
        parameters: ArrayObject | DictionaryObject | IndirectObject | None,
        rows: int | IndirectObject,
    ) -> CCITTParameters:
        def get_integer(value: Any, key: str) -> int:
            if isinstance(value, PdfObject):
                value = value.get_object()
            if not isinstance(value, int):
                raise PdfReadError(f"Expected integer for {key}, got {type(value).__name__}: {value!r}!")
            return value

        def get_boolean(value: Any, key: str) -> bool:
            if not isinstance(value, BooleanObject):
                raise PdfReadError(f"Expected boolean for {key}, got {type(value).__name__}: {value!r}!")
            return value.value

        ccitt_parameters = CCITTParameters(
            rows=0 if is_null_or_none(rows) else get_integer(rows, CCITT.ROWS)
        )
        if parameters:
            parameters_unwrapped = parameters.get_object()
            if isinstance(parameters_unwrapped, ArrayObject):
                decode_parm_list = list(parameters_unwrapped)
            else:
                decode_parm_list = [parameters_unwrapped]
            for decode_parm in decode_parm_list:
                if isinstance(decode_parm, PdfObject):
                    decode_parm = decode_parm.get_object()
                if is_null_or_none(decode_parm):
                    continue
                if not isinstance(decode_parm, dict):
                    logger_warning(
                        "Ignoring invalid DecodeParms entry: %(value)s",
                        source=__name__, value=decode_parm,
                    )
                    continue
                if CCITT.K in decode_parm:
                    ccitt_parameters.K = get_integer(decode_parm[CCITT.K], CCITT.K)
                if CCITT.COLUMNS in decode_parm:
                    ccitt_parameters.columns = get_integer(decode_parm[CCITT.COLUMNS], CCITT.COLUMNS)
                if CCITT.BLACK_IS_1 in decode_parm:
                    ccitt_parameters.BlackIs1 = get_boolean(decode_parm[CCITT.BLACK_IS_1], CCITT.BLACK_IS_1)

        if ccitt_parameters.columns < 0 or ccitt_parameters.columns > CCITTFaxDecode._MAXIMUM_UNSIGNED_LONG:
            raise PdfReadError(
                f"Expected valid 32 bit unsigned value for {CCITT.COLUMNS}, got {ccitt_parameters.columns}!"
            )
        if ccitt_parameters.rows < 0 or ccitt_parameters.rows > CCITTFaxDecode._MAXIMUM_UNSIGNED_LONG:
            raise PdfReadError(
                f"Expected valid 32 bit unsigned value for {CCITT.ROWS}, got {ccitt_parameters.rows}!"
            )
        return ccitt_parameters

    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        height: int = 0,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        params = CCITTFaxDecode._get_parameters(decode_parms, height)

        img_size = len(data)
        if budget is not None:
            # The output consists of a fixed TIFF header plus the raw fax data.
            tiff_header_size = struct.calcsize("<2sHLH" + "HHLL" * 8 + "H")
            budget.check_output(budget.decompressed_bytes + tiff_header_size + img_size)
        # TIFF SHORT and LONG fields are unsigned (TIFF 6.0, §2); pack them with
        # unsigned codes so dimensions with the high bit set do not overflow.
        tiff_header_struct = "<2sHLH" + "HHLL" * 8 + "H"
        tiff_header = struct.pack(
            tiff_header_struct,
            b"II",  # Byte order indication: Little endian
            42,     # Version number (always 42)
            8,      # Offset to the first image file directory (IFD)
            8,      # Number of tags in IFD
            256,    # ImageWidth, LONG, 1, width
            4,
            1,
            params.columns,
            257,    # ImageLength, LONG, 1, length
            4,
            1,
            params.rows,
            258,    # BitsPerSample, SHORT, 1, 1
            3,
            1,
            1,
            259,    # Compression, SHORT, 1, compression Type
            3,
            1,
            params.group,
            262,    # Thresholding, SHORT, 1, 0 = BlackIs1
            3,
            1,
            int(params.BlackIs1),
            273,    # StripOffsets, LONG, 1, length of header
            4,
            1,
            struct.calcsize(
                tiff_header_struct
            ),
            278,    # RowsPerStrip, LONG, 1, length
            4,
            1,
            params.rows,
            279,    # StripByteCounts, LONG, 1, size of image
            4,
            1,
            img_size,
            0,      # last IFD
        )

        return tiff_header + data


JBIG2DEC_BINARY = shutil.which("jbig2dec")  # DEPRECATED: Use pypdf.Configuration.


class JBIG2Decode:
    @staticmethod
    def decode(
        data: bytes,
        decode_parms: DictionaryObject | None = None,
        budget: StreamDecodingBudget | None = None,
        **kwargs: Any,
    ) -> bytes:
        configuration = get_configuration()
        if configuration.jbig2dec_binary is None:
            raise DependencyError("jbig2dec binary is not available.")
        maximum_output_length = configuration.jbig2_maximum_output_length
        if budget is not None:
            maximum_output_length = min(maximum_output_length, budget.remaining_output_budget())

        with TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            paths: list[Path] = []

            if decode_parms and "/JBIG2Globals" in decode_parms:
                jbig2_globals = decode_parms["/JBIG2Globals"]
                if not is_null_or_none(jbig2_globals) and not is_null_or_none(pointer := jbig2_globals.get_object()):
                    assert pointer is not None, "mypy"
                    if isinstance(pointer, StreamObject):
                        path = directory.joinpath("globals.jbig2")
                        path.write_bytes(pointer.get_data())
                        paths.append(path)

            path = directory.joinpath("image.jbig2")
            path.write_bytes(data)
            paths.append(path)

            environment = os.environ.copy()
            environment["LC_ALL"] = "C"
            result = subprocess.run(  # noqa: S603
                [
                    configuration.jbig2dec_binary,
                    "--embedded",
                    "--format", "png",
                    "--output", "-",
                    "-M", str(maximum_output_length),
                    *paths
                ],
                capture_output=True,
                env=environment,
            )
            if b"unrecognized option '--embedded'" in result.stderr or b"unrecognized option '-M'" in result.stderr:
                raise DependencyError("jbig2dec>=0.19 is required.")
            if b"FATAL ERROR failed to allocate image data buffer" in result.stderr:
                raise LimitReachedError(
                    f"Memory limit reached while reading JBIG2 data:\n{result.stderr.decode('utf-8')}"
                )
            if result.stderr:
                for line in result.stderr.decode("utf-8").splitlines():
                    logger_warning(line, source=__name__)
            if result.returncode != 0:
                raise PdfStreamError(f"Unable to decode JBIG2 data. Exit code: {result.returncode}")
        return result.stdout

    @staticmethod
    def _is_binary_compatible() -> bool:
        configuration = get_configuration()
        if not configuration.jbig2dec_binary:  # pragma: no cover
            return False
        result = subprocess.run(  # noqa: S603
            [configuration.jbig2dec_binary, "--version"],
            capture_output=True,
            text=True,
        )
        version = result.stdout.split(" ", maxsplit=1)[1]

        from ._utils import Version  # noqa: PLC0415
        return Version(version) >= Version("0.19")


def _deprecate_inline_image_filters(filter_name: str, old_name: str, new_name: str) -> None:
    if filter_name != old_name:
        return
    deprecation(
        f"The filter name {old_name} is deprecated and has been removed in pypdf 7.0.0. Use {new_name} instead."
    )


def _stream_decoding_cache_key(
    stream: StreamObject,
    filters: tuple[Any, ...],
    budget: StreamDecodingBudget,
) -> tuple[Any, ...]:
    """Build a cache key covering the raw data, filter chain and budget limits.

    The same stream object can be decoded repeatedly (e.g. after its data was
    replaced), so the raw data identity and length participate in the key.
    Budget limits are part of the key because a result accepted under a large
    budget must not be served to a caller constrained by a smaller one.
    """
    return (
        id(stream),
        len(stream._data),
        hash(stream._data),
        tuple(str(filter_name) for filter_name in filters),
        budget.maximum_compressed_input_bytes,
        budget.maximum_decompressed_bytes,
        budget.maximum_filter_steps,
        budget.maximum_single_step_ratio,
        round(budget.maximum_cumulative_time_seconds, 6),
    )


def decode_stream_data(stream: StreamObject) -> bytes:
    """
    Decode the stream data based on the specified filters.

    This function decodes the stream data using the filters provided in the
    stream.

    Args:
        stream: The input stream object containing the data and filters.

    Returns:
        The decoded stream data.

    Raises:
        NotImplementedError: If an unsupported filter type is encountered.

    """
    configuration = get_configuration()
    filters = stream.get(StreamAttributes.FILTER, ())
    if isinstance(filters, IndirectObject):
        filters = cast(ArrayObject, filters.get_object())
    if not isinstance(filters, ArrayObject):
        # We have a single filter instance
        filters = (filters,)

    decode_parms = stream.get(StreamAttributes.DECODE_PARMS, (DictionaryObject(),) * len(filters))
    if not isinstance(decode_parms, (list, tuple)):
        decode_parms = (decode_parms,)
    data: bytes = stream._data
    # If there is no data to decode, we should not try to decode it.
    if not data:
        return data

    budget = get_budget_for_stream(stream, configuration)
    cache_key = _stream_decoding_cache_key(stream, tuple(filters), budget)
    decoded_cache = getattr(stream, "_decoded_stream_cache", None)
    if decoded_cache is None:
        decoded_cache = {}
        stream._decoded_stream_cache = decoded_cache
    cached_result = decoded_cache.get(cache_key)
    if cached_result is not None:
        return cached_result

    # Keep the historical per-stream filter-count guard for the exact error
    # message; the shared budget enforces the same limit across streams as well.
    if (filter_count := len(filters)) > configuration.stream_filters_maximum_length:
        raise LimitReachedError(
            f"Maximum filter count {configuration.stream_filters_maximum_length} exceeded: {filter_count}"
        )

    with StreamBudgetContext(budget):
        result = _decode_filter_chain(
            stream=stream,
            data=data,
            filters=tuple(filters),
            decode_parms=decode_parms,
            budget=budget,
            configuration=configuration,
        )

    # The result is cached only after the complete chain succeeded, so a failed
    # decode never leaves partial content behind for page parsing.
    decoded_cache[cache_key] = result
    return result


def _decode_filter_chain(
    *,
    stream: StreamObject,
    data: bytes,
    filters: tuple[Any, ...],
    decode_parms: tuple[Any, ...] | list[Any],
    budget: StreamDecodingBudget,
    configuration: Any,
) -> bytes:
    accumulated_decoding_work = 0
    decoding_work_maximum_length = configuration.stream_decoding_work_maximum_length

    def _check_decoding_work(amount: int) -> None:
        nonlocal accumulated_decoding_work
        accumulated_decoding_work += amount
        if accumulated_decoding_work > decoding_work_maximum_length:
            raise LimitReachedError(
                "Stream decoding exceeded the maximum accumulated "
                f"decoding work of {decoding_work_maximum_length} bytes."
            )

    for filter_name, params in zip(filters, decode_parms):
        input_length = len(data)
        # Only the original compressed bytes count against the input budget;
        # outputs of earlier filter steps are already accounted for as output.
        if budget.filter_steps == 0:
            budget.charge_input(input_length)
        _check_decoding_work(amount=input_length)

        params = params.get_object()
        if is_null_or_none(params):
            # The decoders are typed for a DictionaryObject; a plain {} is not
            # one, so a null /DecodeParms entry would hand them the wrong type.
            params = DictionaryObject()
        elif not isinstance(params, (dict, list)):
            logger_warning(
                "Ignoring invalid DecodeParms: %(value)s",
                source=__name__, value=params,
            )
            params = DictionaryObject()
        budget.begin_filter_step(str(filter_name), input_length)
        with budget.time_step():
            if filter_name in (FT.ASCII_HEX_DECODE, FTA.AHx):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.AHx, new_name=FT.ASCII_HEX_DECODE)
                decoded = ASCIIHexDecode.decode(data, budget=budget)
            elif filter_name in (FT.ASCII_85_DECODE, FTA.A85):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.A85, new_name=FT.ASCII_85_DECODE)
                decoded = ASCII85Decode.decode(data, budget=budget)
            elif filter_name in (FT.LZW_DECODE, FTA.LZW):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.LZW, new_name=FT.LZW_DECODE)
                decoded = LZWDecode.decode(data, params, budget=budget)
            elif filter_name in (FT.FLATE_DECODE, FTA.FL):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.FL, new_name=FT.FLATE_DECODE)
                decoded = FlateDecode.decode(data, params, budget=budget)
            elif filter_name in (FT.RUN_LENGTH_DECODE, FTA.RL):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.RL, new_name=FT.RUN_LENGTH_DECODE)
                decoded = RunLengthDecode.decode(data, budget=budget)
            elif filter_name in (FT.CCITT_FAX_DECODE, FTA.CCF):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.CCF, new_name=FT.CCITT_FAX_DECODE)
                height = stream.get(ImageAttributes.HEIGHT, 0)
                decoded = CCITTFaxDecode.decode(data, params, height, budget=budget)
            elif filter_name in (FT.DCT_DECODE, FTA.DCT):
                _deprecate_inline_image_filters(filter_name=filter_name, old_name=FTA.DCT, new_name=FT.DCT_DECODE)
                decoded = DCTDecode.decode(data, budget=budget)
            elif filter_name == FT.JPX_DECODE:
                decoded = JPXDecode.decode(data, budget=budget)
            elif filter_name == FT.BROTLI_DECODE:
                decoded = BrotliDecode.decode(data, budget=budget)
            elif filter_name == FT.JBIG2_DECODE:
                decoded = JBIG2Decode.decode(data, params, budget=budget)
            elif filter_name == "/Crypt":
                if "/Name" in params or "/Type" in params:
                    raise NotImplementedError(
                        "/Crypt filter with /Name or /Type not supported yet"
                    )
                decoded = data
            else:
                raise NotImplementedError(f"Unsupported filter {filter_name}")

        # Filters which wrap timed codecs (Flate, LZW) report their own
        # elapsed time; the remaining steps are effectively instantaneous
        # byte transformations bounded by the other budgets.
        output_length = len(decoded)
        budget.check_actual_ratio(str(filter_name), input_length, output_length)
        # Charge the produced output against the remaining shared budget. The
        # decoders already bounded their allocations, so this never materializes
        # data that exceeded the budget first.
        budget.charge_output(output_length)
        _check_decoding_work(amount=output_length)
        data = decoded

    return data
