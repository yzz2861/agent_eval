"""
Read-only forensics support for pcap-ng streams.

Early capture software sometimes wrote block types that current readers
do not know how to interpret. Before deciding whether such material can
be archived verbatim for later review, a backend needs evidence about
where each unknown block lives, how much data it claims to contain, how
much of that claim is actually readable, and a stable digest of the
recovered bytes.

The :class:`ForensicsScanner` in this module never re-interprets or
re-serializes a block. It walks the raw stream, keeps each section's
byte-order state local to that section, and records a
:class:`UnknownBlockEvidence` for every block type that is not listed in
:data:`pcapng.blocks.KNOWN_BLOCKS`. When the declared boundary cannot be
fully read, the available bytes are still recorded and the evidence is
flagged as incomplete instead of aborting the whole scan. Known,
supported blocks are simply skipped; the recorded bytes include any
spec-mandated 32-bit alignment padding so a digest covers the exact
bytes found on disk.
"""

import hashlib
import struct

from pcapng._compat import namedtuple
from pcapng.blocks import KNOWN_BLOCKS
from pcapng.constants.block_types import (
    BLK_RESERVED,
    BLK_RESERVED_CORRUPTED,
    BLK_SECTION_HEADER,
)
from pcapng.exceptions import StreamEmpty
from pcapng.structs import BYTE_ORDER_MAGIC, BYTE_ORDER_MAGIC_INVERSE


# Minimum block framing: block type (4) + block length (4) +
# trailing block length (4).
_BLOCK_HEADER_SIZE = 8
_BLOCK_TRAILER_SIZE = 4
_MIN_BLOCK_SIZE = _BLOCK_HEADER_SIZE + _BLOCK_TRAILER_SIZE


UnknownBlockEvidence = namedtuple(
    "UnknownBlockEvidence",
    [
        # Zero-based index of the section owning the block.
        "section",
        # File offset of the block type field, in bytes.
        "offset",
        # The 32-bit block type as found on disk.
        "block_type",
        # Total block length declared by the leading length field.
        # ``None`` when the leading length itself is unreadable.
        "declared_length",
        # Offset range of the payload actually recovered from the
        # stream, half-open: [payload_start, payload_end).
        "readable_start",
        "readable_end",
        # Number of payload bytes the block claims, derived from the
        # declared length (``declared_length - 12``). ``None`` when the
        # declared length is missing or structurally invalid.
        "declared_payload_length",
        # Number of payload bytes that were actually available.
        "readable_payload_length",
        # The recovered payload bytes exactly as stored, including any
        # 32-bit alignment padding; never decoded or re-encoded.
        "data",
        # Hex digest computed over the recovered payload bytes.
        "digest_algorithm",
        "digest",
        # ``True`` when the full declared block could not be verified
        # (truncated stream, invalid declared length or missing/mismatched
        # trailing length).
        "incomplete",
        # Human-readable reasons why the evidence is incomplete, if any.
        "issues",
    ],
)


ForensicsReport = namedtuple(
    "ForensicsReport",
    [
        # Number of sections (Section Header Blocks) encountered.
        "section_count",
        # Evidence recorded for each unknown block, in stream order.
        "unknown_blocks",
        # True when every unknown block was fully bounded and verified.
        "complete",
    ],
)


def _is_corrupted_marker(block_type):
    for start, end in BLK_RESERVED_CORRUPTED:
        if start <= block_type <= end:
            return True
    return False


def _read_available(stream, size):
    """Read up to ``size`` bytes, tolerating a truncated stream.

    Returns the bytes read (possibly shorter than requested) and a flag
    telling whether the stream ended before the request was satisfied.
    Raises :class:`StreamEmpty` only when no byte at all was available.
    """
    if size == 0:
        return b"", False
    data = stream.read(size)
    if len(data) == 0:
        raise StreamEmpty("Zero bytes read from stream")
    return data, len(data) < size


def _detect_endianness(stream):
    """Read the SHB byte-order magic and resolve section endianness."""
    magic_raw = stream.read(4)
    if len(magic_raw) < 4:
        return None, magic_raw
    magic = struct.unpack(">I", magic_raw)[0]
    if magic == BYTE_ORDER_MAGIC:
        return ">", magic_raw
    if magic == BYTE_ORDER_MAGIC_INVERSE:
        return "<", magic_raw
    return None, magic_raw


class ForensicsScanner(object):
    """
    Read-only scanner collecting preservation evidence about unknown blocks.

    Unlike :class:`pcapng.scanner.FileScanner`, this scanner is deliberately
    tolerant of damaged material:

    * It only records evidence, never decodes or writes block payloads.
    * A truncated or otherwise unverifiable block is recorded with
      ``incomplete=True`` and scanning stops, because no further block
      boundary can be located reliably.
    * Byte order is re-established from every Section Header Block, so a
      later section never inherits the endianness (or block framing) of
      the previous one.

    :param stream: a binary, seekable file-like object providing
        ``read()`` and ``tell()``.
    :param hash_algorithm: any :mod:`hashlib` algorithm name, defaulting
        to ``"sha256"``.
    """

    __slots__ = [
        "stream",
        "hash_algorithm",
        "section_index",
        "endianness",
        "_exhausted",
    ]

    def __init__(self, stream, hash_algorithm="sha256"):
        if not hasattr(stream, "read") or not hasattr(stream, "tell"):
            raise TypeError("stream must provide read() and tell()")
        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(
                "Unsupported hash algorithm: {0}".format(hash_algorithm)
            )
        self.stream = stream
        self.hash_algorithm = hash_algorithm
        self.section_index = -1
        self.endianness = None
        self._exhausted = False

    def __iter__(self):
        while not self._exhausted:
            try:
                evidence = self._read_next_block()
            except StreamEmpty:
                return
            if evidence is None:
                continue
            yield evidence
            if evidence.incomplete:
                self._exhausted = True
                return

    def scan(self):
        """Run the full scan and build a :class:`ForensicsReport`."""
        unknown_blocks = list(self)
        complete = all(not item.incomplete for item in unknown_blocks)
        return ForensicsReport(
            section_count=self.section_index + 1,
            unknown_blocks=unknown_blocks,
            complete=complete,
        )

    def _digest(self, data):
        return hashlib.new(self.hash_algorithm, data).hexdigest()

    def _read_next_block(self):
        stream = self.stream
        block_offset = stream.tell()

        type_raw = stream.read(4)
        if len(type_raw) == 0:
            raise StreamEmpty("Zero bytes read from stream")
        if len(type_raw) < 4:
            # We cannot even read the block type; record the orphan bytes
            # against the current section, if any, then stop scanning.
            return self._record_orphan(block_offset, type_raw)

        # Decode the block type using the current section byte order.
        # Before any section is established there is no framing to trust,
        # so fall back to big-endian and let the orphan path handle it.
        order = self.endianness if self.endianness is not None else ">"
        block_type = struct.unpack(order + "I", type_raw)[0]

        if block_type == BLK_SECTION_HEADER:
            self._enter_section(stream)
            return None

        if self.endianness is None:
            # Data before any valid Section Header Block cannot be framed
            # reliably. Preserve the raw bytes as evidence and stop.
            return self._record_orphan(block_offset, type_raw)

        if block_type in KNOWN_BLOCKS:
            return self._skip_known_block()

        return self._read_unknown_block(block_offset, block_type)

    def _skip_known_block(self):
        # A supported block needs no preservation evidence. Skip its
        # declared boundary so the stream lands on the next block; a
        # short read marks the material incomplete and stops the scan.
        stream = self.stream
        length_raw, length_short = self._read_raw(4)
        if length_short:
            self._exhausted = True
            return None
        declared_length = struct.unpack(self.endianness + "I", length_raw)[0]
        if declared_length < _MIN_BLOCK_SIZE or declared_length % 4 != 0:
            self._exhausted = True
            return None
        remaining = declared_length - _BLOCK_HEADER_SIZE
        tail = stream.read(remaining)
        if len(tail) < remaining:
            self._exhausted = True
        return None

    def _enter_section(self, stream):
        # Read an SHB enough to establish a fresh, section-local state.
        # On disk: block type (already read), block length, byte-order
        # magic, body, trailing length. Keep length bytes raw until the
        # magic establishes this section own byte order.
        length_raw, length_short = self._read_raw(4)
        endianness, magic_raw = _detect_endianness(stream)
        if endianness is None:
            self.endianness = None
            self.section_index += 1
            self._exhausted = True
            return
        self.endianness = endianness
        self.section_index += 1
        if length_short:
            self._exhausted = True
            return
        declared_length = struct.unpack(endianness + "I", length_raw)[0]
        if declared_length < _MIN_BLOCK_SIZE or declared_length % 4 != 0:
            self._exhausted = True
            return
        remaining = declared_length - (
            _BLOCK_HEADER_SIZE + len(magic_raw)
        )
        if remaining > 0:
            tail = stream.read(remaining)
            if len(tail) < remaining:
                self._exhausted = True

    def _read_raw(self, size):
        """Read exactly ``size`` bytes or return the short read."""
        if size == 0:
            return b"", False
        data = self.stream.read(size)
        if len(data) == 0:
            raise StreamEmpty("Zero bytes read from stream")
        return data, len(data) < size

    def _read_unknown_block(self, block_offset, block_type):
        stream = self.stream
        endianness = self.endianness
        issues = []
        incomplete = False

        length_raw, length_short = self._read_raw(4)
        if length_short:
            # No usable declared length; keep whatever bytes exist and
            # stop. The orphan helper handles section bookkeeping.
            orphan = self._record_orphan(
                block_offset, struct.pack(">I", block_type) + length_raw
            )
            return orphan

        declared_length = struct.unpack(endianness + "I", length_raw)[0]

        if declared_length < _MIN_BLOCK_SIZE or declared_length % 4 != 0:
            # The declared length cannot describe a legal block. We still
            # preserve evidence of the header, but cannot find a safe
            # boundary, so scanning ends here.
            issues.append(
                "invalid declared block length: {0}".format(declared_length)
            )
            return self._build_evidence(
                block_offset=block_offset,
                block_type=block_type,
                declared_length=declared_length,
                data=b"",
                payload_start=stream.tell(),
                truncated=True,
                extra_issues=issues,
            )

        declared_payload_length = declared_length - _MIN_BLOCK_SIZE
        payload_start = stream.tell()
        payload, payload_truncated = _read_available(
            stream, declared_payload_length
        )
        if payload_truncated:
            incomplete = True
            issues.append(
                "stream ended after {0} of {1} declared payload bytes".format(
                    len(payload), declared_payload_length
                )
            )

        readable_end = stream.tell()

        # Only trust the trailing length when the full block was read.
        if not payload_truncated:
            trailer_raw, trailer_short = self._read_raw(4)
            if trailer_short:
                incomplete = True
                issues.append("missing trailing block length")
            else:
                trailing_length = struct.unpack(
                    endianness + "I", trailer_raw
                )[0]
                if trailing_length != declared_length:
                    incomplete = True
                    issues.append(
                        "mismatching block lengths: {0} and {1}".format(
                            declared_length, trailing_length
                        )
                    )

        if block_type == BLK_RESERVED or _is_corrupted_marker(block_type):
            issues.append(
                "block type 0x{0:08X} is reserved/corruption marker".format(
                    block_type
                )
            )
            incomplete = True

        return self._build_evidence(
            block_offset=block_offset,
            block_type=block_type,
            declared_length=declared_length,
            declared_payload_length=declared_payload_length,
            data=payload,
            payload_start=payload_start,
            truncated=incomplete,
            readable_end=readable_end,
            extra_issues=issues,
        )

    def _record_orphan(self, block_offset, raw_bytes):
        """Preserve bytes that cannot be framed, then halt the scan."""
        stream = self.stream
        payload_start = block_offset
        evidence = self._build_evidence(
            block_offset=block_offset,
            block_type=None,
            declared_length=None,
            declared_payload_length=None,
            data=raw_bytes,
            payload_start=payload_start,
            truncated=True,
            readable_end=stream.tell(),
            extra_issues=[
                "unreadable or missing block framing at offset {0}".format(
                    block_offset
                )
            ],
        )
        return evidence

    def _build_evidence(
        self,
        block_offset,
        block_type,
        declared_length,
        data,
        payload_start,
        truncated,
        declared_payload_length=None,
        readable_end=None,
        extra_issues=None,
    ):
        if readable_end is None:
            readable_end = payload_start + len(data)
        if declared_payload_length is None and declared_length is not None:
            if declared_length >= _MIN_BLOCK_SIZE:
                declared_payload_length = declared_length - _MIN_BLOCK_SIZE
        issues = list(extra_issues or [])
        if truncated and not issues:
            issues.append("block boundary could not be fully verified")

        return UnknownBlockEvidence(
            section=max(self.section_index, 0) if self.section_index >= 0 else -1,
            offset=block_offset,
            block_type=block_type,
            declared_length=declared_length,
            readable_start=payload_start,
            readable_end=readable_end,
            declared_payload_length=declared_payload_length,
            readable_payload_length=len(data),
            data=data,
            digest_algorithm=self.hash_algorithm,
            digest=self._digest(data),
            incomplete=truncated,
            issues=tuple(issues),
        )
