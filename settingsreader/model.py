"""Data model describing caller-supplied table layouts and the read results.

The reader never hard-codes the on-medium layout.  The caller describes where
the two copies live, which fields carry the commit flag/generation/checksum
and how a checksum is validated.  Everything in this module is plain data so
the descriptions can be built once and reused across images of the same type.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable, Protocol, runtime_checkable

if TYPE_CHECKING:
    from dissect.cstruct.types.structure import Structure


class WriteState(str, Enum):
    """The provable write state of a single settings region.

    The states only describe what can be proven from the bytes on disk.  A
    region that never reached its commit marker must never be presented as an
    active configuration, even when its generation counter is higher.
    """

    ERASED = "erased"
    """The region only contains the erased fill pattern (e.g. all ``0xff``)."""

    PARTIAL = "partial"
    """A write was interrupted: the bytes cannot be parsed or fail the checksum."""

    PENDING = "pending"
    """The record parses and validates but the commit flag was never set."""

    COMMITTED = "committed"
    """The record parses, validates and carries the committed marker."""


class ChecksumStatus(str, Enum):
    """Outcome of running the caller-supplied checksum rule."""

    NOT_CONFIGURED = "not_configured"
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


@runtime_checkable
class ChecksumRule(Protocol):
    """Callable protocol for the caller-supplied checksum decision rule.

    Implementations receive the raw region bytes and the parsed record and
    return ``True`` only when the stored checksum proves the record is intact.
    Returning ``False`` marks an interrupted write; raising an exception is
    treated the same way but keeps the error message for the forensic report.
    """

    def __call__(self, raw: bytes, record: Structure) -> bool: ...


@dataclass(frozen=True)
class TableLayout:
    """Description of the two security settings copies inside an image.

    Args:
        record_type: A compiled cstruct structure type used to parse each copy.
        region_offsets: Absolute byte offsets of the two equally sized regions.
        commit_field: Name of the field holding the commit marker.
        generation_field: Name of the field holding the monotonic generation.
        committed_value: Field value proving the commit marker was written.
        checksum_field: Field carrying the stored checksum, or ``None``.
        checksum_rule: Callable validating the checksum, or ``None``.
        erased_fill: Byte repeated across an erased (never written) region.
        generation_modulus: Wrap modulus; defaults to ``2 ** field bits``.
    """

    record_type: type
    region_offsets: tuple[int, int]
    commit_field: str
    generation_field: str
    committed_value: int = 1
    checksum_field: str | None = None
    checksum_rule: ChecksumRule | None = None
    erased_fill: int = 0xFF
    generation_modulus: int | None = None

    def __post_init__(self) -> None:
        if len(self.region_offsets) != 2:
            raise ValueError("exactly two region offsets are required")
        if self.region_offsets[0] == self.region_offsets[1]:
            raise ValueError("region offsets must be distinct")
        if not 0 <= self.erased_fill <= 0xFF:
            raise ValueError("erased_fill must be a single byte value")
        lookup = self.record_type.__lookup__
        for required in (self.commit_field, self.generation_field):
            if required not in lookup:
                raise ValueError(f"record type has no field named {required!r}")
        if self.checksum_field is not None and self.checksum_field not in lookup:
            raise ValueError(f"record type has no field named {self.checksum_field!r}")
        if self.checksum_rule is not None and not callable(self.checksum_rule):
            raise ValueError("checksum_rule must be callable")

    @property
    def record_size(self) -> int:
        """Size of one settings table in bytes."""
        return len(self.record_type)

    @property
    def modulus(self) -> int:
        """Effective generation modulus, derived from the field width unless overridden."""
        if self.generation_modulus is not None:
            return self.generation_modulus
        field_type = self.record_type.__lookup__[self.generation_field].type
        return 1 << (len(field_type) * 8)


@dataclass
class RegionObservation:
    """Everything that can be proven about one of the two regions.

    Attributes:
        index: Region index, ``0`` or ``1``.
        offset: Absolute byte offset inside the image.
        state: Provable write state.
        generation: Parsed generation, or ``None`` when unreadable/erased.
        committed: Parsed commit flag value, or ``None`` when unreadable.
        checksum_status: Checksum decision for this region.
        record: Parsed cstruct record, or ``None`` when unavailable.
        raw: Exact bytes read from the image for this region.
        error: Human-readable reason for ``PARTIAL``/checksum ``ERROR``.
    """

    index: int
    offset: int
    state: WriteState
    generation: int | None = None
    committed: int | None = None
    checksum_status: ChecksumStatus = ChecksumStatus.NOT_CONFIGURED
    record: Structure | None = None
    raw: bytes = b""
    error: str | None = None

    @property
    def is_committed(self) -> bool:
        """Whether this region is a provably committed table."""
        return self.state == WriteState.COMMITTED

    @property
    def is_evidence_only(self) -> bool:
        """Whether the region may be quoted as evidence but never as active."""
        return self.state in (WriteState.PARTIAL, WriteState.PENDING)


@dataclass
class SelectionResult:
    """Result of reading both regions and selecting the provable active copy.

    Attributes:
        regions: Observations in the same order as ``TableLayout.region_offsets``.
        active_index: Index of the selected region, or ``None`` if none qualifies.
        tie: True when both committed regions share the same newest generation.
    """

    regions: list[RegionObservation]
    active_index: int | None = None
    tie: bool = False

    @property
    def active(self) -> RegionObservation | None:
        """The selected active region, or ``None`` when no table is provably active."""
        if self.active_index is None:
            return None
        return self.regions[self.active_index]

    @property
    def active_record(self) -> Structure | None:
        """Parsed record of the active region, or ``None``."""
        region = self.active
        return region.record if region is not None else None

    @property
    def evidence_only(self) -> list[RegionObservation]:
        """Regions that are no more than pending/interrupted write evidence."""
        return [region for region in self.regions if region.is_evidence_only]

    def region(self, index: int) -> RegionObservation:
        """Return the observation for the region at ``index``."""
        return self.regions[index]

    def summary(self) -> str:
        """Render a short, report-friendly description of the decision."""
        lines = []
        for region in self.regions:
            generation = "n/a" if region.generation is None else str(region.generation)
            suffix = f" - {region.error}" if region.error else ""
            lines.append(
                f"region {region.index} @0x{region.offset:x}: {region.state.value} "
                f"(generation={generation}, checksum={region.checksum_status.value}){suffix}"
            )
        active = self.active
        if active is None:
            lines.append("active: none - no region contains a provably committed table")
        else:
            tie_note = " (tie broken by region order)" if self.tie else ""
            lines.append(
                f"active: region {active.index} @0x{active.offset:x} "
                f"generation {active.generation}{tie_note}"
            )
        return "\n".join(lines)


def field_crc32(
    covered_fields: tuple[str, ...],
    *,
    stored_checksum_field: str,
    xor_value: int = 0,
) -> Callable[[bytes, Structure], bool]:
    """Build a checksum rule that CRC32s a concatenation of record fields.

    The exact checksum algorithm differs between devices, so this is only a
    convenience factory for the common "CRC32 over the preceding fields"
    scheme.  Callers with different algorithms pass their own callable to
    :class:`TableLayout` instead.

    Args:
        covered_fields: Field names serialised, in order, into the CRC input.
        stored_checksum_field: Field holding the expected checksum value.
        xor_value: Optional final XOR applied to the raw CRC32.
    """
    import zlib

    def _verify(raw: bytes, record: Structure) -> bool:
        buffer = b"".join(_field_bytes(record, name) for name in covered_fields)
        expected = getattr(record, stored_checksum_field)
        return (zlib.crc32(buffer) ^ xor_value) & 0xFFFFFFFF == expected

    return _verify


def _field_bytes(record: Structure, field_name: str) -> bytes:
    struct_field = type(record).__lookup__[field_name]
    stream = io.BytesIO()
    struct_field.type.write(stream, getattr(record, field_name))
    return stream.getvalue()


__all__ = [
    "ChecksumStatus",
    "ChecksumRule",
    "RegionObservation",
    "SelectionResult",
    "TableLayout",
    "WriteState",
    "field_crc32",
]
