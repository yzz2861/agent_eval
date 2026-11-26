"""Read-only activity/slot audit helpers for fixed-size EVTX files.

The default :class:`Evtx.Evtx.records` and :class:`Evtx.FileHeader.chunks`
iteration semantics intentionally remain unchanged.  The helpers in this
module add a separate audit view that keeps header declarations, physical slot
geometry, chunk record ranges, and carved residual ranges distinct.
"""

from __future__ import annotations

import binascii
import json
import mmap
import struct
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .Evtx import ChunkHeader, FileHeader, Record

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
RECORD_DATA_OFFSET = 0x200
RECORD_MAGIC = 0x00002A2A
RECORD_MAGIC_BYTES = struct.pack("<I", RECORD_MAGIC)
MAX_RECORD_SIZE = 0x10000
QWORD_MASK = (1 << 64) - 1

ACTIVE = "active"
RESIDUAL = "residual"
INDETERMINATE = "indeterminate"
EMPTY = "empty"

CHUNK_MAGIC = b"ElfChnk\x00"
FILE_MAGIC = b"ElfFile\x00"


@dataclass
class Conflict:
    """A verifiable disagreement encountered while auditing a file."""

    code: str
    message: str
    offset: Optional[int] = None
    field_name: Optional[str] = None
    expected: Any = None
    actual: Any = None
    stored: Any = None
    calculated: Any = None
    values: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "offset": self.offset,
            "offset_hex": _hex(self.offset),
            "field": self.field_name,
            "expected": self.expected,
            "actual": self.actual,
            "stored": self.stored,
            "calculated": self.calculated,
            "stored_hex": _hex(self.stored),
            "calculated_hex": _hex(self.calculated),
            "values": self.values,
        }


@dataclass
class RecordAssessment:
    offset: int
    classification: str
    origin: str
    countable: bool
    slot: Optional[int] = None
    chunk_relative_offset: Optional[int] = None
    length: Optional[int] = None
    record_number: Optional[int] = None
    magic: Optional[int] = None
    structurally_complete: bool = False
    issues: List[Conflict] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    record: Any = field(default=None, repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "offset_hex": _hex(self.offset),
            "classification": self.classification,
            "origin": self.origin,
            "countable": self.countable,
            "slot": self.slot,
            "chunk_relative_offset": self.chunk_relative_offset,
            "chunk_relative_offset_hex": _hex(self.chunk_relative_offset),
            "length": self.length,
            "record_number": self.record_number,
            "magic": _hex(self.magic) if self.magic is not None else None,
            "structurally_complete": self.structurally_complete,
            "issues": [issue.to_dict() for issue in self.issues],
            "reasons": list(self.reasons),
        }


@dataclass
class SlotAssessment:
    offset: int
    physical_slot: Optional[int] = None
    exists: bool = True
    full_slot: bool = True
    available_length: Optional[int] = CHUNK_SIZE
    size: int = CHUNK_SIZE
    size: int = CHUNK_SIZE
    classification: str = INDETERMINATE
    status: str = "unknown"
    countable: bool = False
    declared_role: Optional[str] = None
    active_order: Optional[int] = None
    magic: Optional[str] = None
    magic_ok: Optional[bool] = None
    integrity_verified: bool = False
    checks: Dict[str, Any] = field(default_factory=dict)
    field_offsets: Dict[str, int] = field(default_factory=dict)
    declared_ranges: Dict[str, Any] = field(default_factory=dict)
    observed_ranges: Dict[str, Any] = field(default_factory=dict)
    records: List[RecordAssessment] = field(default_factory=list)
    conflicts: List[Conflict] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    chunk: Any = field(default=None, repr=False, compare=False)

    def records_with_classification(self, classification: str) -> List[RecordAssessment]:
        return [record for record in self.records if record.classification == classification]

    @property
    def active_records(self) -> List[RecordAssessment]:
        return self.records_with_classification(ACTIVE)

    @property
    def residual_records(self) -> List[RecordAssessment]:
        return self.records_with_classification(RESIDUAL)

    @property
    def indeterminate_records(self) -> List[RecordAssessment]:
        return self.records_with_classification(INDETERMINATE)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "physical_slot": self.physical_slot,
            "offset": self.offset,
            "offset_hex": _hex(self.offset),
            "exists": self.exists,
            "full_slot": self.full_slot,
            "available_length": self.available_length,
            "classification": self.classification,
            "status": self.status,
            "countable": self.countable,
            "declared_role": self.declared_role,
            "active_order": self.active_order,
            "magic": self.magic,
            "magic_ok": self.magic_ok,
            "integrity_verified": self.integrity_verified,
            "checks": self.checks,
            "field_offsets": {key: _hex(value) for key, value in self.field_offsets.items()},
            "declared_ranges": self.declared_ranges,
            "observed_ranges": self.observed_ranges,
            "record_counts": {
                "all": len(self.records),
                ACTIVE: len(self.active_records),
                RESIDUAL: len(self.residual_records),
                INDETERMINATE: len(self.indeterminate_records),
            },
            "records": [record.to_dict() for record in self.records],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "reasons": list(self.reasons),
        }


@dataclass
class HeaderAssessment:
    offset: int
    file_length: int
    values: Dict[str, Any]
    checks: Dict[str, Any]
    conflicts: List[Conflict]
    trusted: bool
    ring_size: Optional[int]
    first_chunk_offset: int
    physical_slot_count: int
    partial_tail_length: int
    claimed_physical_order: List[int] = field(default_factory=list)
    active_physical_order: List[int] = field(default_factory=list)
    active_logical_order: Optional[List[int]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "offset_hex": _hex(self.offset),
            "file_length": self.file_length,
            "values": self.values,
            "checks": self.checks,
            "trusted": self.trusted,
            "ring_size": self.ring_size,
            "first_chunk_offset": self.first_chunk_offset,
            "physical_slot_count": self.physical_slot_count,
            "partial_tail_length": self.partial_tail_length,
            "claimed_physical_order": self.claimed_physical_order,
            "active_physical_order": self.active_physical_order,
            "active_logical_order": self.active_logical_order,
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
        }


@dataclass
class ActivityReport:
    path: Optional[str]
    header: HeaderAssessment
    slots: List[SlotAssessment]
    active_physical_order: List[int]
    claimed_physical_order: List[int]
    active_logical_order: Optional[List[int]]
    chunk_size: int = CHUNK_SIZE
    read_only: bool = True
    _buf: Any = field(default=None, repr=False, compare=False)
    _slots_by_number: Dict[int, SlotAssessment] = field(default_factory=dict, repr=False, compare=False)

    def slot_by_number(self, slot_number: int) -> Optional[SlotAssessment]:
        return self._slots_by_number.get(slot_number)

    @property
    def conflicts(self) -> List[Conflict]:
        conflicts = list(self.header.conflicts)
        for slot in self.slots:
            conflicts.extend(slot.conflicts)
        return conflicts

    def active_chunks(self, countable_only: bool = True) -> Iterator[ChunkHeader]:
        order = self.active_physical_order if countable_only else self.claimed_physical_order
        for slot_number in order:
            slot = self.slot_by_number(slot_number)
            if slot is None or slot.chunk is None:
                continue
            if countable_only and slot.classification != ACTIVE:
                continue
            yield slot.chunk

    def active_slot_reports(self, countable_only: bool = True) -> Iterator[SlotAssessment]:
        order = self.active_physical_order if countable_only else self.claimed_physical_order
        for slot_number in order:
            slot = self.slot_by_number(slot_number)
            if slot is None:
                continue
            if countable_only and slot.classification != ACTIVE:
                continue
            yield slot

    def active_slots(self, countable_only: bool = True) -> Iterator[SlotAssessment]:
        yield from self.active_slot_reports(countable_only=countable_only)

    def active_records(self, countable_only: bool = True) -> Iterator[Record]:
        for slot_number in self.active_physical_order:
            slot = self.slot_by_number(slot_number)
            if slot is None:
                continue
            if countable_only and (slot.classification != ACTIVE or not slot.countable):
                continue
            for assessed in slot.records:
                if countable_only and (not assessed.countable or assessed.classification != ACTIVE):
                    continue
                if assessed.record is not None:
                    yield assessed.record

    def conclusions(self) -> Dict[str, List[str]]:
        active: List[str] = []
        residual: List[str] = []
        indeterminate: List[str] = []

        for slot in self.slots:
            location = _slot_label(slot)
            if slot.classification == ACTIVE:
                active.append(f"{location}: {len(slot.active_records)} verified active record(s); {'; '.join(slot.reasons)}")
            elif slot.classification == RESIDUAL:
                residual.append(f"{location}: readable/non-active slot; {'; '.join(slot.reasons)}")
            elif slot.classification == EMPTY:
                residual.append(f"{location}: empty physical slot; no records")
            else:
                indeterminate.append(f"{location}: {'; '.join(slot.reasons)}")

            for summary in _record_group_summaries(slot.records):
                scoped = f"{location}: {summary}"
                if summary.startswith(f"{ACTIVE}/"):
                    active.append(scoped)
                elif summary.startswith(f"{RESIDUAL}/"):
                    residual.append(scoped + "; structurally readable residue, not joined to timeline")
                else:
                    indeterminate.append(scoped + "; readable candidate but activity cannot be concluded")

        for conflict in self.header.conflicts:
            indeterminate.append(f"header {conflict.code} at {_hex(conflict.offset)}: {conflict.message}")
        return {ACTIVE: active, RESIDUAL: residual, INDETERMINATE: indeterminate}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "read_only": self.read_only,
            "chunk_size": self.chunk_size,
            "active_physical_order": self.active_physical_order,
            "claimed_physical_order": self.claimed_physical_order,
            "active_logical_order": self.active_logical_order,
            "header": self.header.to_dict(),
            "slots": [slot.to_dict() for slot in self.slots],
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "conclusions": self.conclusions(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def format_text(self) -> str:
        return render_report(self)


def inspect_buffer(buf: Any, path: Optional[str] = None, header_offset: int = 0) -> ActivityReport:
    """Audit an EVTX-like buffer without modifying it."""
    file_length = len(buf)
    fh = FileHeader(buf, header_offset)
    header_conflicts: List[Conflict] = []
    values = _read_header_values(fh, header_offset, header_conflicts)
    checks = _header_checks(buf, fh, header_offset, values, header_conflicts)

    header_size_value = values.get("header_chunk_size")
    geometry_ok = checks.get("header_chunk_size") is True
    if isinstance(header_size_value, int) and header_size_value > 0 and geometry_ok:
        first_chunk_offset = header_offset + header_size_value
    else:
        first_chunk_offset = header_offset + FILE_HEADER_SIZE
        if isinstance(header_size_value, int) and header_size_value != FILE_HEADER_SIZE:
            header_conflicts.append(
                Conflict(
                    "header_geometry_fallback",
                    "Declared header chunk offset is not the standard 0x1000; using reviewable standard offset",
                    offset=header_offset + _field_offset(fh, "header_chunk_size"),
                    field_name="header_chunk_size",
                    expected=FILE_HEADER_SIZE,
                    actual=header_size_value,
                    values={"fallback_first_chunk_offset": first_chunk_offset},
                )
            )

    body_length = max(0, file_length - first_chunk_offset)
    physical_slot_count = body_length // CHUNK_SIZE if first_chunk_offset <= file_length else 0
    partial_tail_length = body_length % CHUNK_SIZE if first_chunk_offset <= file_length else 0

    ring_size = values.get("chunk_count")
    if not isinstance(ring_size, int) or ring_size <= 0:
        ring_size = None
    claimed_order, logical_order, order_conflict = _resolve_order(
        values.get("oldest_chunk"), values.get("current_chunk_number"), ring_size
    )
    if order_conflict is not None:
        header_conflicts.append(order_conflict)

    trusted = bool(checks.get("magic") and checks.get("version") and checks.get("header_chunk_size") and checks.get("checksum"))
    active_order = list(claimed_order) if trusted and order_conflict is None and claimed_order is not None else []
    active_order_set = set(active_order)
    claimed_order_set = set(claimed_order or [])

    header = HeaderAssessment(
        offset=header_offset,
        file_length=file_length,
        values=values,
        checks=checks,
        conflicts=header_conflicts,
        trusted=trusted,
        ring_size=ring_size,
        first_chunk_offset=first_chunk_offset,
        physical_slot_count=physical_slot_count,
        partial_tail_length=partial_tail_length,
        claimed_physical_order=list(claimed_order or []),
        active_physical_order=active_order,
        active_logical_order=logical_order,
    )

    slots: List[SlotAssessment] = []
    slots_by_number: Dict[int, SlotAssessment] = {}

    for slot_number in range(physical_slot_count):
        offset = first_chunk_offset + slot_number * CHUNK_SIZE
        slot = _assess_full_slot(
            buf=buf,
            offset=offset,
            slot_number=slot_number,
            header=header,
            trusted=trusted,
            ring_size=ring_size,
            claimed_order_set=claimed_order_set,
            active_order_set=active_order_set,
        )
        slots.append(slot)
        slots_by_number[slot_number] = slot

    if partial_tail_length:
        tail = _assess_partial_slot(
            buf,
            first_chunk_offset + physical_slot_count * CHUNK_SIZE,
            partial_tail_length,
            physical_slot_count,
        )
        slots.append(tail)
        slots_by_number[physical_slot_count] = tail

    if isinstance(ring_size, int) and ring_size > physical_slot_count:
        header.conflicts.append(
            Conflict(
                "declared_chunk_count_has_missing_physical_slots",
                "Header declares more chunk slots than are fully present in the file",
                offset=header_offset + _field_offset(fh, "chunk_count"),
                field_name="chunk_count",
                stored=ring_size,
                actual=physical_slot_count,
                values={
                    "missing_slot_count": ring_size - physical_slot_count,
                    "first_expected_missing_offset": first_chunk_offset + physical_slot_count * CHUNK_SIZE,
                    "next_declared_slot_offset": first_chunk_offset + physical_slot_count * CHUNK_SIZE,
                },
            )
        )

    for order_index, slot_number in enumerate(active_order):
        if slot_number < physical_slot_count or slot_number in slots_by_number:
            continue
        offset = first_chunk_offset + slot_number * CHUNK_SIZE
        missing = SlotAssessment(
            physical_slot=slot_number,
            offset=offset,
            exists=False,
            full_slot=False,
            available_length=max(0, file_length - offset),
            classification=INDETERMINATE,
            status="missing_declared_active_slot",
            countable=False,
            declared_role=_role_for_order_index(order_index, len(active_order)),
            active_order=order_index,
            reasons=["header activity order requires this slot, but a full chunk is absent from the file"],
        )
        missing.conflicts.append(
            Conflict(
                "declared_active_slot_missing",
                "A slot in the header-declared active order is not physically present",
                offset=offset,
                field_name="current_chunk_number/oldest_chunk",
                expected=CHUNK_SIZE,
                actual=missing.available_length,
                values={"physical_slot": slot_number, "active_order": order_index},
            )
        )
        slots.append(missing)
        slots_by_number[slot_number] = missing

    slots.sort(key=lambda slot: slot.offset)
    _add_range_conflicts(header, slots_by_number, fh, active_order)
    _reclassify_slots_with_identity_conflicts(slots)

    report = ActivityReport(
        path=str(path) if path is not None else None,
        header=header,
        slots=slots,
        active_physical_order=active_order,
        claimed_physical_order=list(claimed_order or []),
        active_logical_order=logical_order,
        _buf=buf,
        _slots_by_number=slots_by_number,
    )
    return report


def inspect_path(path: str | Path) -> ActivityReport:
    """Read a path into memory and return a read-only activity report."""
    file_path = Path(path)
    data = file_path.read_bytes()
    return inspect_buffer(data, path=file_path)


@contextmanager
def audit_path(path: str | Path) -> Iterator[ActivityReport]:
    """Memory-map a file read-only and expose its activity report."""
    file_path = str(path)
    with open(file_path, "rb") as handle:
        mapping = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            yield inspect_buffer(mapping, path=file_path)
        finally:
            mapping.close()


def _read_header_values(fh: FileHeader, offset: int, conflicts: List[Conflict]) -> Dict[str, Any]:
    names = [
        "oldest_chunk",
        "current_chunk_number",
        "next_record_number",
        "header_size",
        "minor_version",
        "major_version",
        "header_chunk_size",
        "chunk_count",
        "flags",
        "checksum",
    ]
    values: Dict[str, Any] = {}
    for name in names:
        value, error = _safe_call(getattr(fh, name))
        values[name] = value
        if error is not None:
            field_offset = _field_offset(fh, name)
            conflicts.append(
                Conflict(
                    "header_field_unreadable",
                    f"FileHeader field {name} could not be read",
                    offset=offset + field_offset if field_offset is not None else offset,
                    field_name=name,
                    actual=error,
                )
            )
    return values


def _header_checks(
    buf: Any, fh: FileHeader, offset: int, values: Dict[str, Any], conflicts: List[Conflict]
) -> Dict[str, Any]:
    magic_bytes = _read_bytes(buf, offset, 8)
    magic_ok = magic_bytes == FILE_MAGIC
    magic = _magic_repr(magic_bytes)
    if not magic_ok:
        conflicts.append(
            Conflict(
                "file_magic_mismatch",
                "File header magic does not match ElfFile",
                offset=offset,
                field_name="magic",
                expected=repr(FILE_MAGIC),
                actual=magic,
                values={"actual_hex": magic_bytes.hex()},
            )
        )

    major = values.get("major_version")
    minor = values.get("minor_version")
    version_ok = major == 3 and minor == 1
    if not version_ok:
        conflicts.append(
            Conflict(
                "file_version_mismatch",
                "Unsupported EVTX header version; expected 3.1",
                offset=offset + 0x24,
                field_name="major_version/minor_version",
                expected={"major": 3, "minor": 1},
                actual={"major": major, "minor": minor},
            )
        )

    header_chunk_size = values.get("header_chunk_size")
    geometry_ok = header_chunk_size == FILE_HEADER_SIZE
    if not geometry_ok:
        field_offset = _field_offset(fh, "header_chunk_size")
        conflicts.append(
            Conflict(
                "file_header_chunk_size_mismatch",
                "File header block size does not match the standard EVTX file-header size",
                offset=offset + field_offset if field_offset is not None else offset + 0x28,
                field_name="header_chunk_size",
                expected=FILE_HEADER_SIZE,
                actual=header_chunk_size,
            )
        )

    stored_checksum = values.get("checksum")
    calculated_checksum, error = _safe_call(fh.calculate_checksum)
    checksum_ok = error is None and stored_checksum == calculated_checksum
    if not checksum_ok:
        field_offset = _field_offset(fh, "checksum")
        conflicts.append(
            Conflict(
                "file_header_checksum_mismatch",
                "File header CRC32 does not match its stored value",
                offset=offset + field_offset if field_offset is not None else offset + 0x7C,
                field_name="checksum",
                stored=stored_checksum,
                calculated=calculated_checksum,
                expected=stored_checksum,
                actual=calculated_checksum,
                values={"error": error},
            )
        )

    flags = values.get("flags") or 0
    return {
        "magic": magic_ok,
        "version": version_ok,
        "header_chunk_size": geometry_ok,
        "checksum": checksum_ok,
        "dirty": bool(flags & 0x1),
        "full": bool(flags & 0x2),
        "magic_value": magic,
        "stored_checksum_hex": _hex(stored_checksum),
        "calculated_checksum_hex": _hex(calculated_checksum),
    }


def _assess_full_slot(
    buf: Any,
    offset: int,
    slot_number: int,
    header: HeaderAssessment,
    trusted: bool,
    ring_size: Optional[int],
    claimed_order_set: set,
    active_order_set: set,
) -> SlotAssessment:
    chunk = ChunkHeader(buf, offset)
    raw_magic = _read_bytes(buf, offset, 8)
    magic_ok = raw_magic == CHUNK_MAGIC
    magic_text = _magic_repr(raw_magic)
    empty = not any(raw_magic)

    field_names = [
        "file_first_record_number",
        "file_last_record_number",
        "log_first_record_number",
        "log_last_record_number",
        "header_size",
        "last_record_offset",
        "next_record_offset",
        "data_checksum",
        "header_checksum",
    ]
    values: Dict[str, Any] = {}
    field_offsets: Dict[str, int] = {}
    for name in field_names:
        field_offsets[name] = offset + (_field_offset(chunk, name) or 0)
        value, _ = _safe_call(getattr(chunk, name))
        values[name] = value

    conflicts: List[Conflict] = []
    if not magic_ok and not empty:
        conflicts.append(
            Conflict(
                "chunk_magic_mismatch",
                "Physical chunk identity magic is not ElfChnk",
                offset=offset,
                field_name="magic",
                expected=repr(CHUNK_MAGIC),
                actual=magic_text,
                values={"actual_hex": raw_magic.hex()},
            )
        )
    if empty and slot_number in active_order_set:
        conflicts.append(
            Conflict(
                "declared_active_slot_empty",
                "Header active order references a zeroed slot without ElfChnk identity",
                offset=offset,
                field_name="magic",
                expected=repr(CHUNK_MAGIC),
                actual="<zero>",
            )
        )

    next_offset = values.get("next_record_offset")
    next_offset_valid = isinstance(next_offset, int) and RECORD_DATA_OFFSET <= next_offset <= CHUNK_SIZE
    if magic_ok and not next_offset_valid:
        conflicts.append(
            Conflict(
                "chunk_next_record_offset_invalid",
                "Chunk next_record_offset is outside the record area or chunk size",
                offset=field_offsets["next_record_offset"],
                field_name="next_record_offset",
                expected=[RECORD_DATA_OFFSET, CHUNK_SIZE],
                actual=next_offset,
            )
        )

    calculated_header_checksum, header_checksum_error = _safe_call(chunk.calculate_header_checksum)
    stored_header_checksum = values.get("header_checksum")
    header_checksum_ok = magic_ok and stored_header_checksum == calculated_header_checksum
    if magic_ok and not header_checksum_ok:
        conflicts.append(
            Conflict(
                "chunk_header_checksum_mismatch",
                "Chunk header CRC32 does not match its stored value",
                offset=field_offsets["header_checksum"],
                field_name="header_checksum",
                stored=stored_header_checksum,
                calculated=calculated_header_checksum,
                expected=stored_header_checksum,
                actual=calculated_header_checksum,
                values={"error": header_checksum_error},
            )
        )

    calculated_data_checksum = None
    data_checksum_error = None
    if next_offset_valid:
        calculated_data_checksum, data_checksum_error = _safe_call(chunk.calculate_data_checksum)
    stored_data_checksum = values.get("data_checksum")
    data_checksum_ok = bool(
        next_offset_valid and data_checksum_error is None and stored_data_checksum == calculated_data_checksum
    )
    if magic_ok and next_offset_valid and not data_checksum_ok:
        conflicts.append(
            Conflict(
                "chunk_data_checksum_mismatch",
                "Chunk data CRC32 does not match its stored value",
                offset=field_offsets["data_checksum"],
                field_name="data_checksum",
                stored=stored_data_checksum,
                calculated=calculated_data_checksum,
                expected=stored_data_checksum,
                actual=calculated_data_checksum,
                values={"error": data_checksum_error},
            )
        )

    integrity_verified = bool(magic_ok and header_checksum_ok and data_checksum_ok and next_offset_valid)
    role = None
    active_order_index = None
    if slot_number in header.active_physical_order:
        active_order_index = header.active_physical_order.index(slot_number)
        role = _role_for_order_index(active_order_index, len(header.active_physical_order))
    elif slot_number in header.claimed_physical_order:
        active_order_index = header.claimed_physical_order.index(slot_number)
        role = "claimed_" + _role_for_order_index(active_order_index, len(header.claimed_physical_order))
    elif isinstance(ring_size, int) and slot_number >= ring_size:
        role = "outside_declared_chunk_count"
    else:
        role = "inactive_generation"

    reasons: List[str] = []
    if not trusted:
        classification = EMPTY if empty else INDETERMINATE
        status = "empty_slot" if empty else "header_untrusted_identity_unverified"
        reasons.append("file header checksum/identity is not trusted, so header activity order cannot certify this slot")
    elif slot_number in active_order_set:
        if integrity_verified:
            classification = ACTIVE
            status = "active_verified"
            reasons.append("slot is in header-declared active order and chunk identity/checksums verify")
        else:
            classification = INDETERMINATE
            status = "declared_active_slot_conflicted"
            reasons.append("slot is required by active order, but chunk identity, range pointer, or checksum conflicts")
    elif magic_ok:
        classification = RESIDUAL
        status = "inactive_generation_readable"
        reasons.append("chunk parses, but this physical slot is outside the header-declared active order")
        if not integrity_verified:
            reasons.append("chunk integrity checks fail, so its contents are not trustworthy but still non-active")
    elif empty:
        classification = EMPTY
        status = "empty_slot"
        reasons.append("physical slot contains zero bytes and no chunk identity")
    else:
        classification = INDETERMINATE
        status = "unrecognized_chunk_identity"
        reasons.append("slot is outside active order but has non-zero bytes without a valid chunk identity")

    slot = SlotAssessment(
        physical_slot=slot_number,
        offset=offset,
        exists=True,
        full_slot=True,
        available_length=CHUNK_SIZE,
        classification=classification,
        status=status,
        countable=classification == ACTIVE and integrity_verified,
        declared_role=role,
        active_order=active_order_index,
        magic=magic_text,
        magic_ok=magic_ok,
        integrity_verified=integrity_verified,
        checks={
            "header_checksum_ok": header_checksum_ok,
            "data_checksum_ok": data_checksum_ok,
            "next_record_offset_valid": next_offset_valid,
            "stored_header_checksum": _unsigned_hex(stored_header_checksum),
            "calculated_header_checksum": _unsigned_hex(calculated_header_checksum),
            "stored_data_checksum": _unsigned_hex(stored_data_checksum),
            "calculated_data_checksum": _unsigned_hex(calculated_data_checksum),
        },
        field_offsets=field_offsets,
        declared_ranges={
            "file_first_record_number": values.get("file_first_record_number"),
            "file_last_record_number": values.get("file_last_record_number"),
            "log_first_record_number": values.get("log_first_record_number"),
            "log_last_record_number": values.get("log_last_record_number"),
            "last_record_offset": values.get("last_record_offset"),
            "next_record_offset": next_offset,
            "header_size": values.get("header_size"),
        },
        conflicts=conflicts,
        reasons=reasons,
        chunk=chunk,
    )

    _assess_slot_records(buf, slot, chunk, next_offset, trusted, header)
    return slot


def _assess_partial_slot(buf: Any, offset: int, length: int, slot_number: int) -> SlotAssessment:
    raw_magic = _read_bytes(buf, offset, min(8, length))
    magic_ok = raw_magic == CHUNK_MAGIC
    conflicts = [
        Conflict(
            "partial_physical_slot",
            "File ends before a complete 0x10000-byte chunk slot",
            offset=offset,
            field_name="chunk",
            expected=CHUNK_SIZE,
            actual=length,
            values={"file_end_offset": offset + length},
        )
    ]
    if length >= 8 and not magic_ok and any(raw_magic):
        conflicts.append(
            Conflict(
                "partial_chunk_identity_mismatch",
                "Short trailing region does not start with ElfChnk magic",
                offset=offset,
                field_name="magic",
                expected=repr(CHUNK_MAGIC),
                actual=_magic_repr(raw_magic),
                values={"actual_hex": raw_magic.hex()},
            )
        )

    slot = SlotAssessment(
        physical_slot=slot_number,
        offset=offset,
        exists=True,
        full_slot=False,
        available_length=length,
        classification=INDETERMINATE,
        status="short_tail",
        countable=False,
        declared_role="partial_tail",
        magic=_magic_repr(raw_magic),
        magic_ok=magic_ok if length >= 8 else None,
        reasons=["trailing bytes are shorter than one chunk, so chunk checksum and full identity cannot be verified"],
        conflicts=conflicts,
        chunk=ChunkHeader(buf, offset) if length >= 8 else None,
    )

    records = _carve_region(
        buf=buf,
        start=offset + RECORD_DATA_OFFSET,
        end=offset + length,
        chunk_offset=offset,
        slot_number=slot_number,
        origin="partial_tail_carve",
        classification=INDETERMINATE,
        allow_truncated=True,
        chunk=slot.chunk,
    )
    slot.records.extend(records)
    if records:
        slot.reasons.append("structurally readable record(s) exist in the short tail, but their active generation cannot be proven")
    return slot


def _assess_slot_records(
    buf: Any,
    slot: SlotAssessment,
    chunk: ChunkHeader,
    next_offset: Optional[int],
    header: HeaderAssessment,
    trusted: bool,
) -> None:
    active_ranges: List[Tuple[int, int]] = []
    base_classification = slot.classification if slot.classification in (ACTIVE, RESIDUAL) else INDETERMINATE

    try:
        default_records = list(chunk.records())
    except Exception as exc:  # parser exceptions must not prevent a read-only report
        slot.conflicts.append(
            Conflict(
                "chunk_record_iteration_failed",
                "Default ChunkHeader.records() entry raised while reading chain",
                offset=slot.offset + RECORD_DATA_OFFSET,
                field_name="records",
                actual=f"{type(exc).__name__}: {exc}",
            )
        )
        default_records = []

    for record in default_records:
        info = _record_info_from_object(
            record,
            slot_number=slot.physical_slot,
            origin="default_records",
            classification=base_classification,
        )
        slot.records.append(info)
        if info.length is not None:
            active_ranges.append((info.offset, info.offset + info.length))

    if slot.classification == RESIDUAL:
        carve_classification = RESIDUAL
        carve_reason = "physical slot is outside active order"
    elif trusted and slot.magic_ok and slot.checks.get("header_checksum_ok") and next_offset is not None:
        carve_classification = RESIDUAL
        carve_reason = "record lies outside the trusted next_record_offset boundary"
    else:
        carve_classification = INDETERMINATE
        carve_reason = "chunk header boundary is not trustworthy"

    carved = _carve_region(
        buf=buf,
        start=slot.offset + RECORD_DATA_OFFSET,
        end=slot.offset + CHUNK_SIZE,
        chunk_offset=slot.offset,
        slot_number=slot.physical_slot,
        origin="slack_or_unindexed_carve",
        classification=carve_classification,
        allow_truncated=False,
        overlap_ranges=active_ranges,
        chunk=chunk,
    )
    for info in carved:
        info.reasons.append(carve_reason)
        relative = info.chunk_relative_offset
        if carve_classification == RESIDUAL and isinstance(next_offset, int):
            if relative is not None and relative >= next_offset:
                info.origin = "slack_carve"
            else:
                info.origin = "unindexed_carve"
        slot.records.append(info)

    chain_records = [record for record in slot.records if record.origin == "default_records"]
    numbers = [record.record_number for record in chain_records if record.record_number is not None]
    if numbers:
        slot.observed_ranges["record_count"] = len(numbers)
        slot.observed_ranges["first_record_number"] = numbers[0]
        slot.observed_ranges["last_record_number"] = numbers[-1]
        slot.observed_ranges["min_record_number"] = min(numbers)
        slot.observed_ranges["max_record_number"] = max(numbers)

    if chain_records and all(record.length for record in chain_records):
        last = chain_records[-1]
        if last.length is not None:
            slot.observed_ranges["chain_end_offset"] = last.offset + last.length
            slot.observed_ranges["chain_end_relative_offset"] = (
                last.offset - slot.offset + last.length
            )


def _record_info_from_object(
    record: Record,
    slot_number: Optional[int],
    origin: str,
    classification: str,
) -> RecordAssessment:
    offset = record.offset()
    length, _ = _safe_call(record.size)
    number, _ = _safe_call(record.record_num)
    magic, _ = _safe_call(record.magic)
    size2, _ = _safe_call(record.size2)
    issues: List[Conflict] = []
    complete = True

    if magic != RECORD_MAGIC:
        complete = False
        issues.append(
            Conflict(
                "record_magic_mismatch",
                "Structural record magic is not 0x2a2a",
                offset=offset,
                field_name="magic",
                expected=_hex(RECORD_MAGIC),
                actual=_hex(magic),
            )
        )
    if not isinstance(length, int) or length <= 0 or length > MAX_RECORD_SIZE:
        complete = False
        issues.append(
            Conflict(
                "record_size_invalid",
                "Record size is missing or outside the chunk record limit",
                offset=offset + 4,
                field_name="size",
                actual=length,
            )
        )
    if not isinstance(size2, int) or size2 != length:
        complete = False
        issues.append(
            Conflict(
                "record_size_sentinel_conflict",
                "Record leading size and trailing size do not match",
                offset=offset + (length - 4 if isinstance(length, int) and length >= 4 else 4),
                field_name="size2",
                expected=length,
                actual=size2,
            )
        )

    effective_classification = classification
    reasons: List[str] = []
    if issues and classification == ACTIVE:
        effective_classification = INDETERMINATE
        reasons.append("record is in an active slot but has a structural identity conflict")
    elif classification == ACTIVE:
        reasons.append("record structure and size sentinel verify")

    return RecordAssessment(
        offset=offset,
        classification=effective_classification,
        origin=origin,
        countable=effective_classification == ACTIVE and not issues,
        slot=slot_number,
        chunk_relative_offset=offset - (record._chunk._offset if record._chunk is not None else 0) or None,
        length=length if isinstance(length, int) else None,
        record_number=number if isinstance(number, int) else None,
        magic=magic if isinstance(magic, int) else None,
        structurally_complete=complete and not issues,
        issues=issues,
        reasons=reasons,
        record=record,
    )


def _carve_region(
    buf: Any,
    start: int,
    end: int,
    chunk_offset: int,
    slot_number: Optional[int],
    origin: str,
    classification: str,
    allow_truncated: bool,
    overlap_ranges: Optional[List[Tuple[int, int]]] = None,
    chunk: Optional[ChunkHeader] = None,
) -> List[RecordAssessment]:
    if start >= end:
        return []
    overlap_ranges = overlap_ranges or []
    found: List[RecordAssessment] = []
    position = start

    while True:
        position = buf.find(RECORD_MAGIC_BYTES, position, end)
        if position < 0:
            break

        if _overlaps_known_record(position, overlap_ranges):
            position += 4
            continue

        if position + 8 > end:
            if allow_truncated:
                found.append(
                    RecordAssessment(
                        offset=position,
                        classification=INDETERMINATE,
                        origin=origin,
                        countable=False,
                        slot=slot_number,
                        chunk_relative_offset=position - chunk_offset,
                        magic=RECORD_MAGIC,
                        structurally_complete=False,
                        reasons=["record magic is present but the size field is beyond file end"],
                        issues=[Conflict("truncated_record_header", "Record header is truncated by EOF", offset=position)],
                    )
                )
            break

        size = struct.unpack_from("<I", buf, position + 4)[0]
        if size < 24 or size > MAX_RECORD_SIZE:
            position += 4
            continue

        record_end = position + size
        if record_end > end:
            if allow_truncated:
                found.append(
                    RecordAssessment(
                        offset=position,
                        classification=INDETERMINATE,
                        origin=origin,
                        countable=False,
                        slot=slot_number,
                        chunk_relative_offset=position - chunk_offset,
                        length=size,
                        magic=RECORD_MAGIC,
                        structurally_complete=False,
                        reasons=["record header declares bytes that extend beyond the available region"],
                        issues=[
                            Conflict(
                                "truncated_record_data",
                                "Record extends beyond the available chunk/tail region",
                                offset=position + 4,
                                field_name="size",
                                expected=f"region end {end}",
                                actual=record_end,
                                values={"available_end": end},
                            )
                        ],
                    )
                )
            position += 4
            continue

        trailing_size = struct.unpack_from("<I", buf, record_end - 4)[0]
        if trailing_size != size:
            position += 4
            continue

        try:
            record = Record(buf, position, chunk)
            magic = record.magic()
            record_number = record.record_num()
            record_size2 = record.size2()
        except Exception:
            position += 4
            continue

        if magic != RECORD_MAGIC or record_size2 != size:
            position += 4
            continue

        found.append(
            RecordAssessment(
                offset=position,
                classification=classification,
                origin=origin,
                countable=False,
                slot=slot_number,
                chunk_relative_offset=position - chunk_offset,
                length=size,
                record_number=record_number,
                magic=magic,
                structurally_complete=True,
                reasons=["record magic, size, and trailing size sentinel are structurally complete"],
                record=record,
            )
        )
        position = record_end

    return found


def _add_range_conflicts(
    header: HeaderAssessment,
    slots_by_number: Dict[int, SlotAssessment],
    fh: FileHeader,
    active_order: List[int],
) -> None:
    for slot_number, slot in slots_by_number.items():
        if slot.chunk is None or not slot.declared_ranges:
            continue
        first_declared = slot.declared_ranges.get("log_first_record_number")
        last_declared = slot.declared_ranges.get("log_last_record_number")
        observed_first = slot.observed_ranges.get("first_record_number")
        observed_last = slot.observed_ranges.get("last_record_number")

        if observed_first is not None and first_declared != observed_first:
            slot.conflicts.append(
                Conflict(
                    "chunk_first_record_identity_conflict",
                    "Chunk header first log record number conflicts with the first parsed record",
                    offset=slot.field_offsets.get("log_first_record_number"),
                    field_name="log_first_record_number",
                    stored=first_declared,
                    calculated=observed_first,
                    expected=first_declared,
                    actual=observed_first,
                )
            )
        if observed_last is not None and last_declared != observed_last:
            slot.conflicts.append(
                Conflict(
                    "chunk_last_record_identity_conflict",
                    "Chunk header last log record number conflicts with the last parsed record",
                    offset=slot.field_offsets.get("log_last_record_number"),
                    field_name="log_last_record_number",
                    stored=last_declared,
                    calculated=observed_last,
                    expected=last_declared,
                    actual=observed_last,
                )
            )

        declared_next = slot.declared_ranges.get("next_record_offset")
        observed_end = slot.observed_ranges.get("chain_end_relative_offset")
        if isinstance(declared_next, int) and observed_end is not None and declared_next != observed_end:
            slot.conflicts.append(
                Conflict(
                    "chunk_record_chain_end_conflict",
                    "Walked default record chain ends at a different offset than next_record_offset",
                    offset=slot.field_offsets.get("next_record_offset"),
                    field_name="next_record_offset",
                    stored=declared_next,
                    calculated=observed_end,
                    expected=declared_next,
                    actual=observed_end,
                )
            )

    for left_number, right_number in zip(active_order, active_order[1:]):
        left = slots_by_number.get(left_number)
        right = slots_by_number.get(right_number)
        if left is None or right is None or left.chunk is None or right.chunk is None:
            continue
        left_last = left.declared_ranges.get("log_last_record_number")
        right_first = right.declared_ranges.get("log_first_record_number")
        if isinstance(left_last, int) and isinstance(right_first, int) and right_first != left_last + 1:
            conflict = Conflict(
                "active_chunk_record_range_discontinuity",
                "Adjacent chunks in active order do not have contiguous log record ranges",
                offset=right.field_offsets.get("log_first_record_number"),
                field_name="log_first_record_number",
                expected=left_last + 1,
                actual=right_first,
                values={"left_slot": left_number, "left_last": left_last, "right_slot": right_number},
            )
            right.conflicts.append(conflict)

    current_number = header.values.get("current_chunk_number")
    current_slot_number = header.active_physical_order[-1] if header.active_physical_order else None
    current_slot = slots_by_number.get(current_slot_number) if current_slot_number is not None else None
    if current_slot is not None:
        observed_last = current_slot.observed_ranges.get("last_record_number")
        next_record = header.values.get("next_record_number")
        if isinstance(observed_last, int) and isinstance(next_record, int) and next_record != observed_last + 1:
            header.conflicts.append(
                Conflict(
                    "header_next_record_conflict",
                    "File header next_record_number does not follow the current chunk's parsed range; dirty headers may lag",
                    offset=header.offset + _field_offset(fh, "next_record_number"),
                    field_name="next_record_number",
                    stored=next_record,
                    calculated=observed_last + 1,
                    expected=next_record,
                    actual=observed_last + 1,
                    values={"current_physical_slot": current_slot_number},
                )
            )


def _reclassify_slots_with_identity_conflicts(slots: List[SlotAssessment]) -> None:
    severe_codes = {
        "chunk_first_record_identity_conflict",
        "chunk_last_record_identity_conflict",
        "chunk_record_chain_end_conflict",
    }
    for slot in slots:
        if slot.classification != ACTIVE:
            continue
        severe = [conflict for conflict in slot.conflicts if conflict.code in severe_codes]
        if not severe:
            continue
        slot.classification = INDETERMINATE
        slot.countable = False
        slot.status = "active_slot_identity_conflict"
        slot.reasons.append("chunk record range/chain identity conflicts; slot remains declared active but cannot be counted")


def _resolve_order(
    oldest: Any, current: Any, ring_size: Optional[int]
) -> Tuple[Optional[List[int]], Optional[List[int]], Optional[Conflict]]:
    if not isinstance(oldest, int) or not isinstance(current, int) or not ring_size:
        return None, None, None

    first = oldest % ring_size
    last = current % ring_size
    order: List[int] = []
    cursor = first
    while True:
        order.append(cursor)
        if cursor == last:
            break
        cursor = (cursor + 1) % ring_size
        if len(order) > ring_size:
            break

    logical_order: Optional[List[int]] = None
    conflict: Optional[Conflict] = None
    if oldest <= current:
        span = current - oldest + 1
        if span <= ring_size:
            logical_order = list(range(oldest, current + 1))
        else:
            conflict = Conflict(
                "declared_active_span_exceeds_ring",
                "Header oldest/current logical sequence claims more active generations than declared chunk slots",
                offset=0x08,
                field_name="oldest_chunk/current_chunk_number",
                expected=f"span <= {ring_size}",
                actual=span,
                values={"oldest_chunk": oldest, "current_chunk_number": current, "ring_size": ring_size},
            )
    else:
        unsigned_delta = ((current - oldest) & QWORD_MASK) + 1
        if unsigned_delta <= ring_size:
            logical_order = [((oldest + index) & QWORD_MASK) for index in range(unsigned_delta)]

    return order, logical_order, conflict


def _role_for_order_index(index: int, length: int) -> str:
    if length == 1:
        return "current_and_oldest"
    if index == 0:
        return "oldest"
    if index == length - 1:
        return "current"
    return "active"


def _overlaps_known_record(position: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in ranges)


def _safe_call(callback: Any) -> Tuple[Any, Optional[str]]:
    try:
        return callback(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _read_bytes(buf: Any, offset: int, length: int) -> bytes:
    try:
        return bytes(buf[offset : offset + length])
    except Exception:
        return b""


def _field_offset(block: Any, name: str) -> Optional[int]:
    offset = getattr(block, "_off_" + name, None)
    return offset


def _hex(value: Any) -> Optional[str]:
    if not isinstance(value, int):
        return None if value is None else str(value)
    return hex(value)


def _unsigned_hex(value: Any) -> Any:
    return _hex(value)


def _magic_repr(raw: bytes) -> Optional[str]:
    if not raw:
        return None
    if raw == b"\x00" * len(raw):
        return "<zero>"
    return raw.split(b"\x00", 1)[0].decode("latin1", errors="replace")


def _slot_label(slot: SlotAssessment) -> str:
    slot_number = "?" if slot.physical_slot is None else slot.physical_slot
    return f"slot {slot_number} at {_hex(slot.offset)}"


def _record_label(record: RecordAssessment) -> str:
    number = f" record #{record.record_number}" if record.record_number is not None else ""
    return f"{_hex(record.offset)} ({record.origin}){number}"


def _record_group_summaries(records: List[RecordAssessment]) -> List[str]:
    groups: Dict[Tuple[str, str], List[RecordAssessment]] = {}
    for record in records:
        groups.setdefault((record.classification, record.origin), []).append(record)

    summaries: List[str] = []
    for (classification, origin), grouped in groups.items():
        numbers = [item.record_number for item in grouped if item.record_number is not None]
        first = grouped[0]
        last = grouped[-1]
        number_range = f"{numbers[0]}..{numbers[-1]}" if numbers else "unparsed-number"
        if numbers and (min(numbers) != numbers[0] or max(numbers) != numbers[-1]):
            number_range += f" (min={min(numbers)}, max={max(numbers)})"
        end_offset = last.offset + last.length if last.length is not None else None
        offset_range = f"{_hex(first.offset)}..{_hex(end_offset)}"
        summaries.append(
            f"{classification}/{origin}: count={len(grouped)} records={number_range} offsets={offset_range}"
        )
    return summaries


def render_report(report: ActivityReport) -> str:
    lines: List[str] = []
    header = report.header
    lines.append("EVTX activity/slot audit")
    if report.path:
        lines.append(f"Path: {report.path}")
    lines.append(f"File length: {header.file_length} bytes")
    lines.append(f"Read-only: {report.read_only}")
    lines.append("")

    lines.append("File header declarations:")
    lines.append(f"  offset              : {_hex(header.offset)}")
    lines.append(f"  magic/checks        : magic={header.checks.get('magic_value')} checksum={header.checks.get('stored_checksum_hex')} ({'pass' if header.checks.get('checksum') else 'FAIL'})")
    lines.append(f"  oldest_chunk        : {header.values.get('oldest_chunk')}")
    lines.append(f"  current_chunk_number: {header.values.get('current_chunk_number')}")
    lines.append(f"  next_record_number  : {header.values.get('next_record_number')}")
    lines.append(f"  chunk_count         : {header.ring_size}")
    lines.append(f"  flags               : {_hex(header.values.get('flags'))} dirty={header.checks.get('dirty')} full={header.checks.get('full')}")
    lines.append(f"  first chunk offset  : {_hex(header.first_chunk_offset)}")
    lines.append(f"  physical full slots : {header.physical_slot_count}")
    lines.append(f"  partial tail bytes  : {header.partial_tail_length}")
    lines.append(f"  claimed slot order  : {report.claimed_physical_order}")
    lines.append(f"  active slot order   : {report.active_physical_order}")
    if report.active_logical_order is not None:
        lines.append(f"  logical order       : {report.active_logical_order}")
    lines.append("")

    if report.header.conflicts:
        lines.append("Header conflicts:")
        for conflict in report.header.conflicts:
            lines.append(f"  - [{conflict.code}] {_hex(conflict.offset)} {conflict.message}")
            lines.append(f"      stored/expected={conflict.stored if conflict.stored is not None else conflict.expected}")
            lines.append(f"      calculated/actual={conflict.calculated if conflict.calculated is not None else conflict.actual}")
        lines.append("")

    lines.append("Physical slots and record ranges:")
    for slot in report.slots:
        label = _slot_label(slot)
        lines.append(f"  {label}: {slot.classification}/{slot.status} countable={slot.countable}")
        if slot.declared_role:
            lines.append(f"    role/order: {slot.declared_role} {slot.active_order if slot.active_order is not None else ''}")
        if not slot.full_slot:
            lines.append(f"    short slot: available={slot.available_length} required={CHUNK_SIZE}")
        if slot.magic is not None:
            lines.append(f"    identity: magic={slot.magic!r} magic_ok={slot.magic_ok} integrity_verified={slot.integrity_verified}")
        if slot.declared_ranges:
            lines.append(
                "    declared records: file={}..{} log={}..{} next_offset={}".format(
                    slot.declared_ranges.get("file_first_record_number"),
                    slot.declared_ranges.get("file_last_record_number"),
                    slot.declared_ranges.get("log_first_record_number"),
                    slot.declared_ranges.get("log_last_record_number"),
                    _hex(slot.declared_ranges.get("next_record_offset")),
                )
            )
        if slot.observed_ranges:
            lines.append(f"    observed chain : {slot.observed_ranges}")
        counts = {
            ACTIVE: len(slot.active_records),
            RESIDUAL: len(slot.residual_records),
            INDETERMINATE: len(slot.indeterminate_records),
        }
        lines.append(f"    record counts  : {counts}")
        for summary in _record_group_summaries(slot.records):
            lines.append(f"    record range   : {summary}")
        for conflict in slot.conflicts:
            lines.append(f"    conflict [{conflict.code}] {_hex(conflict.offset)}: {conflict.message}")
            lines.append(f"      stored/expected={conflict.stored if conflict.stored is not None else conflict.expected}")
            lines.append(f"      calculated/actual={conflict.calculated if conflict.calculated is not None else conflict.actual}")
        for reason in slot.reasons:
            lines.append(f"    reason: {reason}")
    lines.append("")

    conclusions = report.conclusions()
    lines.append("Conclusions:")
    lines.append("  Active current scope:")
    for item in conclusions[ACTIVE] or ["    none proven"]:
        lines.append(f"    - {item}")
    lines.append("  Readable residue (not joined to timeline):")
    for item in conclusions[RESIDUAL] or ["    none"]:
        lines.append(f"    - {item}")
    lines.append("  Indeterminate / conflicts:")
    for item in conclusions[INDETERMINATE] or ["    none"]:
        lines.append(f"    - {item}")
    return "\n".join(lines)


# Compatibility aliases for callers that prefer audit/slot terminology.
audit_buffer = inspect_buffer
audit_path_context = audit_path
inspect_file = inspect_path
ActivityAudit = ActivityReport
SlotReport = SlotAssessment
RecordRangeReport = RecordAssessment
