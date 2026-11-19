"""Data model for field attribution verdicts.

Every verdict is deliberately evidence-first: the classification is only
meaningful together with the relocation entries, symbol table indices and
raw bytes that justify it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VerdictKind(str, Enum):
    """The three answer classes required by the analysis workflow."""

    PROVEN = "proven"
    """A relocation whose target symbol is fully resolved in this object."""

    CANDIDATE = "candidate"
    """Relocation evidence exists but cannot be proven (special symbol,
    missing name, architecture without a validated relocation recipe)."""

    GAP = "gap"
    """No explaining relocation exists for the field."""


class RelocForm(str, Enum):
    """The two common ELF relocation representations."""

    REL = "REL"
    RELA = "RELA"


@dataclass(frozen=True)
class RelocEvidence:
    """One relocation entry that touches an audited field."""

    reloc_section: str
    entry_index: int
    form: RelocForm
    r_offset: int
    r_info_type: int
    r_info_type_name: str
    r_info_sym: int
    symbol_name: str | None
    symbol_section: str | None
    symbol_index: int
    addend: int | None
    addend_source: str
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["form"] = self.form.value
        return data


@dataclass(frozen=True)
class FieldVerdict:
    """Attribution result for one slot in the audited range."""

    field_index: int
    section_name: str
    section_offset: int
    width: int
    raw_bytes_hex: str
    raw_value: int
    kind: VerdictKind
    relocations: tuple[RelocEvidence, ...] = ()
    reasons: tuple[str, ...] = ()
    group_id: str | None = None
    overlaps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_index": self.field_index,
            "section_name": self.section_name,
            "section_offset": self.section_offset,
            "width": self.width,
            "raw_bytes_hex": self.raw_bytes_hex,
            "raw_value": self.raw_value,
            "kind": self.kind.value,
            "relocations": [r.to_dict() for r in self.relocations],
            "reasons": list(self.reasons),
            "group_id": self.group_id,
            "overlaps": list(self.overlaps),
        }


@dataclass(frozen=True)
class OverlapNote:
    """Source explanation for two named ranges sharing section bytes."""

    range_a: str
    range_b: str
    section_name: str
    first_shared_offset: int
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class AuditTable:
    """One named range supplied by the analyst."""

    range_name: str
    section_name: str
    field_width: int
    start_field: int
    field_count: int

    @property
    def byte_start(self) -> int:
        return self.start_field * self.field_width

    @property
    def byte_end(self) -> int:
        return (self.start_field + self.field_count) * self.field_width

    def to_dict(self) -> dict[str, Any]:
        return {
            "range_name": self.range_name,
            "section_name": self.section_name,
            "field_width": self.field_width,
            "start_field": self.start_field,
            "field_count": self.field_count,
            "byte_range": [self.byte_start, self.byte_end],
        }


@dataclass
class AuditResult:
    """All verdicts for one ELF member plus provenance metadata."""

    source: str
    member_name: str | None
    machine: str
    elf_class: int
    endianness: str
    arch_supported: bool
    tables: list[AuditTable]
    fields: list[FieldVerdict] = field(default_factory=list)
    overlaps: list[OverlapNote] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {kind.value: 0 for kind in VerdictKind}
        for verdict in self.fields:
            counts[verdict.kind.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "member_name": self.member_name,
            "machine": self.machine,
            "elf_class": self.elf_class,
            "endianness": self.endianness,
            "arch_supported": self.arch_supported,
            "read_only": True,
            "relocations_applied": False,
            "tables": [t.to_dict() for t in self.tables],
            "summary": self.summary(),
            "overlaps": [o.to_dict() for o in self.overlaps],
            "warnings": list(self.warnings),
            "fields": [f.to_dict() for f in self.fields],
        }
