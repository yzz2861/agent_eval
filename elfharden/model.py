"""Data model for offline ELF hardening audits.

Every conclusion is tied to Evidence records that point at concrete byte
ranges in the audited file. Nothing in this module executes the target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleId(str, Enum):
    """Selectable audit rules."""

    STACK_EXECUTABLE = "stack_executable"
    RELRO = "relro"
    BIND_NOW = "bind_now"


class ViewKind(str, Enum):
    """Which legal ELF view produced a piece of evidence."""

    SEGMENT = "segment"
    DYNAMIC = "dynamic"
    SECTION = "section"


class Status(str, Enum):
    """Rule-level verdict.

    INDETERMINATE means the file lacks enough evidence to decide; the
    auditor never promotes a missing marker to a pass.
    """

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    CONFLICT = "conflict"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class Range:
    """A byte interval; size 0 (SHT_NOBITS) keeps the logical offset."""

    start: int
    size: int

    @property
    def end(self) -> int:
        return self.start + self.size

    def to_dict(self) -> dict[str, int]:
        return {"start": self.start, "size": self.size, "end": self.end}


@dataclass(frozen=True)
class Evidence:
    """One located claim. File range is the auditable byte interval; the
    memory range is the load view for segment/section evidence."""

    view: ViewKind
    kind: str
    detail: dict[str, Any]
    file_range: Range | None
    memory_range: Range | None = None
    supports_verdict: Status | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "view": self.view.value,
            "kind": self.kind,
            "detail": _jsonable(self.detail),
            "file_range": self.file_range.to_dict() if self.file_range else None,
            "memory_range": self.memory_range.to_dict() if self.memory_range else None,
        }
        if self.supports_verdict is not None:
            out["supports_verdict"] = self.supports_verdict.value
        return out


@dataclass
class RuleResult:
    """Outcome of one rule with every witness retained."""

    rule_id: RuleId | str
    status: Status = Status.INDETERMINATE
    summary: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    conflicts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": RuleId(self.rule_id).value,
            "status": self.status.value,
            "summary": self.summary,
            "conflicts": [_jsonable(item) for item in self.conflicts],
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class AuditReport:
    """Top-level machine-readable report."""

    source: str
    elf_class: int
    endianness: str
    elf_type: str
    machine: str
    is_dynamic: bool
    section_headers_present: bool
    rules_selected: list[str]
    results: list[RuleResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "elf": {
                "class": self.elf_class,
                "endianness": self.endianness,
                "type": self.elf_type,
                "machine": self.machine,
                "is_dynamic": self.is_dynamic,
                "section_headers_present": self.section_headers_present,
            },
            "rules_selected": list(self.rules_selected),
            "results": [result.to_dict() for result in self.results],
        }




def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value
