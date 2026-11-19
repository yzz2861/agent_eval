"""Mutation records: every transformation documents its bookkeeping.

Each :class:`MutationRecord` captures *what* changed, *which structural
fields depended on the change* (and therefore had to be rewritten), and
*which invariants* an observer (the pefile parser) is expected to keep
holding.  ``broken_constraint`` is populated only by the deliberately
constraint-breaking mutators in :mod:`pefuzz.mutators`, where exactly one
invariant is violated on purpose.
"""

from dataclasses import dataclass, field
from enum import Enum


class SemanticChange(str, Enum):
    """Categories of change that a mutation is allowed to produce."""

    NONE = "none"
    COORDINATE_ONLY = "coordinate_only"
    IMPORT_NAME = "import_name"
    EXPORT_NAME = "export_name"
    DOS_HEADER = "dos_header"
    SUSPICIOUS_DIAGNOSTIC = "suspicious_diagnostic"


@dataclass(frozen=True)
class FieldRef:
    """A single pointer-like field that participates in a transformation.

    ``location`` is an RVA or a file offset depending on ``space``.
    """

    space: str
    location: int
    note: str = ""
    size: int = 4

    def __str__(self):
        return self.space + "@" + hex(self.location)


@dataclass
class MutationRecord:
    """Description of one applied mutation.

    Attributes:
        name: stable machine-readable identifier, e.g. ``move_section_raw``.
        allowed_semantic_changes: change kinds the comparator must tolerate.
        dependent_fields: fields rewritten to keep the image consistent.
        expected_invariants: invariants the mutated image must preserve.
        broken_constraint: empty for structure-preserving mutations, else
            the single constraint that was intentionally violated.
        summary: human-readable description of the transformation.
    """

    name: str
    allowed_semantic_changes: list = field(default_factory=list)
    dependent_fields: list = field(default_factory=list)
    expected_invariants: list = field(default_factory=list)
    broken_constraint: str = ""
    summary: str = ""

    @property
    def preserves_structure(self):
        """True when no constraint was intentionally broken."""
        return not self.broken_constraint

    def as_dict(self):
        return {
            "name": self.name,
            "allowed_semantic_changes": [
                change.value for change in self.allowed_semantic_changes
            ],
            "dependent_fields": [
                {"space": ref.space, "location": ref.location, "note": ref.note}
                for ref in self.dependent_fields
            ],
            "expected_invariants": list(self.expected_invariants),
            "broken_constraint": self.broken_constraint,
            "summary": self.summary,
        }
