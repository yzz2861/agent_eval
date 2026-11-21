"""Data model for the offline Jinja publication pre-audit.

Everything here is plain data so audit reports and approvals are easy to
serialize and archive alongside a template release.  No rendering happens at
any point; only source text and its parsed AST are ever touched.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class ReferenceKind(str, Enum):
    """The four Jinja constructs that pull another template into play."""

    EXTENDS = "extends"
    INCLUDE = "include"
    IMPORT = "import"
    FROM_IMPORT = "from_import"


class Resolution(str, Enum):
    """How much the auditor could know about a template-name expression."""

    STATIC = "static"
    CANDIDATES = "candidates"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Findings are ordered from least to most severe."""

    INFO = "info"
    WARNING = "warning"
    HOLD = "hold"
    ERROR = "error"


class Decision(str, Enum):
    """Final publication decision for one entry template."""

    RELEASE = "release"
    HOLD = "hold"
    REJECT = "reject"


def content_hash(source: str) -> str:
    """Stable content hash used to pin template versions."""
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TemplateRepository:
    """An immutable, in-memory view over the templates under review.

    ``sources`` maps logical template names (the same identifiers used inside
    Jinja tags) to their raw source text.  The repository is deliberately
    loader-free: the audit runs fully offline and never touches the real
    template loader or the file system during traversal.
    """

    sources: Mapping[str, str]

    def exists(self, name: str) -> bool:
        return name in self.sources

    def get(self, name: str) -> str:
        return self.sources[name]

    def version_of(self, name: str) -> str:
        return content_hash(self.sources[name])


@dataclass(frozen=True)
class ResolutionResult:
    """Outcome of evaluating one template-name expression.

    ``values`` holds the finite set of names when the expression is static or
    bounded; for an unbounded expression it is empty and ``unknown_reason``
    explains which construct the host has to review manually.
    """

    resolution: Resolution
    values: tuple[str, ...] = ()
    unknown_reason: str | None = None


@dataclass(frozen=True)
class Reference:
    """A single ``extends``/``include``/``import`` edge in the template graph."""

    source: str
    kind: ReferenceKind
    lineno: int
    expression: str
    resolution: Resolution
    targets: tuple[str, ...] = ()
    ignore_missing: bool = False
    unknown_reason: str | None = None

    @property
    def is_unknown(self) -> bool:
        return self.resolution is Resolution.UNKNOWN


@dataclass(frozen=True)
class Finding:
    """A single review item attached to a reference or to the entry itself."""

    code: str
    severity: Severity
    message: str
    template: str | None = None
    lineno: int | None = None
    reference: Reference | None = None


@dataclass(frozen=True)
class Approval:
    """A snapshot proving that an entry closure was once reviewed.

    ``versions`` pins the content hash of every template reachable at approval
    time.  The approval is valid only while the current hashes match exactly;
    any edit (including to a transitive, two-levels-deep include) invalidates
    it.
    """

    entry: str
    versions: Mapping[str, str]
    reviewed_references: tuple[Reference, ...]
    note: str = ""


@dataclass
class AuditReport:
    """The full pre-audit result handed back to the caller."""

    entry: str
    decision: Decision
    findings: list[Finding] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    closure: tuple[str, ...] = ()
    versions: dict[str, str] = field(default_factory=dict)

    @property
    def holds(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.HOLD]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]


def build_approval(
    entry: str,
    repository: TemplateRepository,
    closure: tuple[str, ...],
    references: tuple[Reference, ...] = (),
    note: str = "",
) -> Approval:
    """Pin an approval to the exact versions currently in ``repository``."""
    return Approval(
        entry=entry,
        versions={name: repository.version_of(name) for name in closure},
        reviewed_references=references,
        note=note,
    )
