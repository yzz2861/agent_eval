"""Data models for the read-only evidence binding inspection.

The vocabulary mirrors the forensic workflow:

Artifact
    One physical file delivered in the case bundle (a primary hive, a
    transaction log copy or a standalone excerpt manifest plus payload).
RecordOccurrence
    One registry key/value encountered inside an artifact together with the
    complete, layer-by-layer citation that proves where the bytes live.
Exhibit
    The binding result.  Occurrences share an exhibit only when their source
    chains are demonstrably consistent.  Content-identical excerpts without a
    common-source proof stay in separate exhibits.
"""

from dataclasses import dataclass, field
from enum import Enum


class ArtifactKind(str, Enum):
    """How an artifact was delivered."""

    PRIMARY = "primary"
    TRANSACTION_LOG = "transaction_log"
    EXCERPT = "excerpt"
    UNKNOWN = "unknown"


class Reachability(str, Enum):
    """Whether an occurrence can be reached from the live hive root."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    EXCERPT_ONLY = "excerpt_only"


class ProvenanceGrade(str, Enum):
    """Strength of the common-source proof attached to an excerpt."""

    FULL = "full"
    CONTENT_ONLY = "content_only"
    NONE = "none"


@dataclass
class Citation:
    """A single layer in the raw byte reference chain."""

    layer: str
    detail: str
    offset: int | None = None

    def as_dict(self):
        data = {"layer": self.layer, "detail": self.detail}
        if self.offset is not None:
            data["offset_hex"] = "0x%x" % self.offset
        return data


@dataclass
class Artifact:
    """A physical file inside the case bundle."""

    relative_path: str
    kind: ArtifactKind
    size: int
    sha256: str
    parse_error: str | None = None
    hive_name: str | None = None
    hive_sequence1: int | None = None
    hive_sequence2: int | None = None
    checksum_valid: bool | None = None
    recover_header: bool | None = None
    recover_data: bool | None = None
    extra: dict = field(default_factory=dict)

    def as_dict(self):
        data = {
            "relative_path": self.relative_path,
            "kind": self.kind.value,
            "size": self.size,
            "sha256": self.sha256,
        }
        if self.parse_error is not None:
            data["parse_error"] = self.parse_error
        if self.hive_name is not None:
            data["hive_name"] = self.hive_name
        if self.hive_sequence1 is not None:
            data["hive_sequence1"] = self.hive_sequence1
            data["hive_sequence2"] = self.hive_sequence2
            data["checksum_valid"] = self.checksum_valid
            data["recovery_required"] = {
                "recover_header": self.recover_header,
                "recover_data": self.recover_data,
            }
        if self.extra:
            data["details"] = self.extra
        return data


def _offset_hex(value):
    if value is None or value < 0:
        return None
    return "0x%x" % value


@dataclass
class RecordOccurrence:
    """One key or value occurrence with its full source chain."""

    record_id: str
    record_kind: str
    registry_path: str
    value_name: str | None
    value_type: str | None
    content_fingerprint: str
    timestamp: str | None
    artifact_path: str
    artifact_sha256: str
    hive_relative_offset: int
    absolute_offset: int
    reachability: Reachability
    provenance_grade: ProvenanceGrade
    citations: list[Citation] = field(default_factory=list)
    source_claim: dict = field(default_factory=dict)
    binding_blockers: list[str] = field(default_factory=list)
    artifact_kind: ArtifactKind = ArtifactKind.UNKNOWN

    def as_dict(self):
        return {
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "registry_path": self.registry_path,
            "value_name": self.value_name,
            "value_type": self.value_type,
            "content_fingerprint": self.content_fingerprint,
            "timestamp": self.timestamp,
            "artifact": {
                "relative_path": self.artifact_path,
                "sha256": self.artifact_sha256,
                "kind": self.artifact_kind.value,
            },
            "hive_relative_offset_hex": _offset_hex(self.hive_relative_offset),
            "absolute_offset_hex": _offset_hex(self.absolute_offset),
            "reachability": self.reachability.value,
            "provenance_grade": self.provenance_grade.value,
            "source_chain": [citation.as_dict() for citation in self.citations],
            "source_claim": self.source_claim,
            "binding_blockers": self.binding_blockers,
        }


@dataclass
class BindingDecision:
    """Why occurrences were bound together or kept apart."""

    bound: bool
    reason: str
    evidence: list[str] = field(default_factory=list)

    def as_dict(self):
        return {
            "bound": self.bound,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass
class Exhibit:
    """One bound evidence item backed by one or more occurrences."""

    exhibit_id: str
    title: str
    occurrences: list[RecordOccurrence] = field(default_factory=list)
    decision: BindingDecision | None = None

    def as_dict(self):
        return {
            "exhibit_id": self.exhibit_id,
            "title": self.title,
            "binding_decision": self.decision.as_dict() if self.decision else None,
            "occurrence_count": len(self.occurrences),
            "occurrences": [occurrence.as_dict() for occurrence in self.occurrences],
        }
