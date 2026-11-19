"""Evidence adjudication data model.

The model turns raw plugin output into *facts* (normalized observations that
support explicit propositions) and keeps them separate from *conclusions*
(verdicts reached by combining facts under explicit rules).

Missing observations are never represented as negative facts. A hive that does
not contain an artifact is a coverage gap, not evidence of non-execution.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Union


class Proposition(str, Enum):
    """Propositions a single fact can support.

    A fact never supports negation: absence of an artifact is expressed via
    coverage gaps on the conclusion, not via a proposition.
    """

    FILE_PRESENT = "file_present"
    EXECUTION_POSSIBLE = "execution_possible"
    EXECUTION_OCCURRED = "execution_occurred"


class FactStrength(str, Enum):
    """How strongly a fact supports its proposition."""

    WEAK = "weak"
    STRONG = "strong"


class Verdict(str, Enum):
    """Adjudication verdicts, ordered from weakest to strongest."""

    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    PRESENT = "present"
    POSSIBLY_EXECUTED = "possibly_executed"
    EXECUTION_EVIDENCED = "execution_evidenced"


# Chinese labels mirror the verdicts requested in the adjudication vocabulary.
VERDICT_LABELS_ZH = {
    Verdict.INSUFFICIENT_EVIDENCE: "证据不足",
    Verdict.PRESENT: "存在",
    Verdict.POSSIBLY_EXECUTED: "可能执行",
    Verdict.EXECUTION_EVIDENCED: "已获执行证据",
}


class CounterEvidenceReason(str, Enum):
    """Why a fact is held back instead of being spliced into a conclusion."""

    IDENTITY_MISMATCH = "identity_mismatch"
    WINDOW_DISJOINT = "window_disjoint"
    WINDOW_UNKNOWN = "window_unknown"
    PATH_NOT_EQUIVALENT = "path_not_equivalent"


@dataclass(frozen=True)
class CollectionWindow:
    """The acquisition time range of a hive / artifact source.

    Bounds are timezone-aware datetimes. Either bound may be ``None`` when the
    source does not record it; an entirely unknown window cannot be proven
    disjoint, but it also cannot be used to splice facts across hives.
    """

    start: Optional[dt.datetime] = None
    end: Optional[dt.datetime] = None
    source_name: Optional[str] = None

    def is_fully_known(self) -> bool:
        return self.start is not None and self.end is not None

    def overlaps(self, other: "CollectionWindow") -> bool:
        """Return True when the two windows are known to overlap.

        Unknown bounds never produce a positive overlap: callers must treat
        unprovable overlap as an alignment failure rather than guessing.
        """
        if not (self.is_fully_known() and other.is_fully_known()):
            return False
        return self.start <= other.end and other.start <= self.end

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "source_name": self.source_name,
        }


@dataclass(frozen=True)
class UserIdentity:
    """A user as observed in an artifact.

    ``sid`` is the authoritative identity when known. ``username`` and
    ``hive_origin`` are descriptive. Two facts can only share an identity when
    the SIDs match, or when both come from the same user-scoped hive and no
    conflicting SID is known.
    """

    sid: Optional[str] = None
    username: Optional[str] = None
    hive_origin: Optional[str] = None

    @property
    def key(self) -> str:
        if self.sid:
            return f"sid:{self.sid}"
        if self.hive_origin:
            return f"hive:{self.hive_origin}"
        return "unknown"

    def aligns_with(self, other: Optional["UserIdentity"]) -> bool:
        if other is None:
            return False
        if self.sid and other.sid:
            return self.sid == other.sid
        if self.sid or other.sid:
            # One side is attributable, the other is not: do not guess.
            return False
        if self.hive_origin and other.hive_origin:
            return self.hive_origin == other.hive_origin
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"sid": self.sid, "username": self.username, "hive_origin": self.hive_origin}


@dataclass(frozen=True)
class Fact:
    """A single normalized observation supporting one proposition.

    Facts are immutable and JSON-serializable via :meth:`to_dict`. ``fact_id``
    is stable within an adjudication run so conclusions can reference minimal
    support sets without duplicating fact payloads.
    """

    fact_id: str
    source: str
    proposition: Proposition
    strength: FactStrength
    path: str
    observed_at: Optional[dt.datetime]
    identity: Optional[UserIdentity]
    collection_window: CollectionWindow
    machine_wide: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "source": self.source,
            "proposition": self.proposition.value,
            "strength": self.strength.value,
            "path": self.path,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "identity": self.identity.to_dict() if self.identity else None,
            "collection_window": self.collection_window.to_dict(),
            "machine_wide": self.machine_wide,
            "raw": self.raw,
        }


@dataclass(frozen=True)
class CounterEvidence:
    """A fact that could not be spliced into a conclusion, with the reason."""

    fact_id: str
    source: str
    reason: CounterEvidenceReason
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "source": self.source,
            "reason": self.reason.value,
            "detail": self.detail,
        }


@dataclass
class EvidenceConclusion:
    """The adjudication result for one program/user pairing."""

    path: str
    identity_key: Optional[str]
    verdict: Verdict
    verdict_label_zh: str
    minimal_support: list[str] = field(default_factory=list)
    supporting_fact_ids: list[str] = field(default_factory=list)
    counter_evidence: list[CounterEvidence] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "identity_key": self.identity_key,
            "verdict": self.verdict.value,
            "verdict_label_zh": self.verdict_label_zh,
            "minimal_support": list(self.minimal_support),
            "supporting_fact_ids": list(self.supporting_fact_ids),
            "counter_evidence": [item.to_dict() for item in self.counter_evidence],
            "coverage_gaps": list(self.coverage_gaps),
            "conflicts": list(self.conflicts),
        }


JSONValue = Union[str, int, float, bool, None, dict[str, Any], list[Any]]
