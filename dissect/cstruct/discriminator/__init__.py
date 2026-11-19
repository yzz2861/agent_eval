"""Multi-schema discrimination for version-less binary firmware records.

The discriminator chooses between candidate structure definitions using the
caller-declared structural invariants and the bytes that are actually readable,
never the candidate order or mere parse success.
"""

from __future__ import annotations

from dissect.cstruct.discriminator.engine import discriminate, evaluate_candidate
from dissect.cstruct.discriminator.evidence import build_evidence_plan
from dissect.cstruct.discriminator.exceptions import (
    DiscriminatorError,
    SchemaDefinitionError,
    TruncatedRead,
)
from dissect.cstruct.discriminator.invariants import PayloadChecksum, RecordLengthEquals, sum16
from dissect.cstruct.discriminator.io import ByteWindow, CacheStats, ReadCache
from dissect.cstruct.discriminator.model import (
    CandidateStatus,
    Constraint,
    DiscriminationOutcome,
    DiscriminationResult,
    EvidenceItem,
    EvidencePlan,
    FieldSpec,
    InvariantContext,
    InvariantOutcome,
    RecordInvariant,
    SchemaSpec,
    Verdict,
    Violation,
    byte_eq,
    equal_to,
    integer_range,
    masked_equals,
    one_of,
    reserved_zero,
)

__all__ = [
    "ByteWindow",
    "CacheStats",
    "CandidateStatus",
    "Constraint",
    "DiscriminationOutcome",
    "DiscriminationResult",
    "DiscriminatorError",
    "EvidenceItem",
    "EvidencePlan",
    "FieldSpec",
    "InvariantContext",
    "InvariantOutcome",
    "PayloadChecksum",
    "ReadCache",
    "RecordInvariant",
    "RecordLengthEquals",
    "SchemaDefinitionError",
    "SchemaSpec",
    "TruncatedRead",
    "Verdict",
    "Violation",
    "build_evidence_plan",
    "byte_eq",
    "discriminate",
    "equal_to",
    "evaluate_candidate",
    "integer_range",
    "masked_equals",
    "one_of",
    "reserved_zero",
    "sum16",
]
