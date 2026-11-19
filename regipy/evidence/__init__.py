"""Execution evidence adjudication API.

This subpackage normalizes existing plugin output into conservative facts and
combines them under explicit rules. It never changes plugin output itself:
plugins keep emitting their original entries, and adjudication is opt-in.
"""

from __future__ import annotations

from regipy.evidence.adjudication import EvidenceAdjudicator, adjudicate
from regipy.evidence.models import (
    CollectionWindow,
    CounterEvidence,
    CounterEvidenceReason,
    EvidenceConclusion,
    Fact,
    FactStrength,
    UserIdentity,
    Proposition,
    VERDICT_LABELS_ZH,
    Verdict,
)
from regipy.evidence.normalizers import (
    NORMALIZERS,
    SourceContext,
    normalize_amcache,
    normalize_bam,
    normalize_shimcache,
    normalize_user_assist,
)
from regipy.evidence.pathnorm import NormalizedPath, normalize_path

__all__ = [
    "CollectionWindow",
    "CounterEvidence",
    "CounterEvidenceReason",
    "EvidenceAdjudicator",
    "EvidenceConclusion",
    "Fact",
    "FactStrength",
    "UserIdentity",
    "NORMALIZERS",
    "NormalizedPath",
    "Proposition",
    "SourceContext",
    "VERDICT_LABELS_ZH",
    "Verdict",
    "adjudicate",
    "normalize_amcache",
    "normalize_bam",
    "normalize_path",
    "normalize_shimcache",
    "normalize_user_assist",
]
