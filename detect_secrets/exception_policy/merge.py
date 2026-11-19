# Branch-merge semantics for exception decisions.
#
# Merging two branches must never silently choose one side when they disagree
# about the same secret identity. This module unions the append-only logs and
# returns an explicit report: every identity whose heads diverge is listed as a
# conflict with the candidate decision ids and the fields that differ, so the
# caller can request a fresh, explicit decision instead of inheriting a winner.
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import List
from typing import Sequence

from .records import ExceptionRecord
from .store import Conflict
from .store import ExceptionStore
from .store import merge_stores


@dataclass(frozen=True)
class ConflictDetail:
    conflict: Conflict
    candidates: List[ExceptionRecord]
    differing_fields: List[str]


@dataclass(frozen=True)
class MergeReport:
    store: ExceptionStore
    merged_decision_ids: List[str]
    conflicts: List[ConflictDetail] = field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        return bool(self.conflicts)


def _diff_fields(a: ExceptionRecord, b: ExceptionRecord) -> List[str]:
    comparisons = (
        ("scope", a.scope != b.scope),
        ("rule", a.rule != b.rule),
        ("expires_at", a.expires_at != b.expires_at),
        ("state", a.state != b.state),
        ("decided_by", a.decided_by != b.decided_by),
        ("rationale", a.rationale != b.rationale),
    )
    return sorted(name for name, differs in comparisons if differs)


def merge_exception_stores(stores: Sequence[ExceptionStore]) -> MergeReport:
    merged = merge_stores(stores)
    all_ids = sorted(record.decision_id for record in merged.records)

    details: List[ConflictDetail] = []
    for conflict in merged.active_conflicts():
        candidates = [
            record
            for record in merged.heads_for(conflict.secret_identity)
            if record.is_approved
        ]
        differing = sorted(
            {
                field_name
                for index, left in enumerate(candidates)
                for right in candidates[index + 1 :]
                for field_name in _diff_fields(left, right)
            },
        )
        details.append(
            ConflictDetail(
                conflict=conflict,
                candidates=candidates,
                differing_fields=differing,
            ),
        )

    return MergeReport(
        store=merged,
        merged_decision_ids=all_ids,
        conflicts=details,
    )


def conflict_detail_to_dict(detail: ConflictDetail) -> Dict[str, Any]:
    return {
        "conflict": detail.conflict.to_dict(),
        "candidate_decision_ids": [
            record.decision_id for record in detail.candidates
        ],
        "differing_fields": list(detail.differing_fields),
    }
