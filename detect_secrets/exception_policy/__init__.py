# Independent exception decision API for detect-secrets.
#
# Unlike the upstream baseline (which copies an ``is_secret`` audit marker along
# with the file location, so a moved file loses the decision and a replaced
# secret keeps a stale "approved" flag), this package makes exception decisions
# an independent, first-class object:
#
# * bound to a content-derived :class:`SecretIdentity` (not the file path);
# * scoped to a project/path via :class:`Scope`;
# * pinned to a :class:`RuleVersion`, invalidated by breaking rule upgrades;
# * time-boxed with an explicit expiry, evaluated against a caller-supplied
#   clock snapshot so historical reports replay deterministically;
# * stored in an append-only :class:`ExceptionStore` that keeps hashed approval
#   evidence but never plaintext;
# * merge-aware: conflicting branch decisions are surfaced, never auto-picked.
from .adapter import finding_from_baseline_entry
from .adapter import finding_from_potential_secret
from .engine import Decision
from .engine import DecisionStatus
from .engine import ExceptionEngine
from .engine import Finding
from .engine import utc_now
from .identity import SecretIdentity
from .merge import MergeReport
from .merge import conflict_detail_to_dict
from .merge import merge_exception_stores
from .records import DecisionState
from .records import ExceptionRecord
from .records import build_record
from .records import evidence_fingerprint
from .rules import RuleVersion
from .scope import Scope
from .store import Conflict
from .store import DuplicateDecisionError
from .store import ExceptionStore
from .store import merge_stores

__all__ = [
    "Conflict",
    "MergeReport",
    "conflict_detail_to_dict",
    "Decision",
    "DecisionState",
    "DecisionStatus",
    "DuplicateDecisionError",
    "ExceptionEngine",
    "ExceptionRecord",
    "ExceptionStore",
    "Finding",
    "RuleVersion",
    "Scope",
    "SecretIdentity",
    "build_record",
    "evidence_fingerprint",
    "finding_from_baseline_entry",
    "finding_from_potential_secret",
    "merge_exception_stores",
    "merge_stores",
    "utc_now",
]
