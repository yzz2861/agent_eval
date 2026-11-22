"""Offline Bandit-upgrade regression data model.

All inputs are caller-frozen, on-disk artefacts: a human-adjudicated sample
manifest, a rule catalogue, a rule/sample applicability matrix, gate settings
and two raw ``bandit -f json`` style scan outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


class Adjudication(str, Enum):
    """Human verdict recorded in the frozen sample set."""

    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    CLEAN = "clean"


class PairVerdict(str, Enum):
    """Recomputed outcome for one (sample, applicable rule) pair."""

    HIT = "hit"
    SCAN_MISSING = "scan_missing"
    RULE_DISABLED = "rule_disabled"
    CORRECTLY_SILENT = "correctly_silent"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    family: str
    title: str
    default_severity: str


@dataclass(frozen=True)
class Sample:
    sample_id: str
    path: str
    family: str
    adjudication: Adjudication
    rule_id: str | None
    severity: str | None
    note: str = ""
    sha256: str = ""
    duplicate_of: str | None = None


@dataclass(frozen=True)
class Scope:
    """One applicable (sample, rule) cell of the applicability matrix."""

    sample_id: str
    rule_id: str
    in_scope: bool = True


@dataclass(frozen=True)
class Hit:
    """Deduplicated scanner finding, keyed by (path, rule, line range)."""

    path: str
    rule_id: str
    line_number: int
    line_range: tuple[int, ...]
    severity: str
    test_name: str


@dataclass
class ScanLoadResult:
    label: str
    unique_hits: list[Hit]
    disabled_rules: set[str]
    duplicate_hits_removed: int
    raw_hit_count: int
    errors: list[dict]
    hit_index: dict[tuple[str, str], list[Hit]] = field(default_factory=dict)


@dataclass
class PairResult:
    sample_id: str
    path: str
    family: str
    rule_id: str
    rule_family: str
    severity: str
    adjudication: Adjudication
    expected: bool
    in_scope: bool
    verdict: PairVerdict
    matched_line: int | None = None


@dataclass
class Bucket:
    """Recomputed counters for one slice (overall or a gate group)."""

    name: str
    applicable_pairs: int = 0
    expected_pairs: int = 0
    true_hits: int = 0
    false_positive_hits: int = 0
    scan_missing: int = 0
    rule_disabled: int = 0
    correctly_silent: int = 0
    out_of_scope: int = 0
    missed_critical: list[PairResult] = field(default_factory=list)
    disabled_rules: set[str] = field(default_factory=set)

    @property
    def hits(self) -> int:
        """All in-scope cells that fired, including adjudicated false alarms."""
        return self.true_hits + self.false_positive_hits

    @property
    def recall(self) -> float | None:
        if self.expected_pairs == 0:
            return None
        return self.true_hits / self.expected_pairs


@dataclass
class ScanSummary:
    label: str
    raw_hits: int
    unique_hits: int
    duplicate_hits_removed: int
    disabled_rule_count: int
    error_count: int
    confirmed_hits: int
    fp_hits_on_adjudicated: int
    unadjudicated_hits: int


@dataclass
class GroupGate:
    family: str
    min_recall: float
    block_on_critical_miss: bool
    bucket: Bucket
    old_bucket: Bucket
    blocked: bool
    reasons: list[str]


@dataclass
class RegressionResult:
    freeze_id: str
    sample_rows: int
    unique_samples: int
    duplicate_samples_removed: int
    pair_results: list[PairResult]
    overall: Bucket
    old_overall: Bucket
    groups: list[GroupGate]
    new_scan: ScanSummary
    old_scan: ScanSummary
    blocked: bool
