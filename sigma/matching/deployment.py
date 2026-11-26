"""Coverage-driven deployment planning for small Sigma rule change sets.

The planner is deliberately built on :class:`sigma.matching.SigmaMatcher`, pySigma's
local matcher.  It evaluates every candidate rule against a corpus of manually labelled
events, builds a rule x case coverage matrix, and enumerates deployment combinations
subject to hard operational constraints.

The plan is the *post-change* rule set.  ``baseline`` rules are only used to derive the
set of old true-positive hits that must be preserved; select a baseline rule in a plan
if it should remain deployed.

Typical use::

    scenario = DeploymentScenario.from_yaml("scenario.yml")
    planner = DeploymentPlanner(scenario)
    matrix = planner.coverage_matrix
    plans = planner.select_plans()
    for plan in plans:
        assert plan.replay() == plan.alert_rows()

Every malicious case that is not covered by a plan carries an :class:`UncoveredCase`
explanation whose ``kind`` is either ``"capability"`` (no candidate rule can detect it)
or ``"constraint"`` (a capable rule exists but mutual exclusion, prerequisites, capacity,
rule slots, false-positive policy, or old-hit retention prevents deploying it).
"""

from __future__ import annotations

import argparse
import csv
import io
import itertools
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence

import yaml

from sigma.collection import SigmaCollection
from sigma.matching.event import Event, EventLogSource
from sigma.matching.matcher import SigmaMatcher
from sigma.rule.rule import SigmaRule

Severity = Literal["critical", "high", "medium", "low"]
SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low")
_SEVERITY_INDEX = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
_BASELINE_PREFIX = "baseline:"


class DeploymentError(ValueError):
    """Raised for invalid scenarios or deployment requests."""


@dataclass(frozen=True)
class ConstraintViolation:
    """A hard-constraint violation found while evaluating a candidate plan."""

    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class LabeledCase:
    """A manually labelled drill/attack record and the event to match."""

    id: str
    event: Event
    label: Literal["malicious", "benign"] = "malicious"
    severity: Severity = "medium"
    description: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise DeploymentError("case id must not be empty")
        if self.label not in ("malicious", "benign"):
            raise DeploymentError(f"case {self.id}: label must be malicious or benign")
        if self.severity not in _SEVERITY_INDEX:
            raise DeploymentError(f"case {self.id}: unknown severity {self.severity!r}")
        if self.event.timestamp.tzinfo is None:
            raise DeploymentError(f"case {self.id}: event timestamp must be timezone-aware")


@dataclass(frozen=True)
class RuleCandidate:
    """One deployable Sigma rule change.

    ``cost`` models processing capacity in arbitrary consistent units (events/second,
    CPU share, ...).  Candidates in the same non-empty ``group`` are mutually exclusive.
    ``requires`` lists candidate ids that must be deployed together with this rule.
    """

    id: str
    rule: SigmaRule
    cost: float = 1.0
    group: str | None = None
    requires: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise DeploymentError("candidate id must not be empty")
        if not math.isfinite(self.cost) or self.cost < 0:
            raise DeploymentError(f"candidate {self.id}: cost must be finite and non-negative")
        if self.group == "":
            raise DeploymentError(f"candidate {self.id}: group must be non-empty when set")


@dataclass(frozen=True)
class DeploymentConstraints:
    """Hard constraints for a deployment decision."""

    capacity: float = math.inf
    max_rules: int | None = None
    retain_old_hits: bool = True
    required_cases: frozenset[str] = frozenset()
    max_false_positives: int | None = 0
    mutually_exclusive: tuple[frozenset[str], ...] = ()

    def __post_init__(self) -> None:
        if not math.isfinite(self.capacity) and self.capacity != math.inf:
            raise DeploymentError("capacity must be finite or infinity")
        if self.capacity < 0:
            raise DeploymentError("capacity must be non-negative")
        if self.max_rules is not None and self.max_rules < 0:
            raise DeploymentError("max_rules must be non-negative")
        if self.max_false_positives is not None and self.max_false_positives < 0:
            raise DeploymentError("max_false_positives must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return {
            "capacity": None if self.capacity == math.inf else self.capacity,
            "max_rules": self.max_rules,
            "retain_old_hits": self.retain_old_hits,
            "required_cases": sorted(self.required_cases),
            "max_false_positives": self.max_false_positives,
            "mutually_exclusive": [sorted(group) for group in self.mutually_exclusive],
        }


@dataclass
class CoverageMatrix:
    """Rule x case alert matrix produced by the local matcher."""

    case_ids: tuple[str, ...]
    baseline_columns: tuple[str, ...]
    candidate_columns: tuple[str, ...]
    coverage: dict[str, frozenset[str]]
    labels: dict[str, str]
    severities: dict[str, str]
    descriptions: dict[str, str]

    @property
    def columns(self) -> tuple[str, ...]:
        return self.baseline_columns + self.candidate_columns

    def covers(self, column: str, case_id: str) -> bool:
        return case_id in self.coverage.get(column, frozenset())

    def rules_for_case(self, case_id: str) -> tuple[str, ...]:
        return tuple(column for column in self.columns if self.covers(column, case_id))

    def candidate_rules_for_case(self, case_id: str) -> tuple[str, ...]:
        return tuple(column for column in self.candidate_columns if self.covers(column, case_id))

    def baseline_hits(self) -> frozenset[str]:
        hits: set[str] = set()
        for column in self.baseline_columns:
            hits.update(self.coverage.get(column, frozenset()))
        return frozenset(hits)

    def to_dict(self) -> dict[str, Any]:
        rules = []
        for column in self.baseline_columns:
            rules.append(
                {
                    "id": column,
                    "kind": "baseline",
                    "covers": sorted(self.coverage.get(column, frozenset())),
                    "coverage_count": len(self.coverage.get(column, frozenset())),
                }
            )
        for column in self.candidate_columns:
            rules.append(
                {
                    "id": column,
                    "kind": "candidate",
                    "covers": sorted(self.coverage.get(column, frozenset())),
                    "coverage_count": len(self.coverage.get(column, frozenset())),
                }
            )
        return {
            "cases": [
                {
                    "id": case_id,
                    "label": self.labels[case_id],
                    "severity": self.severities[case_id],
                    "description": self.descriptions[case_id],
                }
                for case_id in self.case_ids
            ],
            "columns": list(self.columns),
            "rules": rules,
            "matrix": {
                case_id: {column: self.covers(column, case_id) for column in self.columns}
                for case_id in self.case_ids
            },
        }

    def to_markdown(self) -> str:
        header = ["Case", "Label", "Severity", *self.columns]
        lines = ["| " + " | ".join(header) + " |"]
        lines.append("|" + "|".join("---" for _ in header) + "|")
        for case_id in self.case_ids:
            row = [
                f"`{case_id}`",
                self.labels[case_id],
                self.severities[case_id],
            ]
            row.extend("Y" if self.covers(column, case_id) else "." for column in self.columns)
            lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines)

    def to_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["case", "label", "severity", *self.columns])
        for case_id in self.case_ids:
            writer.writerow(
                [
                    case_id,
                    self.labels[case_id],
                    self.severities[case_id],
                    *(1 if self.covers(column, case_id) else 0 for column in self.columns),
                ]
            )
        return buffer.getvalue()


@dataclass(frozen=True)
class UncoveredCase:
    """Why a labelled malicious case did not alert under a plan."""

    case_id: str
    severity: Severity
    kind: Literal["capability", "constraint"]
    reason: str
    detail: str
    capable_rule_ids: tuple[str, ...] = ()
    blocked_by: tuple[str, ...] = ()
    related_constraints: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "severity": self.severity,
            "kind": self.kind,
            "reason": self.reason,
            "detail": self.detail,
            "capable_rule_ids": list(self.capable_rule_ids),
            "blocked_by": list(self.blocked_by),
            "related_constraints": list(self.related_constraints),
        }


@dataclass(frozen=True)
class DeploymentPlan:
    """One evaluated deployment combination."""

    plan_id: str
    selected_ids: tuple[str, ...]
    cost: float
    score: tuple[int, int, int, int]
    alerts: dict[str, tuple[str, ...]]
    covered_case_ids: tuple[str, ...]
    uncovered: tuple[UncoveredCase, ...]
    false_positive_case_ids: tuple[str, ...]
    retained_old_hit_ids: tuple[str, ...]
    missing_old_hit_ids: tuple[str, ...]
    violations: tuple[ConstraintViolation, ...]
    _scenario: "DeploymentScenario | None" = field(default=None, repr=False, compare=False)

    @property
    def feasible(self) -> bool:
        return not self.violations

    def score_dict(self) -> dict[Severity, int]:
        return dict(zip(SEVERITY_ORDER, self.score))

    def alert_rows(self) -> list[dict[str, Any]]:
        """Cached alert results in a stable, replayable row format."""
        if self._scenario is None:
            raise DeploymentError("plan is not bound to a scenario")
        rows: list[dict[str, Any]] = []
        for case in self._scenario.cases:
            rule_ids = self.alerts.get(case.id, ())
            rows.append(
                {
                    "case_id": case.id,
                    "label": case.label,
                    "severity": case.severity,
                    "alerted": bool(rule_ids),
                    "rule_ids": list(rule_ids),
                }
            )
        return rows

    def replay(self) -> list[dict[str, Any]]:
        """Recompute alerts from scratch with ``SigmaMatcher``.

        This intentionally does not reuse the coverage matrix.  It builds a fresh
        collection from the selected rules so a plan's reported alerts can be audited.
        """
        if self._scenario is None:
            raise DeploymentError("plan is not bound to a scenario")
        scenario = self._scenario
        selected = set(self.selected_ids)
        rules = [candidate.rule for candidate in scenario.candidates if candidate.id in selected]
        order = {candidate.id: index for index, candidate in enumerate(scenario.candidates)}
        rule_to_id = {
            id(candidate.rule): candidate.id
            for candidate in scenario.candidates
            if candidate.id in selected
        }
        matcher = SigmaMatcher(SigmaCollection(rules))
        rows: list[dict[str, Any]] = []
        try:
            for case in scenario.cases:
                matched_ids = {
                    rule_to_id[id(match.rule)]
                    for match in matcher.match(case.event)
                    if id(match.rule) in rule_to_id
                }
                rows.append(
                    {
                        "case_id": case.id,
                        "label": case.label,
                        "severity": case.severity,
                        "alerted": bool(matched_ids),
                        "rule_ids": sorted(matched_ids, key=lambda rule_id: order[rule_id]),
                    }
                )
        finally:
            matcher.close()
        return rows

    def to_dict(self, include_replay: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "plan_id": self.plan_id,
            "selected": list(self.selected_ids),
            "cost": self.cost,
            "score": self.score_dict(),
            "feasible": self.feasible,
            "violations": [violation.to_dict() for violation in self.violations],
            "covered_case_ids": list(self.covered_case_ids),
            "retained_old_hit_ids": list(self.retained_old_hit_ids),
            "missing_old_hit_ids": list(self.missing_old_hit_ids),
            "false_positive_case_ids": list(self.false_positive_case_ids),
            "alerts": self.alert_rows(),
            "uncovered": [case.to_dict() for case in self.uncovered],
        }
        if include_replay:
            result["replay"] = self.replay()
        return result


@dataclass
class DeploymentScenario:
    """Inputs for coverage planning: labelled cases, candidates, baseline, constraints."""

    cases: tuple[LabeledCase, ...]
    candidates: tuple[RuleCandidate, ...]
    baseline: tuple[SigmaRule, ...] = ()
    constraints: DeploymentConstraints = field(default_factory=DeploymentConstraints)
    title: str = ""
    description: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DeploymentScenario":
        if not isinstance(data, Mapping):
            raise DeploymentError("scenario must be a mapping")
        raw_cases = data.get("cases") or []
        raw_candidates = data.get("candidates") or []
        cases = tuple(
            _labeled_case_from_dict(item, index) for index, item in enumerate(raw_cases, start=1)
        )
        candidates = tuple(
            _candidate_from_dict(item, index) for index, item in enumerate(raw_candidates, start=1)
        )
        constraints = _constraints_from_dict(data.get("constraints"))
        baseline = _parse_baseline(data.get("baseline"))
        return cls(
            cases=cases,
            candidates=candidates,
            baseline=baseline,
            constraints=constraints,
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
        )

    @classmethod
    def from_yaml(cls, source: str | Path) -> "DeploymentScenario":
        text = _read_text(source)
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as error:
            raise DeploymentError(f"invalid scenario YAML: {error}") from error
        if not isinstance(data, Mapping):
            raise DeploymentError("scenario YAML must contain a mapping")
        return cls.from_dict(data)

    @classmethod
    def from_json(cls, source: str | Path) -> "DeploymentScenario":
        text = _read_text(source)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise DeploymentError(f"invalid scenario JSON: {error}") from error
        return cls.from_dict(data)

    @property
    def case_map(self) -> dict[str, LabeledCase]:
        return {case.id: case for case in self.cases}

    @property
    def candidate_map(self) -> dict[str, RuleCandidate]:
        return {candidate.id: candidate for candidate in self.candidates}


class DeploymentPlanner:
    """Builds coverage matrices and enumerates constrained deployment combinations."""

    def __init__(self, scenario: DeploymentScenario) -> None:
        self.scenario = scenario
        self._matrix: CoverageMatrix | None = None
        self._case_order = {case.id: index for index, case in enumerate(scenario.cases)}
        self._candidate_order = {
            candidate.id: index for index, candidate in enumerate(scenario.candidates)
        }
        self._validate()

    def _validate(self) -> None:
        case_ids = [case.id for case in self.scenario.cases]
        if len(case_ids) != len(set(case_ids)):
            raise DeploymentError("case ids must be unique")
        candidate_ids = [candidate.id for candidate in self.scenario.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise DeploymentError("candidate ids must be unique")
        known = set(candidate_ids)
        for candidate in self.scenario.candidates:
            for requirement in candidate.requires:
                if requirement not in known:
                    raise DeploymentError(
                        f"candidate {candidate.id} requires unknown candidate {requirement}"
                    )
                if requirement == candidate.id:
                    raise DeploymentError(f"candidate {candidate.id} cannot require itself")
        for group in self.scenario.constraints.mutually_exclusive:
            unknown = set(group) - known
            if unknown:
                raise DeploymentError(
                    f"mutual-exclusion group references unknown candidates: {sorted(unknown)}"
                )
        unknown_required_cases = set(self.scenario.constraints.required_cases) - set(case_ids)
        if unknown_required_cases:
            raise DeploymentError(
                "required_cases references unknown cases: " f"{sorted(unknown_required_cases)}"
            )

    @property
    def coverage_matrix(self) -> CoverageMatrix:
        if self._matrix is None:
            self._matrix = self.build_coverage_matrix()
        return self._matrix

    def build_coverage_matrix(self) -> CoverageMatrix:
        """Match every candidate and baseline rule against every labelled case."""
        baseline_columns: list[str] = []
        used_columns: set[str] = set()
        for index, rule in enumerate(self.scenario.baseline, start=1):
            name = rule.name or f"rule-{index}"
            column = f"{_BASELINE_PREFIX}{name}"
            suffix = 2
            while column in used_columns:
                column = f"{_BASELINE_PREFIX}{name}-{suffix}"
                suffix += 1
            used_columns.add(column)
            baseline_columns.append(column)
        candidate_columns = [candidate.id for candidate in self.scenario.candidates]
        column_by_rule_id: dict[int, str] = {}
        rules: list[SigmaRule] = []
        for rule, column in zip(self.scenario.baseline, baseline_columns):
            rules.append(rule)
            column_by_rule_id[id(rule)] = column
        for candidate in self.scenario.candidates:
            rules.append(candidate.rule)
            column_by_rule_id[id(candidate.rule)] = candidate.id

        coverage: dict[str, set[str]] = {
            column: set() for column in [*baseline_columns, *candidate_columns]
        }
        matcher = SigmaMatcher(SigmaCollection(rules))
        try:
            for case in self.scenario.cases:
                for match in matcher.match(case.event):
                    column = column_by_rule_id.get(id(match.rule))
                    if column is not None:
                        coverage[column].add(case.id)
        finally:
            matcher.close()

        return CoverageMatrix(
            case_ids=tuple(case.id for case in self.scenario.cases),
            baseline_columns=tuple(baseline_columns),
            candidate_columns=tuple(candidate_columns),
            coverage={column: frozenset(cases) for column, cases in coverage.items()},
            labels={case.id: case.label for case in self.scenario.cases},
            severities={case.id: case.severity for case in self.scenario.cases},
            descriptions={case.id: case.description for case in self.scenario.cases},
        )

    def old_hit_ids(self) -> tuple[str, ...]:
        """Malicious cases hit by the baseline; these are the old hits to retain."""
        matrix = self.coverage_matrix
        hits = {
            case.id
            for case in self.scenario.cases
            if case.label == "malicious"
            and any(matrix.covers(column, case.id) for column in matrix.baseline_columns)
        }
        return tuple(sorted(hits, key=lambda case_id: self._case_order[case_id]))

    def _required_case_ids(self) -> tuple[str, ...]:
        required: set[str] = set(self.scenario.constraints.required_cases)
        if self.scenario.constraints.retain_old_hits:
            required.update(self.old_hit_ids())
        return tuple(sorted(required, key=lambda case_id: self._case_order[case_id]))

    def _normalize_selection(self, selected_ids: Iterable[str]) -> tuple[str, ...]:
        unique: list[str] = []
        seen: set[str] = set()
        for candidate_id in selected_ids:
            if candidate_id not in self._candidate_order:
                raise DeploymentError(f"unknown candidate {candidate_id}")
            if candidate_id not in seen:
                seen.add(candidate_id)
                unique.append(candidate_id)
        return tuple(sorted(unique, key=lambda candidate_id: self._candidate_order[candidate_id]))

    def evaluate(self, selected_ids: Iterable[str]) -> DeploymentPlan:
        """Evaluate one combination, including why remaining malicious cases are open."""
        matrix = self.coverage_matrix
        selected = self._normalize_selection(selected_ids)
        selected_set = set(selected)
        constraints = self.scenario.constraints
        candidates = self.scenario.candidate_map
        violations: list[ConstraintViolation] = []

        for candidate_id in selected:
            missing = [
                requirement
                for requirement in candidates[candidate_id].requires
                if requirement not in selected_set
            ]
            if missing:
                violations.append(
                    ConstraintViolation(
                        "prerequisite",
                        f"{candidate_id} requires {', '.join(missing)} to be selected",
                    )
                )

        groups: dict[str, list[str]] = defaultdict(list)
        for candidate_id in selected:
            group = candidates[candidate_id].group
            if group is not None:
                groups[group].append(candidate_id)
        for group, members in sorted(groups.items()):
            if len(members) > 1:
                violations.append(
                    ConstraintViolation(
                        "mutual_exclusion",
                        f"group {group!r} selects mutually exclusive rules: {', '.join(members)}",
                    )
                )
        for index, group in enumerate(constraints.mutually_exclusive):
            conflicts = [candidate_id for candidate_id in selected if candidate_id in group]
            if len(conflicts) > 1:
                violations.append(
                    ConstraintViolation(
                        "mutual_exclusion",
                        f"constraint #{index + 1} selects mutually exclusive rules: "
                        f"{', '.join(conflicts)}",
                    )
                )

        cost = sum(candidates[candidate_id].cost for candidate_id in selected)
        if cost > constraints.capacity:
            violations.append(
                ConstraintViolation(
                    "capacity",
                    f"cost {_format_number(cost)} exceeds capacity "
                    f"{_format_number(constraints.capacity)}",
                )
            )
        if constraints.max_rules is not None and len(selected) > constraints.max_rules:
            violations.append(
                ConstraintViolation(
                    "rule_limit",
                    f"{len(selected)} rules exceed the {constraints.max_rules}-rule slot limit",
                )
            )

        alert_sets: dict[str, set[str]] = defaultdict(set)
        for candidate_id in selected:
            for case_id in matrix.coverage.get(candidate_id, frozenset()):
                alert_sets[case_id].add(candidate_id)
        alerts = {
            case_id: tuple(sorted(rule_ids, key=lambda cid: self._candidate_order[cid]))
            for case_id, rule_ids in alert_sets.items()
        }

        covered = tuple(
            case.id
            for case in self.scenario.cases
            if case.label == "malicious" and case.id in alerts
        )
        false_positives = tuple(
            case.id for case in self.scenario.cases if case.label == "benign" and case.id in alerts
        )
        if (
            constraints.max_false_positives is not None
            and len(false_positives) > constraints.max_false_positives
        ):
            violations.append(
                ConstraintViolation(
                    "false_positive",
                    f"{len(false_positives)} benign drill(s) alert, limit is "
                    f"{constraints.max_false_positives}: {', '.join(false_positives)}",
                )
            )

        required_cases = self._required_case_ids()
        missing_required = tuple(case_id for case_id in required_cases if case_id not in alerts)
        old_hits = self.old_hit_ids()
        missing_old_hits = tuple(case_id for case_id in old_hits if case_id not in alerts)
        retained_old_hits = tuple(case_id for case_id in old_hits if case_id in alerts)
        if missing_required:
            violations.append(
                ConstraintViolation(
                    "retention",
                    "required cases are not covered: " f"{', '.join(missing_required)}",
                )
            )

        uncovered = tuple(
            self._explain_uncovered_case(
                case,
                selected=selected,
                cost=cost,
                required_cases=required_cases,
            )
            for case in self.scenario.cases
            if case.label == "malicious" and case.id not in alerts
        )

        severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
        for case_id in covered:
            severity = self.scenario.case_map[case_id].severity
            severity_counts[severity] += 1
        score = (
            severity_counts["critical"],
            severity_counts["high"],
            severity_counts["medium"],
            severity_counts["low"],
        )

        return DeploymentPlan(
            plan_id="+".join(selected) if selected else "empty",
            selected_ids=selected,
            cost=cost,
            score=score,
            alerts=alerts,
            covered_case_ids=covered,
            uncovered=uncovered,
            false_positive_case_ids=false_positives,
            retained_old_hit_ids=retained_old_hits,
            missing_old_hit_ids=missing_old_hits,
            violations=tuple(violations),
            _scenario=self.scenario,
        )

    def _explain_uncovered_case(
        self,
        case: LabeledCase,
        selected: tuple[str, ...],
        cost: float,
        required_cases: tuple[str, ...],
    ) -> UncoveredCase:
        matrix = self.coverage_matrix
        candidates = self.scenario.candidate_map
        selected_set = set(selected)
        capable = [
            candidate.id
            for candidate in self.scenario.candidates
            if matrix.covers(candidate.id, case.id)
        ]
        if not capable:
            return UncoveredCase(
                case_id=case.id,
                severity=case.severity,
                kind="capability",
                reason="no_rule_capability",
                detail=(
                    "no candidate rule's logsource/detection logic matches this event; "
                    "this is a rule-capability gap"
                ),
            )

        priority = (
            "retention",
            "mutual_exclusion",
            "prerequisite",
            "capacity",
            "rule_limit",
            "false_positive",
            "not_selected",
        )
        priority_index = {reason: index for index, reason in enumerate(priority)}
        all_blockers: set[str] = set()
        related: set[str] = set()
        details: list[str] = []

        for candidate_id in capable:
            if candidate_id in selected_set:
                continue
            candidate = candidates[candidate_id]
            blockers: list[str] = []
            messages: list[str] = []

            conflicts: list[str] = []
            if candidate.group is not None:
                conflicts.extend(
                    other for other in selected if candidates[other].group == candidate.group
                )
            for group in self.scenario.constraints.mutually_exclusive:
                if candidate_id in group:
                    conflicts.extend(
                        other for other in selected if other != candidate_id and other in group
                    )
            conflicts = list(dict.fromkeys(conflicts))
            retention_conflict = self._retention_conflict(
                candidate_id, conflicts, selected, required_cases
            )
            if conflicts:
                blockers.append("mutual_exclusion")
                group_name = candidate.group or "explicit constraint"
                messages.append(
                    f"{candidate_id} matches but is exclusive ({group_name}) with selected "
                    f"{', '.join(conflicts)}"
                )

            missing_requirements = [
                requirement for requirement in candidate.requires if requirement not in selected_set
            ]
            if missing_requirements:
                blockers.append("prerequisite")
                messages.append(
                    f"{candidate_id} needs prerequisite(s) " f"{', '.join(missing_requirements)}"
                )

            extra_ids = [candidate_id, *missing_requirements]
            extra_cost = sum(
                candidates[extra_id].cost
                for extra_id in dict.fromkeys(extra_ids)
                if extra_id not in selected_set
            )
            if cost + extra_cost > self.scenario.constraints.capacity:
                blockers.append("capacity")
                messages.append(
                    f"adding {candidate_id} needs {_format_number(extra_cost)} more capacity "
                    f"but only "
                    f"{_format_number(self.scenario.constraints.capacity - cost)} remains"
                )
                if not retention_conflict:
                    retention_conflict = self._capacity_retention_conflict(
                        candidate_id, extra_cost, selected, required_cases, cost
                    )

            max_rules = self.scenario.constraints.max_rules
            if max_rules is not None and len(selected) + len(missing_requirements) + 1 > max_rules:
                blockers.append("rule_limit")
                messages.append(
                    f"adding {candidate_id} exceeds the {max_rules}-rule slot limit "
                    f"({len(selected)} already selected)"
                )

            benign_hits = [
                other.id
                for other in self.scenario.cases
                if other.label == "benign" and matrix.covers(candidate_id, other.id)
            ]
            if self.scenario.constraints.max_false_positives == 0 and benign_hits:
                blockers.append("false_positive")
                messages.append(f"{candidate_id} alerts benign drill(s): {', '.join(benign_hits)}")

            if retention_conflict:
                blockers.insert(0, "retention")
                related.update(blockers[1:])
                messages.insert(
                    0,
                    f"{candidate_id} cannot be swapped in within capacity without dropping a "
                    "rule that uniquely preserves a retained old hit",
                )

            if not blockers:
                blockers.append("not_selected")
                messages.append(
                    f"{candidate_id} is compatible but is not part of this optimal plan"
                )

            all_blockers.update(blockers)
            if retention_conflict:
                related.add("retention")
            details.append("; ".join(messages))

        if not all_blockers:
            all_blockers.add("not_selected")
        reason = min(all_blockers, key=lambda item: priority_index.get(item, len(priority)))
        blocked_by = tuple(
            sorted(all_blockers, key=lambda item: priority_index.get(item, len(priority)))
        )
        return UncoveredCase(
            case_id=case.id,
            severity=case.severity,
            kind="constraint",
            reason=reason,
            detail="; ".join(details),
            capable_rule_ids=tuple(capable),
            blocked_by=blocked_by,
            related_constraints=tuple(
                sorted(related, key=lambda item: priority_index.get(item, len(priority)))
            ),
        )

    def _retention_conflict(
        self,
        candidate_id: str,
        conflicts: Sequence[str],
        selected: Sequence[str],
        required_cases: Sequence[str],
    ) -> bool:
        matrix = self.coverage_matrix
        for conflicting in conflicts:
            for required_case in required_cases:
                if not matrix.covers(conflicting, required_case):
                    continue
                others = [
                    other
                    for other in selected
                    if other != conflicting and matrix.covers(other, required_case)
                ]
                if not others and not matrix.covers(candidate_id, required_case):
                    return True
        return False

    def _capacity_retention_conflict(
        self,
        candidate_id: str,
        extra_cost: float,
        selected: Sequence[str],
        required_cases: Sequence[str],
        current_cost: float,
    ) -> bool:
        candidates = self.scenario.candidate_map
        matrix = self.coverage_matrix
        capacity = self.scenario.constraints.capacity
        swap_possible = False
        for dropped in selected:
            if current_cost - candidates[dropped].cost + extra_cost > capacity:
                continue
            remaining = [other for other in selected if other != dropped]
            breaks_prerequisite = any(dropped in candidates[other].requires for other in remaining)
            if breaks_prerequisite:
                continue
            retention_holds = all(
                matrix.covers(candidate_id, required_case)
                or any(matrix.covers(other, required_case) for other in remaining)
                for required_case in required_cases
            )
            if retention_holds:
                swap_possible = True
                break
        return not swap_possible

    def select_plans(self) -> list[DeploymentPlan]:
        """Return every feasible plan tied on coverage, then cost, then rule count."""
        candidates = self.scenario.candidates
        best_key: tuple[Any, ...] | None = None
        best: list[DeploymentPlan] = []
        candidate_ids = [candidate.id for candidate in candidates]
        for size in range(len(candidate_ids) + 1):
            for combination in itertools.combinations(candidate_ids, size):
                plan = self.evaluate(combination)
                if not plan.feasible:
                    continue
                key = (
                    tuple(-count for count in plan.score),
                    plan.cost,
                    len(plan.selected_ids),
                )
                if best_key is None or key < best_key:
                    best_key = key
                    best = [plan]
                elif key == best_key:
                    best.append(plan)
        best.sort(key=lambda plan: (plan.cost, plan.selected_ids))
        return [replace(plan, plan_id=f"plan-{index}") for index, plan in enumerate(best, 1)]


def _labeled_case_from_dict(item: Mapping[str, Any], index: int) -> LabeledCase:
    if not isinstance(item, Mapping):
        raise DeploymentError(f"case #{index} must be a mapping")
    case_id = str(item.get("id") or f"case-{index}")
    event = _event_from_case_dict(item, case_id)
    tags = item.get("tags") or ()
    if isinstance(tags, str):
        tags = (tags,)
    return LabeledCase(
        id=case_id,
        event=event,
        label=item.get("label", "malicious"),
        severity=item.get("severity", "medium"),
        description=str(item.get("description") or ""),
        tags=tuple(str(tag) for tag in tags),
    )


def _event_from_case_dict(item: Mapping[str, Any], case_id: str) -> Event:
    spec = item.get("event")
    if isinstance(spec, Event):
        return spec
    if spec is not None and not isinstance(spec, Mapping):
        raise DeploymentError(f"case {case_id}: event must be a mapping or Event")
    event_spec: Mapping[str, Any] = spec if isinstance(spec, Mapping) else item
    timestamp = event_spec.get("timestamp")
    if timestamp is None:
        raise DeploymentError(f"case {case_id}: timestamp is required")
    logsource_spec = event_spec.get("logsource")
    if isinstance(logsource_spec, EventLogSource):
        logsource = logsource_spec
    elif isinstance(logsource_spec, Mapping):
        logsource = EventLogSource(
            category=logsource_spec.get("category"),
            product=logsource_spec.get("product"),
            service=logsource_spec.get("service"),
        )
    elif logsource_spec is None:
        logsource = EventLogSource()
    else:
        raise DeploymentError(f"case {case_id}: logsource must be a mapping")
    data = event_spec.get("data") or {}
    if not isinstance(data, Mapping):
        raise DeploymentError(f"case {case_id}: data must be a mapping")
    raw = event_spec.get("raw")
    return Event(
        timestamp=_parse_timestamp(timestamp, case_id),
        logsource=logsource,
        data=dict(data),
        raw=str(raw) if raw is not None else None,
    )


def _parse_timestamp(value: Any, case_id: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise DeploymentError(
                f"case {case_id}: timestamp is not valid ISO-8601: {value!r}"
            ) from error
    else:
        raise DeploymentError(f"case {case_id}: timestamp must be a datetime or ISO string")
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def _candidate_from_dict(item: Mapping[str, Any], index: int) -> RuleCandidate:
    if not isinstance(item, Mapping):
        raise DeploymentError(f"candidate #{index} must be a mapping")
    rule = _coerce_rule(item.get("rule"), f"candidate #{index}")
    candidate_id = str(item.get("id") or rule.name or f"candidate-{index}")
    requires = item.get("requires") or ()
    if isinstance(requires, str):
        requires = (requires,)
    return RuleCandidate(
        id=candidate_id,
        rule=rule,
        cost=float(item.get("cost", 1.0)),
        group=item.get("group"),
        requires=tuple(str(requirement) for requirement in requires),
        description=str(item.get("description") or ""),
    )


def _coerce_rule(value: Any, source: str) -> SigmaRule:
    if isinstance(value, SigmaRule):
        return value
    if isinstance(value, str):
        try:
            collection = SigmaCollection.from_yaml(value)
        except Exception as error:  # pySigma exposes several parsing exception types
            raise DeploymentError(f"{source}: invalid Sigma rule YAML: {error}") from error
        if len(collection.rules) != 1 or not isinstance(collection.rules[0], SigmaRule):
            raise DeploymentError(f"{source}: expected exactly one plain Sigma rule")
        return collection.rules[0]
    if isinstance(value, Mapping):
        try:
            return SigmaRule.from_dict(dict(value))
        except Exception as error:
            raise DeploymentError(f"{source}: invalid Sigma rule mapping: {error}") from error
    raise DeploymentError(f"{source}: rule must be a YAML string, mapping, or SigmaRule")


def _parse_baseline(value: Any) -> tuple[SigmaRule, ...]:
    if value is None:
        return ()
    if isinstance(value, SigmaCollection):
        return tuple(rule for rule in value.rules if isinstance(rule, SigmaRule))
    if isinstance(value, SigmaRule):
        return (value,)
    if isinstance(value, str):
        try:
            collection = SigmaCollection.from_yaml(value)
        except Exception as error:
            raise DeploymentError(f"baseline: invalid Sigma rule YAML: {error}") from error
        return tuple(rule for rule in collection.rules if isinstance(rule, SigmaRule))
    if isinstance(value, Sequence):
        rules: list[SigmaRule] = []
        for index, item in enumerate(value, start=1):
            if isinstance(item, str):
                try:
                    collection = SigmaCollection.from_yaml(item)
                except Exception as error:
                    raise DeploymentError(
                        f"baseline rule #{index}: invalid Sigma rule YAML: {error}"
                    ) from error
                rules.extend(rule for rule in collection.rules if isinstance(rule, SigmaRule))
            else:
                rules.append(_coerce_rule(item, f"baseline rule #{index}"))
        return tuple(rules)
    raise DeploymentError("baseline must be Sigma YAML, a rule, or a list of rules")


def _constraints_from_dict(value: Any) -> DeploymentConstraints:
    if value is None:
        return DeploymentConstraints()
    if not isinstance(value, Mapping):
        raise DeploymentError("constraints must be a mapping")
    data = dict(value)
    if "capacity" in data and data["capacity"] is None:
        data["capacity"] = math.inf
    if "required_cases" in data:
        data["required_cases"] = frozenset(str(case_id) for case_id in data["required_cases"])
    if "mutually_exclusive" in data:
        data["mutually_exclusive"] = tuple(
            frozenset(str(candidate_id) for candidate_id in group)
            for group in data["mutually_exclusive"]
        )
    try:
        return DeploymentConstraints(**data)
    except TypeError as error:
        raise DeploymentError(f"invalid constraints: {error}") from error


def _read_text(source: str | Path) -> str:
    if isinstance(source, Path):
        return source.read_text(encoding="utf-8")
    if "\n" in source or "\r" in source:
        return source
    path = Path(source)
    if path.exists():
        return path.read_text(encoding="utf-8")
    return source


def _format_number(value: float) -> str:
    if value == math.inf:
        return "infinity"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:g}"


def build_coverage_matrix(scenario: DeploymentScenario) -> CoverageMatrix:
    """Convenience wrapper for building a coverage matrix from a scenario."""
    return DeploymentPlanner(scenario).coverage_matrix


def select_deployment_plans(scenario: DeploymentScenario) -> list[DeploymentPlan]:
    """Convenience wrapper for selecting all tied optimal deployment plans."""
    return DeploymentPlanner(scenario).select_plans()


def _render_report(
    scenario: DeploymentScenario,
    matrix: CoverageMatrix,
    plans: Sequence[DeploymentPlan],
    reproduce_command: str | None = None,
) -> str:
    constraints = scenario.constraints
    lines: list[str] = []
    title = scenario.title or "Sigma Rule Deployment Review"
    lines.extend([f"# {title}", ""])
    if scenario.description:
        lines.extend([scenario.description, ""])
    lines.extend(
        [
            "## Constraints",
            "",
            f"- Processing capacity: `{_format_number(constraints.capacity)}` cost units",
            f"- Rule slots: `{constraints.max_rules if constraints.max_rules is not None else 'unlimited'}`",
            f"- Retain old true-positive hits: `{constraints.retain_old_hits}`",
            f"- Benign drill alert limit: `{constraints.max_false_positives}`",
            "- Mutual exclusion: candidates sharing a `group`, plus explicit pairs",
            "",
            f"Old true-positive hits to retain: "
            f"{', '.join(f'`{case_id}`' for case_id in _planner_old_hits(plans)) or 'none'}",
            "",
            "## Coverage Matrix",
            "",
            matrix.to_markdown(),
            "",
            "`baseline:*` columns are reference-only; a plan is the post-change rule set.",
            "",
            "## Selected Deployment Plans",
            "",
        ]
    )
    if not plans:
        lines.extend(["No feasible deployment combination exists.", ""])
        return "\n".join(lines)

    for index, plan in enumerate(plans, start=1):
        lines.append(f"### Plan {index}: {' + '.join(plan.selected_ids) or '(empty)'}")
        lines.append("")
        lines.append(
            f"- Cost: `{_format_number(plan.cost)}` / " f"`{_format_number(constraints.capacity)}`"
        )
        lines.append(
            "- Severity score: "
            + ", ".join(f"{severity}={plan.score_dict()[severity]}" for severity in SEVERITY_ORDER)
        )
        retention_state = "pass" if not plan.missing_old_hit_ids else "FAIL"
        lines.append(
            f"- Retention: `{retention_state}` "
            f"({', '.join(plan.retained_old_hit_ids) or 'none'})"
        )
        lines.append(
            f"- False positives on labelled benign drills: "
            f"`{len(plan.false_positive_case_ids)}`"
        )
        lines.append("")
        lines.append("| Case | Label | Severity | Alert | Rules |")
        lines.append("|---|---|---|---|---|")
        for row in plan.alert_rows():
            lines.append(
                f"| `{row['case_id']}` | {row['label']} | {row['severity']} | "
                f"{'Y' if row['alerted'] else '.'} | "
                f"{', '.join(f'`{rule_id}`' for rule_id in row['rule_ids']) or '-'} |"
            )
        lines.append("")
        replay_ok = plan.replay() == plan.alert_rows()
        lines.append(
            f"Replay check: `{'pass' if replay_ok else 'FAIL'}` "
            f"(`SigmaMatcher` recomputation equals the cached alert rows)."
        )
        lines.append("")
        lines.append("| Uncovered case | Kind | Reason | Capable rules | Explanation |")
        lines.append("|---|---|---|---|---|")
        for uncovered in plan.uncovered:
            capable = ", ".join(uncovered.capable_rule_ids) or "-"
            lines.append(
                f"| `{uncovered.case_id}` | {uncovered.kind} | {uncovered.reason} | "
                f"{capable} | {uncovered.detail} |"
            )
        lines.append("")

    if len(plans) > 1:
        lines.extend(
            [
                "## Equal-Plan Tie",
                "",
                f"{len(plans)} plans are tied on severity coverage, total cost, and rule count. "
                "Each plan above carries its own replayed alert rows; prefer the one whose "
                "uncovered-case explanation is operationally cheaper to accept.",
                "",
            ]
        )

    if reproduce_command:
        lines.extend(
            [
                "## Reproduce",
                "",
                "```bash",
                reproduce_command,
                "```",
                "",
            ]
        )
    return "\n".join(lines)


def _planner_old_hits(plans: Sequence[DeploymentPlan]) -> tuple[str, ...]:
    if not plans:
        return ()
    plan = plans[0]
    return tuple(plan.retained_old_hit_ids) + tuple(plan.missing_old_hit_ids)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a Sigma rule coverage matrix and select constrained deployment plans."
    )
    parser.add_argument("scenario", help="Scenario YAML or JSON file")
    parser.add_argument("--coverage", help="Write the coverage matrix Markdown to this path")
    parser.add_argument("--json", help="Write full machine-readable results to this path")
    parser.add_argument("--report", help="Write the review report Markdown to this path")
    parser.add_argument("--quiet", action="store_true", help="Do not print the report")
    args = parser.parse_args(argv)

    scenario = (
        DeploymentScenario.from_json(args.scenario)
        if str(args.scenario).lower().endswith(".json")
        else DeploymentScenario.from_yaml(args.scenario)
    )
    planner = DeploymentPlanner(scenario)
    matrix = planner.coverage_matrix
    plans = planner.select_plans()
    command_parts = [f"python -m sigma.matching.deployment {args.scenario}"]
    if args.coverage:
        command_parts.append(f"  --coverage {args.coverage}")
    if args.json:
        command_parts.append(f"  --json {args.json}")
    if args.report:
        command_parts.append(f"  --report {args.report}")
    report = _render_report(scenario, matrix, plans, reproduce_command=" \\\n".join(command_parts))

    if args.coverage:
        Path(args.coverage).write_text(matrix.to_markdown() + "\n", encoding="utf-8")
    if args.report:
        Path(args.report).write_text(report + "\n", encoding="utf-8")
    if args.json:
        payload = {
            "title": scenario.title,
            "description": scenario.description,
            "constraints": scenario.constraints.to_dict(),
            "old_hit_ids": list(planner.old_hit_ids()),
            "coverage_matrix": matrix.to_dict(),
            "plans": [plan.to_dict(include_replay=True) for plan in plans],
        }
        Path(args.json).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    if not args.quiet:
        print(report)
    return 0 if plans else 2


if __name__ == "__main__":
    raise SystemExit(main())
