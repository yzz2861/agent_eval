"""Rule comparison backend: find and reduce programs on which two rule
versions disagree within a bounded AST subset.

The search is deliberately finite. When it finds no differing program this
module never claims the rules are equivalent; it only reports that no
difference was observed inside the explored, bounded subset.
"""

from __future__ import annotations

import dataclasses
import time
from typing import Dict, Iterable, List, Optional, Tuple

from . import language, reducer, runner


DEFAULT_BUDGET_SECONDS = 20.0
DEFAULT_MAX_PROGRAMS = 4000
DEFAULT_MAX_WITNESSES = 3


# Difference categories. Alerts and rule exceptions live in disjoint
# categories so a crashed rule is never conflated with "no warning".
ALERT_REMOVED = "alert_removed"        # old warned, new silent -> false negative risk
ALERT_ADDED = "alert_added"            # new warned, old silent -> false positive risk
ALERT_CHANGED = "alert_changed"        # both warned, different alert identities
ERROR_INTRODUCED = "error_introduced"  # new rule raises where old did not
ERROR_CLEARED = "error_cleared"        # old rule raised, new no longer does

DIFF_CATEGORIES = frozenset((
    ALERT_REMOVED, ALERT_ADDED, ALERT_CHANGED,
    ERROR_INTRODUCED, ERROR_CLEARED,
))

CATEGORY_MEANING = {
    ALERT_REMOVED: "old version warned, new version is silent (possible false negative)",
    ALERT_ADDED: "new version warns where old was silent (possible false positive)",
    ALERT_CHANGED: "both versions warn, but on different findings",
    ERROR_INTRODUCED: "new rule raises an exception where the old rule did not",
    ERROR_CLEARED: "old rule raised an exception that the new rule no longer raises",
}


@dataclasses.dataclass(frozen=True)
class Budget:
    """Hard caps keeping the comparison finite and within the time limit."""

    deadline_seconds: float = DEFAULT_BUDGET_SECONDS
    max_programs: int = DEFAULT_MAX_PROGRAMS
    max_witnesses: int = DEFAULT_MAX_WITNESSES


def classify(old_result, new_result):
    """Difference category for one program, or None when identical."""
    old_has_error = bool(old_result.errors)
    new_has_error = bool(new_result.errors)
    if old_has_error and not new_has_error:
        return ERROR_CLEARED
    if new_has_error and not old_has_error:
        return ERROR_INTRODUCED
    if old_has_error and new_has_error:
        if old_result.error_identities() == new_result.error_identities():
            # Same crashes and, checked below, same alerts.
            pass
        else:
            return ALERT_CHANGED
    old_ids = old_result.alert_identities()
    new_ids = new_result.alert_identities()
    if old_ids == new_ids and old_result.error_identities() == new_result.error_identities():
        return None
    if old_ids == new_ids:
        return ALERT_CHANGED
    if not old_ids:
        return ALERT_ADDED
    if not new_ids:
        return ALERT_REMOVED
    return ALERT_CHANGED


# Public alias for callers that think in terms of an enum-like namespace.
class DifferenceCategory(object):
    ALERT_REMOVED = ALERT_REMOVED
    ALERT_ADDED = ALERT_ADDED
    ALERT_CHANGED = ALERT_CHANGED
    ERROR_INTRODUCED = ERROR_INTRODUCED
    ERROR_CLEARED = ERROR_CLEARED


@dataclasses.dataclass
class Difference:
    """A single reduced, replayable difference between the rule revisions."""

    category: str
    source: str
    old_result: runner.RunResult
    new_result: runner.RunResult
    premises: List[str]
    rule_locations: List[str]
    generation_step: int
    reduction_steps: int

    def to_dict(self):
        return {
            "category": self.category,
            "category_meaning": CATEGORY_MEANING[self.category],
            "program": self.source,
            "premises": self.premises,
            "rule_locations": self.rule_locations,
            "old": self.old_result.to_dict(),
            "new": self.new_result.to_dict(),
            "generation_step": self.generation_step,
            "reduction_steps": self.reduction_steps,
        }


@dataclasses.dataclass
class DiffReport:
    old_rules: List[str]
    new_rules: List[str]
    budget_seconds: float
    elapsed_seconds: float
    program_budget: int
    programs_evaluated: int
    truncated: bool
    coverage: language.Coverage
    differences: List[Difference]
    category_counts: Dict[str, int]
    alerts_removed: List[Dict]
    alerts_added: List[Dict]
    old_error_count: int
    new_error_count: int

    @property
    def difference_found(self):
        return bool(self.differences)

    def equivalence_statement(self):
        """Bounded search is never an equivalence proof."""
        if self.difference_found:
            return ("Differences were found inside the bounded subset; the "
                    "rule versions are NOT equivalent on that subset.")
        return (
            "No difference was found within the bounded AST subset "
            "({n} program(s) explored). This is a bounded exploration "
            "result, NOT a proof of equivalence: programs outside this "
            "finite subset were not examined.".format(n=self.programs_evaluated)
        )

    def to_dict(self):
        return {
            "old_rules": self.old_rules,
            "new_rules": self.new_rules,
            "budget_seconds": self.budget_seconds,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "program_budget": self.program_budget,
            "programs_evaluated": self.programs_evaluated,
            "truncated": self.truncated,
            "difference_found": self.difference_found,
            "equivalence_statement": self.equivalence_statement(),
            "coverage": self.coverage.as_dict(),
            "category_counts": self.category_counts,
            "alert_set_changes": {
                "removed": self.alerts_removed,
                "added": self.alerts_added,
            },
            "exception_counts": {
                "old": self.old_error_count,
                "new": self.new_error_count,
            },
            "differences": [diff.to_dict() for diff in self.differences],
        }


def _rule_names(rules):
    return [runner.rule_name(rule) for rule in rules]


def _locations(old_result, new_result):
    locations = set()
    for result in (old_result, new_result):
        for alert in result.alerts:
            locations.add(alert.rule_location)
        for error in result.errors:
            locations.add(error.rule_location)
    return sorted(locations)


def _classify_source(source, old_rules, new_rules):
    old_result, new_result = runner.compare(source, old_rules, new_rules)
    return classify(old_result, new_result)


def compare_rules(old_rules, new_rules, subset=None, budget=None):
    """Generate, classify and reduce programs distinguishing two rule sets.

    :param old_rules: iterable of linter classes/objects (dlint protocol).
    :param new_rules: the refactored rule set using the same protocol.
    :param subset: BoundedSubset instance (defaults to the fixed SUBSET).
    :param budget: Budget caps (time, program count, witnesses per category).
    """
    subset = subset or language.SUBSET
    budget = budget or Budget()
    start = time.monotonic()
    deadline = start + budget.deadline_seconds

    def time_left():
        return time.monotonic() < deadline

    found = {}
    category_counts = {category: 0 for category in DIFF_CATEGORIES}
    removed_alerts = {}
    added_alerts = {}
    old_error_count = 0
    new_error_count = 0
    evaluated = 0
    truncated = False
    step = 0

    for source in subset.iter_programs():
        step += 1
        if evaluated >= budget.max_programs or not time_left():
            truncated = True
            break
        evaluated += 1
        old_result, new_result = runner.compare(source, old_rules, new_rules)
        old_error_count += len(old_result.errors)
        new_error_count += len(new_result.errors)

        new_alert_ids = new_result.alert_identities()
        old_alert_ids = old_result.alert_identities()
        for alert in old_result.alerts:
            if alert.identity() not in new_alert_ids:
                removed_alerts.setdefault(alert.identity(), alert.to_dict())
        for alert in new_result.alerts:
            if alert.identity() not in old_alert_ids:
                added_alerts.setdefault(alert.identity(), alert.to_dict())

        category = classify(old_result, new_result)
        if category is None:
            continue
        category_counts[category] += 1
        bucket = found.setdefault(category, [])
        if len(bucket) >= budget.max_witnesses:
            continue

        classify_fn = lambda src: _classify_source(src, old_rules, new_rules)
        reduced_source, reduction_steps = reducer.reduce_witness(
            source, category, classify_fn, time_left
        )
        reduced_old, reduced_new = runner.compare(
            reduced_source, old_rules, new_rules
        )
        bucket.append(Difference(
            category=category,
            source=reduced_source,
            old_result=reduced_old,
            new_result=reduced_new,
            premises=language.extract_premises(reduced_source),
            rule_locations=_locations(reduced_old, reduced_new),
            generation_step=step,
            reduction_steps=reduction_steps,
        ))

    differences = []
    for category in sorted(found):
        differences.extend(found[category])

    return DiffReport(
        old_rules=_rule_names(old_rules),
        new_rules=_rule_names(new_rules),
        budget_seconds=budget.deadline_seconds,
        elapsed_seconds=time.monotonic() - start,
        program_budget=budget.max_programs,
        programs_evaluated=evaluated,
        truncated=truncated,
        coverage=subset.coverage(),
        differences=differences,
        category_counts={k: v for k, v in category_counts.items() if v},
        alerts_removed=list(removed_alerts.values()),
        alerts_added=list(added_alerts.values()),
        old_error_count=old_error_count,
        new_error_count=new_error_count,
    )


def replay(source, old_rules, new_rules):
    """Deterministically re-evaluate a program; returns (category, results)."""
    old_result, new_result = runner.compare(source, old_rules, new_rules)
    return classify(old_result, new_result), old_result, new_result


def uncovered_features(features, subset=None):
    """Declare requested AST features that fall outside the subset."""
    subset = subset or language.SUBSET
    _, uncovered = subset.declare_coverage(list(features))
    return uncovered


def render_text(report):
    """Human-readable summary used by the CLI."""
    lines = []
    lines.append("rule-diff report")
    lines.append("  old rules: {}".format(", ".join(report.old_rules)))
    lines.append("  new rules: {}".format(", ".join(report.new_rules)))
    lines.append("  programs evaluated: {}".format(report.programs_evaluated))
    lines.append("  elapsed: {:.3f}s (budget {}s)".format(
        report.elapsed_seconds, report.budget_seconds))
    lines.append("  truncated by budget: {}".format(report.truncated))
    lines.append("  category counts: {}".format(report.category_counts))
    lines.append("  exceptions old/new: {}/{}".format(
        report.old_error_count, report.new_error_count))
    lines.append("  alert changes -> removed: {}, added: {}".format(
        len(report.alerts_removed), len(report.alerts_added)))
    for diff in report.differences:
        lines.append("")
        lines.append("  [{}] {}".format(diff.category,
                                        CATEGORY_MEANING[diff.category]))
        lines.append("    locations: {}".format("; ".join(diff.rule_locations)))
        for premise in diff.premises:
            lines.append("    premise: {}".format(premise))
        for line in diff.source.splitlines():
            lines.append("    | {}".format(line))
    lines.append("")
    lines.append(report.equivalence_statement())
    lines.append(report.coverage.uncovered_note)
    return "\n".join(lines)
