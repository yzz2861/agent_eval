"""Offline review orchestration.

A review cross-checks the policy against the frozen roster, evaluates both
metrics on the confirmed ownership view, and -- when some keys only have
candidate owners -- enumerates every possible assignment to report the range
each metric can take, with the assignments producing the extremes kept for
manual confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product

from securesystemslib.policy_review.metrics import (
    minimum_blocking_domains,
    minimum_satisfying_domains,
)
from securesystemslib.policy_review.models import (
    CandidateRange,
    Metric,
    Policy,
    PolicyReviewError,
    ResolutionResult,
    Roster,
)

# Pseudo-domain used in the confirmed view for keys with no confirmed owner.
PENDING_DOMAIN = "UNASSIGNED-PENDING-CONFIRMATION"

MAX_ENUMERATED_ASSIGNMENTS = 100_000


@dataclass
class ReviewReport:
    """Structured result of one policy review."""

    policy_id: str
    roster_id: str
    frozen_at: str | None
    combination_count: int
    distinct_key_count: int
    domain_count: int
    warnings: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    unassigned_keyids: list[str] = field(default_factory=list)
    confirmed_satisfying: Metric | None = None
    confirmed_blocking: Metric | None = None
    candidate_range: CandidateRange | None = None
    policy: Policy | None = None
    roster: Roster | None = None
    confirmed_key_domains: dict[str, frozenset[str]] = field(default_factory=dict)


def review(policy: Policy, roster: Roster) -> ReviewReport:
    """Cross-check policy and roster and compute all review metrics."""
    _cross_check(policy, roster)

    warnings: list[str] = []
    findings: list[str] = []
    unassigned = sorted(
        keyid for keyid in policy.keyids if roster.ownership[keyid].unresolved
    )
    if unassigned:
        warnings.append(
            "keys with no confirmed owner (candidate-only): " + ", ".join(unassigned)
        )

    confirmed_view = _confirmed_view(policy, roster)
    satisfying = minimum_satisfying_domains(policy, confirmed_view)
    blocking = minimum_blocking_domains(policy, confirmed_view)

    unresolved = [k for k in unassigned if roster.ownership[k].candidates]
    candidate_range = None
    if unresolved:
        candidate_range = _enumerate_candidates(policy, roster, unresolved, warnings)

    report = ReviewReport(
        policy_id=policy.policy_id,
        roster_id=roster.roster_id,
        frozen_at=roster.frozen_at,
        combination_count=len(policy.rules),
        distinct_key_count=len(policy.keyids),
        domain_count=len(roster.domains),
        warnings=warnings,
        findings=findings,
        unassigned_keyids=unassigned,
        confirmed_satisfying=satisfying,
        confirmed_blocking=blocking,
        candidate_range=candidate_range,
        policy=policy,
        roster=roster,
        confirmed_key_domains=confirmed_view,
    )
    _collect_findings(report)
    return report


def _cross_check(policy: Policy, roster: Roster) -> None:
    missing = sorted(policy.keyids - frozenset(roster.ownership))
    if missing:
        raise PolicyReviewError(
            "roster has no entry for policy key id(s): " + ", ".join(missing)
        )
    extra = sorted(frozenset(roster.ownership) - policy.keyids)
    if extra:
        raise PolicyReviewError(
            "roster lists key id(s) not used by the policy: " + ", ".join(extra)
        )


def _confirmed_view(
    policy: Policy, roster: Roster
) -> dict[str, frozenset[str]]:
    view: dict[str, frozenset[str]] = {}
    for keyid in sorted(policy.keyids):
        ownership = roster.ownership[keyid]
        if ownership.confirmed:
            view[keyid] = ownership.confirmed
        else:
            # Explicit placeholder keeps the key visible instead of silently
            # dropping it; metrics flag that the view is not fully confirmed.
            view[keyid] = frozenset({PENDING_DOMAIN})
    return view


def _enumerate_candidates(
    policy: Policy,
    roster: Roster,
    unresolved: list[str],
    warnings: list[str],
) -> CandidateRange:
    options = [sorted(roster.ownership[keyid].candidates) for keyid in unresolved]
    total = 1
    for choices in options:
        total *= len(choices)

    exhaustive = total <= MAX_ENUMERATED_ASSIGNMENTS
    if not exhaustive:
        warnings.append(
            f"candidate assignments ({total}) exceed cap "
            f"{MAX_ENUMERATED_ASSIGNMENTS}; range bounds are not exhaustive"
        )

    base = {
        keyid: roster.ownership[keyid].confirmed
        for keyid in policy.keyids
        if roster.ownership[keyid].confirmed
    }
    best: ResolutionResult | None = None
    worst: ResolutionResult | None = None
    enumerated = 0
    for picked in product(*options):
        if enumerated >= MAX_ENUMERATED_ASSIGNMENTS:
            break
        assignment = dict(zip(unresolved, picked))
        concrete = dict(base)
        for keyid, domain in assignment.items():
            concrete[keyid] = frozenset({domain})
        satisfying = minimum_satisfying_domains(policy, concrete)
        blocking = minimum_blocking_domains(policy, concrete)
        if satisfying.value is None or blocking.value is None:
            raise PolicyReviewError(
                "candidate assignment produced an unevaluable metric"
            )
        result = ResolutionResult(assignment, satisfying.value, blocking.value)
        enumerated += 1
        best, worst = _update_extremes(best, worst, result)

    assert best is not None and worst is not None
    return CandidateRange(
        unresolved_keyids=tuple(unresolved),
        exhaustive=exhaustive,
        enumerated=enumerated,
        total_assignments=total,
        satisfying_min=best.satisfying,
        satisfying_max=worst.satisfying,
        blocking_min=best.blocking,
        blocking_max=worst.blocking,
        best_resolution=best,
        worst_resolution=worst,
    )


def _update_extremes(
    best: ResolutionResult | None,
    worst: ResolutionResult | None,
    result: ResolutionResult,
) -> tuple[ResolutionResult, ResolutionResult]:
    # "Best" for an attacker = most concentrated (smallest satisfying set);
    # "worst" = most dispersed. Blocking values travel with the same
    # assignment so the range is backed by a real, checkable resolution.
    if best is None or result.satisfying < best.satisfying:
        best = result
    if worst is None or result.satisfying > worst.satisfying:
        worst = result
    assert best is not None and worst is not None
    return best, worst


def _collect_findings(report: ReviewReport) -> None:
    assert report.policy is not None and report.roster is not None
    roster = report.roster
    seen: set[str] = set()

    def add_finding(message: str) -> None:
        if message not in seen:
            seen.add(message)
            report.findings.append(message)

    # Finding 1: a single confirmed domain holds enough keys to satisfy a rule.
    for combo, rule_ids in sorted(report.policy.rule_index.items()):
        for domain in sorted(roster.domains):
            held = {
                keyid
                for keyid in combo
                if domain in roster.ownership[keyid].confirmed
            }
            if held == set(combo):
                joined = ", ".join(rule_ids)
                add_finding(
                    f"shared-owner concentration: domain {domain!r} alone "
                    f"holds every key "
                    f"of rule(s) {joined}; one domain can satisfy the rule"
                )

    # Finding 2: one confirmed domain is the sole holder of some policy key.
    for keyid in sorted(report.policy.keyids):
        confirmed = roster.ownership[keyid].confirmed
        if len(confirmed) == 1:
            domain = next(iter(confirmed))
            add_finding(
                f"single point of failure: key {keyid!r} is held only "
                f"by domain {domain!r}"
            )

    # Finding 3: the confirmed view cannot complete any combination.
    satisfying = report.confirmed_satisfying
    if satisfying is not None and satisfying.value is None:
        report.findings.append(
            "no combination can be completed with confirmed owners; release depends on "
            "unconfirmed candidate ownership"
        )
