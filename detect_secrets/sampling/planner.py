"""End-to-end sampling plan construction and fixed-seed replay."""

from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from .loader import load_findings
from .loader import load_queue_map
from .models import Finding
from .report import build_report
from .report import check_exception
from .review import load_reviewed_ids
from .review import summarize_strata
from .stratify import DEFAULT_UNDER_REVIEW_THRESHOLD
from .stratify import allocate_sample
from .stratify import build_strata
from .stratify import select_sample
from .stratify import under_reviewed_strata


@dataclass
class SamplingPlan:
    """A fully replayable sampling plan and its coverage report."""

    seed: int
    sample_budget: int
    under_review_threshold: float
    findings: List[Finding]
    selected_ids: Set[str]
    plan: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return self.plan


def build_plan(
    baseline_path: str,
    seed: int,
    sample_budget: int,
    queue_map_path: Optional[str] = None,
    reviewed_path: Optional[str] = None,
    under_review_threshold: float = DEFAULT_UNDER_REVIEW_THRESHOLD,
    allocation_mode: str = "even",
    queue_caps: Optional[Dict[str, int]] = None,
) -> SamplingPlan:
    """Build the stratified plan, report and selected finding list.

    Re-running with the same baseline, seed, budget and allocation settings
    returns byte-identical sampling decisions; only the review annotations
    may change over time.
    """
    queue_map = load_queue_map(queue_map_path)
    findings = load_findings(baseline_path, queue_map)
    reviewed_ids = load_reviewed_ids(reviewed_path)

    strata = build_strata(findings)
    allocation = allocate_sample(
        strata,
        sample_budget,
        mode=allocation_mode,
        queue_caps=queue_caps,
    )
    selected = select_sample(strata, allocation, seed)
    selected_ids = {
        finding.finding_id
        for members in selected.values()
        for finding in members
    }
    stats = summarize_strata(strata, selected, reviewed_ids)
    flagged = set(
        under_reviewed_strata(strata, allocation, under_review_threshold),
    )
    report = build_report(strata, stats, flagged)

    serialised_selection = {
        "{}|{}".format(key[0], key[1]): [
            finding.finding_id for finding in selected[key]
        ]
        for key in sorted(strata)
    }
    plan = {
        "seed": seed,
        "sample_budget": sample_budget,
        "allocation_mode": allocation_mode,
        "queue_caps": queue_caps or {},
        "under_review_threshold": under_review_threshold,
        "inputs": {
            "baseline_path": baseline_path,
            "queue_map_path": queue_map_path,
            "reviewed_path": reviewed_path,
        },
        "allocation": {
            "{}|{}".format(key[0], key[1]): allocation[key]
            for key in sorted(strata)
        },
        "selection": serialised_selection,
        "report": report,
    }
    return SamplingPlan(
        seed=seed,
        sample_budget=sample_budget,
        under_review_threshold=under_review_threshold,
        findings=findings,
        selected_ids=selected_ids,
        plan=plan,
    )


def verify_exception(
    plan: SamplingPlan,
    finding_id: str,
    reviewed_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Recompute the status of one exception id against an existing plan."""
    reviewed_ids = load_reviewed_ids(reviewed_path)
    findings_by_id = {
        finding.finding_id: finding for finding in plan.findings
    }
    return check_exception(
        finding_id,
        findings_by_id,
        plan.selected_ids,
        reviewed_ids,
    )
