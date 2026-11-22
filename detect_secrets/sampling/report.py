"""Coverage and residual-uncertainty reporting, plus exception checks."""

import math
from typing import Any
from typing import Dict
from typing import List
from typing import Set

from .models import Finding
from .review import StratumReviewStats
from .stratify import StratumKey

Z_SCORE_95CI = 1.959963984540054


def wilson_interval(successes: int, trials: int) -> List[float]:
    """Wilson score interval for a binomial proportion, bounded to [0, 1]."""
    if trials == 0:
        return [0.0, 0.0]
    phat = successes / trials
    z = Z_SCORE_95CI
    denom = 1 + z * z / trials
    center = (phat + z * z / (2 * trials)) / denom
    margin = (
        z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
    ) / denom
    return [max(0.0, center - margin), min(1.0, center + margin)]


def build_stratum_row(
    key: StratumKey,
    stats: StratumReviewStats,
    under_reviewed: bool,
) -> Dict[str, Any]:
    """Serialise one stratum with its coverage and uncertainty figures."""
    interval = wilson_interval(
        stats.reviewed_in_sample,
        stats.sample_size,
    )
    return {
        "source_queue": key[0],
        "primary_detector": key[1],
        "population_size": stats.population_size,
        "sample_size": stats.sample_size,
        "sample_fraction": round(stats.sample_fraction, 6),
        "reviewed_findings": stats.reviewed_findings,
        "human_coverage": round(stats.human_coverage, 6),
        "unreviewed_findings": stats.unreviewed_findings,
        "review_rate_in_sample_95ci": [
            round(interval[0], 6),
            round(interval[1], 6),
        ],
        "under_reviewed": under_reviewed,
    }


def build_report(
    strata: Dict[StratumKey, List[Finding]],
    stats: Dict[StratumKey, StratumReviewStats],
    under_reviewed: Set[StratumKey],
) -> Dict[str, Any]:
    """Build the full report: aggregate view plus every stratum."""
    total_population = sum(item.population_size for item in stats.values())
    total_sample = sum(item.sample_size for item in stats.values())
    total_reviewed = sum(item.reviewed_findings for item in stats.values())

    aggregate = {
        "total_findings": total_population,
        "total_sampled": total_sample,
        "total_reviewed": total_reviewed,
        "aggregate_sample_fraction": round(
            total_sample / total_population if total_population else 0.0,
            6,
        ),
        "aggregate_human_coverage": round(
            total_reviewed / total_population if total_population else 0.0,
            6,
        ),
        "total_unreviewed": total_population - total_reviewed,
        "strata_under_reviewed": len(under_reviewed),
    }

    rows = [
        build_stratum_row(key, stats[key], key in under_reviewed)
        for key in sorted(strata)
    ]
    return {"aggregate": aggregate, "strata": rows}


def check_exception(
    finding_id: str,
    findings_by_id: Dict[str, Finding],
    selected_ids: Set[str],
    reviewed_ids: Set[str],
) -> Dict[str, Any]:
    """Let compliance verify whether a specific exception was missed.

    The answer is derived from the immutable finding id and the fixed plan,
    so it can be recomputed independently by anyone holding the seed.
    """
    finding = findings_by_id.get(finding_id)
    if finding is None:
        return {
            "finding_id": finding_id,
            "known": False,
            "in_sample": False,
            "reviewed": False,
            "missed_by_manual_review": True,
            "detail": "finding id is not present in the baseline input",
        }

    in_sample = finding_id in selected_ids
    reviewed = finding_id in reviewed_ids
    return {
        "finding_id": finding_id,
        "known": True,
        "source_queue": finding.source_queue,
        "primary_detector": finding.primary_detector,
        "detector_types": finding.detector_types,
        "plugin_hit_count": finding.plugin_hit_count,
        "in_sample": in_sample,
        "reviewed": reviewed,
        "missed_by_manual_review": in_sample and not reviewed,
        "not_in_sample": not in_sample,
        "detail": (
            "selected for the manual sample but no review annotation exists"
            if in_sample and not reviewed
            else "reviewed"
            if reviewed
            else "not drawn into the fixed-seed sample"
        ),
    }
