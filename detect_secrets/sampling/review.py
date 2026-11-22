"""Human review annotations and per-stratum coverage statistics."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from .models import Finding
from .stratify import StratumKey


def load_reviewed_ids(path: Optional[str]) -> Set[str]:
    """Load finding ids that a human has already reviewed.

    Accepts either a JSON list of finding ids or a JSON object whose keys are
    finding ids (values are ignored). Review records come from the human
    audit workflow, so the sampler can never make a finding look reviewed.
    """
    if path is None:
        return set()

    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, list):
        return {str(item) for item in data}
    if isinstance(data, dict):
        return {str(key) for key in data}
    raise ValueError("review file must be a JSON list or a JSON object")


@dataclass
class StratumReviewStats:
    """Coverage and residual-uncertainty numbers for one stratum."""

    population_size: int
    sample_size: int
    reviewed_findings: int
    reviewed_in_sample: int

    @property
    def sample_fraction(self) -> float:
        return self.sample_size / self.population_size if self.population_size else 0.0

    @property
    def human_coverage(self) -> float:
        return self.reviewed_findings / self.population_size if self.population_size else 0.0

    @property
    def unreviewed_findings(self) -> int:
        return self.population_size - self.reviewed_findings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "population_size": self.population_size,
            "sample_size": self.sample_size,
            "sample_fraction": round(self.sample_fraction, 6),
            "reviewed_findings": self.reviewed_findings,
            "reviewed_in_sample": self.reviewed_in_sample,
            "human_coverage": round(self.human_coverage, 6),
            "unreviewed_findings": self.unreviewed_findings,
        }


def summarize_strata(
    strata: Dict[StratumKey, List[Finding]],
    selected: Dict[StratumKey, List[Finding]],
    reviewed_ids: Set[str],
) -> Dict[StratumKey, StratumReviewStats]:
    """Compute review statistics independently for every stratum."""
    stats: Dict[StratumKey, StratumReviewStats] = {}
    for key, members in strata.items():
        selected_ids = {finding.finding_id for finding in selected.get(key, [])}
        reviewed = sum(
            1 for finding in members if finding.finding_id in reviewed_ids
        )
        reviewed_in_sample = sum(
            1
            for finding in members
            if finding.finding_id in selected_ids
            and finding.finding_id in reviewed_ids
        )
        stats[key] = StratumReviewStats(
            population_size=len(members),
            sample_size=len(selected_ids),
            reviewed_findings=reviewed,
            reviewed_in_sample=reviewed_in_sample,
        )
    return stats
