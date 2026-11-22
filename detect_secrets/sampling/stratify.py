"""Stratification, quota allocation and fixed-seed sample selection."""

from collections import defaultdict
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from .models import Finding
from .randomness import order_findings

StratumKey = Tuple[str, str]

DEFAULT_UNDER_REVIEW_THRESHOLD = 0.1


def build_strata(findings: Sequence[Finding]) -> Dict[StratumKey, List[Finding]]:
    """Group findings into exactly one (queue, primary detector) stratum each.

    A finding belongs to one stratum no matter how many plugins reported it,
    so plugin overlap can never inflate its sampling weight.
    """
    strata: Dict[StratumKey, List[Finding]] = defaultdict(list)
    for finding in findings:
        strata[finding.stratum_key].append(finding)
    for members in strata.values():
        members.sort(key=lambda finding: finding.finding_id)
    return dict(strata)


def allocate_evenly(
    strata: Dict[StratumKey, List[Finding]],
    sample_budget: int,
) -> Dict[StratumKey, int]:
    """Spread the manual-review budget round-robin across strata.

    Every stratum gets the same offer of a review slot; allocations differ
    only when a stratum runs out of findings. Ties resolve through the
    deterministic (queue, detector) order, so allocation is reproducible.
    """
    if sample_budget < 0:
        raise ValueError("sample_budget must be non-negative")

    population = {key: len(members) for key, members in strata.items()}
    allocation = {key: 0 for key in strata}
    ordered_keys = sorted(strata)

    remaining = min(sample_budget, sum(population.values()))
    while remaining > 0:
        progressed = False
        for key in ordered_keys:
            if remaining == 0:
                break
            if allocation[key] < population[key]:
                allocation[key] += 1
                remaining -= 1
                progressed = True
        if not progressed:
            break
    return allocation


def allocate_proportionally(
    strata: Dict[StratumKey, List[Finding]],
    sample_budget: int,
) -> Dict[StratumKey, int]:
    """Allocate slots in proportion to stratum population.

    Small strata receive few or zero slots, mirroring what happens when a
    review budget is distributed by raw volume: a small queue can then be
    almost unreviewed even though aggregate coverage looks healthy. The
    largest-remainder method keeps the total equal to the budget and uses a
    deterministic key order for every tie.
    """
    if sample_budget < 0:
        raise ValueError("sample_budget must be non-negative")

    population = {key: len(members) for key, members in strata.items()}
    total = sum(population.values())
    if total == 0:
        return {key: 0 for key in strata}

    budget = min(sample_budget, total)
    raw = {key: budget * population[key] / total for key in strata}
    allocation = {key: int(value) for key, value in raw.items()}
    leftovers = sorted(
        strata,
        key=lambda key: (raw[key] - allocation[key], key),
        reverse=True,
    )
    remaining = budget - sum(allocation.values())
    for key in leftovers:
        if remaining == 0:
            break
        if allocation[key] < population[key]:
            allocation[key] += 1
            remaining -= 1
    return allocation


def apply_queue_caps(
    allocation: Dict[StratumKey, int],
    strata: Dict[StratumKey, List[Finding]],
    queue_caps: Optional[Dict[str, int]],
) -> Dict[StratumKey, int]:
    """Cap how many slots each source queue may consume.

    This reproduces operational limits, for example a legacy queue that the
    team has decided not to staff. Unused cap is not silently redistributed,
    so the starved queue stays visible rather than being hidden by the
    coverage of other queues.
    """
    if not queue_caps:
        return dict(allocation)

    capped = dict(allocation)
    queue_used: Dict[str, int] = defaultdict(int)
    for key in sorted(strata):
        queue = key[0]
        if queue not in queue_caps:
            continue
        limit = queue_caps[queue]
        available = max(limit - queue_used[queue], 0)
        capped[key] = min(capped[key], available, len(strata[key]))
        queue_used[queue] += capped[key]
    return capped


ALLOCATORS: Dict[str, Callable] = {
    "even": allocate_evenly,
    "proportional": allocate_proportionally,
}


def allocate_sample(
    strata: Dict[StratumKey, List[Finding]],
    sample_budget: int,
    mode: str = "even",
    queue_caps: Optional[Dict[str, int]] = None,
) -> Dict[StratumKey, int]:
    """Allocate the review budget using the requested distribution mode."""
    if mode not in ALLOCATORS:
        raise ValueError(
            "unknown allocation mode: {} expected one of {}".format(
                mode,
                sorted(ALLOCATORS),
            ),
        )
    allocation = ALLOCATORS[mode](strata, sample_budget)
    return apply_queue_caps(allocation, strata, queue_caps)


def select_sample(
    strata: Dict[StratumKey, List[Finding]],
    allocation: Dict[StratumKey, int],
    seed: int,
) -> Dict[StratumKey, List[Finding]]:
    """Draw without replacement inside each stratum using fixed-seed ranks."""
    selected: Dict[StratumKey, List[Finding]] = {}
    for key in sorted(strata):
        quota = allocation.get(key, 0)
        ranked = order_findings(seed, strata[key])
        selected[key] = ranked[:quota]
    return selected


def under_reviewed_strata(
    strata: Dict[StratumKey, List[Finding]],
    allocation: Dict[StratumKey, int],
    threshold: float = DEFAULT_UNDER_REVIEW_THRESHOLD,
) -> List[StratumKey]:
    """Return strata whose planned sample fraction is below the threshold.

    This is computed per stratum, so a small queue with almost no sample is
    flagged even when the aggregate human coverage looks healthy.
    """
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")

    flagged: List[StratumKey] = []
    for key in sorted(strata):
        population = len(strata[key])
        if population == 0:
            continue
        if allocation.get(key, 0) / population < threshold:
            flagged.append(key)
    return flagged
