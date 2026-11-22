"""Offline stratified sampling of detect-secrets findings.

The package turns a detect-secrets baseline (or an equivalent findings
export) into a reproducible manual-review sampling plan. A finding is one
distinct (filename, line_number, hashed_secret) location regardless of how
many plugins reported it, so duplicate plugin hits can never inflate its
chance of being sampled.
"""

from .loader import load_findings
from .loader import load_queue_map
from .models import Finding
from .planner import SamplingPlan
from .planner import build_plan
from .planner import verify_exception
from .randomness import stable_rank

__all__ = [
    "Finding",
    "SamplingPlan",
    "build_plan",
    "load_findings",
    "load_queue_map",
    "stable_rank",
    "verify_exception",
]
