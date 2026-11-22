"""Deterministic, seed-replayable ordering for offline sampling.

The :mod:`random` module is deliberately avoided so global interpreter state
can never change the result. Each rank is derived from an explicit integer
seed and the stable finding identifier via SHA-256, giving identical draws
on every machine and Python version.
"""

import hashlib
import struct
from typing import Sequence

from .models import Finding


def stable_rank(seed: int, finding_id: str) -> bytes:
    """Return the deterministic ranking digest for one finding id."""
    if not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")

    digest = hashlib.sha256()
    digest.update(struct.pack(">Q", seed))
    digest.update(b"|")
    digest.update(finding_id.encode("utf-8"))
    return digest.digest()


def order_findings(seed: int, findings: Sequence[Finding]) -> list:
    """Order findings by their fixed-seed rank, without replacement.

    Finding ids are unique by construction, so the SHA-256 ordering is a
    total order and never needs a platform-dependent tie breaker.
    """
    return sorted(findings, key=lambda finding: stable_rank(seed, finding.finding_id))
