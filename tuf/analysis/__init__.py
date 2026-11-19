# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline key-compromise analysis for TUF repositories.

The analysis package answers a supply-chain review question that cannot be
answered by looking at a single role threshold at a time:

    Which is the smallest set of signing keys an attacker must compromise to
    publish an unauthorized update for a specific target path?

Roles are not independent lines of defense. The same keyid may be reused
across several roles and delegation edges, and a target may be reachable
through more than one delegation path. :mod:`tuf.analysis` therefore solves
role thresholds, the delegation graph and shared keyids jointly: a key that
unlocks several gates is counted exactly once.

The module is purely read-only. It consumes already verified metadata
(typically produced by normal signature verification) and public key
metadata only. It never touches private keys and it does not alter metadata
or the regular signature verification code paths.
"""

from tuf.analysis.compromise import (
    LIMIT_DEFAULTS,
    AnalysisLimits,
    Assumption,
    CompromiseAnalysis,
    CompromiseLimitReachedError,
    MinimalityWitness,
    analyze_target_compromise,
    exhaustive_minimum_keyids,
)

__all__ = [
    "LIMIT_DEFAULTS",
    "AnalysisLimits",
    "Assumption",
    "CompromiseAnalysis",
    "CompromiseLimitReachedError",
    "MinimalityWitness",
    "analyze_target_compromise",
    "exhaustive_minimum_keyids",
]
