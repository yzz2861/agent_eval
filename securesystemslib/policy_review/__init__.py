"""Offline review of DSSE signing policies against control-domain ownership.

The package is intentionally read-only with respect to signing material: it
never loads private keys or touches a network. It takes:

1. a policy document listing every key combination that makes a DSSE envelope
   a valid release, and
2. a roster document listing, for every key id, the control domain(s) that
   actually hold it (with candidate-only ownership marked explicitly),

and reports the minimum number of domains whose joint control satisfies the
policy, the minimum number whose simultaneous absence blocks all releases, and
the ranges of those numbers while candidate ownership is unconfirmed.
"""

# ruff: noqa: F401
from securesystemslib.policy_review.models import (
    CandidateRange,
    KeyOwnership,
    Metric,
    Policy,
    PolicyReviewError,
    ResolutionResult,
    Roster,
    Rule,
    Witness,
)
from securesystemslib.policy_review.policy import load_policy, parse_policy
from securesystemslib.policy_review.review import review
from securesystemslib.policy_review.roster import load_roster, parse_roster

__all__ = [
    "CandidateRange",
    "KeyOwnership",
    "Metric",
    "Policy",
    "PolicyReviewError",
    "ResolutionResult",
    "Roster",
    "Rule",
    "Witness",
    "load_policy",
    "load_roster",
    "parse_policy",
    "parse_roster",
    "review",
]
