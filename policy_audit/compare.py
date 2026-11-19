"""Compare two policy states and report which deployment scope changes hands.

Both states are analysed over the union of their finite domains, so a
priority swap (or any other edit) can be pinned to concrete points of the
deployment space, each with a verifiable match example.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .analyze import Context, _validate_rule, _winner, build_domain
from .loader import load_policy


@dataclass
class ScopeChange:
    """A region of the deployment space whose winning rule changed."""

    environment: object
    old_winner: Optional[str]
    new_winner: Optional[str]
    points: int
    example: Context


def _effective_rules(paths):
    """Load a policy state and keep only rules inside the analysis language."""
    policy = load_policy(paths)
    analyzable = []
    for entry in policy.rules:
        if _validate_rule(entry) is None:
            analyzable.append(entry)
    return policy, analyzable


def compare_policies(old_paths, new_paths) -> tuple:
    """Return (changes, old_policy, new_policy).

    ``changes`` is a list of ScopeChange, one per (environment, old winner,
    new winner) region whose effective rule differs between the two states.
    """
    old_policy, old_rules = _effective_rules(old_paths)
    new_policy, new_rules = _effective_rules(new_paths)

    declared = new_policy.data.get("environments") or old_policy.data.get(
        "environments"
    )
    if not isinstance(declared, list):
        declared = None
    domain = build_domain(
        [e.data for e in old_rules] + [e.data for e in new_rules], declared
    )

    regions = {}
    for context in domain:
        old_winner = _winner(old_rules, context)
        new_winner = _winner(new_rules, context)
        old_id = old_winner.rule_id if old_winner else None
        new_id = new_winner.rule_id if new_winner else None
        if old_id == new_id:
            continue
        key = (context.environment, old_id, new_id)
        if key not in regions:
            regions[key] = ScopeChange(
                environment=context.environment,
                old_winner=old_id,
                new_winner=new_id,
                points=0,
                example=context,
            )
        regions[key].points += 1

    changes = sorted(
        regions.values(),
        key=lambda c: (repr(c.environment), repr(c.old_winner), repr(c.new_winner)),
    )
    return changes, old_policy, new_policy
