"""Property checks, deterministic runner and greedy shrinker.

The engine is deliberately self-contained (no Hypothesis, no network):

* :func:`run_property` drives a fixed number of generated documents through a
  loader and compares the import with the independent tri-state contract;
* :func:`shrink` greedily reduces a failing document to a small, hand-checkable
  shape that still fails;
* :class:`PropertyFailure` carries both the seed and the reduced YAML so a
  report can be filed without rerunning the whole campaign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

import yaml

from .contract import (
    Decision,
    Policy,
    PolicyError,
)
from .strategy import (
    AMBIGUOUS_TOKENS,
    ANCHOR_NAMES,
    FIELDS,
    DocumentSpec,
    PolicySpec,
    Scalar,
    documents,
)

#: A loader is any callable taking YAML text and returning list[Policy].
Loader = Callable[[str], List[Policy]]


@dataclass
class PropertyFailure:
    """A reproducible, already-shrunk property violation."""

    seed: int
    index: int
    kind: str
    message: str
    document: DocumentSpec
    yaml_text: str
    details: List[str] = field(default_factory=list)

    def render_report(self) -> str:
        lines = [
            f"PROPERTY FAILED ({self.kind})",
            f"  seed={self.seed} iteration={self.index}",
            f"  reason: {self.message}",
            "  reduced YAML:",
        ]
        for yaml_line in self.yaml_text.rstrip("\n").splitlines():
            lines.append(f"    | {yaml_line}")
        if self.details:
            lines.append("  trace:")
            lines.extend(f"    - {detail}" for detail in self.details)
        return "\n".join(lines)


@dataclass
class CheckOutcome:
    """Result of checking one document against the contract."""

    ok: bool
    kind: str
    message: str
    details: List[str] = field(default_factory=list)


def _expected_decisions(spec: DocumentSpec) -> List[Optional[Decision]]:
    """Contract expectation for every rendered policy, including aliases.

    An alias repeats the anchor policy's mapping, so it repeats the same
    expectation. Ambiguous scalars have ``None`` expected state and must be
    rejected rather than imported.
    """

    base = [policy.expected_decision for policy in spec.policies]
    if spec.alias_count:
        base.extend([base[0]] * spec.alias_count)
    return base


def check_document(load: Loader, spec: DocumentSpec) -> CheckOutcome:
    """Compare the import of ``spec`` against the independent contract."""

    text = spec.render()
    expected = _expected_decisions(spec)
    ambiguous_index = next(
        (idx for idx, decision in enumerate(expected) if decision is None), None
    )
    ambiguous_policy_index = next(
        (
            idx
            for idx, policy in enumerate(spec.policies)
            if policy.scalar.ambiguous
        ),
        None,
    )

    if ambiguous_index is not None:
        # Contract: an ambiguous scalar is un-importable. A compliant loader
        # raises a PolicyError; anything that returns a Policy swallowed it.
        try:
            imported = load(text)
        except PolicyError as error:
            return CheckOutcome(True, "ambiguous-rejected", str(error))
        except Exception as error:  # pragma: no cover - defensive
            return CheckOutcome(
                False,
                "unexpected-exception",
                f"non-contract exception {type(error).__name__}: {error}",
            )

        # The loader returned instead of rejecting: locate the swallowed state.
        details = [
            f"policies[{ambiguous_index}] carried an ambiguous decision scalar",
        ]
        if ambiguous_policy_index is not None:
            scalar = spec.policies[ambiguous_policy_index].scalar
            details.append(
                f"rendered token: {scalar.token!r} (style={scalar.style})"
            )
            try:
                decoded = yaml.safe_load(scalar.token)
                details.append(
                    f"yaml decodes it to {decoded!r} ({type(decoded).__name__}), "
                    "which is not any of the three legal states"
                )
            except yaml.YAMLError as error:
                details.append(f"token is not standalone-valid YAML: {error}")
        if ambiguous_index < len(imported):
            swallowed = imported[ambiguous_index].decision
            details.append(
                f"loader returned Decision.{swallowed.name} for the ambiguous slot"
            )
        return CheckOutcome(
            False,
            "swallowed-decision",
            "an ambiguous decision was imported instead of rejected",
            details,
        )

    # Contract: every scalar is canonical, so import must fully round-trip.
    try:
        imported = load(text)
    except PolicyError as error:
        return CheckOutcome(
            False,
            "spurious-rejection",
            f"legal document rejected: {error}",
        )

    if len(imported) != len(expected):
        return CheckOutcome(
            False,
            "cardinality",
            f"expected {len(expected)} policies, loader returned {len(imported)}",
        )

    for index, (policy, want) in enumerate(zip(imported, expected)):
        if not isinstance(policy, Policy):
            return CheckOutcome(
                False, "type", f"policies[{index}] is not a contract Policy"
            )
        if policy.decision is not want:
            return CheckOutcome(
                False,
                "state-collapse",
                f"policies[{index}] expected Decision.{want.name}, "
                f"got Decision.{policy.decision.name}",
                [f"id={policy.policy_id!r} reviewer={policy.reviewer!r}"],
            )
    return CheckOutcome(True, "round-trip", "all three states preserved")


def run_property(
    load: Loader, *, seed: int, iterations: int
) -> Optional[PropertyFailure]:
    """Generate documents until a violation is found, then shrink it."""

    specs = documents(seed, iterations)
    for index, spec in enumerate(specs):
        outcome = check_document(load, spec)
        if outcome.ok:
            continue
        reduced = shrink(load, spec)
        reduced_outcome = check_document(load, reduced)
        return PropertyFailure(
            seed=seed,
            index=index,
            kind=reduced_outcome.kind,
            message=reduced_outcome.message,
            document=reduced,
            yaml_text=reduced.render(),
            details=reduced_outcome.details,
        )
    return None


# --------------------------------------------------------------------------- #
# Shrinking
# --------------------------------------------------------------------------- #


def _still_fails(load: Loader, candidate: DocumentSpec) -> bool:
    try:
        return not check_document(load, candidate).ok
    except Exception:  # pragma: no cover - a crash is not a valid reduction
        return False


def _complexity(spec: DocumentSpec) -> tuple:
    """Lexicographic measure of document size; every shrink must lower it."""

    style_rank = {"plain": 0, "single": 1, "double": 2}
    scalar_costs = []
    for policy in spec.policies:
        order_rank = 0 if policy.key_order == tuple(FIELDS) else 1
        scalar_costs.append(
            (len(policy.scalar.token), style_rank[policy.scalar.style], order_rank)
        )
    anchor_rank = 0 if spec.anchor_name is None else (
        1 + sorted(ANCHOR_NAMES).index(spec.anchor_name)
    )
    return (
        len(spec.policies),
        spec.alias_count,
        anchor_rank,
        tuple(scalar_costs),
        len(spec.render()),
    )


def _clone(spec: DocumentSpec, **changes) -> DocumentSpec:
    data = {
        "policies": spec.policies,
        "anchor_name": spec.anchor_name,
        "alias_count": spec.alias_count,
        "seed": spec.seed,
        "extras": list(spec.extras),
    }
    data.update(changes)
    return DocumentSpec(**data)


def _with_policy(spec: DocumentSpec, index: int, policy: PolicySpec) -> DocumentSpec:
    policies = list(spec.policies)
    policies[index] = policy
    return _clone(spec, policies=policies)


def _style_token(token: str, style: str) -> str:
    if style == "plain":
        return token
    if style == "single":
        return chr(39) + token.replace(chr(39), chr(39) * 2) + chr(39)
    escaped = token.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))
    return chr(34) + escaped + chr(34)


def _candidates(spec: DocumentSpec) -> List[DocumentSpec]:
    """All one-step reductions, ordered from smallest complexity to largest."""

    found: List[DocumentSpec] = []

    if spec.alias_count:
        found.append(_clone(spec, alias_count=0))

    if spec.anchor_name is not None and spec.alias_count == 0:
        found.append(_clone(spec, anchor_name=None))

    # Remove any single policy (not just a prefix) so a failing scalar that
    # lives later in the list can still shrink down to a one-policy repro.
    if len(spec.policies) > 1:
        for drop in range(len(spec.policies)):
            kept = spec.policies[:drop] + spec.policies[drop + 1:]
            found.append(_clone(spec, policies=kept, alias_count=0))

    canonical_order = tuple(FIELDS)
    ambiguous_order = sorted(AMBIGUOUS_TOKENS, key=lambda token: (len(token), token))
    for index, policy in enumerate(spec.policies):
        if policy.key_order != canonical_order:
            found.append(
                _with_policy(spec, index, PolicySpec(
                    policy_id=policy.policy_id,
                    reviewer=policy.reviewer,
                    scalar=policy.scalar,
                    key_order=canonical_order,
                ))
            )
        tokens = ambiguous_order if policy.scalar.ambiguous else [
            policy.scalar.token.strip(chr(39) + chr(34))
        ]
        for token in tokens:
            for style in ("plain", "single", "double"):
                rendered = _style_token(token, style)
                if rendered == policy.scalar.token and style == policy.scalar.style:
                    continue
                scalar = Scalar(
                    token=rendered,
                    style=style,
                    ambiguous=policy.scalar.ambiguous,
                    expected=None if policy.scalar.ambiguous else policy.scalar.expected,
                )
                found.append(
                    _with_policy(spec, index, PolicySpec(
                        policy_id=policy.policy_id,
                        reviewer=policy.reviewer,
                        scalar=scalar,
                        key_order=policy.key_order,
                    ))
                )

    if spec.anchor_name is not None:
        for name in sorted(ANCHOR_NAMES, key=lambda item: (len(item), item)):
            if name != spec.anchor_name:
                found.append(_clone(spec, anchor_name=name))

    unique = {candidate.render(): candidate for candidate in found}
    return sorted(unique.values(), key=_complexity)


def shrink(load: Loader, spec: DocumentSpec) -> DocumentSpec:
    """Greedily reduce ``spec`` while keeping the property failing.

    Every accepted move strictly lowers :func:`_complexity`, so the search
    is a finite descent and cannot oscillate between equal-size documents.
    Candidates are emitted simplest-first, biasing the result toward a short,
    plain, single-policy repro that can be read by hand.
    """

    current = spec
    while True:
        baseline = _complexity(current)
        for candidate in _candidates(current):
            if _complexity(candidate) >= baseline:
                continue
            if _still_fails(load, candidate):
                current = candidate
                break
        else:
            return current


__all__ = [
    "CheckOutcome",
    "PropertyFailure",
    "check_document",
    "run_property",
    "shrink",
]
