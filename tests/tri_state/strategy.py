"""Synthetic policy objects and the many legal YAML shapes they can take.

The generator does not use ``yaml.dump``: emitting text by hand is what lets
the property test exercise surface variety that a single dumper would never
produce - different key orders, anchor/alias spellings, scalar quoting styles
and, crucially, ambiguous scalars (``yes``/``no``/``null`` ...) that a caller
has no reason to accept as one of the three approval states.

Everything is deterministic given a :class:`random.Random` instance so a
failing seed can be replayed exactly.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from itertools import permutations
from typing import List, Optional

from .contract import Decision


#: Field names rendered inside each policy mapping. ``decision`` is the
#: tri-state field; the other two give key-order permutations something to do.
FIELDS = ("id", "reviewer", "decision")

#: Every possible key ordering, used both for generation and for shrinking.
KEY_ORDERS: tuple[tuple[str, ...], ...] = tuple(permutations(FIELDS))

#: Quoting styles for a *canonical* decision token. All three decode back to
#: the same string under SafeLoader, so all are legal representations.
SCALAR_STYLES = ("plain", "single", "double")

#: Scalars a caller cannot endorse as an approval state. PyYAML's YAML 1.1
#: resolver turns the booleans/nulls into ``bool``/``None``; the rest decode to
#: plain strings that are simply not one of the three canonical tokens.
AMBIGUOUS_TOKENS = (
    "yes",      # -> True
    "no",       # -> False
    "on",       # -> True
    "off",      # -> False
    "true",     # -> True
    "false",    # -> False
    "null",     # -> None
    "~",        # -> None
    "approve",  # near-miss string, not the canonical "approved"
    "aprove",   # typo a lenient pipeline might silently accept
    "ENABLED",  # foreign vocabulary
    "disabled",
)

#: Distinct anchor spellings the generator may bind to the first policy.
ANCHOR_NAMES = ("a", "pol", "decision_anchor", "x1", "reviewed_item")


@dataclass(frozen=True)
class Scalar:
    """One rendered decision scalar.

    ``token`` is the raw YAML text emitted between the key and the newline.
    ``expected`` is the contract decision the surrounding policy object means
    when the scalar is canonical, or ``None`` when the scalar is ambiguous.
    """

    token: str
    style: str
    ambiguous: bool
    expected: Optional[Decision]


def _quote(token: str, style: str) -> str:
    if style == "plain":
        return token
    if style == "single":
        return "'" + token.replace("'", "''") + "'"
    if style == "double":
        escaped = token.replace("\\", "\\\\").replace('"', '\\"')
        return '"' + escaped + '"'
    raise ValueError(f"unknown scalar style {style!r}")


def canonical_scalar(decision: Decision, rng: random.Random) -> Scalar:
    style = rng.choice(SCALAR_STYLES)
    return Scalar(
        token=_quote(decision.value, style),
        style=style,
        ambiguous=False,
        expected=decision,
    )


def ambiguous_scalar(rng: random.Random) -> Scalar:
    token = rng.choice(AMBIGUOUS_TOKENS)
    # Quoted "no" stays the string "no" (still not a legal token), whereas the
    # plain form is coerced to False - keep both so the loader is hit both ways.
    style = rng.choice(SCALAR_STYLES)
    return Scalar(
        token=_quote(token, style),
        style=style,
        ambiguous=True,
        expected=None,
    )


@dataclass(frozen=True)
class PolicySpec:
    """A synthetic policy plus exactly how it should be rendered."""

    policy_id: str
    reviewer: str
    scalar: Scalar
    key_order: tuple[str, ...]

    @property
    def expected_decision(self) -> Optional[Decision]:
        return self.scalar.expected


@dataclass
class DocumentSpec:
    """A whole renderable document.

    When ``anchor_name`` is set the first policy is emitted with that anchor
    and, if ``alias_count`` > 0, repeated through ``*alias`` references that
    share the first policy's mapping node.
    """

    policies: List[PolicySpec]
    anchor_name: Optional[str] = None
    alias_count: int = 0
    seed: int = 0
    extras: List[str] = field(default_factory=list)

    def render(self) -> str:
        lines: List[str] = ["policies:"]
        anchor_decl = f" &{self.anchor_name}" if self.anchor_name else ""

        for index, spec in enumerate(self.policies):
            if index == 0:
                lines.append(f"  -{anchor_decl}")
            else:
                lines.append("  -")
            lines.extend(_render_mapping(spec, indent=4))

        for _ in range(self.alias_count):
            if self.anchor_name is None:
                raise ValueError("alias without an anchor declaration")
            lines.append(f"  - *{self.anchor_name}")

        for extra in self.extras:
            lines.append(extra)
        return "\n".join(lines) + "\n"


def _render_mapping(spec: PolicySpec, indent: int) -> List[str]:
    pad = " " * indent
    values = {
        "id": spec.policy_id,
        "reviewer": spec.reviewer,
        "decision": spec.scalar.token,
    }
    return [f"{pad}{key}: {values[key]}" for key in spec.key_order]


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #


def make_policy(rng: random.Random, index: int) -> PolicySpec:
    decision = rng.choice(list(Decision))
    # Roughly one policy in three carries an ambiguous decision so the strict
    # loader's rejection path and the lenient loader's swallow path are both
    # exercised regularly.
    if rng.random() < 1.0 / 3.0:
        scalar = ambiguous_scalar(rng)
    else:
        scalar = canonical_scalar(decision, rng)
    return PolicySpec(
        policy_id=f"pol-{index:03d}",
        reviewer=rng.choice(("alice", "bob", "carol", "dave")),
        scalar=scalar,
        key_order=rng.choice(KEY_ORDERS),
    )


def make_document(rng: random.Random, *, seed: int) -> DocumentSpec:
    count = rng.randint(1, 3)
    policies = [make_policy(rng, index) for index in range(count)]

    anchor_name: Optional[str] = None
    alias_count = 0
    if rng.random() < 0.6:
        anchor_name = rng.choice(ANCHOR_NAMES)
        alias_count = rng.randint(0, 2)

    return DocumentSpec(
        policies=policies,
        anchor_name=anchor_name,
        alias_count=alias_count,
        seed=seed,
    )


def documents(seed: int, iterations: int) -> List[DocumentSpec]:
    """Generate ``iterations`` independent, reproducible documents."""

    rng = random.Random(seed)
    return [make_document(rng, seed=seed * 1_000_000 + i) for i in range(iterations)]
