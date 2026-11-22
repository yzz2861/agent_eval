"""Data model for offline signing-policy review.

The review is deliberately independent of any online signing or verification
code: it consumes two frozen JSON documents (the signer combinations that a
DSSE envelope may be accepted under, and the roster mapping each key id to the
control domain that actually holds it) and answers two questions:

* how few domains can together satisfy the policy (concentration), and
* how few domains can block every legal combination by being absent
  (availability).
"""

from __future__ import annotations

from dataclasses import dataclass, field


class PolicyReviewError(ValueError):
    """Raised when an input document cannot be interpreted."""


@dataclass(frozen=True)
class Rule:
    """One normalized authorization rule.

    A rule is stored as the set of key ids whose signatures it requires.
    Threshold and slot rules are expanded to this same shape before review, so
    the analysis only ever reasons about concrete key combinations.

    Attributes:
        rule_id: Stable identifier copied from or derived for the input rule.
        keyids: Distinct key ids that must sign for this rule to be satisfied.
        source: Human-readable rule type used in reports.
    """

    rule_id: str
    keyids: frozenset[str]
    source: str


@dataclass(frozen=True)
class Policy:
    """All signer combinations accepted by a DSSE policy.

    Attributes:
        policy_id: Identifier copied from the input document.
        rules: Normalized rules, each representing one legal combination.
        keyids: Every distinct key id referenced by any rule.
        rule_index: Mapping of each normalized combination to the rules that
            produce it (one combination may be implied by several rules).
    """

    policy_id: str
    rules: tuple[Rule, ...]
    keyids: frozenset[str]
    rule_index: dict[frozenset[str], tuple[str, ...]]


@dataclass(frozen=True)
class KeyOwnership:
    """Domain ownership of one key id.

    Attributes:
        keyid: Identifier of the signing key.
        confirmed: Domains that definitely control this key.
        candidates: Domains that may control this key but are not yet
            confirmed. A key with candidates and no confirmed owner makes the
            review result a range rather than a single number.
    """

    keyid: str
    confirmed: frozenset[str] = field(default_factory=frozenset)
    candidates: frozenset[str] = field(default_factory=frozenset)

    @property
    def unresolved(self) -> bool:
        """Return True if the confirmed owner list is empty."""
        return not self.confirmed


@dataclass(frozen=True)
class Roster:
    """Frozen control-domain roster.

    Attributes:
        roster_id: Identifier copied from the input document.
        frozen_at: Optional free-form timestamp marking when the roster was
            frozen.
        ownership: Mapping of key id to its domain ownership record.
        domains: Every domain mentioned in confirmed or candidate entries.
    """

    roster_id: str
    frozen_at: str | None
    ownership: dict[str, KeyOwnership]
    domains: frozenset[str]


@dataclass(frozen=True)
class Witness:
    """A human-checkable example proving one metric value.

    Attributes:
        domains: Minimum-size set of domains making the witness true.
        covers: Mapping of each rule id to the domains that supply its keys.
            Every required key id appears in at least one listed domain.
        key_to_domains: Mapping of each relevant key id to the domains in
            ``domains`` that hold it, including whether ownership is only
            candidate-based.
    """

    domains: frozenset[str]
    covers: dict[str, dict[str, tuple[str, ...]]]
    key_to_domains: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class Metric:
    """One evaluated metric together with proof material.

    Attributes:
        value: Minimum number of domains needed. ``None`` means no set of
            domains can achieve the goal under the current ownership data.
        witness: Witness set attaining ``value`` when one exists.
        exhaustive: True when all subsets up to the answer size were checked,
            i.e. the minimum is proven rather than a search bound.
        note: Explanation for a missing value or a non-exhaustive search.
    """

    value: int | None
    witness: Witness | None
    exhaustive: bool
    note: str | None = None


@dataclass(frozen=True)
class ResolutionResult:
    """Metrics for one concrete assignment of candidate-owned keys."""

    assignment: dict[str, str]
    satisfying: int
    blocking: int


@dataclass(frozen=True)
class CandidateRange:
    """Range of metric values across all candidate assignments.

    Attributes:
        unresolved_keyids: Keys whose owner is only known as a candidate set.
        exhaustive: True when every assignment was enumerated.
        enumerated: Number of assignments that were evaluated.
        total_assignments: Number of assignments that exist in total.
        satisfying_min/satisfying_max: Bounds of the minimum-satisfying metric.
        blocking_min/blocking_max: Bounds of the minimum-blocking metric.
        best_resolution/worst_resolution: Assignments producing the most
            concentrated and most dispersed outcomes, for manual checking.
    """

    unresolved_keyids: tuple[str, ...]
    exhaustive: bool
    enumerated: int
    total_assignments: int
    satisfying_min: int
    satisfying_max: int
    blocking_min: int
    blocking_max: int
    best_resolution: ResolutionResult
    worst_resolution: ResolutionResult
