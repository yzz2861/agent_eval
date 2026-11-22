"""Independent three-state contract for exported approval policies.

The approval system distinguishes three decisions that must never collapse
into one another when a YAML export is re-imported:

* ``APPROVED`` - the request was explicitly accepted ("批准");
* ``DENIED``   - the request was explicitly rejected ("明确拒绝");
* ``PENDING``  - no decision has been recorded yet ("未审").

Everything here is defined independently of any YAML representation, so the
property test compares an import result against this contract rather than
against another YAML round-trip.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

import yaml


class Decision(str, Enum):
    """The three mutually exclusive approval states."""

    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"


#: Canonical wire tokens. Only these strings are legal decisions; every other
#: scalar is an ambiguity that must be rejected, never defaulted.
LEGAL_TOKENS: frozenset[str] = frozenset(state.value for state in Decision)


class PolicyError(ValueError):
    """Base class for every condition that makes a policy un-importable."""


class MissingFieldError(PolicyError):
    """Raised when a policy object omits a required field."""


class AmbiguousDecisionError(PolicyError):
    """Raised when the decision scalar is not one of the three legal tokens."""


@dataclass(frozen=True)
class Policy:
    """A single synthetic policy entry as understood by the contract."""

    policy_id: str
    decision: Decision
    reviewer: str

    @classmethod
    def from_mapping(
        cls, mapping: dict[str, Any], *, origin: str = "<document>"
    ) -> "Policy":
        try:
            raw_id = mapping["id"]
            raw_decision = mapping["decision"]
            raw_reviewer = mapping["reviewer"]
        except KeyError as missing:
            raise MissingFieldError(
                f"{origin}: missing required field {missing.args[0]!r}"
            ) from None

        if not isinstance(raw_decision, str) or raw_decision not in LEGAL_TOKENS:
            raise AmbiguousDecisionError(
                f"{origin}: decision {raw_decision!r} "
                f"({type(raw_decision).__name__}) is not one of "
                f"{sorted(LEGAL_TOKENS)}"
            )

        return cls(
            policy_id=str(raw_id),
            decision=Decision(raw_decision),
            reviewer=str(raw_reviewer),
        )


def _iter_policies(
    document: Any, *, origin: str
) -> Iterable[tuple[str, dict[str, Any]]]:
    if not isinstance(document, dict):
        raise PolicyError(f"{origin}: top-level document must be a mapping")
    policies = document.get("policies")
    if not isinstance(policies, list):
        raise MissingFieldError(f"{origin}: missing required list field 'policies'")
    for index, entry in enumerate(policies):
        entry_origin = f"{origin} policies[{index}]"
        if not isinstance(entry, dict):
            raise PolicyError(f"{entry_origin}: entry must be a mapping")
        yield entry_origin, entry


def strict_load(text: str) -> list[Policy]:
    """Import YAML strictly according to the three-state contract.

    Any ambiguity (YAML 1.1 boolean coercion of ``yes/no``, ``null``, unknown
    tokens, missing fields) raises :class:`PolicyError` instead of guessing a
    state.
    """

    document = yaml.safe_load(text)
    return [
        Policy.from_mapping(mapping, origin=origin)
        for origin, mapping in _iter_policies(document, origin="<doc>")
    ]


def permissive_load(text: str) -> list[Policy]:
    """Ordinary serializer stand-in that treats every unknown value as pass.

This deliberately models the swallowed-decision bug: instead of rejecting
scalars it does not recognise, it maps them to :data:`Decision.APPROVED`. It
still parses the three canonical tokens correctly, so the property test only
fails on genuinely ambiguous inputs - letting the report pin the exact
decision that was silently converted into an approval.
"""

    document = yaml.safe_load(text)

    def coerce(raw_decision: Any) -> Decision:
        if isinstance(raw_decision, str) and raw_decision in LEGAL_TOKENS:
            return Decision(raw_decision)
        # Unknown / coerced values are optimistically treated as a pass.
        return Decision.APPROVED

    result: list[Policy] = []
    for origin, mapping in _iter_policies(document, origin="<doc>"):
        try:
            raw_id = mapping["id"]
            raw_reviewer = mapping["reviewer"]
        except KeyError as missing:
            raise MissingFieldError(
                f"{origin}: missing required field {missing.args[0]!r}"
            ) from None
        result.append(
            Policy(
                policy_id=str(raw_id),
                decision=coerce(mapping.get("decision")),
                reviewer=str(raw_reviewer),
            )
        )
    return result
