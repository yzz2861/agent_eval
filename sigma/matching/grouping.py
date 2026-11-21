from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sigma.correlations import SigmaCorrelationRule
    from sigma.rule.base import SigmaRuleBase


def resolve_group_field(
    rule: "SigmaCorrelationRule",
    field_name: str,
    source_rule: "SigmaRuleBase | None" = None,
) -> str:
    """
    Resolve a correlation ``group-by`` field for a concrete source rule.

    Correlation rules can declare aliases for fields that are named differently in the
    events matched by the referenced rules. This helper is the single source of truth for
    that resolution so that every consumer of a correlation rule groups events the same way.
    """
    alias = rule.aliases.aliases.get(field_name) if rule.aliases is not None else None
    if alias is None:
        return field_name

    for rule_ref, mapped_field in alias.mapping.items():
        if getattr(rule_ref, "rule", None) is source_rule:
            return mapped_field
    return field_name


def extract_group_key(
    rule: "SigmaCorrelationRule",
    source_rule: "SigmaRuleBase | None",
    data: dict[str, Any],
) -> tuple[Any, ...]:
    """
    Extract the correlation group key from an event's data.

    Values are ordered like the rule's ``group-by`` list. An empty ``group-by`` produces
    the single global group ``()``.
    """
    if not rule.group_by:
        return ()

    return tuple(
        data.get(resolve_group_field(rule, field_name, source_rule)) for field_name in rule.group_by
    )


def make_group_values(
    rule: "SigmaCorrelationRule", group_key: tuple[Any, ...]
) -> dict[str, Any] | None:
    """Build the public ``group_values`` mapping for a correlation group key."""
    if not rule.group_by:
        return None
    return dict(zip(rule.group_by, group_key))
