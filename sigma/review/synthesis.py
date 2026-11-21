from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigma.modifiers import (
    SigmaExpandModifier,
    SigmaModifier,
    SigmaRegularExpressionModifier,
    SigmaTimestampModifier,
    modifier_mapping,
)
from sigma.rule.detection import SigmaDetection, SigmaDetectionItem
from sigma.rule.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    Placeholder,
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SigmaTimestampPart,
    SigmaType,
    SpecialChars,
)

#: Modifier classes whose effect on event synthesis the review cannot explain, mapped to the
#: semantics that is missing from the review conclusion.
MISSING_SEMANTICS_BY_MODIFIER: tuple[tuple[type[SigmaModifier[Any, Any]], str], ...] = (
    (SigmaExpandModifier, "placeholder expansion"),
    (SigmaRegularExpressionModifier, "regular expression synthesis"),
    (SigmaTimestampModifier, "timestamp part extraction"),
)

#: Sentinel assigned to negated detection items so the synthesized event does not accidentally
#: carry the negated value.
NEGATED_SENTINEL = "pysigma-review-negated"


@dataclass
class UnexplainedModifier:
    """A modifier the review could not explain, with the semantics missing from the conclusion."""

    rule: str
    field: str | None
    modifier: str
    missing_semantics: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "field": self.field,
            "modifier": self.modifier,
            "missing_semantics": self.missing_semantics,
        }


@dataclass
class SyntheticEvent:
    """A synthesized event candidate with its provenance."""

    data: dict[str, Any]
    raw: str | None
    unexplained: list[UnexplainedModifier] = field(default_factory=list)


class SyntheticEventGenerator:
    """
    Generates synthetic events that satisfy the detections of a Sigma rule.

    Every generated event is only a candidate: callers must verify it against a compiled rule
    matcher before using it as evidence. Modifiers the generator cannot reason about are
    collected as :class:`UnexplainedModifier` together with the missing semantics.
    """

    def events_for_rule(self, rule: SigmaRule) -> list[SyntheticEvent]:
        """Generate candidate events for all detections of a rule."""
        rule_name = self._rule_name(rule)
        events: list[SyntheticEvent] = []
        groups: list[list[SigmaDetectionItem]] = []
        for detection in rule.detection.detections.values():
            groups.extend(self._detection_groups(detection))

        # One event per AND-linked group (covers OR-linked conditions) plus one merged event
        # across all groups (covers AND-linked conditions).
        merged: list[SigmaDetectionItem] = [item for group in groups for item in group]
        if len(groups) > 1:
            groups.append(merged)

        for group in groups:
            events.append(self._event_from_items(rule_name, group))
        return events

    def unexplained_modifiers_for_rule(self, rule: SigmaRule) -> list[UnexplainedModifier]:
        """Collect all modifiers of a rule the review cannot explain."""
        rule_name = self._rule_name(rule)
        unexplained: list[UnexplainedModifier] = []
        seen: set[tuple[str | None, str, str]] = set()
        for detection in rule.detection.detections.values():
            for item in self._iter_detection_items(detection):
                for modifier in item.modifiers:
                    missing = self._missing_semantics(modifier)
                    if missing is None:
                        continue
                    key = (item.field, modifier.__name__, missing)
                    if key in seen:
                        continue
                    seen.add(key)
                    unexplained.append(
                        UnexplainedModifier(
                            rule=rule_name,
                            field=item.field,
                            modifier=modifier.__name__,
                            missing_semantics=missing,
                        )
                    )
                for value in item.value:
                    missing = self._missing_value_semantics(value)
                    if missing is None:
                        continue
                    key = (item.field, "(value)", missing)
                    if key in seen:
                        continue
                    seen.add(key)
                    unexplained.append(
                        UnexplainedModifier(
                            rule=rule_name,
                            field=item.field,
                            modifier="(value)",
                            missing_semantics=missing,
                        )
                    )
        return unexplained

    def _missing_value_semantics(self, value: SigmaType) -> str | None:
        """Semantics of a value type the review cannot synthesize, None if explainable."""
        if isinstance(value, SigmaExpansion):
            for sub_value in value.values:
                missing = self._missing_value_semantics(sub_value)
                if missing is not None:
                    return missing
            return None
        if isinstance(value, SigmaString):
            if any(isinstance(part, Placeholder) for part in value.s):
                return "placeholder resolution"
            return None
        if isinstance(value, Placeholder):
            return "placeholder resolution"
        if isinstance(value, SigmaRegularExpression):
            return "regular expression synthesis"
        if isinstance(value, SigmaTimestampPart):
            return "timestamp part extraction"
        return None

    @staticmethod
    def _rule_name(rule: SigmaRule) -> str:
        return str(rule.title or rule.name or rule.id or "<unnamed rule>")

    def _missing_semantics(self, modifier: type[SigmaModifier[Any, Any]]) -> str | None:
        for modifier_class, semantics in MISSING_SEMANTICS_BY_MODIFIER:
            if issubclass(modifier, modifier_class):
                return semantics
        if modifier not in set(modifier_mapping.values()):
            return f"unrecognized modifier semantics: {modifier.__name__}"
        return None

    def _iter_detection_items(self, detection: SigmaDetection) -> list[SigmaDetectionItem]:
        items: list[SigmaDetectionItem] = []
        for item in detection.detection_items:
            if isinstance(item, SigmaDetectionItem):
                items.append(item)
            elif isinstance(item, SigmaDetection):
                items.extend(self._iter_detection_items(item))
        return items

    def _detection_groups(self, detection: SigmaDetection) -> list[list[SigmaDetectionItem]]:
        """Split a detection into AND-linked groups of leaf detection items."""
        leaf_items = [i for i in detection.detection_items if isinstance(i, SigmaDetectionItem)]
        groups: list[list[SigmaDetectionItem]] = []
        if leaf_items:
            groups.append(leaf_items)
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                groups.extend(self._detection_groups(item))
        return groups

    def _event_from_items(
        self, rule_name: str, items: list[SigmaDetectionItem]
    ) -> SyntheticEvent:
        data: dict[str, Any] = {}
        raw_parts: list[str] = []
        unexplained: list[UnexplainedModifier] = []
        for item in items:
            for modifier in item.modifiers:
                missing = self._missing_semantics(modifier)
                if missing is not None:
                    unexplained.append(
                        UnexplainedModifier(
                            rule=rule_name,
                            field=item.field,
                            modifier=modifier.__name__,
                            missing_semantics=missing,
                        )
                    )
            self._apply_item(item, data, raw_parts)
        raw = " ".join(raw_parts) if raw_parts else None
        return SyntheticEvent(data=data, raw=raw, unexplained=unexplained)

    def _apply_item(
        self,
        item: SigmaDetectionItem,
        data: dict[str, Any],
        raw_parts: list[str],
    ) -> None:
        if item.negated:
            if item.field is not None:
                data[item.field] = NEGATED_SENTINEL
            return
        if not item.value:
            return
        value = item.value[0]
        if isinstance(value, SigmaExists):
            if value.exists and item.field is not None:
                data[item.field] = "present"
            return
        if item.field is None:
            synthesized = self._synthesize_value(value)
            if synthesized is not None:
                raw_parts.append(str(synthesized))
            return
        if isinstance(value, SigmaFieldReference):
            reference_value = data.get(value.field, "reference-value")
            data[value.field] = reference_value
            data[item.field] = reference_value
            return
        synthesized = self._synthesize_value(value)
        if synthesized is not None:
            data[item.field] = synthesized

    def _synthesize_value(self, value: SigmaType) -> Any:
        """Build a concrete event value satisfying the given Sigma type, None if not possible."""
        if isinstance(value, SigmaExpansion):
            for sub_value in value.values:
                synthesized = self._synthesize_value(sub_value)
                if synthesized is not None:
                    return synthesized
            return None
        if isinstance(value, SigmaString):
            return self._synthesize_string(value)
        if isinstance(value, SigmaTimestampPart):
            return None
        if isinstance(value, SigmaNumber):
            return value.number
        if isinstance(value, SigmaBool):
            return bool(value)
        if isinstance(value, SigmaNull):
            return None
        if isinstance(value, SigmaCompareExpression):
            return self._synthesize_comparison(value)
        if isinstance(value, SigmaCIDRExpression):
            network = value.network
            if network.num_addresses > 1:
                return str(network.network_address + 1)
            return str(network.network_address)
        if isinstance(value, (SigmaRegularExpression, Placeholder, SigmaFieldReference)):
            return None
        return None

    @staticmethod
    def _synthesize_string(value: SigmaString) -> str | None:
        parts: list[str] = []
        for part in value.s:
            if isinstance(part, str):
                parts.append(part)
            elif part == SpecialChars.WILDCARD_MULTI:
                parts.append("x")
            elif part == SpecialChars.WILDCARD_SINGLE:
                parts.append("a")
            else:
                return None
        return "".join(parts)

    @staticmethod
    def _synthesize_comparison(value: SigmaCompareExpression) -> Any:
        number = value.number.number
        if value.op == CompareOperators.LT:
            return number - 1
        if value.op == CompareOperators.LTE:
            return number
        if value.op == CompareOperators.GT:
            return number + 1
        if value.op == CompareOperators.GTE:
            return number
        if value.op == CompareOperators.NEQ:
            return number + 1
        return None
