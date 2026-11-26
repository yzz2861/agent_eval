from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sigma.matching.event import Event
from sigma.matching.match import SigmaMatch


@dataclass(frozen=True)
class AssociationGroupKey:
    """Group-by fields and values identifying an association group."""

    fields: tuple[str, ...]
    values: tuple[Any, ...]

    def as_tuple(self) -> tuple[Any, ...]:
        return self.values


@dataclass(frozen=True)
class MatchFact:
    """A rule match treated as a retractable fact by an association layer."""

    id: int
    rule_name: str
    event: Event
    timestamp: datetime


@dataclass(frozen=True)
class RuleCause:
    """One rule confirmation in the causal order of an association condition."""

    rule_name: str
    fact_id: int
    timestamp: datetime


@dataclass(frozen=True)
class ConditionEvidence:
    """Minimal facts proving one association condition in rule order."""

    condition_name: str
    causal_order: tuple[RuleCause, ...]


@dataclass(frozen=True)
class AssociationCondition:
    """Ordered rule names that must all be confirmed for one association group."""

    name: str
    rule_names: tuple[str, ...]
    group_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.rule_names:
            raise ValueError("Association condition must reference at least one rule")
        if len(self.rule_names) != len(set(self.rule_names)):
            raise ValueError("Association condition rules must be unique")

    def group_key(self, event: Event) -> AssociationGroupKey:
        return AssociationGroupKey(
            fields=self.group_by,
            values=tuple(event.data.get(field_name) for field_name in self.group_by),
        )

    def group_values(self, key: AssociationGroupKey) -> dict[str, Any] | None:
        if not self.group_by:
            return None
        return dict(zip(self.group_by, key.values))


@dataclass(frozen=True)
class AssociationAlert:
    """A merged alert with the smallest event subset proving its conditions."""

    key: AssociationGroupKey
    group_values: dict[str, Any] | None
    condition_names: tuple[str, ...]
    condition_evidence: tuple[ConditionEvidence, ...]
    facts: tuple[MatchFact, ...]

    @property
    def minimal_events(self) -> tuple[Event, ...]:
        events: list[Event] = []
        seen: set[int] = set()
        for fact in self.facts:
            event_id = id(fact.event)
            if event_id not in seen:
                seen.add(event_id)
                events.append(fact.event)
        return tuple(events)

    @property
    def causal_order(self) -> tuple[RuleCause, ...]:
        return tuple(
            cause
            for evidence in self.condition_evidence
            for cause in evidence.causal_order
        )


@dataclass(frozen=True)
class AssociationReplayResult:
    """Alerts that remain valid after a hypothetical association-state change."""

    active_alerts: tuple[AssociationAlert, ...]
    retained_alerts: tuple[AssociationAlert, ...]
    updated_alerts: tuple[AssociationAlert, ...]
    retracted_alerts: tuple[AssociationAlert, ...]


@dataclass(frozen=True)
class AssociationUpdate:
    """Result of submitting one local match to the association layer."""

    fact: MatchFact
    new_alerts: tuple[AssociationAlert, ...]
    updated_alerts: tuple[AssociationAlert, ...]


@dataclass
class AssociationMergeLayer:
    """Merge local Sigma matches into replayable, evidence-preserving alerts."""

    conditions: Sequence[AssociationCondition]
    _facts: dict[int, MatchFact] = field(init=False, default_factory=dict)
    _facts_by_group: dict[AssociationGroupKey, list[MatchFact]] = field(
        init=False, default_factory=dict
    )
    _active_alerts: dict[AssociationGroupKey, AssociationAlert] = field(
        init=False, default_factory=dict
    )
    _next_fact_id: int = field(init=False, default=1)

    def __post_init__(self) -> None:
        names = [condition.name for condition in self.conditions]
        if len(names) != len(set(names)):
            raise ValueError("Association condition names must be unique")
        self.conditions = tuple(self.conditions)

    @property
    def active_alerts(self) -> tuple[AssociationAlert, ...]:
        return tuple(self._active_alerts.values())

    def receive_match(self, match: SigmaMatch) -> AssociationUpdate:
        rule_name = getattr(match.rule, "name", None)
        if not rule_name:
            raise ValueError("SigmaMatch rule must have a name")
        if not match.events:
            raise ValueError("SigmaMatch must contain at least one event")

        event = match.events[0]
        affected_keys = {
            condition.group_key(event)
            for condition in self.conditions
            if rule_name in condition.rule_names
        }

        fact = self._create_fact(rule_name, event, match.timestamp)
        self._facts[fact.id] = fact

        new_alerts: list[AssociationAlert] = []
        updated_alerts: list[AssociationAlert] = []
        for key in affected_keys:
            self._facts_by_group.setdefault(key, []).append(fact)
            previous_alert = self._active_alerts.get(key)
            alert = self._build_alert(key)
            if alert is not None and previous_alert is None:
                self._active_alerts[key] = alert
                new_alerts.append(alert)
            elif alert is not None and alert != previous_alert:
                self._active_alerts[key] = alert
                updated_alerts.append(alert)

        return AssociationUpdate(
            fact=fact,
            new_alerts=tuple(new_alerts),
            updated_alerts=tuple(updated_alerts),
        )

    def replay_fact_revocation(self, fact_id: int) -> AssociationReplayResult:
        self._require_fact(fact_id)
        return self._replay(facts=self._facts_without({fact_id}))

    def revoke_fact(self, fact_id: int) -> AssociationReplayResult:
        self._require_fact(fact_id)
        result = self.replay_fact_revocation(fact_id)

        del self._facts[fact_id]
        self._rebuild_state()
        return result

    def replay_rule_replacement(
        self,
        rule_name: str,
        replacement_rule_name: str,
        replacement_matches: Iterable[SigmaMatch] = (),
    ) -> AssociationReplayResult:
        replacements = {rule_name: replacement_rule_name}
        previous_next_fact_id = self._next_fact_id
        replacement_facts = self._facts_from_matches(
            replacement_matches, replacement_rule_name
        )
        self._next_fact_id = previous_next_fact_id
        facts = {**self._facts}
        for fact in replacement_facts:
            facts[fact.id] = fact
        return self._replay(
            facts=facts,
            conditions=self._replaced_conditions(replacements),
        )

    def replace_rule(
        self,
        rule_name: str,
        replacement_rule_name: str,
        replacement_matches: Iterable[SigmaMatch] = (),
    ) -> AssociationReplayResult:
        replacements = {rule_name: replacement_rule_name}
        replacement_matches = tuple(replacement_matches)
        previous_next_fact_id = self._next_fact_id
        result = self.replay_rule_replacement(
            rule_name, replacement_rule_name, replacement_matches
        )
        self._next_fact_id = previous_next_fact_id + len(replacement_matches)
        replacement_facts = tuple(
            fact
            for alert in result.active_alerts
            for fact in alert.facts
            if fact.rule_name == replacement_rule_name
        )

        self.conditions = self._replaced_conditions(replacements)
        for fact in replacement_facts:
            self._facts[fact.id] = fact
        self._rebuild_state()
        return result

    def replay_alert_revocation(self, key: AssociationGroupKey) -> AssociationReplayResult:
        alert = self._active_alerts.get(key)
        if alert is None:
            raise KeyError(key)

        fact_ids = {fact.id for fact in alert.facts}
        result = self._replay(facts=self._facts_without(fact_ids))
        active = tuple(candidate for candidate in result.active_alerts if candidate.key != key)
        retained = tuple(
            candidate for candidate in result.retained_alerts if candidate.key != key
        )
        retracted = tuple(
            candidate for candidate in result.retracted_alerts if candidate.key != key
        ) + (alert,)
        return AssociationReplayResult(active, retained, result.updated_alerts, retracted)

    def revoke_alert(self, key: AssociationGroupKey) -> AssociationReplayResult:
        alert = self._active_alerts.get(key)
        if alert is None:
            raise KeyError(key)

        result = self.replay_alert_revocation(key)
        fact_ids = {fact.id for fact in alert.facts}
        self._facts = self._facts_without(fact_ids)
        self._rebuild_state()
        return result

    def _replay(
        self,
        facts: dict[int, MatchFact],
        conditions: Sequence[AssociationCondition] | None = None,
    ) -> AssociationReplayResult:
        replay_conditions = tuple(self.conditions if conditions is None else conditions)
        facts_by_group = self._group_facts(facts.values(), replay_conditions)
        rebuilt: dict[AssociationGroupKey, AssociationAlert] = {}
        for key, group_facts in facts_by_group.items():
            alert = self._build_alert_from(key, group_facts, replay_conditions)
            if alert is not None:
                rebuilt[key] = alert

        retained = tuple(
            alert
            for key, alert in rebuilt.items()
            if key in self._active_alerts and alert == self._active_alerts[key]
        )
        updated = tuple(
            alert
            for key, alert in rebuilt.items()
            if key in self._active_alerts and alert != self._active_alerts[key]
        )
        retracted = tuple(
            alert for key, alert in self._active_alerts.items() if key not in rebuilt
        )
        return AssociationReplayResult(tuple(rebuilt.values()), retained, updated, retracted)

    def _build_alert(self, key: AssociationGroupKey) -> AssociationAlert | None:
        return self._build_alert_from(key, self._facts_by_group.get(key, []), self.conditions)

    @staticmethod
    def _build_alert_from(
        key: AssociationGroupKey,
        facts: Iterable[MatchFact],
        conditions: Sequence[AssociationCondition],
    ) -> AssociationAlert | None:
        available = list(facts)
        earliest_by_rule: dict[str, MatchFact] = {}
        for fact in available:
            current = earliest_by_rule.get(fact.rule_name)
            if current is None or (fact.timestamp, fact.id) < (current.timestamp, current.id):
                earliest_by_rule[fact.rule_name] = fact

        selected: list[MatchFact] = []
        condition_names: list[str] = []
        evidence: list[ConditionEvidence] = []
        for condition in conditions:
            if condition.group_by != key.fields:
                continue
            if not all(rule_name in earliest_by_rule for rule_name in condition.rule_names):
                continue
            ordered_facts = [
                earliest_by_rule[rule_name] for rule_name in condition.rule_names
            ]
            if any(
                later.timestamp < earlier.timestamp
                for earlier, later in zip(ordered_facts, ordered_facts[1:])
            ):
                continue

            causes: list[RuleCause] = []
            for rule_name in condition.rule_names:
                fact = earliest_by_rule[rule_name]
                causes.append(RuleCause(rule_name, fact.id, fact.timestamp))
                if fact not in selected:
                    selected.append(fact)
            condition_names.append(condition.name)
            evidence.append(ConditionEvidence(condition.name, tuple(causes)))

        if not condition_names:
            return None

        matching_condition = next(
            condition for condition in conditions if condition.group_by == key.fields
        )
        return AssociationAlert(
            key=key,
            group_values=matching_condition.group_values(key),
            condition_names=tuple(condition_names),
            condition_evidence=tuple(evidence),
            facts=tuple(selected),
        )

    def _rebuild_state(self) -> None:
        self._facts_by_group = self._group_facts(self._facts.values(), self.conditions)
        self._active_alerts = {}
        for key, facts in self._facts_by_group.items():
            alert = self._build_alert_from(key, facts, self.conditions)
            if alert is not None:
                self._active_alerts[key] = alert

    def _facts_from_matches(
        self, matches: Iterable[SigmaMatch], expected_rule_name: str
    ) -> tuple[MatchFact, ...]:
        facts: list[MatchFact] = []
        for match in matches:
            rule_name = getattr(match.rule, "name", None)
            if rule_name != expected_rule_name:
                raise ValueError(
                    f"Replacement match must be produced by rule '{expected_rule_name}'"
                )
            if not match.events:
                raise ValueError("SigmaMatch must contain at least one event")
            fact = self._create_fact(rule_name, match.events[0], match.timestamp)
            facts.append(fact)
        return tuple(facts)

    def _create_fact(self, rule_name: str, event: Event, timestamp: datetime) -> MatchFact:
        fact = MatchFact(
            id=self._next_fact_id,
            rule_name=rule_name,
            event=event,
            timestamp=timestamp,
        )
        self._next_fact_id += 1
        return fact

    def _facts_without(self, fact_ids: set[int]) -> dict[int, MatchFact]:
        return {
            fact_id: fact for fact_id, fact in self._facts.items() if fact_id not in fact_ids
        }

    def _replaced_conditions(
        self, replacements: dict[str, str]
    ) -> tuple[AssociationCondition, ...]:
        return tuple(
            AssociationCondition(
                name=condition.name,
                rule_names=tuple(replacements.get(name, name) for name in condition.rule_names),
                group_by=condition.group_by,
            )
            for condition in self.conditions
        )

    @staticmethod
    def _group_facts(
        facts: Iterable[MatchFact], conditions: Sequence[AssociationCondition]
    ) -> dict[AssociationGroupKey, list[MatchFact]]:
        grouped: dict[AssociationGroupKey, list[MatchFact]] = {}
        relevant_rules = {
            rule_name for condition in conditions for rule_name in condition.rule_names
        }
        for fact in facts:
            if fact.rule_name not in relevant_rules:
                continue
            for condition in conditions:
                if fact.rule_name in condition.rule_names:
                    key = condition.group_key(fact.event)
                    grouped.setdefault(key, []).append(fact)
        return grouped

    def _require_fact(self, fact_id: int) -> MatchFact:
        try:
            return self._facts[fact_id]
        except KeyError:
            raise KeyError(fact_id) from None
