from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sigma.collection import SigmaCollection
from sigma.correlations import (
    CorrelationConditionAND,
    CorrelationConditionNOT,
    CorrelationConditionOR,
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaExtendedCorrelationCondition,
    SigmaRuleReference,
)
from sigma.exceptions import SigmaCorrelationRuleError, SigmaLogsourceError
from sigma.matching.compiler import MatchCompiler
from sigma.matching.event import Event
from sigma.matching.grouping import extract_group_key, make_group_values
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule

if TYPE_CHECKING:
    from sigma.correlations import CorrelationConditionItem


class TimeBasis(str, Enum):
    """
    Clock used to order events and measure correlation windows.

    ``EVENT_TIME`` uses :attr:`sigma.matching.Event.timestamp`, the time at which the
    source system says an event happened. ``ARRIVAL_TIME`` uses
    :attr:`sigma.matching.Event.arrival_time`, the time at which the operations platform
    received the record. Keeping the choice explicit prevents a real-time consumer and a
    review consumer from silently disagreeing about ordering.
    """

    EVENT_TIME = "event_time"
    ARRIVAL_TIME = "arrival_time"


class ConclusionStatus(str, Enum):
    """Lifecycle of a correlation conclusion."""

    PROVISIONAL = "provisional"
    CONFIRMED = "confirmed"
    RETRACTED = "retracted"


@dataclass(frozen=True)
class IngestedEvent:
    """An event together with the timing and sequence assigned by the contract."""

    event_id: int
    event: Event
    arrival_time: datetime
    is_backfill: bool = False

    @property
    def event_time(self) -> datetime:
        return self.event.timestamp

    def time_for(self, basis: TimeBasis) -> datetime:
        return self.event_time if basis is TimeBasis.EVENT_TIME else self.arrival_time


@dataclass(frozen=True)
class _Observation:
    """A match of one base rule against one event, placed in a correlation group."""

    event_id: int
    rule_name: str
    rule: SigmaRule
    group_key: tuple[Any, ...]
    event_time: datetime
    arrival_time: datetime
    sequence: int

    def time_for(self, basis: TimeBasis) -> datetime:
        return self.event_time if basis is TimeBasis.EVENT_TIME else self.arrival_time


@dataclass(frozen=True)
class _Evaluation:
    """A satisfying set of observations for one correlation window."""

    observations: tuple[_Observation, ...]

    @property
    def participant_keys(self) -> tuple[tuple[int, str], ...]:
        return tuple(
            (observation.event_id, observation.rule_name) for observation in self.observations
        )


@dataclass(frozen=True)
class CorrelationConclusion:
    """
    A correlation relationship and the events that established it.

    Provisional conclusions are immutable: a later backfill never edits them. Instead it
    emits a :class:`CorrelationRevision` that points at the original conclusion id, so the
    view seen by the on-call operator remains auditable.
    """

    conclusion_id: str
    rule_name: str
    group_key: tuple[Any, ...]
    group_values: dict[str, Any] | None
    status: ConclusionStatus
    event_ids: tuple[int, ...]
    rule_names: tuple[str, ...]
    event_times: tuple[datetime, ...]
    arrival_times: tuple[datetime, ...]
    basis: TimeBasis
    sequence: int
    supersedes: str | None = None
    revision_of: str | None = None
    reason: str | None = None

    @property
    def participant_keys(self) -> tuple[tuple[int, str], ...]:
        return tuple(zip(self.event_ids, self.rule_names))

    @property
    def window_start(self) -> datetime | None:
        return min(self.event_times) if self.event_times else None

    @property
    def window_end(self) -> datetime | None:
        return max(self.event_times) if self.event_times else None

    def window_for(self, basis: TimeBasis) -> tuple[datetime | None, datetime | None]:
        times = self.event_times if basis is TimeBasis.EVENT_TIME else self.arrival_times
        return (min(times), max(times)) if times else (None, None)


@dataclass(frozen=True)
class CorrelationRevision:
    """The review outcome for a relationship the on-call operator already saw."""

    revision_id: str
    conclusion_id: str
    status: ConclusionStatus
    reason: str
    final_event_ids: tuple[int, ...]
    backfill_event_ids: tuple[int, ...]
    sequence: int


@dataclass(frozen=True)
class RevisionReport:
    """Result of an incremental backfill or a full next-day review."""

    affected_groups: tuple[tuple[Any, ...], ...]
    revisions: tuple[CorrelationRevision, ...]
    new_conclusions: tuple[CorrelationConclusion, ...]

    @property
    def confirmed(self) -> tuple[CorrelationRevision, ...]:
        return tuple(
            revision for revision in self.revisions if revision.status is ConclusionStatus.CONFIRMED
        )

    @property
    def retracted(self) -> tuple[CorrelationRevision, ...]:
        return tuple(
            revision for revision in self.revisions if revision.status is ConclusionStatus.RETRACTED
        )

    def __len__(self) -> int:
        return len(self.revisions)


@dataclass(frozen=True)
class OnCallSnapshot:
    """
    The provisional view an on-call operator had after one real-time event.

    Snapshots only reference immutable :class:`CorrelationConclusion` objects and are never
    rewritten by backfill.
    """

    sequence: int
    event_id: int | None
    arrival_time: datetime | None
    conclusions: tuple[CorrelationConclusion, ...]

    @property
    def conclusion_ids(self) -> tuple[str, ...]:
        return tuple(conclusion.conclusion_id for conclusion in self.conclusions)


class OfflineCorrelationContract:
    """
    Deterministic offline execution contract for one temporal correlation rule.

    The contract is shared by two consumers:

    * the real-time consumer calls :meth:`observe` and consumes provisional conclusions
      evaluated on :attr:`provisional_basis` (arrival time by default);
    * the review consumer calls :meth:`backfill` for late records or :meth:`review` for the
      end-of-day pass and consumes event-time revisions.

    Both consumers use the same field aliases, ``group-by`` extraction and ``timespan``
    semantics. Backfill only reconciles groups (and, within a group, relationships whose
    event-time windows overlap the late record), never unrelated relationships.
    """

    def __init__(
        self,
        collection: SigmaCollection | SigmaCorrelationRule,
        rule: SigmaCorrelationRule | str | None = None,
        *,
        provisional_basis: TimeBasis | str = TimeBasis.ARRIVAL_TIME,
        final_basis: TimeBasis | str = TimeBasis.EVENT_TIME,
    ) -> None:
        self.collection: SigmaCollection | None
        self.rule: SigmaCorrelationRule
        if isinstance(collection, SigmaCorrelationRule):
            if rule is not None:
                raise SigmaCorrelationRuleError(
                    "Pass either a correlation rule or a collection and rule name, not both"
                )
            self.collection = None
            self.rule = collection
        else:
            self.collection = collection
            self.rule = self._select_rule(collection, rule)
            self.rule.aliases.resolve_rule_references(collection)
        if self.rule.type not in {
            SigmaCorrelationType.TEMPORAL,
            SigmaCorrelationType.TEMPORAL_ORDERED,
        }:
            raise SigmaCorrelationRuleError(
                "OfflineCorrelationContract supports temporal and temporal_ordered rules, "
                f"not {self.rule.type.name.lower()}"
            )

        self.provisional_basis = self._coerce_basis(provisional_basis)
        self.final_basis = self._coerce_basis(final_basis)
        self._timespan_seconds = self.rule.timespan.seconds
        self._required_rules = self._get_required_rules()
        self._base_matchers = self._build_base_matchers()

        self._events: list[IngestedEvent] = []
        self._groups: dict[tuple[Any, ...], list[_Observation]] = {}
        self._group_order: list[tuple[Any, ...]] = []
        self._observation_index: dict[tuple[int, str], _Observation] = {}
        self._active_provisional: dict[
            tuple[Any, ...], dict[tuple[tuple[int, str], ...], CorrelationConclusion]
        ] = {}
        self._provisional_history: list[CorrelationConclusion] = []
        self._final: dict[
            tuple[Any, ...], dict[tuple[tuple[int, str], ...], CorrelationConclusion]
        ] = {}
        self._revisions: list[CorrelationRevision] = []
        self._resolved_provisionals: set[str] = set()
        self._audit: list[OnCallSnapshot] = []
        self._event_counter = 0
        self._conclusion_counter = 0
        self._revision_counter = 0

    @staticmethod
    def _coerce_basis(basis: TimeBasis | str) -> TimeBasis:
        return basis if isinstance(basis, TimeBasis) else TimeBasis(basis)

    @staticmethod
    def _select_rule(
        collection: SigmaCollection, rule: SigmaCorrelationRule | str | None
    ) -> SigmaCorrelationRule:
        if isinstance(rule, SigmaCorrelationRule):
            return rule
        if isinstance(rule, str):
            selected = collection[rule]
            if not isinstance(selected, SigmaCorrelationRule):
                raise SigmaCorrelationRuleError(f"Rule '{rule}' is not a correlation rule")
            return selected

        correlation_rules = [
            candidate
            for candidate in collection.rules
            if isinstance(candidate, SigmaCorrelationRule)
        ]
        if len(correlation_rules) != 1:
            raise SigmaCorrelationRuleError(
                "Collection must contain exactly one correlation rule when no rule name is given"
            )
        return correlation_rules[0]

    def _get_required_rules(self) -> list[str]:
        references = self.rule.referenced_rules or self.rule.rules or []
        if references:
            return [reference.reference for reference in references]
        if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            return self.rule.condition.get_referenced_rules()
        return []

    def _build_base_matchers(self) -> list[tuple[str, SigmaRule, SigmaRuleMatcher]]:
        references = list(self.rule.referenced_rules or self.rule.rules or [])
        if not references and isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
            references = [
                SigmaRuleReference(name) for name in self.rule.condition.get_referenced_rules()
            ]
        if not references:
            raise SigmaCorrelationRuleError("Correlation rule does not reference any base rules")

        compiler = MatchCompiler()
        matchers: list[tuple[str, SigmaRule, SigmaRuleMatcher]] = []
        for reference in references:
            base_rule = getattr(reference, "rule", None)
            if base_rule is None:
                if self.collection is None:
                    raise SigmaCorrelationRuleError(
                        "Base rule references must be resolved when constructing from a rule"
                    )
                base_rule = self.collection[reference.reference]
            if not isinstance(base_rule, SigmaRule):
                raise SigmaCorrelationRuleError(
                    "OfflineCorrelationContract does not support nested correlation rules"
                )
            matchers.append((reference.reference, base_rule, SigmaRuleMatcher(base_rule, compiler)))
        return matchers

    # ------------------------------------------------------------------
    # Real-time consumer
    # ------------------------------------------------------------------
    def observe(
        self, event: Event, arrival_time: datetime | None = None
    ) -> list[CorrelationConclusion]:
        """
        Ingest one real-time event and return provisional conclusions emitted by it.

        An arrival time must be supplied explicitly (on the event or as an argument) when
        ``provisional_basis`` is :attr:`TimeBasis.ARRIVAL_TIME`.
        """
        arrival = self._resolve_arrival(
            event,
            arrival_time,
            require=self.provisional_basis is TimeBasis.ARRIVAL_TIME,
        )
        ingested, observations = self._ingest(event, arrival, is_backfill=False)

        emitted: list[CorrelationConclusion] = []
        for group_key in dict.fromkeys(observation.group_key for observation in observations):
            emitted.extend(self._update_provisional(group_key, ingested.event_id))

        self._record_snapshot(ingested)
        return emitted

    def on_call_view(self, sequence: int | None = None) -> tuple[CorrelationConclusion, ...]:
        """
        Return the provisional conclusions visible to the on-call operator.

        With ``sequence`` set, returns the view after the latest real-time event whose id
        is less than or equal to that sequence. Sequence ids are returned by
        :meth:`audit_trail` and are stable for a given replay.
        """
        if not self._audit:
            return ()
        if sequence is None:
            return self._audit[-1].conclusions
        for snapshot in reversed(self._audit):
            if snapshot.sequence <= sequence:
                return snapshot.conclusions
        return ()

    def audit_trail(self) -> tuple[OnCallSnapshot, ...]:
        """Return every on-call snapshot in replay order."""
        return tuple(self._audit)

    # ------------------------------------------------------------------
    # Review consumer
    # ------------------------------------------------------------------
    def backfill(
        self, events: Iterable[Event], arrival_time: datetime | None = None
    ) -> RevisionReport:
        """
        Ingest late records and reconcile only the relationships they can affect.

        Revisions are created for unresolved provisional conclusions in the late record's
        group whose event-time window is within one ``timespan`` of the late record. Other
        groups and unrelated windows are left untouched.
        """
        late_by_group: dict[tuple[Any, ...], list[_Observation]] = {}
        for event in events:
            arrival = self._resolve_arrival(
                event, arrival_time, require=self.final_basis is TimeBasis.ARRIVAL_TIME
            )
            _, observations = self._ingest(event, arrival, is_backfill=True)
            for observation in observations:
                late_by_group.setdefault(observation.group_key, []).append(observation)

        if not late_by_group:
            return RevisionReport((), (), ())

        revisions: list[CorrelationRevision] = []
        new_conclusions: list[CorrelationConclusion] = []
        for group_key, late_observations in late_by_group.items():
            group_revisions, group_new = self._reconcile_group(group_key, late_observations)
            revisions.extend(group_revisions)
            new_conclusions.extend(group_new)

        return RevisionReport(
            affected_groups=tuple(late_by_group.keys()),
            revisions=tuple(revisions),
            new_conclusions=tuple(new_conclusions),
        )

    def review(self) -> RevisionReport:
        """
        Run the end-of-day event-time pass over every observed group.

        Unlike :meth:`backfill`, this intentionally resolves all still-provisional
        conclusions. It is the next-day review consumer's final sweep.
        """
        revisions: list[CorrelationRevision] = []
        new_conclusions: list[CorrelationConclusion] = []
        affected_groups: list[tuple[Any, ...]] = []

        for group_key in self._group_order:
            affected_groups.append(group_key)
            final_evaluations = self._evaluate_all(self._groups[group_key], self.final_basis)
            for provisional in self._provisional_history:
                if provisional.group_key != group_key:
                    continue
                if provisional.conclusion_id in self._resolved_provisionals:
                    continue
                revisions.append(self._revise_provisional(provisional, backfill_event_ids=()))
            new_conclusions.extend(self._update_final(group_key, final_evaluations))

        return RevisionReport(
            affected_groups=tuple(affected_groups),
            revisions=tuple(revisions),
            new_conclusions=tuple(new_conclusions),
        )

    def finalize(self) -> RevisionReport:
        """Alias for :meth:`review` for consumers that prefer finalization terminology."""
        return self.review()

    @property
    def provisional_history(self) -> tuple[CorrelationConclusion, ...]:
        return tuple(self._provisional_history)

    @property
    def revisions(self) -> tuple[CorrelationRevision, ...]:
        return tuple(self._revisions)

    @property
    def final_conclusions(self) -> tuple[CorrelationConclusion, ...]:
        return tuple(
            conclusion
            for group_key in self._group_order
            for conclusion in self._final.get(group_key, {}).values()
        )

    @property
    def events(self) -> tuple[IngestedEvent, ...]:
        return tuple(self._events)

    # ------------------------------------------------------------------
    # Ingestion and matching
    # ------------------------------------------------------------------
    def _resolve_arrival(
        self, event: Event, arrival_time: datetime | None, *, require: bool
    ) -> datetime:
        arrival = arrival_time if arrival_time is not None else event.arrival_time
        if arrival is None:
            if require:
                raise ValueError("An explicit arrival_time is required for arrival-time evaluation")
            arrival = event.timestamp
        return arrival

    def _ingest(
        self, event: Event, arrival_time: datetime, *, is_backfill: bool
    ) -> tuple[IngestedEvent, list[_Observation]]:
        self._event_counter += 1
        ingested = IngestedEvent(
            event_id=self._event_counter,
            event=event,
            arrival_time=arrival_time,
            is_backfill=is_backfill,
        )
        self._events.append(ingested)

        observations = self._match_base_rules(ingested)
        for observation in observations:
            if observation.group_key not in self._groups:
                self._groups[observation.group_key] = []
                self._group_order.append(observation.group_key)
            self._groups[observation.group_key].append(observation)
            self._observation_index[(observation.event_id, observation.rule_name)] = observation
        return ingested, observations

    def _match_base_rules(self, ingested: IngestedEvent) -> list[_Observation]:
        event = ingested.event
        try:
            event_logsource = SigmaLogSource(
                category=event.logsource.category,
                product=event.logsource.product,
                service=event.logsource.service,
            )
        except SigmaLogsourceError:
            return []

        observations: list[_Observation] = []
        for rule_name, base_rule, matcher in self._base_matchers:
            if event_logsource not in base_rule.logsource:
                continue
            if matcher.matches(event) is None:
                continue
            observations.append(
                _Observation(
                    event_id=ingested.event_id,
                    rule_name=rule_name,
                    rule=base_rule,
                    group_key=extract_group_key(self.rule, base_rule, event.data),
                    event_time=event.timestamp,
                    arrival_time=ingested.arrival_time,
                    sequence=ingested.event_id,
                )
            )
        return observations

    # ------------------------------------------------------------------
    # Correlation evaluation
    # ------------------------------------------------------------------
    def _evaluate(
        self, observations: Iterable[_Observation], basis: TimeBasis
    ) -> _Evaluation | None:
        ordered = self._ordered_observations(observations, basis)
        if not ordered:
            return None

        for start in range(len(ordered)):
            start_time = ordered[start].time_for(basis)
            end = start
            while (
                end < len(ordered)
                and self._seconds_between(ordered[end].time_for(basis), start_time)
                <= self._timespan_seconds
            ):
                end += 1
            evaluation = self._evaluate_window(ordered[start:end], basis)
            if evaluation is not None:
                return evaluation
        return None

    def _evaluate_all(
        self, observations: Iterable[_Observation], basis: TimeBasis
    ) -> list[_Evaluation]:
        """Enumerate every distinct satisfying relation in the group."""
        ordered = self._ordered_observations(observations, basis)
        evaluations: dict[tuple[tuple[int, str], ...], _Evaluation] = {}
        for start in range(len(ordered)):
            start_time = ordered[start].time_for(basis)
            end = start
            while (
                end < len(ordered)
                and self._seconds_between(ordered[end].time_for(basis), start_time)
                <= self._timespan_seconds
            ):
                end += 1
            evaluation = self._evaluate_window(ordered[start:end], basis)
            if evaluation is not None:
                evaluations.setdefault(evaluation.participant_keys, evaluation)
        return list(evaluations.values())

    def _ordered_observations(
        self, observations: Iterable[_Observation], basis: TimeBasis
    ) -> list[_Observation]:
        unique: dict[tuple[int, str], _Observation] = {}
        for observation in observations:
            unique.setdefault((observation.event_id, observation.rule_name), observation)
        return sorted(
            unique.values(),
            key=lambda observation: (
                observation.time_for(basis),
                observation.sequence,
                observation.rule_name,
            ),
        )

    def _evaluate_window(self, window: list[_Observation], basis: TimeBasis) -> _Evaluation | None:
        first_by_rule: dict[str, _Observation] = {}
        for observation in window:
            first_by_rule.setdefault(observation.rule_name, observation)

        participants: tuple[_Observation, ...] | None = None
        if self.rule.type is SigmaCorrelationType.TEMPORAL:
            if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
                if not self._eval_expression(self.rule.condition.parsed, set(first_by_rule)):
                    return None
                participants = tuple(
                    first_by_rule[name] for name in self._required_rules if name in first_by_rule
                )
            else:
                if not all(name in first_by_rule for name in self._required_rules):
                    return None
                participants = tuple(first_by_rule[name] for name in self._required_rules)
        else:
            if isinstance(self.rule.condition, SigmaExtendedCorrelationCondition):
                first_times = {
                    name: observation.time_for(basis) for name, observation in first_by_rule.items()
                }
                satisfied, _ = self._eval_ordered_expression(
                    self.rule.condition.parsed, first_times
                )
                if not satisfied:
                    return None
                participants = tuple(
                    first_by_rule[name]
                    for name in sorted(
                        (name for name in self._required_rules if name in first_by_rule),
                        key=lambda name: first_times[name],
                    )
                )
            else:
                chain: list[_Observation] = []
                expected_index = 0
                for observation in window:
                    if (
                        expected_index < len(self._required_rules)
                        and observation.rule_name == self._required_rules[expected_index]
                    ):
                        chain.append(observation)
                        expected_index += 1
                        if expected_index == len(self._required_rules):
                            break
                if expected_index < len(self._required_rules):
                    return None
                participants = tuple(chain)

        if not participants:
            return None
        return _Evaluation(participants)

    def _eval_expression(
        self, node: "CorrelationConditionItem | SigmaRuleReference", fired: set[str]
    ) -> bool:
        if isinstance(node, SigmaRuleReference):
            return node.reference in fired
        if isinstance(node, CorrelationConditionAND):
            return all(self._eval_expression(argument, fired) for argument in node.args)
        if isinstance(node, CorrelationConditionOR):
            return any(self._eval_expression(argument, fired) for argument in node.args)
        if isinstance(node, CorrelationConditionNOT):
            return not self._eval_expression(node.args[0], fired)
        return False

    def _eval_ordered_expression(
        self,
        node: "CorrelationConditionItem | SigmaRuleReference",
        first_times: dict[str, datetime],
    ) -> tuple[bool, datetime | None]:
        if isinstance(node, SigmaRuleReference):
            timestamp = first_times.get(node.reference)
            return timestamp is not None, timestamp
        if isinstance(node, CorrelationConditionAND):
            last_timestamp: datetime | None = None
            for argument in node.args:
                satisfied, timestamp = self._eval_ordered_expression(argument, first_times)
                if not satisfied:
                    return False, None
                if (
                    last_timestamp is not None
                    and timestamp is not None
                    and timestamp < last_timestamp
                ):
                    return False, None
                if timestamp is not None:
                    last_timestamp = timestamp
            return True, last_timestamp
        if isinstance(node, CorrelationConditionOR):
            for argument in node.args:
                satisfied, timestamp = self._eval_ordered_expression(argument, first_times)
                if satisfied:
                    return True, timestamp
            return False, None
        if isinstance(node, CorrelationConditionNOT):
            satisfied, _ = self._eval_ordered_expression(node.args[0], first_times)
            return not satisfied, None
        return False, None

    # ------------------------------------------------------------------
    # Provisional and final conclusions
    # ------------------------------------------------------------------
    def _update_provisional(
        self, group_key: tuple[Any, ...], sequence: int
    ) -> list[CorrelationConclusion]:
        evaluations = self._evaluate_all(self._groups[group_key], self.provisional_basis)
        active = self._active_provisional.setdefault(group_key, {})

        emitted: list[CorrelationConclusion] = []
        for evaluation in evaluations:
            participant_key = evaluation.participant_keys
            if participant_key in active:
                continue
            conclusion = self._new_conclusion(
                evaluation,
                status=ConclusionStatus.PROVISIONAL,
                basis=self.provisional_basis,
                sequence=sequence,
            )
            active[participant_key] = conclusion
            self._provisional_history.append(conclusion)
            emitted.append(conclusion)
        return emitted

    def _new_conclusion(
        self,
        evaluation: _Evaluation,
        *,
        status: ConclusionStatus,
        basis: TimeBasis,
        sequence: int,
        supersedes: str | None = None,
        revision_of: str | None = None,
        reason: str | None = None,
    ) -> CorrelationConclusion:
        self._conclusion_counter += 1
        if not evaluation.observations:
            raise ValueError("Cannot build a correlation conclusion without participants")
        group_key = evaluation.observations[0].group_key
        return CorrelationConclusion(
            conclusion_id=f"c{self._conclusion_counter:04d}",
            rule_name=self.rule.name or "",
            group_key=group_key,
            group_values=make_group_values(self.rule, group_key),
            status=status,
            event_ids=tuple(observation.event_id for observation in evaluation.observations),
            rule_names=tuple(observation.rule_name for observation in evaluation.observations),
            event_times=tuple(observation.event_time for observation in evaluation.observations),
            arrival_times=tuple(
                observation.arrival_time for observation in evaluation.observations
            ),
            basis=basis,
            sequence=sequence,
            supersedes=supersedes,
            revision_of=revision_of,
            reason=reason,
        )

    def _reconcile_group(
        self,
        group_key: tuple[Any, ...],
        late_observations: list[_Observation],
    ) -> tuple[list[CorrelationRevision], list[CorrelationConclusion]]:
        revisions: list[CorrelationRevision] = []
        for provisional in self._provisional_history:
            if provisional.group_key != group_key:
                continue
            if provisional.conclusion_id in self._resolved_provisionals:
                continue
            if not self._is_affected(provisional, late_observations):
                continue
            revisions.append(
                self._revise_provisional(
                    provisional,
                    backfill_event_ids=tuple(
                        dict.fromkeys(observation.event_id for observation in late_observations)
                    ),
                )
            )

        final_evaluations = self._evaluate_all(self._groups[group_key], self.final_basis)
        new_conclusions = self._update_final(group_key, final_evaluations)
        return revisions, new_conclusions

    def _is_affected(
        self,
        provisional: CorrelationConclusion,
        late_observations: list[_Observation],
    ) -> bool:
        provisional_times = (
            provisional.event_times
            if self.final_basis is TimeBasis.EVENT_TIME
            else provisional.arrival_times
        )
        for observation in late_observations:
            late_time = observation.time_for(self.final_basis)
            for provisional_time in provisional_times:
                if self._seconds_between(late_time, provisional_time) <= self._timespan_seconds:
                    return True
        return False

    def _revise_provisional(
        self,
        provisional: CorrelationConclusion,
        *,
        backfill_event_ids: tuple[int, ...],
    ) -> CorrelationRevision:
        participants = [
            self._observation_index[(event_id, rule_name)]
            for event_id, rule_name in provisional.participant_keys
            if (event_id, rule_name) in self._observation_index
        ]
        evaluation = self._evaluate(participants, self.final_basis) if participants else None
        if evaluation is not None:
            status = ConclusionStatus.CONFIRMED
            reason = "event-time review kept the provisional relationship"
        else:
            status = ConclusionStatus.RETRACTED
            reason = "event-time review invalidated the provisional relationship"

        self._resolved_provisionals.add(provisional.conclusion_id)
        self._revision_counter += 1
        revision = CorrelationRevision(
            revision_id=f"r{self._revision_counter:04d}",
            conclusion_id=provisional.conclusion_id,
            status=status,
            reason=reason,
            final_event_ids=(
                tuple(observation.event_id for observation in evaluation.observations)
                if evaluation is not None
                else ()
            ),
            backfill_event_ids=backfill_event_ids,
            sequence=self._events[-1].event_id if self._events else provisional.sequence,
        )
        self._revisions.append(revision)
        return revision

    def _update_final(
        self, group_key: tuple[Any, ...], evaluations: list[_Evaluation]
    ) -> list[CorrelationConclusion]:
        finals = self._final.setdefault(group_key, {})
        current_keys = {evaluation.participant_keys for evaluation in evaluations}
        for participant_key in list(finals):
            if participant_key not in current_keys:
                del finals[participant_key]

        new_conclusions: list[CorrelationConclusion] = []
        for evaluation in evaluations:
            participant_key = evaluation.participant_keys
            if participant_key in finals:
                continue
            confirmed_sequence = max(
                observation.event_id for observation in evaluation.observations
            )
            conclusion = self._new_conclusion(
                evaluation,
                status=ConclusionStatus.CONFIRMED,
                basis=self.final_basis,
                sequence=confirmed_sequence,
                reason="event-time review",
            )
            finals[participant_key] = conclusion

            if not any(
                provisional.group_key == group_key
                and provisional.participant_keys == participant_key
                for provisional in self._provisional_history
            ):
                new_conclusions.append(conclusion)
        return new_conclusions

    # ------------------------------------------------------------------
    # Audit and utilities
    # ------------------------------------------------------------------
    def _record_snapshot(self, ingested: IngestedEvent) -> None:
        active = tuple(
            conclusion
            for group_key in self._group_order
            for conclusion in self._active_provisional.get(group_key, {}).values()
        )
        self._audit.append(
            OnCallSnapshot(
                sequence=ingested.event_id,
                event_id=ingested.event_id,
                arrival_time=ingested.arrival_time,
                conclusions=active,
            )
        )

    @staticmethod
    def _seconds_between(first: datetime, second: datetime) -> float:
        try:
            return abs((first - second).total_seconds())
        except TypeError as error:
            raise ValueError(
                "Correlation timestamps must be consistently timezone-aware or naive"
            ) from error
