from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Self

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule, SigmaExtendedCorrelationCondition
from sigma.matching.compiler import MatchCompiler
from sigma.matching.correlation_matcher import SigmaCorrelationRuleMatcher
from sigma.matching.event import Event, EventLogSource
from sigma.matching.handover import (
    HandoverInterval,
    HandoverTracker,
    HandoverUndeterminableRange,
)
from sigma.matching.match import MatchOutcome, SigmaMatch
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule.logsource import SigmaLogSource
from sigma.rule.rule import SigmaRule


class SigmaMatcher:
    """
    Orchestrator that matches events against a collection of Sigma rules.

    Manages logsource dispatch, threading, and correlation.
    """

    def __init__(
        self,
        collection: SigmaCollection,
        pipeline: ProcessingPipeline | None = None,
        max_workers: int | None = None,
        max_events_per_match: int | None = 100,
        max_correlation_state: int | None = None,
        handover_intervals: list[HandoverInterval] | HandoverInterval | None = None,
    ) -> None:
        self._compiler = MatchCompiler()
        self.collection = collection
        self._handover_tracker = HandoverTracker()
        self._handover_tracker.add_intervals(handover_intervals)

        # Apply pipeline if provided
        if pipeline is not None:
            for rule in collection.rules:
                pipeline.apply(rule)

        # Build dispatch table and correlation matchers
        self._dispatch: dict[tuple[str | None, str | None, str | None], list[SigmaRuleMatcher]] = (
            defaultdict(list)
        )
        self._all_rule_matchers: list[SigmaRuleMatcher] = []
        # Map rule name -> list of correlation matchers that reference it
        self._correlation_map: dict[str, list[SigmaCorrelationRuleMatcher]] = defaultdict(list)
        self._correlation_matchers: list[SigmaCorrelationRuleMatcher] = []
        self._correlation_state_keys: dict[SigmaCorrelationRuleMatcher, str] = {}

        for rule in collection.rules:
            if isinstance(rule, SigmaRule):
                rm = SigmaRuleMatcher(rule, self._compiler)
                self._all_rule_matchers.append(rm)
                key = (
                    rule.logsource.category,
                    rule.logsource.product,
                    rule.logsource.service,
                )
                self._dispatch[key].append(rm)
            elif isinstance(rule, SigmaCorrelationRule):
                cm = SigmaCorrelationRuleMatcher(
                    rule,
                    max_state=max_correlation_state,
                    max_events_per_match=max_events_per_match,
                    handover_tracker=self._handover_tracker,
                )
                self._correlation_matchers.append(cm)
                self._correlation_state_keys[cm] = str(
                    rule.name or len(self._correlation_matchers) - 1
                )
                if rule.rules:
                    for ref in rule.rules:
                        self._correlation_map[ref.reference].append(cm)
                elif isinstance(rule.condition, SigmaExtendedCorrelationCondition):
                    for name in rule.condition.get_referenced_rules():
                        self._correlation_map[name].append(cm)

    def match(
        self,
        event: Event,
        handover_intervals: list[HandoverInterval] | HandoverInterval | None = None,
        handover_interval: HandoverInterval | None = None,
    ) -> list[SigmaMatch]:
        intervals = handover_intervals or handover_interval
        return self.process_event(event, intervals).matches

    def match_event(
        self,
        event: Event,
        handover_intervals: list[HandoverInterval] | HandoverInterval | None = None,
        handover_interval: HandoverInterval | None = None,
    ) -> MatchOutcome:
        intervals = handover_intervals or handover_interval
        return self.process_event(event, intervals)

    def process_event(
        self,
        event: Event,
        handover_intervals: list[HandoverInterval] | HandoverInterval | None = None,
        handover_interval: HandoverInterval | None = None,
    ) -> MatchOutcome:
        """Match a single event against all relevant rules. Returns list of matches."""
        self._handover_tracker.add_intervals(handover_intervals or handover_interval)
        self._handover_tracker.record_event(event.timestamp, event.receiver_id)
        matchers = self._get_matchers(event.logsource)
        matches: list[SigmaMatch] = []

        for rm in matchers:
            result = rm.matches(event)
            if result is not None:
                matches.append(result)

        # Route matches to correlation matchers
        correlation_matches: list[SigmaMatch] = []
        for m in matches:
            rule_name = getattr(m.rule, "name", None)
            if rule_name and rule_name in self._correlation_map:
                for cm in self._correlation_map[rule_name]:
                    correlation_matches.extend(cm.receive_match(m, rule_name))

        matches.extend(correlation_matches)
        undeterminable_ranges = self._handover_tracker.flush(event.timestamp)
        return MatchOutcome(matches=matches, undeterminable_ranges=undeterminable_ranges)

    def process_events(self, events: Iterable[Event]) -> list[MatchOutcome]:
        return [self.process_event(event) for event in events]

    def bulk_match(self, events: Iterable[Event]) -> list[SigmaMatch]:
        """Match multiple events, returning all matches. Processes sequentially for ordering."""
        all_matches: list[SigmaMatch] = []
        for event in events:
            all_matches.extend(self.match(event))
        return all_matches

    def finalize(self, now: Any | None = None) -> list[HandoverUndeterminableRange]:
        if now is None:
            now = max(
                (interval.end for interval in self._handover_tracker.intervals),
                default=None,
            )
        if now is None:
            return []
        return self._handover_tracker.flush(now)

    def snapshot_state(self) -> dict[str, object]:
        return {
            "handover": self._handover_tracker.snapshot(),
            "correlations": {
                self._correlation_state_keys[cm]: cm.snapshot()
                for cm in self._correlation_matchers
            },
        }

    def export_state(self) -> dict[str, object]:
        return self.snapshot_state()

    def restore_state(self, state: dict[str, object]) -> None:
        self._handover_tracker.restore(state["handover"])  # type: ignore[arg-type]
        rules_by_name = {rule.name: rule for rule in self.collection.rules if rule.name}
        correlation_states = state["correlations"]
        for cm in self._correlation_matchers:
            correlation_state = correlation_states.get(  # type: ignore[union-attr]
                self._correlation_state_keys[cm]
            )
            if correlation_state is not None:
                cm.restore(correlation_state, rules_by_name)

    def import_state(self, state: dict[str, object]) -> None:
        self.restore_state(state)

    def _get_matchers(self, logsource: EventLogSource) -> list[SigmaRuleMatcher]:
        """Get all rule matchers whose logsource contains the event's logsource."""
        result: list[SigmaRuleMatcher] = []
        event_ls = SigmaLogSource(
            category=logsource.category,
            product=logsource.product,
            service=logsource.service,
        )
        for key, matchers in self._dispatch.items():
            rule_ls = SigmaLogSource(
                category=key[0],
                product=key[1],
                service=key[2],
            )
            if event_ls in rule_ls:
                result.extend(matchers)
        return result

    def close(self) -> None:
        """Clean up resources."""
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
