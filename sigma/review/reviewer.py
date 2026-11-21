from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from sigma.matching.compiler import MatchCompiler
from sigma.matching.event import Event, EventLogSource
from sigma.matching.rule_matcher import SigmaRuleMatcher
from sigma.processing.pipeline import ProcessingPipeline
from sigma.review.consumer import ConsumerProfile
from sigma.review.report import (
    APPROVAL_BASIS_NOTE,
    ReplacementReviewReport,
    UniqueEventEvidence,
)
from sigma.review.synthesis import SyntheticEventGenerator, UnexplainedModifier
from sigma.rule.rule import SigmaRule


@dataclass
class ReplacementCandidate:
    """
    A candidate replacement of old Sigma rules by new consolidated rules.

    * ``old_rules``: rules the business wants to remove as duplicates.
    * ``replacement_rules``: rules that are supposed to take over detection.
    * ``pipeline``: optional processing pipeline with the field transformations that are
      applied before the rules reach the consumers.
    * ``consumers``: downstream consumers with the fields they actually receive.
    """

    old_rules: list[SigmaRule]
    replacement_rules: list[SigmaRule]
    pipeline: ProcessingPipeline | None = None
    consumers: list[ConsumerProfile] = field(default_factory=list)


class ReplacementReviewer:
    """
    Offline review of a candidate replacement of Sigma rules.

    For one candidate the reviewer compares three perspectives:

    1. the original rules as written,
    2. the rules after the field transformations of the processing pipeline,
    3. the fields the associated consumers actually receive.

    If any synthetic event exists that is only detected by an old rule, the event is kept as
    evidence for the maintainers together with an on-call briefing. Modifiers the review
    cannot explain are listed in the conclusion with the semantics that is missing.

    Every call to :meth:`review` computes the result from scratch. Coverage results of
    previous reviews are never consulted and must not be used as approval basis.
    """

    def __init__(self, candidate: ReplacementCandidate) -> None:
        self.candidate = candidate
        self._generator = SyntheticEventGenerator()

    def review(self) -> ReplacementReviewReport:
        """Run the review and return a fresh report. Prior results are never reused."""
        compiler = MatchCompiler()
        unique_events: list[UniqueEventEvidence] = []
        unexplained: list[UnexplainedModifier] = []
        uncovered_rules: list[str] = []

        perspectives = self._perspectives()
        for perspective, old_rules, replacement_rules in perspectives:
            old_matchers = [SigmaRuleMatcher(rule, compiler) for rule in old_rules]
            replacement_matchers = [SigmaRuleMatcher(rule, compiler) for rule in replacement_rules]
            for rule, matcher in zip(old_rules, old_matchers):
                rule_name = SyntheticEventGenerator._rule_name(rule)
                unexplained.extend(self._generator.unexplained_modifiers_for_rule(rule))
                verified = [
                    candidate_event
                    for candidate_event in self._generator.events_for_rule(rule)
                    if matcher.matches(
                        self._to_event(rule, candidate_event.data, candidate_event.raw)
                    )
                    is not None
                ]
                if not verified:
                    uncovered_rules.append(rule_name)
                    continue
                for candidate_event in verified:
                    event = self._to_event(rule, candidate_event.data, candidate_event.raw)
                    if not any(m.matches(event) is not None for m in replacement_matchers):
                        unique_events.append(
                            UniqueEventEvidence(
                                rule=rule_name,
                                perspective=perspective,
                                event_data=dict(candidate_event.data),
                                event_raw=candidate_event.raw,
                                logsource=self._logsource_tuple(rule),
                            )
                        )

        self._evaluate_consumers(compiler, perspectives, unique_events)
        unexplained = self._deduplicate_unexplained(unexplained)
        verdict = self._verdict(unique_events, unexplained, uncovered_rules)
        report = ReplacementReviewReport(
            review_id=str(uuid4()),
            generated_at=datetime.now(timezone.utc),
            verdict=verdict,
            unique_events=unique_events,
            unexplained_modifiers=unexplained,
            uncovered_rules=uncovered_rules,
        )
        report.on_call_briefing = self._on_call_briefing(report)
        return report

    def _perspectives(self) -> list[tuple[str, list[SigmaRule], list[SigmaRule]]]:
        perspectives = [
            ("original", list(self.candidate.old_rules), list(self.candidate.replacement_rules))
        ]
        if self.candidate.pipeline is not None:
            transformed_old = self._transformed(self.candidate.old_rules)
            transformed_replacement = self._transformed(self.candidate.replacement_rules)
            perspectives.append(("transformed", transformed_old, transformed_replacement))
        return perspectives

    def _transformed(self, rules: list[SigmaRule]) -> list[SigmaRule]:
        pipeline = self.candidate.pipeline
        assert pipeline is not None
        transformed = []
        for rule in rules:
            rule_copy = copy.deepcopy(rule)
            pipeline.apply(rule_copy)
            transformed.append(rule_copy)
        return transformed

    def _evaluate_consumers(
        self,
        compiler: MatchCompiler,
        perspectives: list[tuple[str, list[SigmaRule], list[SigmaRule]]],
        unique_events: list[UniqueEventEvidence],
    ) -> None:
        """Check for each unique event which consumers would actually still receive it."""
        if not self.candidate.consumers:
            return
        # Consumers run the transformed rules if a pipeline is in place.
        _, old_rules, replacement_rules = perspectives[-1]
        old_matchers = [SigmaRuleMatcher(rule, compiler) for rule in old_rules]
        replacement_matchers = [SigmaRuleMatcher(rule, compiler) for rule in replacement_rules]
        for evidence in unique_events:
            logsource = EventLogSource(*evidence.logsource)
            for consumer in self.candidate.consumers:
                if not consumer.subscribes_to(logsource):
                    continue
                projected = consumer.project(evidence.event_data)
                event = Event(
                    timestamp=datetime.now(timezone.utc),
                    logsource=logsource,
                    data=projected,
                    raw=evidence.event_raw,
                )
                old_hit = any(m.matches(event) is not None for m in old_matchers)
                replacement_hit = any(m.matches(event) is not None for m in replacement_matchers)
                if old_hit and not replacement_hit:
                    evidence.affected_consumers.append(consumer.name)
                    if "consumer" not in evidence.perspective:
                        evidence.perspective = f"{evidence.perspective}+consumer"

    @staticmethod
    def _verdict(
        unique_events: list[UniqueEventEvidence],
        unexplained: list[UnexplainedModifier],
        uncovered_rules: list[str],
    ) -> str:
        if unique_events:
            return "keep_old_rules"
        if unexplained or uncovered_rules:
            return "inconclusive"
        return "replacement_covers"

    def _on_call_briefing(self, report: ReplacementReviewReport) -> str:
        lines = [f"Replacement review {report.review_id}: verdict {report.verdict}."]
        if report.unique_events:
            lines.append(
                "Keep the old rules: synthetic events exist that only the old rules detect."
            )
            for evidence in report.unique_events:
                consumers = ", ".join(evidence.affected_consumers) or "no subscribed consumer"
                lines.append(
                    f"- Rule '{evidence.rule}' ({evidence.perspective}) uniquely detects "
                    f"{evidence.event_data}; affected consumers: {consumers}."
                )
            on_call_channels = sorted(
                {
                    consumer.on_call
                    for consumer in self.candidate.consumers
                    if consumer.on_call is not None
                    and any(
                        consumer.name in evidence.affected_consumers
                        for evidence in report.unique_events
                    )
                }
            )
            if on_call_channels:
                lines.append("Brief the on-call channels: " + ", ".join(on_call_channels) + ".")
        if report.unexplained_modifiers:
            lines.append("Unexplained modifiers; missing semantics:")
            for modifier in report.unexplained_modifiers:
                lines.append(
                    f"- Rule '{modifier.rule}', field '{modifier.field}', modifier "
                    f"'{modifier.modifier}': missing {modifier.missing_semantics}."
                )
        if report.uncovered_rules:
            lines.append(
                "No verifiable synthetic event could be generated for: "
                + ", ".join(report.uncovered_rules)
                + "."
            )
        lines.append(APPROVAL_BASIS_NOTE)
        return "\n".join(lines)

    @staticmethod
    def _deduplicate_unexplained(
        unexplained: list[UnexplainedModifier],
    ) -> list[UnexplainedModifier]:
        seen: set[tuple[str, str | None, str]] = set()
        result: list[UnexplainedModifier] = []
        for modifier in unexplained:
            key = (modifier.rule, modifier.field, modifier.missing_semantics)
            if key not in seen:
                seen.add(key)
                result.append(modifier)
        return result

    @staticmethod
    def _to_event(rule: SigmaRule, data: dict, raw: str | None) -> Event:
        return Event(
            timestamp=datetime.now(timezone.utc),
            logsource=EventLogSource(
                category=rule.logsource.category,
                product=rule.logsource.product,
                service=rule.logsource.service,
            ),
            data=data,
            raw=raw,
        )

    @staticmethod
    def _logsource_tuple(rule: SigmaRule) -> tuple[str | None, str | None, str | None]:
        return (
            rule.logsource.category,
            rule.logsource.product,
            rule.logsource.service,
        )
