"""Tests for the sigma.review replacement review module."""

import json
from datetime import datetime

import pytest

from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline
from sigma.review import (
    APPROVAL_BASIS_NOTE,
    ConsumerProfile,
    ReplacementCandidate,
    ReplacementReviewer,
)
from sigma.rule.logsource import SigmaLogSource


def rules_from_yaml(yaml: str):
    return [rule for rule in SigmaCollection.from_yaml(yaml).rules]


@pytest.fixture
def old_rule():
    return rules_from_yaml(
        """
title: Old Mimikatz Rule
name: old_mimikatz
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
"""
    )[0]


@pytest.fixture
def covering_replacement():
    return rules_from_yaml(
        """
title: Consolidated Mimikatz Rule
name: consolidated_mimikatz
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
"""
    )[0]


@pytest.fixture
def narrower_replacement():
    return rules_from_yaml(
        """
title: Narrower Replacement
name: narrower_replacement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
        Image|endswith: '\\other.exe'
    condition: selection
"""
    )[0]


class TestReplacementVerdicts:
    def test_replacement_covers(self, old_rule, covering_replacement):
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[covering_replacement],
        )
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "replacement_covers"
        assert report.unique_events == []
        assert report.unexplained_modifiers == []

    def test_keep_old_rules_with_evidence(self, old_rule, narrower_replacement):
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[narrower_replacement],
        )
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "keep_old_rules"
        assert len(report.unique_events) == 1
        evidence = report.unique_events[0]
        assert evidence.rule == "Old Mimikatz Rule"
        assert evidence.perspective.startswith("original")
        assert "mimikatz" in evidence.event_data["CommandLine"]
        assert "Old Mimikatz Rule" in report.on_call_briefing
        assert APPROVAL_BASIS_NOTE in report.on_call_briefing

    def test_unexplained_modifier_marks_missing_semantics(self):
        old_rule = rules_from_yaml(
            """
title: Regex Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|re: "mim.*"
    condition: selection
"""
        )[0]
        candidate = ReplacementCandidate(old_rules=[old_rule], replacement_rules=[])
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "inconclusive"
        semantics = {m.missing_semantics for m in report.unexplained_modifiers}
        assert "regular expression synthesis" in semantics
        assert "regular expression synthesis" in report.on_call_briefing

    def test_uncoverable_rule_is_inconclusive(self):
        old_rule = rules_from_yaml(
            """
title: Timestamp Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventTime|hour: 5
    condition: selection
"""
        )[0]
        candidate = ReplacementCandidate(old_rules=[old_rule], replacement_rules=[])
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "inconclusive"
        assert "Timestamp Rule" in report.uncovered_rules
        semantics = {m.missing_semantics for m in report.unexplained_modifiers}
        assert "timestamp part extraction" in semantics


class TestPerspectives:
    def test_transformed_perspective_uses_pipeline(self, old_rule):
        replacement = rules_from_yaml(
            """
title: Renamed Field Replacement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CmdLine|contains: "mimikatz"
    condition: selection
"""
        )[0]
        pipeline = ProcessingPipeline.from_dict(
            {
                "name": "field-renames",
                "transformations": [
                    {
                        "id": "cmdline-rename",
                        "type": "field_name_mapping",
                        "mapping": {"CommandLine": "CmdLine"},
                    }
                ],
            }
        )
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[replacement],
            pipeline=pipeline,
        )
        report = ReplacementReviewer(candidate).review()
        perspectives = {evidence.perspective for evidence in report.unique_events}
        # The original rules disagree, but after the field transformation the
        # replacement covers the old rule.
        assert any(p.startswith("original") for p in perspectives)
        assert "transformed" not in perspectives

    def test_transformed_perspective_finds_unique_events(self, old_rule, narrower_replacement):
        pipeline = ProcessingPipeline.from_dict(
            {
                "name": "field-renames",
                "transformations": [
                    {
                        "id": "cmdline-rename",
                        "type": "field_name_mapping",
                        "mapping": {"CommandLine": "CmdLine"},
                    }
                ],
            }
        )
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[narrower_replacement],
            pipeline=pipeline,
        )
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "keep_old_rules"
        perspectives = {evidence.perspective for evidence in report.unique_events}
        assert any(p.startswith("original") for p in perspectives)
        assert any(p.startswith("transformed") for p in perspectives)


class TestConsumers:
    def test_consumer_with_missing_fields_is_affected(self, old_rule, narrower_replacement):
        consumer = ConsumerProfile(
            name="edr-old-devices",
            logsource=SigmaLogSource(category="process_creation", product="windows"),
            available_fields=frozenset({"CommandLine", "Image"}),
            on_call="soc-night-shift",
        )
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[narrower_replacement],
            consumers=[consumer],
        )
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "keep_old_rules"
        evidence = report.unique_events[0]
        assert "edr-old-devices" in evidence.affected_consumers
        assert "soc-night-shift" in report.on_call_briefing

    def test_consumer_without_required_old_fields_is_not_affected(
        self, old_rule, narrower_replacement
    ):
        consumer = ConsumerProfile(
            name="limited-consumer",
            logsource=SigmaLogSource(category="process_creation", product="windows"),
            available_fields=frozenset({"Image"}),
        )
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[narrower_replacement],
            consumers=[consumer],
        )
        report = ReplacementReviewer(candidate).review()
        assert report.unique_events[0].affected_consumers == []

    def test_consumer_other_logsource_is_not_affected(self, old_rule, narrower_replacement):
        consumer = ConsumerProfile(
            name="linux-consumer",
            logsource=SigmaLogSource(product="linux"),
            available_fields=None,
        )
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[narrower_replacement],
            consumers=[consumer],
        )
        report = ReplacementReviewer(candidate).review()
        assert report.unique_events[0].affected_consumers == []


class TestFreshness:
    def test_each_review_is_a_fresh_approval_basis(self, old_rule, covering_replacement):
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[covering_replacement],
        )
        reviewer = ReplacementReviewer(candidate)
        first = reviewer.review()
        second = reviewer.review()
        assert first.review_id != second.review_id
        assert isinstance(first.generated_at, datetime)
        for report in (first, second):
            assert report.prior_coverage_accepted is False
            assert report.approval_basis == APPROVAL_BASIS_NOTE

    def test_report_serializes(self, old_rule, narrower_replacement):
        candidate = ReplacementCandidate(
            old_rules=[old_rule],
            replacement_rules=[narrower_replacement],
        )
        report = ReplacementReviewer(candidate).review()
        serialized = json.dumps(report.to_dict())
        assert "keep_old_rules" in serialized


class TestSynthesis:
    def test_keyword_rule_generates_raw_event(self):
        old_rule = rules_from_yaml(
            """
title: Keyword Rule
logsource:
    category: process_creation
    product: windows
detection:
    keywords:
        - mimikatz
    condition: keywords
"""
        )[0]
        candidate = ReplacementCandidate(old_rules=[old_rule], replacement_rules=[])
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "keep_old_rules"
        assert report.unique_events[0].event_raw == "mimikatz"

    def test_and_condition_generates_merged_event(self):
        old_rule = rules_from_yaml(
            """
title: And Condition Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains: "mimikatz"
    selection_img:
        Image|endswith: '\\mimikatz.exe'
    condition: selection_cmd and selection_img
"""
        )[0]
        candidate = ReplacementCandidate(old_rules=[old_rule], replacement_rules=[])
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "keep_old_rules"
        merged = [
            evidence
            for evidence in report.unique_events
            if "CommandLine" in evidence.event_data and "Image" in evidence.event_data
        ]
        assert merged

    def test_explainable_modifiers_are_not_flagged(self):
        old_rule = rules_from_yaml(
            """
title: Windash Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|windash|contains: "-enc"
    condition: selection
"""
        )[0]
        covering = rules_from_yaml(
            """
title: Windash Replacement
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|windash|contains: "-enc"
    condition: selection
"""
        )[0]
        candidate = ReplacementCandidate(old_rules=[old_rule], replacement_rules=[covering])
        report = ReplacementReviewer(candidate).review()
        assert report.verdict == "replacement_covers"
        assert report.unexplained_modifiers == []
