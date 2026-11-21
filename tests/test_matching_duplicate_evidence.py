"""Fault drill: duplicated sensor logs must not count as a second confirmation.

Scenario: after a sensor retrofit, one real event is retained as several logs
whose fields differ slightly. This drill replays copies of one source and a
truly independent second source through pySigma's built-in correlation
matching entry point (SigmaMatcher) and reads out which correlation rules
would mistake a copy for a second confirmation.

Evidence identity is provided explicitly by the fixture via ``Event.event_id``.
Acceptance flow: copies of one source are fed first, then an independent
source; an alert may only escalate once the second source is added.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from sigma.collection import SigmaCollection
from sigma.matching import Event, EventLogSource, SigmaMatcher

DRILL_RULES = """
title: Credential Dumping Tool Execution
name: cred_dump
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "mimikatz"
    condition: selection
---
title: Same Host Confirmed By Second Source
name: corr_confirm
status: test
correlation:
    type: event_count
    rules:
        - cred_dump
    group-by:
        - host
    timespan: 10m
    condition:
        gte: 2
---
title: Distinct Users On Same Host
name: corr_distinct_users
status: test
correlation:
    type: value_count
    rules:
        - cred_dump
    group-by:
        - host
    timespan: 10m
    condition:
        gte: 2
        field: user
"""

CORRELATION_RULE_NAMES = {"corr_confirm", "corr_distinct_users"}


@pytest.fixture
def drill_collection():
    return SigmaCollection.from_yaml(DRILL_RULES)


@pytest.fixture
def logsource():
    return EventLogSource(category="process_creation", product="windows")


def _copy_of_source_a(index, logsource, with_identity=True):
    """A copy of the one real event reported by source A.

    The retrofit sensors keep the copies with slightly different fields
    (sensor version, message wording, reception time), but it is the same
    evidence. The fixture explicitly provides the evidence identity.
    """
    variants = [
        {"sensor": "sensorA-v1", "Message": "mimikatz run", "ReceivedQt": "08:00:01.1"},
        {
            "sensor": "sensorA-v2",
            "Message": "mimikatz run (reserialized)",
            "ReceivedQt": "08:00:01.4",
        },
        {
            "sensor": "sensorA-v2",
            "Message": "mimikatz run (reserialized, retry)",
            "ReceivedQt": "08:00:02.2",
        },
    ]
    data = {
        "CommandLine": "mimikatz.exe",
        "host": "WS1",
        "user": "alice",
        **variants[index],
    }
    return Event(
        timestamp=datetime(2026, 11, 22, 8, 0, 1, tzinfo=timezone.utc) + timedelta(seconds=index),
        logsource=logsource,
        data=data,
        event_id="EVT-1" if with_identity else None,
    )


def _independent_source_b(logsource, with_identity=True):
    """A truly independent second source reporting its own real event."""
    return Event(
        timestamp=datetime(2026, 11, 22, 8, 0, 5, tzinfo=timezone.utc),
        logsource=logsource,
        data={
            "CommandLine": "mimikatz.exe",
            "host": "WS1",
            "user": "bob",
            "sensor": "sensorB-v1",
            "Message": "mimikatz run",
        },
        event_id="EVT-2" if with_identity else None,
    )


@pytest.fixture
def replay(logsource):
    """One replay: copies of a single source, then an independent second source.

    Evidence identity is explicitly provided by this fixture.
    """
    copies = [_copy_of_source_a(i, logsource) for i in range(3)]
    independent = [_independent_source_b(logsource)]
    return copies, independent


def _run_replay(collection, copies, independent):
    """Feed copies of one source first, then the independent source.

    Returns (copies_report, escalation_report): offline match records produced
    while only copies were fed, and those produced after the second source was
    added.
    """
    with SigmaMatcher(collection) as matcher:
        copies_matches = [match for event in copies for match in matcher.match(event)]
        escalation_matches = [match for event in independent for match in matcher.match(event)]
    return (
        [match.to_dict() for match in copies_matches],
        [match.to_dict() for match in escalation_matches],
    )


def _false_confirmations(report):
    """Readout: correlation rules that escalated while only copies were fed."""
    return {record["rule"] for record in report if record["rule"] in CORRELATION_RULE_NAMES}


class TestDuplicateEvidenceDrill:
    def test_copies_do_not_escalate_only_second_source_does(self, drill_collection, replay):
        """Acceptance flow: escalation is only allowed once the second source is added."""
        copies, independent = replay
        copies_report, escalation_report = _run_replay(drill_collection, copies, independent)

        # While only copies of one source were fed, no correlation rule may escalate.
        assert _false_confirmations(copies_report) == set()

        # Once the independent second source is added, the confirmation rule escalates.
        escalations = [r for r in escalation_report if r["rule"] == "corr_confirm"]
        assert len(escalations) == 1
        assert escalations[0]["group_values"] == {"host": "WS1"}
        assert escalations[0]["evidence_ids"] == ["EVT-1", "EVT-2"]
        assert escalations[0]["event_count"] == 2

    def test_drill_readout_flags_rules_that_miscount_copies(self, drill_collection, logsource):
        """The drill reads out which rules mistake a copy for a second confirmation.

        Replaying the same logs without the fixture-provided evidence identity
        shows exactly which correlation rules are vulnerable to duplicated logs.
        """
        copies = [_copy_of_source_a(i, logsource, with_identity=False) for i in range(3)]
        independent = [_independent_source_b(logsource, with_identity=False)]
        copies_report, _ = _run_replay(drill_collection, copies, independent)

        # event_count counts every log line, so it mistakes copies for confirmations;
        # value_count on distinct users is not fooled by copies of one event.
        assert _false_confirmations(copies_report) == {"corr_confirm"}

    def test_single_event_judgments_preserved(self, drill_collection, replay):
        """Each copy still matches the base rule on its own; only correlation dedupes."""
        copies, _ = replay
        with SigmaMatcher(drill_collection) as matcher:
            for event in copies:
                matches = matcher.match(event)
                base_matches = [m for m in matches if m.rule.name == "cred_dump"]
                assert len(base_matches) == 1
                assert base_matches[0].evidence_ids == ("EVT-1",)

    def test_offline_report_is_json_serializable(self, drill_collection, replay):
        copies, independent = replay
        copies_report, escalation_report = _run_replay(drill_collection, copies, independent)
        serialized = json.dumps({"copies": copies_report, "escalation": escalation_report})
        assert "EVT-1" in serialized
        assert "corr_confirm" in serialized


class TestEvidenceIdentity:
    def _match(self, event_id):
        event = Event(
            timestamp=datetime(2026, 11, 22, 8, 0, 0, tzinfo=timezone.utc),
            logsource=EventLogSource(category="process_creation", product="windows"),
            data={"CommandLine": "mimikatz.exe"},
            event_id=event_id,
        )
        collection = SigmaCollection.from_yaml(DRILL_RULES.split("---")[0])
        with SigmaMatcher(collection) as matcher:
            return matcher.match(event)[0]

    def test_match_exposes_evidence_identity(self):
        match = self._match("EVT-9")
        assert match.evidence_ids == ("EVT-9",)
        assert match.to_dict()["evidence_ids"] == ["EVT-9"]

    def test_match_without_identity(self):
        match = self._match(None)
        assert match.evidence_ids == ()
        assert match.to_dict()["evidence_ids"] == []

    def test_to_dict_contains_offline_fields(self):
        record = self._match("EVT-9").to_dict()
        assert record["rule"] == "cred_dump"
        assert record["timestamp"].startswith("2026-11-22T08:00:00")
        assert record["group_values"] is None
        assert record["event_count"] == 1
