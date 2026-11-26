from datetime import datetime, timedelta, timezone

from sigma.collection import SigmaCollection
from sigma.matching import (
    AssociationCondition,
    AssociationGroupKey,
    AssociationMergeLayer,
    Event,
    EventLogSource,
    SigmaMatcher,
)


RULES_YAML = """
title: Login Rule
name: login_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: login
    condition: selection
---
title: Shared Pivot Rule
name: pivot_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: pivot
    condition: selection
---
title: Access Rule
name: access_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: access
    condition: selection
---
title: Export Rule
name: export_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: export
    condition: selection
---
title: Replacement Pivot Rule
name: replacement_pivot_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: replacement_pivot
    condition: selection
"""


def _events():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    logsource = EventLogSource(category="test", product="test")
    return [
        Event(start, logsource, {"event": "login", "user": "alice"}),
        Event(
            start + timedelta(seconds=1),
            logsource,
            {"event": "pivot", "user": "alice"},
        ),
        Event(
            start + timedelta(seconds=2),
            logsource,
            {"event": "access", "user": "alice"},
        ),
        Event(
            start + timedelta(seconds=5),
            logsource,
            {"event": "export", "user": "alice"},
        ),
        Event(
            start + timedelta(seconds=1, microseconds=500000),
            logsource,
            {"event": "replacement_pivot", "user": "alice"},
        ),
    ]


def _matches():
    collection = SigmaCollection.from_yaml(RULES_YAML)
    with SigmaMatcher(collection) as matcher:
        return [match for event in _events() for match in matcher.match(event)]


def _matches_for_rule(rule_name: str):
    return [match for match in _matches() if match.rule.name == rule_name]


def _merge_layer() -> AssociationMergeLayer:
    return AssociationMergeLayer(
        [
            AssociationCondition(
                name="access_confirmation",
                rule_names=("login_rule", "pivot_rule", "access_rule"),
                group_by=("user",),
            ),
            AssociationCondition(
                name="export_confirmation",
                rule_names=("login_rule", "pivot_rule", "export_rule"),
                group_by=("user",),
            ),
        ]
    )


def test_shared_event_merges_with_minimal_evidence_and_rule_order():
    layer = _merge_layer()
    new_alerts = []
    facts_by_rule = {}

    for match in _matches():
        update = layer.receive_match(match)
        new_alerts.extend(update.new_alerts)
        facts_by_rule[update.fact.rule_name] = update.fact

    assert len(new_alerts) == 1
    alert = layer.active_alerts[0]
    assert alert.condition_names == ("access_confirmation", "export_confirmation")
    assert [event.data["event"] for event in alert.minimal_events] == [
        "login",
        "pivot",
        "access",
        "export",
    ]
    assert len(alert.facts) == 4
    pivot_fact_ids = {
        evidence.causal_order[1].fact_id for evidence in alert.condition_evidence
    }
    assert pivot_fact_ids == {facts_by_rule["pivot_rule"].id}
    assert [cause.rule_name for cause in alert.condition_evidence[0].causal_order] == [
        "login_rule",
        "pivot_rule",
        "access_rule",
    ]
    assert [cause.rule_name for cause in alert.condition_evidence[1].causal_order] == [
        "login_rule",
        "pivot_rule",
        "export_rule",
    ]
    assert facts_by_rule["pivot_rule"].event is not facts_by_rule["login_rule"].event
    assert facts_by_rule["pivot_rule"].id in {
        cause.fact_id for cause in alert.causal_order
    }


def test_replay_fact_revocation_recomputes_each_shared_condition_separately():
    layer = _merge_layer()
    facts_by_rule = {}
    for match in _matches():
        update = layer.receive_match(match)
        facts_by_rule[update.fact.rule_name] = update.fact

    without_access = layer.replay_fact_revocation(facts_by_rule["access_rule"].id)
    without_export = layer.replay_fact_revocation(facts_by_rule["export_rule"].id)

    assert len(layer.active_alerts) == 1
    assert without_access.active_alerts[0].condition_names == ("export_confirmation",)
    assert without_access.updated_alerts[0].condition_names == (
        "export_confirmation",
    )
    assert without_access.retracted_alerts == ()
    assert without_export.active_alerts[0].condition_names == ("access_confirmation",)
    assert without_export.updated_alerts[0].condition_names == (
        "access_confirmation",
    )
    assert without_export.retracted_alerts == ()

    without_pivot = layer.replay_fact_revocation(facts_by_rule["pivot_rule"].id)
    assert without_pivot.active_alerts == ()
    assert without_pivot.retracted_alerts[0].condition_names == (
        "access_confirmation",
        "export_confirmation",
    )


def test_mutating_fact_revocation_rebuilds_from_remaining_facts():
    layer = _merge_layer()
    facts_by_rule = {}
    for match in _matches():
        update = layer.receive_match(match)
        facts_by_rule[update.fact.rule_name] = update.fact

    result = layer.revoke_fact(facts_by_rule["export_rule"].id)

    assert result.active_alerts[0].condition_names == ("access_confirmation",)
    assert result.updated_alerts[0].condition_names == (
        "access_confirmation",
    )
    assert result.retracted_alerts == ()
    assert layer.active_alerts[0].condition_names == ("access_confirmation",)


def test_replay_rule_replacement_uses_new_rule_facts_without_mutating_state():
    layer = _merge_layer()
    facts_by_rule = {}
    for match in _matches():
        update = layer.receive_match(match)
        facts_by_rule[update.fact.rule_name] = update.fact

    replacement_matches = _matches_for_rule("replacement_pivot_rule")
    result = layer.replay_rule_replacement(
        "pivot_rule", "replacement_pivot_rule", replacement_matches
    )

    assert len(result.active_alerts) == 1
    alert = result.active_alerts[0]
    assert {event.data["event"] for event in alert.minimal_events} == {
        "login",
        "replacement_pivot",
        "access",
        "export",
    }
    assert [cause.rule_name for cause in alert.causal_order] == [
        "login_rule",
        "replacement_pivot_rule",
        "access_rule",
        "login_rule",
        "replacement_pivot_rule",
        "export_rule",
    ]
    assert alert.condition_evidence[0].causal_order[1].rule_name == "replacement_pivot_rule"
    assert layer.active_alerts[0].facts[1].rule_name == "pivot_rule"
    next_fact_id_before_application = layer._next_fact_id

    applied = layer.replace_rule(
        "pivot_rule", "replacement_pivot_rule", replacement_matches
    )
    assert applied.active_alerts == result.active_alerts
    assert layer.active_alerts[0].facts[1].rule_name == "replacement_pivot_rule"
    assert layer._next_fact_id == next_fact_id_before_application + len(replacement_matches)
    assert facts_by_rule["pivot_rule"].rule_name == "pivot_rule"


def test_alert_revocation_replays_downstream_confirmations():
    layer = _merge_layer()
    for match in _matches():
        layer.receive_match(match)

    key = AssociationGroupKey(fields=("user",), values=("alice",))
    result = layer.replay_alert_revocation(key)

    assert result.active_alerts == ()
    assert result.retracted_alerts[0].key == key
    assert len(layer.active_alerts) == 1

    applied = layer.revoke_alert(key)
    assert applied.retracted_alerts == result.retracted_alerts
    assert layer.active_alerts == ()


def test_alert_revocation_leaves_other_association_groups_intact():
    layer = _merge_layer()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    logsource = EventLogSource(category="test", product="test")
    events = [
        Event(start, logsource, {"event": "login", "user": "alice"}),
        Event(
            start + timedelta(seconds=1),
            logsource,
            {"event": "pivot", "user": "alice"},
        ),
        Event(
            start + timedelta(seconds=2),
            logsource,
            {"event": "access", "user": "alice"},
        ),
        Event(
            start + timedelta(seconds=3),
            logsource,
            {"event": "export", "user": "alice"},
        ),
        Event(start, logsource, {"event": "login", "user": "bob"}),
        Event(
            start + timedelta(seconds=1),
            logsource,
            {"event": "pivot", "user": "bob"},
        ),
        Event(
            start + timedelta(seconds=2),
            logsource,
            {"event": "access", "user": "bob"},
        ),
        Event(
            start + timedelta(seconds=3),
            logsource,
            {"event": "export", "user": "bob"},
        ),
    ]
    for match in _matches_for_events(*events):
        layer.receive_match(match)

    alice_key = AssociationGroupKey(fields=("user",), values=("alice",))
    bob_key = AssociationGroupKey(fields=("user",), values=("bob",))
    result = layer.replay_alert_revocation(alice_key)

    assert [alert.key for alert in result.active_alerts] == [bob_key]
    assert [alert.key for alert in result.retracted_alerts] == [alice_key]


def test_rule_causal_order_requires_ascending_fact_timestamps():
    layer = AssociationMergeLayer(
        [
            AssociationCondition(
                name="ordered_confirmation",
                rule_names=("login_rule", "pivot_rule"),
                group_by=("user",),
            )
        ]
    )
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    logsource = EventLogSource(category="test", product="test")
    pivot_event = Event(start, logsource, {"event": "pivot", "user": "bob"})
    login_event = Event(
        start + timedelta(seconds=1), logsource, {"event": "login", "user": "bob"}
    )

    for match in _matches_for_events(pivot_event, login_event):
        layer.receive_match(match)

    assert layer.active_alerts == ()


def _matches_for_events(*events: Event):
    collection = SigmaCollection.from_yaml(RULES_YAML)
    with SigmaMatcher(collection) as matcher:
        return [match for event in events for match in matcher.match(event)]
