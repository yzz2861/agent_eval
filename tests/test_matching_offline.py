"""Tests for the offline temporal correlation execution contract."""

from datetime import datetime, timedelta, timezone

import pytest

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaCorrelationRuleError
from sigma.matching import (
    ConclusionStatus,
    Event,
    EventLogSource,
    OfflineCorrelationContract,
    TimeBasis,
)

BASE = datetime(2026, 11, 21, 10, 0, tzinfo=timezone.utc)
LOGSOURCE = EventLogSource(category="test", product="test")


def ts(minutes: float) -> datetime:
    return BASE + timedelta(minutes=minutes)


def make_event(
    kind: str,
    event_minutes: float,
    arrival_minutes: float | None = None,
    user: str = "alice",
) -> Event:
    return Event(
        timestamp=ts(event_minutes),
        arrival_time=None if arrival_minutes is None else ts(arrival_minutes),
        logsource=LOGSOURCE,
        data={"event": kind, "user": user},
    )


ORDERED_RULES = """
title: Successful Login
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
title: Resource Access
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
title: Login Followed by Access
name: ordered_corr
status: test
correlation:
    type: temporal_ordered
    rules:
        - login_rule
        - access_rule
    group-by:
        - user
    timespan: 5m
"""

UNORDERED_RULES = ORDERED_RULES.replace("type: temporal_ordered", "type: temporal")

ALIAS_RULES = """
title: Login From Source
name: login_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: login
        src: 1.2.3.4
    condition: selection
---
title: Access From Source
name: access_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: access
        source_ip: 1.2.3.4
    condition: selection
---
title: Aliased Source Correlation
name: aliased_corr
status: test
correlation:
    type: temporal
    rules:
        - login_rule
        - access_rule
    group-by:
        - src_ip
    timespan: 5m
    aliases:
        src_ip:
            login_rule: src
            access_rule: source_ip
"""

EVENT_COUNT_RULES = """
title: Base
name: base_rule
status: test
logsource:
    category: test
    product: test
detection:
    selection:
        event: login
    condition: selection
---
title: Count
name: count_corr
status: test
correlation:
    type: event_count
    rules:
        - base_rule
    timespan: 5m
    condition:
        gte: 2
"""


@pytest.fixture
def ordered_collection() -> SigmaCollection:
    return SigmaCollection.from_yaml(ORDERED_RULES)


@pytest.fixture
def unordered_collection() -> SigmaCollection:
    return SigmaCollection.from_yaml(UNORDERED_RULES)


def test_observe_emits_provisional_on_arrival_basis(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")

    assert contract.observe(make_event("login", 0, 0)) == []
    emitted = contract.observe(make_event("access", 1, 1))

    assert len(emitted) == 1
    conclusion = emitted[0]
    assert conclusion.status is ConclusionStatus.PROVISIONAL
    assert conclusion.basis is TimeBasis.ARRIVAL_TIME
    assert conclusion.rule_names == ("login_rule", "access_rule")
    assert conclusion.group_values == {"user": "alice"}


def test_missing_arrival_time_is_rejected(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")

    with pytest.raises(ValueError, match="arrival_time"):
        contract.observe(make_event("login", 0, None))


def test_explicit_arrival_time_argument(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")

    contract.observe(make_event("login", 0, None), arrival_time=ts(5))
    emitted = contract.observe(make_event("access", 1, None), arrival_time=ts(6))

    assert len(emitted) == 1
    assert emitted[0].arrival_times == (ts(5), ts(6))


def test_review_confirms_when_event_order_matches(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    contract.observe(make_event("login", 0, 0))
    contract.observe(make_event("access", 1, 1))

    report = contract.review()

    assert [revision.status for revision in report.revisions] == [ConclusionStatus.CONFIRMED]
    assert contract.provisional_history[0].status is ConclusionStatus.PROVISIONAL
    assert len(contract.final_conclusions) == 1
    assert contract.final_conclusions[0].status is ConclusionStatus.CONFIRMED


def test_review_retracts_when_arrival_order_hides_event_order(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    # On-call sees login first because access arrived later, but access happened earlier.
    contract.observe(make_event("login", 2, 2))
    contract.observe(make_event("access", -2, 3))

    report = contract.review()

    assert [revision.status for revision in report.revisions] == [ConclusionStatus.RETRACTED]
    assert contract.final_conclusions == ()
    assert contract.provisional_history[0].status is ConclusionStatus.PROVISIONAL


def test_backfill_confirms_provisional_and_preserves_on_call_view(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    contract.observe(make_event("login", 0, 0))
    contract.observe(make_event("access", 1, 1))
    snapshot_before = contract.on_call_view()

    report = contract.backfill([make_event("login", -1, 30)])

    assert [revision.status for revision in report.revisions] == [ConclusionStatus.CONFIRMED]
    assert report.affected_groups == (("alice",),)
    assert contract.on_call_view() == snapshot_before
    assert contract.on_call_view()[0].status is ConclusionStatus.PROVISIONAL


def test_backfill_retracts_provisional(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    contract.observe(make_event("login", 2, 2))
    contract.observe(make_event("access", -2, 3))

    report = contract.backfill([make_event("login", 0, 30)])

    assert [revision.status for revision in report.revisions] == [ConclusionStatus.RETRACTED]
    assert contract.on_call_view()[0].status is ConclusionStatus.PROVISIONAL


def test_unordered_relation_uses_event_time_window_on_review(unordered_collection):
    contract = OfflineCorrelationContract(unordered_collection, "ordered_corr")
    # Arrival gap is two minutes, but the events are ten minutes apart in event time.
    contract.observe(make_event("login", 0, 0))
    contract.observe(make_event("access", 10, 2))

    assert len(contract.on_call_view()) == 1
    report = contract.review()

    assert [revision.status for revision in report.revisions] == [ConclusionStatus.RETRACTED]


def test_backfill_only_revises_affected_group(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    for user in ("alice", "bob"):
        contract.observe(make_event("login", 0, 0, user))
        contract.observe(make_event("access", 1, 1, user))

    alice_id = contract.provisional_history[0].conclusion_id
    bob_id = contract.provisional_history[1].conclusion_id

    report = contract.backfill([make_event("login", -1, 30, "alice")])

    assert report.affected_groups == (("alice",),)
    assert [revision.conclusion_id for revision in report.revisions] == [alice_id]
    assert all(revision.conclusion_id != bob_id for revision in report.revisions)
    assert {conclusion.conclusion_id for conclusion in contract.on_call_view()} == {
        alice_id,
        bob_id,
    }


def test_backfill_ignores_relation_outside_timespan(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    contract.observe(make_event("login", 0, 0))
    contract.observe(make_event("access", 1, 1))

    report = contract.backfill([make_event("login", 60, 90)])

    assert report.revisions == ()
    assert len(contract.on_call_view()) == 1


def test_on_call_view_by_sequence(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")

    contract.observe(make_event("login", 0, 0))
    assert contract.on_call_view(1) == ()

    provisional = contract.observe(make_event("access", 1, 1))[0]
    assert contract.on_call_view(2) == (provisional,)
    assert [snapshot.sequence for snapshot in contract.audit_trail()] == [1, 2]


def test_group_by_alias_shared_by_both_consumers():
    collection = SigmaCollection.from_yaml(ALIAS_RULES)
    contract = OfflineCorrelationContract(collection, "aliased_corr")

    login = Event(
        timestamp=ts(0),
        arrival_time=ts(0),
        logsource=LOGSOURCE,
        data={"event": "login", "src": "1.2.3.4"},
    )
    access = Event(
        timestamp=ts(1),
        arrival_time=ts(1),
        logsource=LOGSOURCE,
        data={"event": "access", "source_ip": "1.2.3.4"},
    )

    contract.observe(login)
    emitted = contract.observe(access)

    assert emitted[0].group_values == {"src_ip": "1.2.3.4"}
    report = contract.review()
    assert [revision.status for revision in report.revisions] == [ConclusionStatus.CONFIRMED]
    assert contract.final_conclusions[0].group_values == {"src_ip": "1.2.3.4"}


def test_event_time_basis_can_be_selected_for_both_consumers(ordered_collection):
    contract = OfflineCorrelationContract(
        ordered_collection,
        "ordered_corr",
        provisional_basis=TimeBasis.EVENT_TIME,
        final_basis=TimeBasis.EVENT_TIME,
    )
    # No arrival time is needed when both consumers explicitly choose event time.
    contract.observe(make_event("login", 0, None))
    emitted = contract.observe(make_event("access", 1, None))

    assert emitted[0].basis is TimeBasis.EVENT_TIME
    report = contract.review()
    assert [revision.status for revision in report.revisions] == [ConclusionStatus.CONFIRMED]


def test_review_discovers_relation_hidden_by_arrival_order(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    # Arrival order is access then login, but event order is login then access.
    contract.observe(make_event("access", 1, 0))
    contract.observe(make_event("login", 0, 1))

    assert contract.on_call_view() == ()
    report = contract.review()

    assert report.revisions == ()
    assert len(report.new_conclusions) == 1
    assert report.new_conclusions[0].rule_names == ("login_rule", "access_rule")


def test_timespan_boundary_is_inclusive(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    contract.observe(make_event("login", 0, 0))
    emitted = contract.observe(make_event("access", 5, 5))

    assert len(emitted) == 1


def test_unsupported_correlation_type_is_rejected():
    collection = SigmaCollection.from_yaml(EVENT_COUNT_RULES)

    with pytest.raises(SigmaCorrelationRuleError, match="temporal"):
        OfflineCorrelationContract(collection, "count_corr")


def test_event_exposes_both_explicit_clocks():
    event = make_event("login", 1, 2)

    assert event.event_time == event.timestamp == ts(1)
    assert event.arrival_time == ts(2)


def test_multiple_disjoint_relations_in_one_group(ordered_collection):
    contract = OfflineCorrelationContract(ordered_collection, "ordered_corr")
    for kind, minutes in (("login", 0), ("access", 1), ("login", 120), ("access", 121)):
        contract.observe(make_event(kind, minutes, minutes))

    assert len(contract.provisional_history) == 2
    first, second = contract.provisional_history

    report = contract.backfill([make_event("login", 119, 200)])

    assert [revision.conclusion_id for revision in report.revisions] == [second.conclusion_id]
    assert all(revision.conclusion_id != first.conclusion_id for revision in report.revisions)
    assert len(contract.on_call_view()) == 2


def test_contract_can_wrap_an_already_resolved_rule(ordered_collection):
    rule = ordered_collection["ordered_corr"]
    contract = OfflineCorrelationContract(rule)

    contract.observe(make_event("login", 0, 0))
    emitted = contract.observe(make_event("access", 1, 1))

    assert len(emitted) == 1
    assert emitted[0].conclusion_id == "c0001"


def test_contract_rejects_rule_and_name_together(ordered_collection):
    rule = ordered_collection["ordered_corr"]

    with pytest.raises(SigmaCorrelationRuleError, match="not both"):
        OfflineCorrelationContract(rule, "ordered_corr")
