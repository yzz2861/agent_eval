#!/usr/bin/env python3
"""Short offline replay for the temporal correlation execution contract.

The same ordered temporal rule is consumed twice:

* the on-call consumer receives events in arrival order and emits a provisional
  relationship;
* the review consumer backfills a late record and re-evaluates that relationship on
  event time.

Run from the repository root::

    python examples/offline_correlation_replay.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sigma.collection import SigmaCollection
from sigma.matching import (
    CorrelationConclusion,
    Event,
    EventLogSource,
    OfflineCorrelationContract,
    RevisionReport,
)

RULES = """
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

BASE = datetime(2026, 11, 21, 10, 0, tzinfo=timezone.utc)
LOGSOURCE = EventLogSource(category="test", product="test")


@dataclass(frozen=True)
class Scenario:
    label: str
    login_event: timedelta
    access_event: timedelta
    access_arrival: timedelta
    backfill_event: timedelta
    backfill_arrival: timedelta


SCENARIOS = (
    Scenario(
        label="late log CONFIRMS the on-call relation",
        login_event=timedelta(0),
        access_event=timedelta(minutes=1),
        access_arrival=timedelta(minutes=1),
        backfill_event=timedelta(minutes=-1),
        backfill_arrival=timedelta(minutes=30),
    ),
    Scenario(
        label="late log RETRACTS the on-call relation",
        login_event=timedelta(minutes=2),
        access_event=timedelta(minutes=-2),
        access_arrival=timedelta(minutes=3),
        backfill_event=timedelta(0),
        backfill_arrival=timedelta(minutes=30),
    ),
)


def make_event(kind: str, event_offset: timedelta, arrival_offset: timedelta) -> Event:
    return Event(
        timestamp=BASE + event_offset,
        arrival_time=BASE + arrival_offset,
        logsource=LOGSOURCE,
        data={"event": kind, "user": "alice"},
    )


def format_conclusion(conclusion: CorrelationConclusion) -> str:
    event_times = " -> ".join(t.strftime("%H:%M:%S") for t in conclusion.event_times)
    arrival_times = " -> ".join(t.strftime("%H:%M:%S") for t in conclusion.arrival_times)
    return f"event {event_times}; arrival {arrival_times}"


def print_provisional(conclusion: CorrelationConclusion) -> None:
    rules = " -> ".join(conclusion.rule_names)
    print(f"  on-call provisional {conclusion.conclusion_id}: {rules}")
    print(f"    group={conclusion.group_values}  {format_conclusion(conclusion)}")
    print("    basis=arrival time (what the operator saw)")


def print_report(report: RevisionReport) -> None:
    if not report.revisions:
        print("  no revision produced")
        return
    for revision in report.revisions:
        status = revision.status.value.upper()
        print(f"  revision {revision.revision_id}: {revision.conclusion_id} -> {status}")
        print(f"    {revision.reason}")
    print(f"  affected groups: {report.affected_groups}")


def run_scenario(scenario: Scenario) -> RevisionReport:
    collection = SigmaCollection.from_yaml(RULES)
    contract = OfflineCorrelationContract(collection, "ordered_corr")

    contract.observe(make_event("login", scenario.login_event, scenario.login_event))
    contract.observe(make_event("access", scenario.access_event, scenario.access_arrival))

    print("=" * 78)
    print(scenario.label)
    print("=" * 78)
    print("real-time phase (arrival order):")
    snapshot_before = contract.on_call_view()
    if not snapshot_before:
        print("  no provisional relationship")
        return RevisionReport((), (), ())
    for conclusion in snapshot_before:
        print_provisional(conclusion)

    print()
    print(
        "backfill record: login_rule event_time="
        f"{(BASE + scenario.backfill_event).strftime('%H:%M:%S')} "
        "arrival_time="
        f"{(BASE + scenario.backfill_arrival).strftime('%H:%M:%S')}"
    )
    report = contract.backfill(
        [make_event("login", scenario.backfill_event, scenario.backfill_arrival)]
    )
    print_report(report)

    snapshot_after = contract.on_call_view()
    if snapshot_after != snapshot_before:
        raise RuntimeError("backfill rewrote the on-call view")
    print("  audit check: on-call snapshot unchanged after backfill")

    final = contract.final_conclusions
    if final:
        for conclusion in final:
            print(
                f"  final event-time relation {conclusion.conclusion_id}: "
                f"{' -> '.join(conclusion.rule_names)} {format_conclusion(conclusion)}"
            )
    else:
        print("  no event-time relation survives")
    print()
    return report


def main() -> None:
    reports = [run_scenario(scenario) for scenario in SCENARIOS]
    print("=" * 78)
    print("summary")
    print("=" * 78)
    for scenario, report in zip(SCENARIOS, reports):
        outcomes = ", ".join(revision.status.value for revision in report.revisions)
        print(f"  {scenario.label}: {outcomes or 'none'}")


if __name__ == "__main__":
    main()
