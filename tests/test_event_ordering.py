#!/usr/bin/env python
# -*- coding: utf-8 -*-

import itertools
import pathlib

import pytest

from Registry import event_ordering as eo
from Registry.Registry import Registry


ROOT = r"FIXTURE_HIVE"
PARENT = ROOT + r"\App"
CHILD = PARENT + r"\Child"


def src(snapshot_id):
    return eo.Source(kind="snapshot_diff", snapshot_id=snapshot_id, detail="fixture")


def test_clock_rollback_keeps_structural_order():
    events = [
        eo.Event("write_old", timestamp=100),
        eo.Event("write_rollback", timestamp=90),
        eo.Event("write_recovered", timestamp=95),
    ]
    constraints = [
        eo.Constraint("write_old", "write_rollback", constraint_id="c1",
                      kind="structural_change", sources=(src("s1-s2"),)),
        eo.Constraint("write_rollback", "write_recovered", constraint_id="c2",
                      kind="structural_change", sources=(src("s2-s3"),)),
    ]

    report = eo.build_report(events=events, constraints=constraints)

    assert report.ok
    assert report.relation("write_old", "write_rollback").relation == eo.BEFORE
    assert report.relation("write_old", "write_recovered").relation == eo.BEFORE
    assert report.legal_orders == (
        ("write_old", "write_rollback", "write_recovered"),
    )

    mechanical = [e.event_id for e in sorted(events, key=lambda e: e.timestamp)]
    assert mechanical == ["write_rollback", "write_recovered", "write_old"]


def test_equal_timestamps_leave_open_order_and_possible_concurrency():
    interval = eo.Interval(20, 30)
    events = [
        eo.Event("a", timestamp=77, collection_interval=interval),
        eo.Event("b", timestamp=77, collection_interval=interval),
    ]

    report = eo.build_report(events=events)

    relation = report.relation("a", "b")
    assert relation.relation == eo.POSSIBLY_CONCURRENT
    assert not relation.definite
    assert set(report.legal_orders) == {("a", "b"), ("b", "a")}
    assert report.graph["edges"] == []


def test_missing_snapshot_does_not_create_middle_transition():
    snapshots = [
        {
            "id": "s3",
            "interval": (40, 50),
            "keys": {
                PARENT: {
                    "timestamp": 90,
                    "values": {"version": 2},
                },
            },
        },
        {
            "id": "s1",
            "interval": (0, 10),
            "keys": {
                PARENT: {
                    "timestamp": 100,
                    "values": {"version": 1},
                },
            },
        },
    ]

    report = eo.build_report(
        snapshots=snapshots,
        missing_snapshots=["s2"],
    )

    assert report.ok
    assert any(item["kind"] == "missing_snapshot" and item["snapshot_id"] == "s2"
               for item in report.facts)

    changes = [e for e in report.events if e.kind == "key_modified"]
    assert len(changes) == 1
    assert changes[0].snapshot_ids == ("s1", "s3")
    assert changes[0].attributes["old_timestamp"] == 100
    assert changes[0].attributes["new_timestamp"] == 90
    assert not any("s2" in str(c.sources) for c in report.constraints)
    assert len(report.legal_orders) == 1


def test_true_conflict_returns_minimal_cycle_and_sources():
    constraints = [
        eo.Constraint("a", "b", constraint_id="forward",
                      sources=(eo.Source(kind="explicit", snapshot_id="one"),)),
        eo.Constraint("b", "a", constraint_id="backward",
                      sources=(eo.Source(kind="explicit", snapshot_id="two"),)),
    ]

    report = eo.build_report(events=[eo.Event("a"), eo.Event("b")],
                              constraints=constraints)

    assert not report.ok
    assert report.legal_orders == ()
    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert set(conflict.event_ids) == {"a", "b"}
    assert set(conflict.constraint_ids) == {"forward", "backward"}
    assert {source.snapshot_id for source in conflict.sources} == {"one", "two"}

    with pytest.raises(eo.PartialOrderConflictError):
        eo.build_report(
            events=[eo.Event("a"), eo.Event("b")],
            constraints=constraints,
            strict=True,
        )


def test_reordering_inputs_does_not_change_graph():
    events = [eo.Event(name) for name in ("e1", "e2", "e3", "e4")]
    constraints = [
        eo.Constraint("e1", "e2", constraint_id="c1"),
        eo.Constraint("e2", "e3", constraint_id="c2"),
        eo.Constraint("e1", "e4", constraint_id="c3"),
    ]
    baseline = eo.build_report(events=events, constraints=constraints)

    for event_order in itertools.permutations(events):
        for constraint_order in itertools.permutations(constraints):
            report = eo.build_report(
                events=list(event_order),
                constraints=list(constraint_order),
            )
            assert report.graph == baseline.graph
            assert report.signature == baseline.signature
            assert report.legal_orders == baseline.legal_orders

    snapshots = [
        {"id": "s1", "interval": (0, 1), "keys": {PARENT: {"timestamp": 1}}},
        {"id": "s2", "interval": (2, 3), "keys": {PARENT: {"timestamp": 2}}},
        {"id": "s3", "interval": (4, 5), "keys": {PARENT: {"timestamp": 3}}},
    ]
    snapshot_baseline = eo.build_report(snapshots=snapshots)
    snapshot_reversed = eo.build_report(snapshots=list(reversed(snapshots)))
    assert snapshot_reversed.graph == snapshot_baseline.graph
    assert snapshot_reversed.signature == snapshot_baseline.signature


def test_parent_timestamp_is_not_inherited_by_child():
    snapshots = [
        {
            "id": "s1",
            "interval": (0, 1),
            "keys": {
                ROOT: {"timestamp": 1},
            },
        },
        {
            "id": "s2",
            "interval": (2, 3),
            "keys": {
                ROOT: {"timestamp": 2},
                PARENT: {"timestamp": 999},
                CHILD: {"timestamp": 17},
            },
        },
    ]

    report = eo.build_report(snapshots=snapshots)

    child_timestamp_facts = [
        item for item in report.facts
        if item.get("kind") == "key_timestamp" and item.get("subject") == CHILD
    ]
    assert child_timestamp_facts
    assert all(item["timestamp"] == 17 for item in child_timestamp_facts)
    assert not any(item.get("timestamp") == 999 and item.get("subject") == CHILD
                   for item in report.facts)

    created = {
        event.subject: event
        for event in report.events
        if event.kind == "key_created"
    }
    assert PARENT in created and CHILD in created
    dependency = [
        constraint for constraint in report.constraints
        if constraint.kind == "structural_dependency"
        and constraint.before == created[PARENT].event_id
        and constraint.after == created[CHILD].event_id
    ]
    assert dependency
    assert all("timestamp" not in constraint.reason.lower()
               for constraint in dependency)


def test_real_parsed_registry_snapshot_is_supported():
    hive_path = pathlib.Path(__file__).parent / "reg_samples" / "issue22.hive"
    registry = Registry(str(hive_path))
    snapshot = eo.snapshot_from_registry("issue22", registry, eo.Interval(0, 1))

    assert snapshot.keys
    report = eo.build_report(snapshots=[snapshot])
    assert report.ok
    assert any(item["kind"] == "key_timestamp" for item in report.facts)


def test_module_does_not_use_system_clock_or_windows_api():
    source = pathlib.Path(eo.__file__).read_text(encoding="utf-8")
    assert "datetime.now(" not in source
    assert "datetime.utcnow(" not in source
    assert "winreg" not in source
    assert "ctypes.windll" not in source
