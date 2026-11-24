"""
Small-fixture tests for the RegistryOrder partial-order backend.

All timestamps are fixed constants; the backend never reads the system
clock, so these tests are fully deterministic.
"""

import itertools
import os.path
from datetime import datetime, timedelta

import pytest

from Registry import Registry
from Registry.RegistryOrder import (
    AFTER,
    BEFORE,
    CREATED,
    DELETED,
    INCOMPARABLE,
    MODIFIED,
    POSSIBLY_CONCURRENT,
    RULE_CHANGE_BUMPS_LAST_WRITE,
    RULE_CREATED_AFTER_ABSENT,
    RULE_MONOTONIC_LAST_WRITE,
    KeyState,
    Snapshot,
    analyze,
    snapshot_from_registry,
)

BASE = datetime(2026, 1, 1, 12, 0, 0)


def t(seconds):
    return BASE + timedelta(seconds=seconds)


def rollback_snapshots():
    """K2 is rewritten while the clock is rolled back: its new LastWrite
    (t=95) is earlier than K1's LastWrite (t=125), so a naive LastWrite
    sort would place K2's rewrite before K1's.  The collection intervals
    prove the opposite order."""
    s1 = Snapshot("s1", t(100), t(110), {
        "K1": KeyState.present(t(105), {"v": 1}),
        "K2": KeyState.present(t(108), {"v": 1}),
    })
    s2 = Snapshot("s2", t(120), t(130), {
        "K1": KeyState.present(t(125), {"v": 2}),
        "K2": KeyState.present(t(108), {"v": 1}),
    })
    s3 = Snapshot("s3", t(140), t(150), {
        "K1": KeyState.present(t(125), {"v": 2}),
        "K2": KeyState.present(t(95), {"v": 2}),  # rolled-back stamp
    })
    return [s1, s2, s3]


def event_ids(report, kind=None, key=None):
    return [e.id for e in report.events
            if (kind is None or e.kind == kind)
            and (key is None or e.key == key)]


def test_clock_rollback_does_not_reorder_events():
    report = analyze(rollback_snapshots())

    (m1,) = event_ids(report, MODIFIED, "K1")
    (m2,) = event_ids(report, MODIFIED, "K2")

    # Collection windows prove K1's modification precedes K2's, even
    # though K2's rolled-back LastWrite (t=95) sorts before K1's (t=125).
    assert report.relation(m1, m2) == BEFORE
    assert report.relation(m2, m1) == AFTER
    assert report.linear_extension_count() == 1

    # The rolled-back timestamp is surfaced as a conflict with
    # provenance, not silently used for ordering.
    assert not report.is_consistent()
    rules = {c.provenance["rules"][0] for c in report.conflicts}
    assert RULE_MONOTONIC_LAST_WRITE in rules
    for conflict in report.conflicts:
        assert conflict.provenance["keys"] == ["K2"]
        assert conflict.provenance["snapshots"] == ["s2", "s3"]


def test_same_collection_interval_yields_concurrency_not_order():
    s1 = Snapshot("s1", t(100), t(110), {
        "K1": KeyState.present(t(105), {"v": 1}),
        "K2": KeyState.present(t(105), {"v": 1}),
    })
    s2 = Snapshot("s2", t(120), t(130), {
        "K1": KeyState.present(t(125), {"v": 2}),
        "K2": KeyState.present(t(125), {"v": 2}),
    })
    report = analyze([s1, s2])

    (m1,) = event_ids(report, MODIFIED, "K1")
    (m2,) = event_ids(report, MODIFIED, "K2")
    # Identical event windows: possibly concurrent, never ordered.
    assert report.relation(m1, m2) == POSSIBLY_CONCURRENT
    # Several legal orders exist; the report must not pick one.
    assert report.linear_extension_count() == 2
    assert report.is_consistent()


def test_identical_snapshot_intervals_block_event_derivation():
    states_a = {"K": KeyState.present(t(105), {"v": 1})}
    states_b = {"K": KeyState.present(t(105), {"v": 2})}
    s1 = Snapshot("s1", t(100), t(110), states_a)
    s2 = Snapshot("s2", t(100), t(110), states_b)
    report = analyze([s1, s2])

    # Overlapping collections cannot be ordered, so no event is derived
    # even though the observed states differ.
    assert report.snapshot_relation("s1", "s2") == POSSIBLY_CONCURRENT
    assert report.events == ()
    # Both differing observations remain available as facts.
    assert len(report.observations) == 2


def test_missing_collection_interval_is_incomparable():
    s1 = Snapshot("s1", t(100), t(110), {
        "K": KeyState.present(t(105), {"v": 1}),
    })
    undated = Snapshot("undated", None, None, {
        "K": KeyState.present(t(105), {"v": 2}),
    })
    s2 = Snapshot("s2", t(120), t(130), {
        "K": KeyState.present(t(125), {"v": 2}),
    })
    report = analyze([s1, undated, s2])

    assert report.snapshot_relation("s1", "undated") == INCOMPARABLE
    assert report.snapshot_relation("undated", "s2") == INCOMPARABLE
    assert report.snapshot_relation("s1", "s2") == BEFORE

    # The dated snapshots still yield an ordered event; the undated
    # snapshot contributes facts only.
    (m,) = event_ids(report, MODIFIED, "K")
    event = report.events[0]
    assert event.lower == t(110) and event.upper == t(130)
    assert any(o.snapshot == "undated" for o in report.observations)
    assert report.is_consistent()


def test_genuine_conflict_returns_minimal_subset_with_provenance():
    # Values changed but LastWrite did not move: impossible for a live
    # key, so this is a real inconsistency, not a clock artifact.
    s1 = Snapshot("s1", t(100), t(110), {
        "K": KeyState.present(t(105), {"a": 1}),
    })
    s2 = Snapshot("s2", t(120), t(130), {
        "K": KeyState.present(t(105), {"a": 2}),
    })
    report = analyze([s1, s2])

    assert not report.is_consistent()
    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    # Minimal: the single violated constraint is the whole core.
    assert len(conflict.constraints) == 1
    assert conflict.provenance["rules"] == [RULE_CHANGE_BUMPS_LAST_WRITE]
    assert conflict.provenance["keys"] == ["K"]
    assert conflict.provenance["snapshots"] == ["s1", "s2"]
    assert "s1->s2" in conflict.explanation
    # The event is still reported as an inference; no order is forced.
    assert len(event_ids(report, MODIFIED, "K")) == 1


def test_created_and_deleted_events_and_created_after_absent_rule():
    s1 = Snapshot("s1", t(100), t(110), {
        "Doomed": KeyState.present(t(105), {"v": 1}),
        "New": KeyState.absent(),
    })
    s2 = Snapshot("s2", t(120), t(130), {
        "Doomed": KeyState.absent(),
        # LastWrite predates s1's collection although the key was absent
        # then: the clock-rollback signature for creations.
        "New": KeyState.present(t(95), {"v": 1}),
    })
    report = analyze([s1, s2])

    assert len(event_ids(report, DELETED, "Doomed")) == 1
    assert len(event_ids(report, CREATED, "New")) == 1
    created, deleted = report.events[0], report.events[1]
    assert report.relation(created.id, deleted.id) == POSSIBLY_CONCURRENT

    rules = [c.provenance["rules"][0] for c in report.conflicts]
    assert rules == [RULE_CREATED_AFTER_ABSENT]
    assert report.conflicts[0].provenance["keys"] == ["New"]


def test_parent_timestamp_is_not_propagated_to_children():
    s1 = Snapshot("s1", t(100), t(110), {
        "P": KeyState.present(t(100), {}),
        "P\\C": KeyState.present(t(100), {}),
    })
    s2 = Snapshot("s2", t(120), t(130), {
        "P": KeyState.present(t(120), {}),
        "P\\C": KeyState.present(t(100), {}),
    })
    report = analyze([s1, s2])

    # Only the parent's own modification is an event; the untouched
    # child yields none.
    assert event_ids(report, key="P") != []
    assert event_ids(report, key="P\\C") == []
    assert report.is_consistent()


def test_input_permutation_does_not_change_relation_graph():
    snapshots = rollback_snapshots()
    reference = analyze(snapshots)
    for perm in itertools.permutations(snapshots):
        report = analyze(list(perm))
        assert report.relation_graph() == reference.relation_graph()
        assert report.events == reference.events
        assert report.conflicts == reference.conflicts
        assert report.observations == reference.observations
        assert [s.label for s in report.snapshots] == ["s1", "s2", "s3"]


def test_invalid_collection_interval_rejected():
    with pytest.raises(ValueError):
        Snapshot("bad", t(10), t(5), {})


def test_snapshot_from_parsed_hive():
    path = os.path.join(os.path.dirname(__file__),
                        "reg_samples", "issue22.hive")
    reg = Registry.Registry(path)
    snap = snapshot_from_registry(reg, "hive", None, None)
    assert snap.states, "expected a non-empty snapshot"
    assert all(state.exists for state in snap.states.values())

    # An unchanged pair of snapshots yields no events and no conflicts.
    report = analyze([snap, snapshot_from_registry(reg, "hive2", None, None)])
    assert report.events == ()
    assert report.is_consistent()
