import pytest

from stix2 import MemoryStore
from stix2.equivalence.adjudication import (
    AdjudicationLayer, Adjudicator, PairState, ReviewLedger, ReviewOpinion,
)
from stix2.v21 import Malware


A = "malware--00000000-0000-4000-8000-00000000000a"
B = "malware--00000000-0000-4000-8000-00000000000b"
C = "malware--00000000-0000-4000-8000-00000000000c"
D = "malware--00000000-0000-4000-8000-00000000000d"

V1 = "2026-01-01T00:00:00Z"
V2 = "2026-01-02T00:00:00Z"


def _malware(object_id, version=V1):
    return Malware(
        id=object_id,
        name="sample-{}".format(object_id[-1]),
        is_family=True,
        created=V1,
        modified=version,
    )


def _initial_edges():
    return [
        (A, B, 91),
        (B, C, 88),
    ]


def _bridge_edges():
    return _initial_edges() + [
        (A, D, 95),
        (C, D, 94),
    ]


def _record_sample_reviews(recorder):
    recorder(
        A, B, "confirm", "alice", source="feed-1", review_id="r1",
    )
    recorder(
        A, B, "confirm", "carol", source="feed-1", review_id="r2",
    )
    recorder(
        A, B, "confirm", "bob", source="feed-2", review_id="r3",
    )
    recorder(
        B, C, "confirm", "alice", source="feed-1", review_id="r4",
    )
    recorder(
        B, C, "reject", "bob", source="feed-2", review_id="r5",
    )


def test_ledger_keeps_applicable_versions_and_retraction_record():
    ledger = ReviewLedger()
    opinion = ledger.record(
        A,
        B,
        "confirm",
        "alice",
        source="feed-1",
        versions={A: V1, B: V1},
        review_id="r1",
    )

    assert opinion.applies_to({A: V1, B: V1})
    assert not opinion.applies_to({A: V2, B: V1})
    assert ledger.confirmation_sources((A, B), {A: V1, B: V1}) == {
        "feed-1",
    }
    assert ledger.confirmation_sources((A, B), {A: V2, B: V1}) == set()

    retraction = ledger.retract(
        "r1",
        at="2026-02-01T00:00:00Z",
        actor="lead",
        reason="duplicate collection source",
    )

    assert len(ledger) == 1
    assert ledger.active_opinions() == []
    assert ledger.confirmation_sources((A, B), {A: V1, B: V1}) == set()
    assert ledger.history()[0].opinion == opinion
    assert ledger.history()[0].retraction == retraction
    assert retraction.reason == "duplicate collection source"


def test_same_collection_source_is_only_one_independent_confirmation():
    ledger = ReviewLedger()
    ledger.record(
        A, B, "confirm", "alice", source="feed-1", versions={A: V1, B: V1},
    )
    ledger.record(
        A, B, "confirm", "carol", source="feed-1", versions={A: V1, B: V1},
    )

    adjudicator = Adjudicator(
        ledger=ledger,
        min_independent_confirmations=2,
    )
    result = adjudicator.adjudicate(
        {
            A: _malware(A),
            B: _malware(B),
        },
        [(A, B, 95)],
    )

    decision = result.pair_decisions[(A, B)]
    assert decision.state_enum is PairState.INSUFFICIENT
    assert decision.confirmations == 1
    assert result.group_for(A).group_id != result.group_for(B).group_id

    ledger.record(
        A, B, "confirm", "bob", source="feed-2", versions={A: V1, B: V1},
    )
    result = adjudicator.adjudicate(
        {
            A: _malware(A),
            B: _malware(B),
        },
        [(A, B, 95)],
    )

    decision = result.pair_decisions[(A, B)]
    assert decision.state_enum is PairState.CONFIRMED
    assert decision.confirmations == 2
    assert result.group_for(A) is result.group_for(B)


def test_four_object_bridge_and_retraction_deltas():
    store = MemoryStore([_malware(A), _malware(B), _malware(C)])
    layer = AdjudicationLayer(
        store,
        min_independent_confirmations=2,
    )

    def record(*args, **kwargs):
        return layer.review(*args, **kwargs)

    _record_sample_reviews(record)

    initial = layer.refresh(_initial_edges(), trigger="initial")
    initial_groups = {
        frozenset(group.members): group
        for group in initial.after.groups
    }
    assert set(initial_groups) == {
        frozenset((A, B)),
        frozenset((C,)),
    }
    assert initial.after.pair_decisions[(B, C)].conflicted

    store.add(_malware(D, V2))
    bridge = layer.refresh(_bridge_edges(), trigger="add bridge D")

    assert [group.members for group in bridge.added_groups] == [(D,)]
    assert not bridge.changed_groups
    assert not bridge.removed_groups
    assert {
        edge.reason for edge in bridge.new_blocked_edges
    } == {"reviewed-object-pinned"}
    assert {
        tuple(edge.pair) for edge in bridge.new_blocked_edges
    } == {
        (A, D),
        (C, D),
    }
    assert bridge.after.group_for(A) is bridge.after.group_for(B)
    assert bridge.after.group_for(D) not in (
        bridge.after.group_for(A),
        bridge.after.group_for(C),
    )

    layer.retract("r3")
    retraction = layer.refresh(
        _bridge_edges(),
        trigger="retract r3",
    )

    assert [change.group_id for change in retraction.changed_groups] == [
        initial.after.group_for(A).group_id,
    ]
    change = retraction.changed_groups[0]
    assert set(change.before_members) == {A, B}
    assert change.after_members == (A,)
    assert [group.members for group in retraction.added_groups] == [(B,)]
    assert [
        (move.object_id, move.from_group, move.to_group)
        for move in retraction.object_moves
    ] == [(B, change.group_id, retraction.added_groups[0].group_id)]

    decision = retraction.after.pair_decisions[(A, B)]
    assert decision.state_enum is PairState.INSUFFICIENT
    assert decision.confirmations == 1
    assert retraction.after.group_for(A) is not retraction.after.group_for(B)


def test_review_for_old_version_does_not_pin_new_version():
    ledger = ReviewLedger()
    ledger.record(
        A, B, "confirm", "alice", source="feed-1",
        versions={A: V1, B: V1},
    )
    adjudicator = Adjudicator(
        ledger=ledger,
        min_independent_confirmations=2,
    )

    result = adjudicator.adjudicate(
        {
            A: _malware(A, V2),
            B: _malware(B, V2),
        },
        [(A, B, 95)],
    )

    decision = result.pair_decisions[(A, B)]
    assert decision.state_enum is PairState.UNREVIEWED
    assert result.group_for(A) is result.group_for(B)


def test_retracting_unknown_or_twice_rejects():
    ledger = ReviewLedger()
    ledger.record(A, B, "confirm", "alice", review_id="r1")

    with pytest.raises(KeyError):
        ledger.retract("missing")

    ledger.retract("r1")
    with pytest.raises(ValueError):
        ledger.retract("r1")


def test_ledger_round_trip():
    ledger = ReviewLedger()
    ledger.record(
        A, B, "confirm", "alice", source="feed-1",
        versions={A: V1, B: V1}, review_id="r1",
    )
    ledger.retract("r1", actor="lead", reason="withdrawn")

    restored = ReviewLedger.from_dict(ledger.to_dict())

    assert restored.to_dict() == ledger.to_dict()
    assert restored.history((A, B))[0].retraction.actor == "lead"


def test_opinion_rejects_same_object_pair():
    with pytest.raises(ValueError):
        ReviewOpinion(A, A, "confirm", "alice")
