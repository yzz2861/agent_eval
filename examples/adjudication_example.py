"""Four-object adjudication example.

The example starts with three malware objects.  Pair A-B is confirmed by two
independent collection sources, while B-C has conflicting reviews and is
therefore kept apart.  The chain of above-threshold similarities A-B-C is
split into the groups {A, B} and {C}.

Two changes are then shown:

1. D is imported as a bridge.  It is similar to both A and C, but A, B and C
   are already reviewed, so similarity alone cannot silently merge the
   existing groups.  D becomes its own group and the blocked merges are
   reported.
2. One of the two independent A-B confirmations is retracted.  The remaining
   confirmation is not enough, so the old group splits and the object move is
   reported explicitly.
"""

from stix2 import MemoryStore
from stix2.equivalence.adjudication import AdjudicationLayer
from stix2.v21 import Malware


A = "malware--00000000-0000-4000-8000-00000000000a"
B = "malware--00000000-0000-4000-8000-00000000000b"
C = "malware--00000000-0000-4000-8000-00000000000c"
D = "malware--00000000-0000-4000-8000-00000000000d"

LABELS = {
    A: "A",
    B: "B",
    C: "C",
    D: "D",
}


def malware(object_id, version):
    return Malware(
        id=object_id,
        name="sample-{}".format(LABELS[object_id]),
        is_family=True,
        created="2026-01-01T00:00:00Z",
        modified=version,
    )


def labels(members):
    return "{" + ", ".join(LABELS[member] for member in members) + "}"


def show_result(title, result):
    print("\n== {} ==".format(title))
    for group in result.groups:
        print(
            "  {} = {} [{}]".format(
                group.group_id,
                labels(group.members),
                group.status,
            ),
        )


def show_delta(delta):
    print(delta.describe())


def main():
    store = MemoryStore(
        [
            malware(A, "2026-01-01T00:00:00Z"),
            malware(B, "2026-01-01T00:00:00Z"),
            malware(C, "2026-01-01T00:00:00Z"),
        ],
    )
    layer = AdjudicationLayer(store, min_independent_confirmations=2)

    layer.review(
        A,
        B,
        "confirm",
        reviewer="alice",
        source="feed-1",
        review_id="r1",
        created_at="2026-01-02T00:00:00Z",
    )
    layer.review(
        A,
        B,
        "confirm",
        reviewer="carol",
        source="feed-1",
        review_id="r2",
        created_at="2026-01-02T00:01:00Z",
    )
    layer.review(
        A,
        B,
        "confirm",
        reviewer="bob",
        source="feed-2",
        review_id="r3",
        created_at="2026-01-02T00:02:00Z",
    )
    layer.review(
        B,
        C,
        "confirm",
        reviewer="alice",
        source="feed-1",
        review_id="r4",
        created_at="2026-01-02T00:03:00Z",
    )
    layer.review(
        B,
        C,
        "reject",
        reviewer="bob",
        source="feed-2",
        review_id="r5",
        created_at="2026-01-02T00:04:00Z",
    )

    initial_edges = [
        (A, B, 91),
        (B, C, 88),
    ]
    initial = layer.refresh(initial_edges, trigger="initial")
    show_result("Initial adjudication", initial.after)
    show_delta(initial)

    store.add(malware(D, "2026-01-02T00:00:00Z"))
    bridge = layer.refresh(
        initial_edges + [
            (A, D, 95),
            (C, D, 94),
        ],
        trigger="add bridge object D",
    )
    show_result("After importing bridge D", bridge.after)
    show_delta(bridge)

    layer.retract(
        "r3",
        at="2026-01-03T00:00:00Z",
        actor="lead",
        reason="upstream source retracted the judgment",
    )
    retracted = layer.refresh(
        initial_edges + [
            (A, D, 95),
            (C, D, 94),
        ],
        trigger="retract review r3",
    )
    show_result("After retracting review r3", retracted.after)
    show_delta(retracted)


if __name__ == "__main__":
    main()
