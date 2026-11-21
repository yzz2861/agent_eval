# Scoped maintenance review demo

This example turns a TUF `Targets` diff into maintenance notices without
letting one maintenance group infer what another group replaced.

Run it from the repository root:

```sh
python examples/scoped_review/demo.py
```

The demo shows:

- a sealed, scope-aware review built from two trusted target snapshots;
- a pump-crew notice that contains only pump paths, pump totals, and pump
  deletion notes, while security operations can still see the full review;
- independent evidence for a component rename, a shared digest, and two
  delivery channels of the same artifact;
- an abandoned notification batch after the visibility policy changes, with
  no draft deliverable at or after the boundary.

The implementation lives in `tuf/maintenance/`. The key privacy rule is that
`ScopedReviewView` stores only changes already filtered to one scope. Totals,
deletion notes, old artifacts, evidence peers, and even the view digest are
derived from that filtered set, so a group cannot recover another group from
counts or deletion text.
