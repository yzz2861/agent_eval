# Tri-state approval YAML property tests

Offline, dependency-free property tests that prove an approval export keeps
three decisions distinct through every legal YAML representation:

- `APPROVED` - explicit approval;
- `DENIED` - explicit rejection;
- `PENDING` - not reviewed yet.

The suite needs only the standard library plus the in-tree PyYAML. It ships
its own deterministic generator and shrinker, so it runs with no network and
without Hypothesis.

## Layout

- `contract.py` - the independently defined tri-state contract and two loaders:
  `strict_load` (rejects ambiguity) and `permissive_load` (an ordinary
  serializer stand-in that maps every unknown value to `APPROVED`).
- `strategy.py` - synthetic policy objects and a hand-written YAML emitter that
  varies key order, anchor names/aliases, scalar quoting and ambiguous tokens.
- `properties.py` - the property checks, deterministic runner, monotonic greedy
  shrinker and the hand-checkable failure report.
- `test_property.py` - pytest cases: hand-pinned shapes plus the campaign.
- `demo.py` - a script that prints sample documents and the reduced repro.

## What is generated

For each policy the emitter can independently vary:

- key order (all six permutations of `id`/`reviewer`/`decision`);
- anchor spelling (`a`, `pol`, `decision_anchor`, ...) plus `*alias` repeats;
- decision scalar style (plain, single-quoted, double-quoted);
- ambiguous scalars a caller cannot endorse: `yes/no/on/off/true/false`
  (PyYAML coerces these to booleans), `null`/`~` (coerced to `None`) and
  near-miss strings such as `approve`, `aprove`, `ENABLED`.

## The two properties

1. Every all-canonical document round-trips to exactly the contract decisions,
   including across anchors and aliases and every key order.
2. Any document carrying an ambiguous decision is un-importable: a compliant
   loader must raise `PolicyError`. The lenient stand-in instead returns
   `APPROVED`, so the test fails and the shrinker reduces the document to a
   single-policy, canonical-order repro.

## Running

From the repository root (the sandbox restricts `stat()` on parent dirs, so
collection is confined with `--confcutdir`):

    python -m pytest tests/tri_state -q --confcutdir=tests/tri_state

For the printed demonstration:

    python tests/tri_state/demo.py [seed] [iterations]

A fixed seed makes every run reproducible; the report embeds the seed and the
reduced YAML so a failure can be replayed without rerunning the campaign.
