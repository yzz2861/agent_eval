# Offline Maintenance Admission Gate

A local gate for offline device maintenance, built directly on the TUF trusted
metadata reading model. Pause-update and resume-update authorization slips are
modeled as signed TUF delegated targets metadata, so a device only acts on a
statement after it survives the standard TUF verification chain

```
root -> timestamp -> snapshot -> targets -> delegated targets
```

The arrival order of slips on different maintenance channels cannot change the
final admission decision.

## Why TUF metadata

Each maintenance channel is a TUF delegated role. A slip is a targets document
whose target paths are the *target set* the statement points at, and whose TUF
`custom` field carries the maintenance action (`pause` or `resume`). The
authorization version is not a separate counter: it is the role metadata
`version`, which snapshot pins and the trusted reader refuses to roll back.

A release (epoch) is one self-consistent set: timestamp and snapshot are bumped
together and every targets role is pinned by version, length and hash. This is
what lets the device distinguish a complete, verifiable release from a half set
that merely arrived out of order.

## Components

- `repo.py` (`AuthorizationRepository`) - publisher side. Generates ed25519
  keys, builds the delegation graph and signs coherent multi-epoch releases.
- `gate.py` (`MaintenanceGate`) - device side. Feeds on signed bytes in any
  order and produces admission verdicts from the verified view.
- `model.py` - statements, ingest statuses, verdicts and decisions.

## Document lifecycle: trusted, staged, rejected

Every document handed to `MaintenanceGate.ingest` ends in one of three states:

- `trusted` - the full TUF chain verified and the release became the active
  view. Promotion is all-or-nothing, so a release missing any required role
  never partially applies.
- `staged` - a half set (for example a delegated slip without its matching
  timestamp/snapshot). It is retained and retried as more material arrives.
- `rejected` - failed verification: bad signature, snapshot hash/length
  mismatch, expiry, or a timestamp version older than the trusted one
  (rollback). Rejected material can never influence an admission.

The first trusted release must be complete; a device with no anchor cannot
bootstrap on a half set. After bootstrap, an incomplete newer release stays
staged while the device keeps deciding on the last fully verified epoch.

## Per-package verdict: proceed, paused, pending

`MaintenanceGate.admit(target)` walks the delegation graph in TUF delegation
order (the same ordered, terminating traversal as a target lookup):

- the first verified role that explicitly lists the target decides it - a
  pause yields `paused`, a resume yields `proceed`;
- a role that covers the path but whose metadata is not part of a verified
  release forces a fail-closed `pending` (operator check);
- a terminating role that lists no statement ends the walk and defaults to
  `proceed`;
- with no verified release at all, every target is `pending`.

Overlapping delegations are therefore resolved deterministically by delegation
order, while version rollback is independently prevented by snapshot.

## Already cached targets

Caching never grants authority. `admit_cached(target, cached_bytes)` re-runs the
authorization verdict and additionally checks the cached content against the
verified length/hashes. Stale or tampered cached content becomes `pending`
rather than being admitted.

## Order independence

Because every decision is recomputed from the highest fully verified release -
never from arrival order - feeding the same slips in different orders, or an
old resume slip arriving last, converges on the same admission. This is covered
exhaustively over all document permutations in
`tests/test_maintenance_gate.py`.

## Running

```
.venv/bin/python -m unittest tests.test_maintenance_gate -v
.venv/bin/python examples/maintenance_gate/demo_gate.py
```
