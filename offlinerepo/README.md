# Offline TUF Repository Release Planner & Executor

An offline, repository-side publication layer for a consistent-snapshot TUF
repository. It takes a bundle of **already-signed** artifacts and derives,
without any network access:

1. the content-addressed, versioned object each artifact becomes;
2. the dependency order in which those objects must be written; and
3. the order in which mutable role pointers are flipped to make a release
   visible.

A thread-safe in-memory fake object store stands in for S3/GCS, and the real
`tuf.ngclient.Updater` from this repository is used as the "existing client"
that reads the mirror at every visibility point.

## Why the ordering looks the way it does

A consistent-snapshot client only ever observes a repository through the
non-versioned `timestamp.json` pointer. The release therefore has two phases:

- **Stage (invisible).** Every versioned metadata object (`<ver>.<role>.json`)
  and every hash-prefixed target is written to an immutable, content-addressed
  key. Writes use `put_if_absent`, so identical bytes are shared and a partial
  write never lands at a visible key. Uploads are topologically sorted from the
  signed cross-references (targets -> target objects, snapshot ->
  targets/delegations, timestamp -> snapshot).
- **Switch (visible).** Pointers move one at a time with compare-and-swap
  semantics guarded by the etags captured at planning time:
  `root -> targets -> delegations -> snapshot -> timestamp`. The timestamp flip
  is the single atomic "go live" step; until it happens a current client keeps
  reading the previous release. After it happens every object the new client
  can request is already present.

Because all content is staged first, every prefix of the switch sequence is
internally consistent. The auditor in `verifier.py` asserts structural
invariants at the internal steps and runs a full client refresh plus target
download at each client-visible (timestamp) point.

## Stale root / concurrent publication

`build_plan` records the etag of every role pointer in the repository
generation it was derived from. Before any byte is written, `validate_plan`
re-reads those etags; if a concurrent publisher has moved any pointer, the plan
raises `StaleRootPlanError` and nothing is switched. Each pointer update also
carries the same precondition as a defense in depth at the storage layer.

## Partial writes and retry

`ObjectStore.fail_puts(key, times)` injects transient failures. The executor
retries the *same* idempotent `put_if_absent` via `retry.RetryPolicy`. Since the
key is content-addressed and immutable, a retry after a partial/failed write
cannot create a duplicate or expose half-written bytes.

## No-op reuse

Object keys include the sha256 of the content. On a content-identical
re-release the target objects (and an unchanged root) already exist, so they are
recorded as `reused` and never rewritten; only the metadata whose signed bytes
actually changed is uploaded.

## Retention

All versioned metadata is retained for rollback/audit. A target object is
retained while the *current* targets/delegated metadata still references it.
Once no current metadata references a target it is reported in
`ReleasePlan.garbage_keys`, but it is never deleted automatically: garbage
collection is a separate, explicit operator action.

## Human-in-the-loop states surface before any switch

Every condition needing an operator decision is a subclass of
`ManualInterventionRequired` and is raised during planning or pre-switch
validation, before the first pointer move: expired metadata, signature
threshold failures, snapshot/timestamp reference mismatches, missing target
payloads, and stale repository generation.

## Layout

- `release/model.py` - pure data model, content/pointer key rules, plan/report.
- `release/objectstore.py` - thread-safe content-addressed fake store, CAS
  pointers, etags and fault injection.
- `release/planner.py` - dependency derivation, topological upload order,
  switch order, retention/garbage, expected etags.
- `release/validator.py` - all pre-switch, fail-closed validation.
- `release/retry.py` - deterministic retry policy with an injectable clock.
- `release/executor.py` - validate -> stage (reuse/retry) -> ordered switches.
- `release/signing.py` - offline construction/signing of demo input artifacts.
- `release/verifier.py` - in-memory `FetcherInterface` and the real `Updater`
  client check, plus the per-switch auditor.
- `demo_offline_release.py` - six end-to-end scenarios.
- `tests/` - pytest suite covering ordering, safety, retry, reuse, retention
  and pre-switch blocking.

## Running

From this directory, using the repository virtualenv:

```sh
python demo_offline_release.py
python -m pytest tests/ -q -c pytest.ini --rootdir=.
ruff check --config ruff.toml release tests demo_offline_release.py
```

Everything runs in memory; no network or manual step is required. The client
path, hash verification and signature verification are the production
`tuf.ngclient` code paths, only the transport is replaced by the fake store.
