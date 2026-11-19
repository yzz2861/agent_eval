# Exception Decision Policy

The upstream baseline stores an `is_secret` audit marker next to the file
location of a finding. That location-based marker has two failure modes:

* moving a file drops the decision, because the entry is keyed by path;
* replacing the secret value keeps the stale "approved" marker, because the
  baseline entry is copied verbatim.

`detect_secrets.exception_policy` is an independent exception decision layer
that fixes both. It is a library/API only: there is no approval UI and no
notifications.

## What an exception is bound to

Every decision is an immutable, append-only record bound to four things:

1. **Secret identity** (`SecretIdentity`) - derived from the secret type and a
   one-way hash of the value. The file path and line number are deliberately
   excluded, so a move preserves the identity while a rotated value produces a
   new one. Plaintext is never stored; baseline hashes are reused directly.
2. **Project scope** (`Scope`) - a project identifier plus an optional relative
   path prefix. An exception covers a finding only when the finding scope is
   contained within the approved scope. Widening the scope fails closed and
   requires a new decision.
3. **Rule version** (`RuleVersion`) - semantic version of the rule/plugin that
   produced the finding. A major version bump denotes a breaking semantic
   change and invalidates the exception; minor/patch bumps carry it forward.
4. **Validity window** - `effective_at` and `expires_at`. The window is
   half-open (`[effective_at, expires_at)`), so the exact expiry instant is no
   longer covered.

The record keeps the approval basis (`decided_by`, `rationale`, and hashed
`evidence_fingerprints`) without persisting any secret material.

## Time is injected, never read

All time checks take an explicit timezone-aware `snapshot`. The engine never
reads the wall clock. Because the decision log is append-only and time is a
parameter, replaying a historical report with the same snapshot against the same
store always reproduces the original verdict. Use `utc_now()` only at the edge
when you want the real clock.

## Decisions

`ExceptionEngine.evaluate(finding, snapshot)` returns a `Decision` whose
`status` is one of:

| Status            | Meaning                                              |
|-------------------|------------------------------------------------------|
| `exempt`          | a valid, active exception covers the finding         |
| `conflict`        | merged branches disagree; no winner is auto-selected |
| `no_exception`    | no record exists for this secret identity            |
| `revoked`         | the latest decision revoked the exception            |
| `not_yet_valid`   | snapshot is before `effective_at`                    |
| `expired`         | snapshot is at or after `expires_at`                 |
| `scope_widened`   | finding scope is not inside the approved scope       |
| `rule_upgraded`   | rule semantics had a breaking major-version change   |

## Branch merges

`merge_exception_stores` unions the append-only logs. Identical shared records
collapse to one; when two branches carry different concurrent `APPROVED`
decisions for the same identity, the report lists a `ConflictDetail` with the
candidate decision ids and the fields that differ. The engine then returns
`conflict` instead of silently picking a side. Resolution requires appending a
new decision that `supersedes` both candidates.

## Example

```python
import datetime as dt
from detect_secrets.exception_policy import (
    ExceptionEngine, ExceptionStore, RuleVersion, Scope,
    build_record, finding_from_potential_secret, merge_exception_stores,
)

snapshot = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
finding = finding_from_potential_secret(potential_secret, "acme", "1.4.0")

record = build_record(
    secret_identity=finding.secret_identity,
    scope=Scope.from_string("acme", "config"),
    rule=RuleVersion.parse(finding.rule.name, "1.4.0"),
    decided_by="alice",
    rationale="documented false positive in SEC-9",
    created_at=snapshot,
    expires_at=snapshot + dt.timedelta(days=30),
    evidence_references=("https://tickets/SEC-9",),
)
store = ExceptionStore([record])
decision = ExceptionEngine(store).evaluate(finding, snapshot)
assert decision.is_exempt
```

## Persistence

`ExceptionStore.write(path)` / `ExceptionStore.read(path)` persist the full
append-only log as versioned JSON. The on-disk format contains hashes and
approval metadata only.
