# Offline Exception-Quota Reconciliation

Count-based Sigma rules raise after a number of matches, but a ticket window is
allowed to ignore a few *known* operations. This package performs the offline
quota bookkeeping on top of existing pySigma match results. It does not change
rule matching; it reconciles which matched events may consume the limited
exception quota.

## Inputs provided by the caller

- **Event identity** (`CallerHints.identity_field`): the field that uniquely
  identifies a real-world event, so two forwarded copies share one identity.
- **Exception scope** (`CallerHints.exempt_scope`): a field or predicate marking
  events that are candidates for the limited ignore quota.
- **Grouping** (`CallerHints.group_field`): the correlation group (for example a
  host). Each group keeps independent windows and quotas.
- **Bounded lateness** (`allowed_lateness`): how long after a window closes a
  record is still admitted. Records arriving later are rejected and listed.

## Guarantees

- A duplicate copy of the same `(group, event_id)` is recorded but deducts the
  quota only once, so two collectors cannot consume the same slot twice.
- Tumbling windows do not overlap; sliding windows overlap but each window keeps
  its own independent quota ledger.
- A watermark of `max(ingest_time) - allowed_lateness` finalizes windows.
  In-lateness late records reopen/re-enter the ledger; out-of-lateness records
  are held out and surfaced as `late_rejected`.
- A later `Correction` (for example confirmation that two records were not the
  same event) replays the affected windows from stored observations, preserving
  duplicate copy counts, and emits a `correction` timeline entry with
  before/after snapshots.
- Replays are deterministic: the same inputs in the same order produce the same
  ledgers and timeline.

## Outputs

`ReconciliationResult` exposes per-window `WindowLedger` objects with
`deductions()` (every quota consumption), `actionable()` (the operations that
still require handling), and duplicate counters. `render_report` produces a
short timeline plus meeting-ready statistics.

Run the worked example with:

```
python examples/quota_reconciliation_demo.py
```
