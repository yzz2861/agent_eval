# Desensitization Key Migration Protocol

## Why this exists

When the platform rotates the key used to produce desensitized secret
identifiers, alerts already stored only carry the old identifier, and the
review pipeline can no longer read the original secret plaintext. A new key
therefore cannot recompute old identifiers, so human adjudication must be
carried forward through trusted linkage material during a bounded transition
window instead of being derived from secret values.

## Where it runs

The protocol sits between baseline loading and audit comparison:

1. Load the old and new baselines with `core.baseline.load`.
2. Load the project-scoped linkage manifest with `LinkageManifest.load`.
3. Call `prepare_comparison_inputs(old, new, manifest, project_id)`.
4. Feed `MigrationResult.migrated_baseline` into the normal audit/compare flow.
5. Persist or inspect `MigrationResult.report`.

Everything is local: baseline objects plus one JSON manifest. No database,
network call, or secret plaintext is involved.

## Linkage material (local JSON)

The manifest stores project id, the transition window, and one or more
records. Each record pairs an old pseudonymous identifier with its
replacement under the new key, scoped by rule id and filename, plus its own
`not_before`/`not_after` validity window. The identifiers are hashes with
the same shape as a baseline `hashed_secret`; secret plaintext never appears.

## Matching rules

- An alert is located by the tuple `(project_id, rule_id, old_secret_id)`.
  Equality of the old identifier alone never merges alerts from different
  projects or different rules. A manifest scoped to another project is
  rejected up front by `require_project`.
- The new-baseline target is located by `(rule_id, new_secret_id)`, with the
  filename used only to disambiguate repeated occurrences.
- The old baseline is never mutated. After a successful migration the same
  human decision (`is_secret`, `is_verified`) is readable on the new
  baseline entry, while the original review record stays intact in the old
  baseline.

## Outcomes

Each old-baseline alert produces exactly one report entry:

| Status | Meaning |
| --- | --- |
| `migrated` | One active, unambiguous evidence record; decision carried forward. |
| `duplicate` | Repeated evidence pointing at the same new identifier; manual review. |
| `conflict` | Evidence disagrees on the new identifier or its filename. |
| `expired` | Every matching record is outside its own validity window. |
| `unmigrated` | No evidence, or the transition window is closed (incl. early close). |
| `target_missing` | Evidence points at an identifier absent from the new baseline. |

Repeated, conflicting, and expired evidence therefore produce distinct
results rather than being silently collapsed.

## Ending the transition early

Pass an `evaluated_at` after `transition_ends_at` (or end the window early
and re-run). Even otherwise fresh evidence can no longer authorize a
migration, so unfinished items stay `unmigrated`. `MigrationResult.
pending_record_refs()` and `MigrationReport.pending_entries` list everything
that did not make it across, which makes an early close auditable.

## Report safety

The report is designed to be shareable:

- It never contains secret plaintext.
- It never contains pseudonymous identifier keys (`old_secret_id`,
  `new_secret_id`, `hashed_secret`, `secret_hash`, `secret_value`). Only
  project id, rule, filename, line, decision, evidence count, and a per-run
  random `record_ref` remain.
- `record_ref` values are generated independently per run, so they cannot
  be used to correlate the same finding across projects or across reports.
- `assert_report_is_sanitized(payload, forbidden_values=...)` validates a
  serialized report and raises `UnsafeMigrationReportError` on any leak.
