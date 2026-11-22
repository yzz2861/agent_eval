# Build Tool Impact Audit Sheet

Archive: `ACME-BBA-2026-05-31` (frozen at 2026-05-31T12:00:00Z)
Advisory: `ACME-FORGEPACK-2026-0042` for `forgepack`

## Summary

| Packages | Affected | Not affected | Tool unconfirmed | Re-verify tool source |
| ---: | ---: | ---: | ---: | ---: |
| 6 | 1 | 4 | 1 | 1 |

## Identical-digest cohort

Identical digests are shared observations, not shared build conclusions. Each row was reconciled against its own frozen build record.

Digest `84ff0b62b508841b...` is shared by 6 package(s).

| Release | Build | Provenance | Tool | Tool source | Status | Re-verify tool source? |
| --- | --- | --- | --- | --- | --- | --- |
| `REL-APAC-REBUILD` | B-4103 | rebuilt | forgepack 2.4.4 | 5a6b7c8d9e0f / da51cd3aa2cc | not_affected | no |
| `REL-CN-PINNED` | B-4104 | built | forgepack 2.4.1 | c0ffee123456 / 55f1e0c0a020 | not_affected | no |
| `REL-EU-BAD` | B-4102 | built | forgepack 2.4.1 | 9f2c7d1e4b6a / 3eb43e330685 | affected | no |
| `REL-LATAM-COPY` | B-4105 | copied | n/a (no independent tool invocation) | UNKNOWN | tool_unconfirmed | YES |
| `REL-US-EARLY` | B-4101 | built | forgepack 2.3.0 | a1b2c3d4e5f6 / 00fb493a8cba | not_affected | no |
| `REL-US-LATE` | B-4106 | built | forgepack 2.4.4 | 5a6b7c8d9e0f / da51cd3aa2cc | not_affected | no |

## Confirmed affected

| Release | Build | Tool | Tool source | Reason |
| --- | --- | --- | --- | --- |
| `REL-EU-BAD` | B-4102 | forgepack 2.4.1 | 9f2c7d1e4b6a / 3eb43e330685 | the observed tool source digest matches the advisory |

## Confirmed not affected

| Release | Build | Tool | Tool source | Reason |
| --- | --- | --- | --- | --- |
| `REL-APAC-REBUILD` | B-4103 | forgepack 2.4.4 | 5a6b7c8d9e0f / da51cd3aa2cc | forgepack 2.4.4: the observed tool source does not match the advisory |
| `REL-CN-PINNED` | B-4104 | forgepack 2.4.1 | c0ffee123456 / 55f1e0c0a020 | forgepack 2.4.1: the observed tool source does not match the advisory |
| `REL-US-EARLY` | B-4101 | forgepack 2.3.0 | a1b2c3d4e5f6 / 00fb493a8cba | forgepack 2.3.0: the observed tool source does not match the advisory |
| `REL-US-LATE` | B-4106 | forgepack 2.4.4 | 5a6b7c8d9e0f / da51cd3aa2cc | forgepack 2.4.4: the observed tool source does not match the advisory |

## Tool provenance unconfirmed (separate list)

These packages are not counted as clean. Their tool origin cannot be confirmed from the frozen archive, so they require tool-source re-verification.

| Release | Build | Provenance | Source build | Source build status | Reason |
| --- | --- | --- | --- | --- | --- |
| `REL-LATAM-COPY` | B-4105 | copied | B-4101 | not_affected | the copy/mirror record contains no independent tool provenance, so the original build conclusion cannot be reused |

## Re-verification answer

**Only `REL-LATAM-COPY` must re-verify tool provenance.**

- Reason: `copied_artifact_does_not_inherit_build_conclusion` - the copy/mirror record contains no independent tool provenance, so the original build conclusion cannot be reused.
- Source build `B-4101` is `not_affected`, but a copy does not inherit that conclusion.

## Reconciliation policy

- The frozen archive is authoritative for actual tool use, fetch time, use time, and source.
- The advisory is authoritative for affected versions, affected source commits/digests, and the distribution window.
- A source commit or digest match outranks a version label; a recorded non-matching source can clear an affected version label.
- A copied or mirrored artifact never inherits the source build conclusion. A rebuild is evaluated only from its own frozen tool invocation.
- A package whose tool origin cannot be confirmed is listed separately and is not counted as clean.
