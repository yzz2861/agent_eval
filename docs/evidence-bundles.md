# Field-scoped EVTX evidence bundles

`Evtx.Evidence` turns an EVTX file into a reviewable, field-level evidence
package.  It is intended for workflows where one reviewer may see the actor but
not the organizational unit, while a second reviewer is approved for both.

## Bundle layout

```
bundle/
  manifest.json
  records.jsonl
  relationships.json
```

`records.jsonl` contains one record per line.  Each record retains:

- the original record number, byte offset, byte length, chunk position, and
  SHA-256 of the raw record bytes;
- an allow-listed metadata excerpt (event id, time, provider, channel);
- one entry per policy field, with `present`, `not_collected`, `redacted`, or
  `parse_failure` status;
- for present fields, the selected path, value, value digest, and the exact
  source byte ranges used for the value.

`manifest.json` records the policy, source digest, selection, canonicalization
rules, per-record digests, and the package-level `forensic_digest`.
`relationships.json` groups records that share an allowed object identity.  A
narrow package contains actor groups only; an `actor-and-org-unit` package also
contains organizational-unit groups.

## Two scopes

```python
from Evtx.Evidence import actor_only_policy, actor_and_org_unit_policy

narrow = actor_only_policy()          # actor visible, org unit redacted
broad = actor_and_org_unit_policy()   # both visible
```

The narrow manifest intentionally omits the selector for the withheld field.
The record still carries `{"name": "org_unit", "status": "redacted"}` so a
reviewer can distinguish an approval decision from a source gap or parser
failure.

## Missing values

| status | meaning |
| --- | --- |
| `not_collected` | the source event did not contain the field, or policy omitted it (`policy_excluded`) |
| `redacted` | the field was present but released only after approval (`approval_withheld`) |
| `parse_failure` | the EVTX/BXML parser could not read the record (`parser_error`) |

When a whole record fails to parse, its raw reference and digest are still
retained, and every policy field is marked `parse_failure` rather than silently
dropped.

## Offline verification

Self-checking uses only the retained package:

```python
from Evtx.Evidence import load_bundle, verify_bundle

report = verify_bundle(load_bundle("bundle"))
```

Checking the original re-resolves every record by byte offset, re-hashes the
record bytes, re-extracts each field, and re-hashes every field source range:

```python
report = verify_bundle("bundle", source="Security.evtx")
```

`report["field_refs_checked"]` counts the exact field and metadata references
that were located.  A false `ok` value includes human-readable errors for the
first mismatch.  Bundles of different record counts use the same protocol, so
two independently scoped excerpts can be checked against the same original.

## Reproducing digests

```python
from Evtx.Evidence import recompute_digests

recompute_digests(bundle.manifest, bundle.records, bundle.relationships)
```

Each record has a `content_digest` over only its retained metadata and field
entries, plus a `digest` that also binds the record reference.  The
relationship digest covers the allowed object groups and links.  The package
digest covers the policy, source identity, selection, summary, record digests,
and relationship digest.  Canonical JSON is UTF-8, sorted-key, and compact.

## CLI

```bash
evtx_evidence create Security.evtx narrow \
  --policy actor-only --records 4-8

evtx_evidence create Security.evtx broad \
  --policy actor-and-org-unit --records 4-8

evtx_evidence verify narrow --evtx Security.evtx
evtx_evidence verify broad --evtx Security.evtx
```
