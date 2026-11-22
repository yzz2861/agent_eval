# mask_audit

Offline consistency check between an original SQL change request and the
desensitized review copy handed to an external team. It never opens a
database connection and only relies on sqlparse plus the standard library.

## Inputs

- Original SQL document and its masked review copy.
- A JSON list of permitted mask ranges. Each range is a half-open character
  span inside the original document with a category, the placeholder it may
  be replaced by and, for database spans, the controlled zone it belongs to.
- An optional session schema mapping concrete database/schema names and
  placeholder names to controlled zones.

Masking a token outside every permitted range is reported as
`mask_violation`. Any other concrete token change is an `error`. Statements
outside simple `CREATE`/`ALTER`, comment-only statements, statement count
mismatches and database names missing from the session schema are emitted as
`manual` items for a human reviewer.

## Target zone protection

The target database of every supported statement is resolved to a controlled
zone on both sides. A masked database uses the zone declared on the mask
permit, so replacing the name cannot hide a retargeting. If the review copy
points at a different zone the report contains a `target_zone_drift` error,
even when the changed token sits inside an allowed mask span.

## CLI

```
python -m mask_audit original.sql review.sql \
    --permits mask_ranges.json --schema session_schema.json
```

The report is printed as JSON. The process exits `0` when nothing blocks
automatic approval and `1` on errors, mask violations or manual items.
