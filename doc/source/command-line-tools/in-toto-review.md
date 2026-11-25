# in-toto-review

`in-toto-review` runs the optional artifact usage review. It accepts a layout,
already verified link metadata and an optional usage declaration, and traces
each copy of an approved artifact through the actual material and product rules
of the layout.

```shell
in-toto-review --layout root.layout --link-dir links \
    --usage-declarations usage.json
```

The command follows paths, not just hashes. If two downstream files have
identical content, only the copy connected to the approved origin by a
`MATCH` rule is in scope. Other uses are reported as out-of-scope evidence.
If a step's link or input is unavailable, the result for that use is `unknown`
instead of a false out-of-scope conclusion.

Exit codes:

- `0`: every reviewed use is in scope
- `1`: at least one use is out of scope
- `2`: the evidence is insufficient (unknown)
