# Forensic observation evidence

This package demonstrates the single-pass evidence API on a small JSON document
that contains an array and a duplicate object key.

Files:

- `source.json` - the original document. The duplicate `sample` key is
  intentional.
- `trusted-root.txt` - the root commitment from the trusted ticket,
  kept separate from the evidence files.
- `evidence.json` - the original evidence bundle. It carries only the selected
  values, typed paths, positions, commitments, and the root commitment. It does
  not copy sibling values.
- `evidence_path_tampered.json` - the first observation path was replaced while
  its value and commitments were left alone.
- `evidence_duplicate_swapped.json` - the two duplicate-key observations had
  their `position`, `order_commitment`, and `sibling_prefix_commitment` fields
  exchanged.
- `build_package.py` - regenerates all of the above.
- `verify_demo.py` - verifies every package against the trusted root and paths.

Run:

```bash
cd examples/forensic_evidence
python build_package.py
python verify_demo.py
```

Expected verification result:

```text
evidence.json                    ok=True   []
evidence_path_tampered.json      ok=False  [path_commitment]
evidence_duplicate_swapped.json  ok=False  [order_commitment]
```

The path variation fails because the observation path is no longer the
caller-specified path. The duplicate swap fails because the physical occurrence
and sibling order no longer match the source, while the path and value
commitments still do.
