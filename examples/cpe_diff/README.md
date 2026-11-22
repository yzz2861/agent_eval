# CPE exclusion diff demo

The old and new expressions differ in exactly one place: the negated `OR`
branch gains a `1.2` fact-ref.  The review file supplies four fully expanded
devices and one device whose `version` is not confirmed but is bounded by the
finite domain `{"1.0", "1.1", "1.2", "2.0"}`.

Run from the repository root:

```bash
.venv/bin/python -m cpe.cpediff2_3 \
  --old examples/cpe_diff/old.xml \
  --new examples/cpe_diff/new.xml \
  --review examples/cpe_diff/review.json
```

Expected result: `edge-1.2` changes from covered to excluded (a new
exclusion).  `edge-1.0` and `edge-1.1` remain excluded, `edge-2.0` remains
covered, and `edge-version-unconfirmed` stays pending because its version can
produce different outcomes inside the supplied domain.

Use `--format json` to get the same result as machine-readable witnesses,
including the exact WFN and the old/new evaluation trace for each changed or
pending device.
