# Structure-aware RTF object fuzzing backend

This package fuzzes the RTF object extraction path of `oletools.rtfobj` at the
**syntactic** level instead of flipping random bytes. Every variant is built
from a parsed syntax tree, so differences in object extraction stay
explainable through an explicit transformation chain.

## Components

- `model.py` - RTF syntax tree (groups, destinations, control words,
  control symbols, `\\bin` entries, hex text). Parse + serialise is byte-exact.
- `seeds.py` - harmless, in-memory OLE 1.0 object and seven semantically
  equivalent RTF encodings (plain/split hex, ignored groups, apostrophe
  escapes, single/multi `\\bin`, mixed hex/bin).
- `mutators.py` - structure-aware mutators split into two pools:
  valid (equivalence-preserving) and invalid (deliberate contradictions).
- `oracle.py` - rtfobj wrapper that captures extracted object fingerprints
  and parser diagnostics, the valid/invalid difference oracles and the dual
  step + byte `Budget`.
- `reducer.py` - syntax-unit ddmin that only accepts a smaller sample when
  the **original difference signature** is preserved (never collapses into an
  unrelated parse exception).
- `campaign.py` / `__main__.py` - deterministic campaign, JSON artifacts and
  command line entry point.

## Two sample classes

- **Valid samples** must always extract byte-identical object bytes. A
  difference is reported as a discrepancy and reduced while keeping the same
  signature.
- **Invalid samples** intentionally corrupt destinations, groups, `\\bin`
  lengths or hex framing. Their diagnostics are compared, and a finding is
  raised when a malformed document silently recovers a complete object or
  when the parser raises instead of producing a documented diagnostic.

## Budgets and artifacts

Every parse counts against both a maximum number of steps and a cumulative
byte budget. Artifacts record the RNG seed, the transformation chain, the
baseline/variant fingerprints and diagnostics, and the minimal reproducing
RTF (base64 in JSON plus a standalone `.rtf` per finding).

## Usage

```
python -m oletools.rtf_fuzz --seed 20261119 --valid-steps 50 \
    --invalid-steps 50 --max-bytes 2097152 --output-dir out/
```

No Office application is invoked; all embedded data is a harmless synthetic
ASCII marker, and the fixed test campaign finishes well under 30 seconds.
