# Offline STIX release gate

Two review cells feed conclusions to the case lead:

- the **entity-attribute cell** may only verify entity properties;
- the **relationship cell** may derive links between objects.

The pipeline merges their outputs by STIX object id. Before any conclusion
is sent outside, this package runs fully offline and checks that each
outbound conclusion has an applicable original investigation authorization
and enough independent actual observations.

## STIX modelling

- `marking-definition` with a registered custom marking type
  `x-investigation-authorization` carries the original authorization:
  `x_authorization_id`, `x_permitted_purposes`, `x_scope`, `x_status`.
- Conclusions are `report` objects carrying `x_conclusion_scope`
  (`entity-attribute` or `relationship`); `object_marking_refs` state which
  authorizations are claimed, and `object_refs` cite the evidence.
- Evidence is `observed-data` (actual observations). Each records its
  producing source via `created_by_ref` and its raw material via
  `x_raw_material_id`. Observations also carry authorization markings.
- Object selection uses `stix2.Filter` against a `MemoryStore`; no network
  or TAXII access is performed.

## Release rules

A conclusion is releasable only when both hold:

1. **Applicable authorization** - at least one referenced marking is an
   approved (`x_status = approved`) investigation authorization that lists
   the `external-release` purpose and covers the conclusion scope.
2. **Independent observations** - at least two eligible observations, where
   eligibility requires a usable authorization on the observation itself and
   an attributed source. Independence is counted on three dimensions:
   distinct `(source, material)` pairs, distinct sources, and distinct raw
   material. Each dimension must reach the threshold of two.

Reuse is never double counted. When several reports (or several references
in one report) point at the same `x_raw_material_id`, every reference is
preserved in `material_reference_counts`, but the material contributes only
one independent item. A long evidence list backed by a single authorized
source therefore stays on HOLD, and the report states why.

## Layout

- `markings.py` - registered authorization marking and its `permits` rule.
- `validator.py` - `ReleaseGate`, filtering, marking checks and de-duplication.
- `report.py` - JSON report and short text report rendering.
- `cli.py` - command line entry point.
- `data/build_sample_bundle.py` - builds the sample bundle.
- `data/sample_bundle.json` - five scenarios across six conclusions.
- `tests/test_release_gate.py` - pytest coverage of every verdict.

## Usage

```
python -m acceptance_validator.data.build_sample_bundle
python -m acceptance_validator.cli acceptance_validator/data/sample_bundle.json \\
    --json-out acceptance_validator/data/acceptance_report.json \\
    --text-out acceptance_validator/data/acceptance_report.txt
```

The CLI exits non-zero when any conclusion is blocked, so it can gate a pipeline step.

## Sample scenarios

- C1 two independent units under the full warrant - RELEASE.
- C2 six references, one source, one shared material - HOLD.
- C3 two independent observations but only a pending draft warrant - HOLD.
- C4 relationship conclusion under an entity-attribute-only authorization - HOLD.
- C5 two reports share one material, each with its own second observation - both RELEASE.
