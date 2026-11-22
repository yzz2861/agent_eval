# Artifact Absence Acceptance

Regular in-toto verification proves that the artifacts a step *did* report
satisfy the layout artifact rules. It has no notion of the scope that was
searched while a link was recorded. An empty `products` table therefore
passes just like a non-empty one, even when the table is empty because the
recording scope was wrong or too narrow.

`in_toto.acceptance` adds an **optional** completeness acceptance on top of
the existing verification. It uses three signed inputs:

- the artifact table of each link (`materials` / `products`),
- a signed enumeration declaration in the link payload, and
- the step artifact commitments from the layout (`expected_products` /
  `expected_materials`).

The acceptance distinguishes three outcomes:

| Outcome | Meaning |
| --- | --- |
| `confirmed_none` | A complete, signed enumeration covers the checked scope, exclusions do not mask the forbidden class, and no forbidden artifact was observed. |
| `allowed_omission` | The scope was not enumerated, but the step made no positive commitment there, or a reason-bearing exclusion explains the omission without hiding the forbidden class. |
| `evidence_missing` | The table is empty or silent, but the signed evidence does not establish that the checked scope was searched. |

`artifacts_present` is reported separately when a forbidden artifact is
actually observed.

## Signed enumeration declaration

Producers can opt in to recording a declaration with `in_toto_run`,
`in_toto_record` or the CLI flag `--record-enumeration`. The declaration is
stored under the reserved `artifact_enumeration` key in `Link.byproducts`
(and is also read from `Link.environment`). Both fields are part of the
signed link payload, so a declaration cannot be added or changed without
invalidating the signature.

Use `--exclude-reason PATTERN=REASON` together with `--record-enumeration`
to explain exclusions in the signed declaration.

```json
{
  "artifact_enumeration": {
    "products": {
      "boundary": ["dist", "build/release"],
      "complete": true,
      "exclusions": [
        {
          "pattern": "dist/**/*.map",
          "reason": "source maps are not part of the release bundle"
        }
      ]
    },
    "materials": {
      "boundary": ["src"],
      "complete": true
    }
  }
}
```

`boundary` lists the paths or prefixes that were enumerated. `complete`
asserts that the enumeration did not silently stop inside the boundary.
`mode: "complete"` is accepted as an alternative to `complete: true`.
`exclusions` records patterns that were intentionally not recorded, with a
human-readable reason. A reason-less masking exclusion is not accepted as
evidence.

## Verification

Enable the check on the existing verification workflow:

```console
in-toto-verify --layout root.layout --verification-keys owner.pub \
  --forbid-artifact "*.debug" --artifact-scope dist
```

The audit report is printed, and can be persisted as JSON with
`--artifact-report report.json`. The verification fails on
`evidence_missing` and on observed forbidden artifacts. `allowed_omission`
is accepted by default; pass `--require-confirmed-artifacts` to require
`confirmed_none`.

For standalone links, for example to compare two independently signed small
links, use:

```console
in-toto-accept --link good.link missing.link \
  --verification-keys functionary.pub \
  --forbid-artifact "*.debug" --artifact-scope dist
```

Example output for two validly signed links whose tables contain no debug
artifacts:

```text
Artifact absence acceptance
  forbid: *.debug
  scope: dist
  direction: products
  overall: evidence_missing (fail)
- good.link [2f685fa7]: confirmed_none
    confirmed_none - complete signed enumeration covers the relevant scope and no forbidden artifact was observed
      observed: 0 artifact(s), 0 forbidden
      signed boundary: [dist]; complete: True
- missing.link [2f685fa7]: evidence_missing
    evidence_missing - no signed artifact enumeration declaration
      observed: 0 artifact(s), 0 forbidden
      signed boundary: <missing>; complete: False
      needs: signed artifact_enumeration.products.boundary covering: dist
      needs: artifact_enumeration.products.complete = true
```

The first link is sufficient because its signed boundary covers `dist` and
is marked complete. The second link is validly signed, but it does not say
which scope was searched, so its empty table is not evidence of absence.

## Independent observations

Each link is judged with its own signed boundary. A following step whose
`expected_materials` contains a `MATCH ... WITH PRODUCTS FROM <step>` rule
is treated as an independent observation of the earlier step products. It
can confirm absence only where its own declaration covers the checked scope.
A narrower observation does not retroactively widen an unrelated scope.

## API

```python
from in_toto.acceptance import ArtifactAbsenceCheck, audit_layout

check = ArtifactAbsenceCheck(patterns=["*.debug"], scope=["dist"])
report = audit_layout(layout, verified_links_by_step, check)
print(report.format_text())
assert report.ok()
```

The same check can be passed to `in_toto.verifylib.in_toto_verify` as
`artifact_absence_check=`.
