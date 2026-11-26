# Differential attribution fixtures

These fixtures form a replaceable 2x2 audit matrix:

| Dependency | Advisory | Saved result |
| --- | --- | --- |
| old | old | `cells/old-old.json` |
| old | new | `cells/old-new.json` |
| new | old | `cells/new-old.json` |
| new | new | `cells/new-new.json` |

Inputs:

- `old-requirements.txt`, `new-requirements.txt`: pinned manifests.
- `advisories-old.json`, `advisories-new.json`: offline freeze snapshots.

A freeze snapshot has a `coverage` map from canonical package name to the
versions the snapshot makes a judgment about. A package/version that is absent
from `coverage` is reported as `unknown`; it is never treated as clean. Each
entry in `advisories` names an `id`, optional `aliases`/`fix_versions`, a
`package`, and the affected `versions` (OSV-style `ranges` are accepted too).

The scenario contains one alert for each attribution category:

- `alpha`: disappears because only the dependency changed (`dependency`).
- `beta`: disappears because only the advisory snapshot changed (`advisory`).
- `gamma`: appears only when the new dependency and new advisory are combined (`both`).
- `delta`: present in all four cells (`unchanged`).
- `zeta`: deliberately absent from both snapshots' coverage lists, so every cell keeps it `unknown`.

Replace or delete any one file under `cells/` and rerun:

```console
$ pip-audit diff --results-dir test/assets/diff/cells
```

The report names the missing cell and lists every observed alert under
`unattributed_alerts`. Regenerate the snapshots from the manifests and
advisory fixtures with:

```console
$ pip-audit diff \
    --old-requirements test/assets/diff/old-requirements.txt \
    --new-requirements test/assets/diff/new-requirements.txt \
    --old-advisories test/assets/diff/advisories-old.json \
    --new-advisories test/assets/diff/advisories-new.json \
    --write-results-dir test/assets/diff/cells
```
