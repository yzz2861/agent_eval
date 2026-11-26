# Offline path contract acceptance report

**Contract:** `windows-linux-path-contract`

Acceptance vectors for ordinary filenames that differ only by case, Unicode normalization, or path root convention.

## Contract setup

- Platforms: `linux` (posix, case-sensitive), `windows` (windows, case-insensitive)
- Primary policy: `after`
- Recorded paths are normalized like in-toto link metadata: platform `normpath`, then backslashes become forward slashes.
- Evaluation uses in-toto's artifact rule functions. No build artifacts are read or written.

## Verdict

| Case | Before policy | After policy | Same decision | linux | windows |
| --- | --- | --- | --- | --- | --- |
| `case-variant` | `DIVERGENT` | `EQUIVALENT_PASS` | yes | pass | pass |
| `unicode-equivalence` | `DIVERGENT` | `EQUIVALENT_PASS` | yes | pass | pass |
| `root-convention` | `DIVERGENT` | `EQUIVALENT_PASS` | yes | pass | pass |
| `material-product-match` | `EQUIVALENT_PASS` | `EQUIVALENT_PASS` | yes | pass | pass |
| `mapping-ambiguity` | `AMBIGUOUS` | `AMBIGUOUS` | indeterminate | fail | pass |

Status values: `EQUIVALENT_PASS` and `EQUIVALENT_FAIL` mean all platforms reached the same decision; `DIVERGENT` means they did not; `AMBIGUOUS` means a mapping collision prevents a decision.

Primary-policy summary: 4 equivalent, 0 divergent, 1 ambiguous; 3 expanded rule(s).

## Rule applicability

Rows are shown for every policy so the original/normalized basis can be compared directly.

### `case-variant`

| Policy | Platform | Match basis | # | Effective rule | Matched recorded paths | Matched canonical artifacts |
| --- | --- | --- | --- | --- | --- | --- |
| `before` | `linux` | `original` | 0 | `ALLOW src/app.py` |  |  |
| `before` | `linux` | `original` | 1 | `DISALLOW *` | `src/App.py` | `src/App.py` |
| `before` | `windows` | `original` | 0 | `ALLOW src/app.py` | `src/App.py` | `src/App.py` |
| `before` | `windows` | `original` | 1 | `DISALLOW *` |  |  |
| `after` | `linux` | `normalized` | 0 | `ALLOW src/app.py` | `src/app.py` | `src/App.py` |
| `after` | `linux` | `normalized` | 1 | `DISALLOW *` |  |  |
| `after` | `windows` | `normalized` | 0 | `ALLOW src/app.py` | `src/app.py` | `src/App.py` |
| `after` | `windows` | `normalized` | 1 | `DISALLOW *` |  |  |

### `unicode-equivalence`

| Policy | Platform | Match basis | # | Effective rule | Matched recorded paths | Matched canonical artifacts |
| --- | --- | --- | --- | --- | --- | --- |
| `before` | `linux` | `original` | 0 | `ALLOW docs/café.txt` |  |  |
| `before` | `linux` | `original` | 1 | `DISALLOW *` | `docs/cafe\u0301.txt` (U+0301) | `docs/caf\xe9.txt` (U+00E9) |
| `before` | `windows` | `original` | 0 | `ALLOW docs/café.txt` | `docs/caf\xe9.txt` (U+00E9) | `docs/caf\xe9.txt` (U+00E9) |
| `before` | `windows` | `original` | 1 | `DISALLOW *` |  |  |
| `after` | `linux` | `normalized` | 0 | `ALLOW docs/café.txt` | `docs/caf\xe9.txt` (U+00E9) | `docs/caf\xe9.txt` (U+00E9) |
| `after` | `linux` | `normalized` | 1 | `DISALLOW *` |  |  |
| `after` | `windows` | `normalized` | 0 | `ALLOW docs/café.txt` | `docs/caf\xe9.txt` (U+00E9) | `docs/caf\xe9.txt` (U+00E9) |
| `after` | `windows` | `normalized` | 1 | `DISALLOW *` |  |  |

### `root-convention`

| Policy | Platform | Match basis | # | Effective rule | Matched recorded paths | Matched canonical artifacts |
| --- | --- | --- | --- | --- | --- | --- |
| `before` | `linux` | `original` | 0 | `ALLOW src/main.py` | `src/main.py` | `src/main.py` |
| `before` | `linux` | `original` | 1 | `DISALLOW *` |  |  |
| `before` | `windows` | `original` | 0 | `ALLOW src/main.py` |  |  |
| `before` | `windows` | `original` | 1 | `DISALLOW *` | `C:/work/src/main.py` | `src/main.py` |
| `after` | `linux` | `normalized` | 0 | `ALLOW src/main.py` | `src/main.py` | `src/main.py` |
| `after` | `linux` | `normalized` | 1 | `DISALLOW *` |  |  |
| `after` | `windows` | `normalized` | 0 | `ALLOW src/main.py` | `src/main.py` | `src/main.py` |
| `after` | `windows` | `normalized` | 1 | `DISALLOW *` |  |  |

### `material-product-match`

| Policy | Platform | Match basis | # | Effective rule | Matched recorded paths | Matched canonical artifacts |
| --- | --- | --- | --- | --- | --- | --- |
| `before` | `linux` | `original` | 0 | `MATCH *.py IN lib WITH PRODUCTS IN lib FROM build` | `lib/util.py` | `lib/util.py` |
| `before` | `linux` | `original` | 1 | `DISALLOW *` |  |  |
| `before` | `windows` | `original` | 0 | `MATCH *.py IN lib WITH PRODUCTS IN lib FROM build` | `lib/util.py` | `lib/util.py` |
| `before` | `windows` | `original` | 1 | `DISALLOW *` |  |  |
| `after` | `linux` | `normalized` | 0 | `MATCH *.py IN lib WITH PRODUCTS IN lib FROM build` | `lib/util.py` | `lib/util.py` |
| `after` | `linux` | `normalized` | 1 | `DISALLOW *` |  |  |
| `after` | `windows` | `normalized` | 0 | `MATCH *.py IN lib WITH PRODUCTS IN lib FROM build` | `lib/util.py` | `lib/util.py` |
| `after` | `windows` | `normalized` | 1 | `DISALLOW *` |  |  |

### `mapping-ambiguity`

| Policy | Platform | Match basis | # | Effective rule | Matched recorded paths | Matched canonical artifacts |
| --- | --- | --- | --- | --- | --- | --- |
| `before` | `linux` | `original` | 0 | `ALLOW src/README.md` | `src/README.md` | `src/README.md` |
| `before` | `linux` | `original` | 1 | `DISALLOW *` | `src/readme.md` | `src/readme.md` |
| `before` | `windows` | `original` | 0 | `ALLOW src/README.md` | `src/README.md`, `src/readme.md` | `src/README.md`, `src/readme.md` |
| `before` | `windows` | `original` | 1 | `DISALLOW *` |  |  |
| `after` | `linux` | `original` | 0 | `ALLOW src/README.md` | `src/README.md` | `src/README.md` |
| `after` | `linux` | `original` | 1 | `DISALLOW *` | `src/readme.md` | `src/readme.md` |
| `after` | `windows` | `original` | 0 | `ALLOW src/README.md` | `src/README.md`, `src/readme.md` | `src/README.md`, `src/readme.md` |
| `after` | `windows` | `original` | 1 | `DISALLOW *` |  |  |

## Cross-platform differences

- `case-variant` (`before`): `DIVERGENT`
  - pass/fail differs: `linux`=fail, `windows`=pass
  - `src/App.py` consumed on `windows`
  - rule 0 `ALLOW src/app.py` matched: `linux`=(none), `windows`=`src/App.py`
  - rule 1 `DISALLOW *` matched: `linux`=`src/App.py`, `windows`=(none)
- `unicode-equivalence` (`before`): `DIVERGENT`
  - pass/fail differs: `linux`=fail, `windows`=pass
  - `docs/caf\xe9.txt` (U+00E9) consumed on `windows`
  - rule 0 `ALLOW docs/café.txt` matched: `linux`=(none), `windows`=`docs/caf\xe9.txt` (U+00E9)
  - rule 1 `DISALLOW *` matched: `linux`=`docs/caf\xe9.txt` (U+00E9), `windows`=(none)
- `root-convention` (`before`): `DIVERGENT`
  - pass/fail differs: `linux`=pass, `windows`=fail
  - `src/main.py` consumed on `linux`
  - rule 0 `ALLOW src/main.py` matched: `linux`=`src/main.py`, `windows`=(none)
  - rule 1 `DISALLOW *` matched: `linux`=(none), `windows`=`src/main.py`
- `mapping-ambiguity` (`before`): `AMBIGUOUS`
  - pass/fail differs: `linux`=fail, `windows`=pass
  - `src/readme.md` consumed on `windows`
  - rule 0 `ALLOW src/README.md` matched: `linux`=`src/README.md`, `windows`=`src/README.md`, `src/readme.md`
  - rule 1 `DISALLOW *` matched: `linux`=`src/readme.md`, `windows`=(none)
- `mapping-ambiguity` (`after`): `AMBIGUOUS`
  - pass/fail differs: `linux`=fail, `windows`=pass
  - `src/readme.md` consumed on `windows`
  - rule 0 `ALLOW src/README.md` matched: `linux`=`src/README.md`, `windows`=`src/README.md`, `src/readme.md`
  - rule 1 `DISALLOW *` matched: `linux`=`src/readme.md`, `windows`=(none)

## Mapping ambiguities

| Case | Policy | Platform | Step | Type | Kind | Key | Blocking | Candidates |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `mapping-ambiguity` | `before` | `windows` | `build` | products | `case-fold-collision` | `src\readme.md` | yes | `src/README.md` (`src\README.md`), `src/readme.md` (`src\readme.md`) |
| `mapping-ambiguity` | `after` | `windows` | `build` | products | `case-fold-collision` | `src\readme.md` | yes | `src/README.md` (`src\README.md`), `src/readme.md` (`src\readme.md`) |

## Policy change: expanded applicability

| Case | Rule # | Rule | Added | Removed | Expanded on |
| --- | --- | --- | --- | --- | --- |
| `case-variant` | 0 | `ALLOW src/app.py` | `src/App.py` |  | `linux`: +`src/App.py` |
| `unicode-equivalence` | 0 | `ALLOW docs/café.txt` | `docs/caf\xe9.txt` (U+00E9) |  | `linux`: +`docs/caf\xe9.txt` (U+00E9) |
| `root-convention` | 0 | `ALLOW src/main.py` | `src/main.py` |  | `windows`: +`src/main.py` |

Expanded rules:
- `case-variant`, rule 0 `ALLOW src/app.py`: linux (+`src/App.py`)
- `unicode-equivalence`, rule 0 `ALLOW docs/café.txt`: linux (+`docs/caf\xe9.txt` (U+00E9))
- `root-convention`, rule 0 `ALLOW src/main.py`: windows (+`src/main.py`)

## Interpretation notes

- `original` means rules see the recorded path spelling. Platform glob semantics still apply: a Windows profile folds case, a POSIX profile does not.
- `normalized` means the explicit normalization (Unicode form, case mode, separator, stripped prefixes) is applied to both recorded names and rule patterns before matching.
- Unicode-equivalent spellings are not implicitly equal in `fnmatch`; an NFC/NFD mismatch remains a mismatch unless a policy normalizes it.
- Ambiguous mappings are never silently resolved. Candidates are listed and a blocking collision makes the verdict `AMBIGUOUS`.

