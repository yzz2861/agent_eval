# XML AST compatibility probe

`dlint.compat` checks whether the `DUO107` XML import rule still reports the
same warnings after a Python minor-version upgrade. It parses placeholder
snippets only; no fixture imports an XML parser or opens an XML document.

## Running

The probe discovers installed Python interpreters automatically. The current
interpreter is used as the baseline when a newer interpreter is available;
otherwise the newest older interpreter is compared against the current one.

```
python -m dlint.compat
python -m dlint.compat --json
python -m dlint.compat --baseline /path/to/python3.12 --candidate /path/to/python3.13
```

The human-readable report groups findings by category. `--json` emits the full
machine-readable fixture, AST-path, warning, plugin-record, and diff report.

## Coverage

The fixture matrix covers:

* The legacy warning positions from `tests/test_bad_xml_use.py`.
* `Import`, `ImportFrom`, `alias`, `Call`, `Attribute`, `Name`, and `Constant`
  node shapes at literal AST paths such as `body[0].names[0]`.
* Aliased/dotted imports, multiple names in one import, wildcard imports,
  whitelisted `xml.sax.saxutils`, relative imports, and safe `defusedxml`.
* The three-field `Flake8Result` contract and the four-field records yielded by
  the flake8 extension: `(lineno, col_offset, message, linter_type)`.

## Reports

* `PARSE_ERROR`: a fixture could not be parsed. No coverage conclusion is drawn
  for that fixture.
* `COVERAGE_GAP`: the rule missed an expected warning, including the case where
  the candidate silently loses every warning the baseline emitted.
* `RESULT_DRIFT`: warning positions or messages changed unexpectedly.
* `SHAPE_DRIFT`: a preset AST path or the semantic AST graph changed.
* `PLUGIN_FORMAT`: the linter result or flake8 tuple contract changed.
* `WORKER_ERROR`: the probe could not import or run `dlint` in an interpreter.
* `MANUAL_REVIEW`: raw `ast.dump` output changed while semantic nodes and rule
  results agree. This is not treated as a hard failure, but should be reviewed
  by anyone consuming golden AST snapshots.

Exit status is `2` for parse/worker errors, `1` for rule/shape/plugin failures,
and `0` for a clean run or a run containing only manual-review findings.

## Current finding

Comparing CPython 3.12 with 3.13 currently yields no `DUO107` warning drift: all
11 fixtures keep the same warning positions and plugin records. The single
manual-review item is that Python 3.13's `ast.dump()` defaults to
`show_empty=False` and omits empty lists / `None` fields such as
`type_ignores=[]`, `keywords=[]`, and `type_params=[]`. This is a serialization
change; clients that snapshot `ast.dump` output must decide whether to update
their golden files or compare a version-normalized representation.

## CI integration

Run the probe on the Python-version boundary being upgraded:

```
python -m dlint.compat --baseline python3.12 --candidate python3.13
python -m unittest tests.test_bad_xml_compat
```

Any non-zero exit blocks the upgrade. A zero exit with a `MANUAL_REVIEW` section
is the signal to inspect the reported snapshots rather than treating the
upgrade as fully automatic.
