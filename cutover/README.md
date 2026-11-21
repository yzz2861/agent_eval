# B102 -> sast_exec_guard cutover validation

This directory contains a fully local cutover validation for retiring the
Bandit built-in rule `B102` (`exec_used`) in favor of the business plugin
`sast_exec_guard`. Nothing here reaches the network or scans outside the
fixed, checked-in corpus.

## Layout

- `sast_exec_guard/` - local replacement plugin package (no install needed).
  - `X901 guard_exec_used` - replacement exec rule (narrower than B102).
  - `X902 guard_eval_used` - brand-new eval rule (new responsibility).
- `corpus/` - the only inputs ever evaluated; fixed Python files under
  `app/` (in replacement scope) and `legacy/` (outside replacement scope).
- `run_cutover_check.py` - validation engine and report generator.
- `tests/test_cutover_validation.py` - pytest coverage of the engine.
- `results/` - generated evidence (regenerated on every run).

## Running the validation (local fixed code only)

From the repository root, with the repository virtualenv:

```
.venv/bin/python cutover/run_cutover_check.py
```

The harness enumerates `corpus/**/*.py` at runtime but never discovers or
scans any other path, and the plugin is loaded in-process from
`sast_exec_guard/` via a stevedore test extension manager. Exit code is `0`
only when the cutover is approved; it is `1` while blocking gaps remain.

Run the pinned tests with:

```
.venv/bin/python -m pytest cutover/tests -c cutover/tests/pytest.ini -q
```

## Recorded facts per input and rule

For every corpus file and each target rule the matrix records:

- `entered` - the rule function was actually invoked while scanning the file.
- `completed` - every invocation returned instead of raising.
- `hit` - the rule emitted at least one issue for the file.
- `parse_status` - `parsed`, or `skipped` (e.g. syntax error) with a note.

## Coverage gaps by responsibility

Only the exec-detection responsibility is compared (`B102` vs `X901`).

- `syntax-coverage-gap` - X901 enters the file but misses syntax B102 catches
  (nested-scope bare `exec(...)` in `app/nested_exec.py`).
- `directory-coverage-gap` - the file lives in the unscanned legacy root, so
  X901 never covers exec there even though B102 does
  (`legacy/legacy_direct_exec.py`, `legacy/legacy_nested_exec.py`).

The new `X902` eval alert (`app/eval_and_exec.py`) is reported separately as
a new-only finding. It represents additional coverage and can never offset an
exec-coverage gap, so the approval form stays NOT APPROVED until the three
blocking gaps are closed.
