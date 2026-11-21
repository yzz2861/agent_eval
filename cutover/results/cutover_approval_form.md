# B102 cutover approval form

## Scope and detection responsibilities

- Retired built-in rule: `B102` (`exec_used`) - detects use of the Python `exec` builtin at any scope depth, across every scanned directory.
- Replacement exec rule: `X901` (`guard_exec_used`, local package `sast_exec_guard`) - owns the same exec-detection responsibility, but only for shallow-scope bare `exec(...)` and only outside the unscanned legacy root.
- Newly added rule: `X902` (`guard_eval_used`) - detects bare `eval(...)`; this is a new responsibility and cannot offset any B102 exec-coverage gap.
- Fixed local corpus: `cutover/corpus` (no network, no repository-wide scan).

## Per-input evidence (real files vs. concrete responsibilities)

| input file | B102 entered/completed/hit | X901 entered/completed/hit | X902 hit | parse status | gap |
| --- | --- | --- | --- | --- | --- |
| `cutover/corpus/app/alias_exec.py` | True/True/False | True/True/False | False | parsed | covered |
| `cutover/corpus/app/builtins_exec.py` | True/True/False | True/True/False | False | parsed | covered |
| `cutover/corpus/app/clean_module.py` | False/True/False | False/True/False | False | parsed | covered |
| `cutover/corpus/app/eval_and_exec.py` | True/True/True | True/True/True | True | parsed | covered |
| `cutover/corpus/app/main_direct_exec.py` | True/True/True | True/True/True | False | parsed | covered |
| `cutover/corpus/app/nested_exec.py` | True/True/True | True/True/False | False | parsed | syntax-coverage-gap |
| `cutover/corpus/legacy/legacy_alias_exec.py` | True/True/False | True/True/False | False | parsed | covered |
| `cutover/corpus/legacy/legacy_broken_syntax.py` | False/True/False | False/True/False | False | skipped | covered |
| `cutover/corpus/legacy/legacy_direct_exec.py` | True/True/True | True/True/False | False | parsed | directory-coverage-gap |
| `cutover/corpus/legacy/legacy_nested_exec.py` | True/True/True | True/True/False | False | parsed | directory-coverage-gap |

## Blocking coverage gaps on the exec responsibility

- `cutover/corpus/app/nested_exec.py` - **syntax-coverage-gap**: replacement plugin enters the file but does not recognize the nested-scope bare exec syntax that B102 covers
- `cutover/corpus/legacy/legacy_direct_exec.py` - **directory-coverage-gap**: file lives in the unscanned legacy root; X901 refuses the directory while legacy B102 still detects exec
- `cutover/corpus/legacy/legacy_nested_exec.py` - **directory-coverage-gap**: file lives in the unscanned legacy root; X901 refuses the directory while legacy B102 still detects exec

## New alerts that do not offset the gaps

- `cutover/corpus/app/eval_and_exec.py:6` - Use of eval detected (replacement plugin X902).

## Decision

**NOT APPROVED** - blocking exec-coverage gaps: 3. New X902 eval alerts are recorded but do not close any B102 exec-coverage gap.

