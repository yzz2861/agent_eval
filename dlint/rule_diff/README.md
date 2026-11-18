# Rule Diff Backend

`dlint.rule_diff` compares two revisions of a set of lint rules over a fixed,
bounded subset of Python programs. It generates programs on which the two
revisions reach different verdicts, reduces each witness while preserving its
difference category, and reports alert-set changes, rule locations and the
structural premises involved.

## Bounded subset, not an equivalence proof

Only the node kinds in `language.SUPPORTED_NODES` are in scope:

- imports and aliases (`import x as y`, `from x import y as z`);
- zero-argument calls, including attribute calls (`mod.fn()`);
- constant conditions (`if <literal>:`);
- simple literal assignment (`name = <literal>`).

Everything else (functions, classes, loops, `try`/`with`, comprehensions,
operators, subscripts, collections, argument-carrying calls, ...) is **out of
scope** and is declared uncovered via `BoundedSubset.coverage()` and
`uncovered_features()`. It is never silently treated as evidence.

Because enumeration is finite (a structural `Bounds` plus a wall-clock and
program-count `Budget`), an empty result means only that **no difference was
found inside the explored subset**. The report always states this explicitly
and never claims the rules are equivalent.

## Alerts versus exceptions

`runner` keeps two disjoint outcomes:

- `Alert` - a rule positively reported a finding; "no warning" is an empty
  alert list;
- `RuleError` - a rule raised while visiting the tree, counted separately.

A crashed rule is therefore never conflated with a silent rule. Reduction
accepts a candidate only when the exact difference category is preserved, so
an injected false negative cannot silently become a false-positive witness.

## Usage

```python
from dlint.rule_diff import Budget, compare_rules

report = compare_rules((OldRule,), (NewRule,),
                        budget=Budget(deadline_seconds=20.0,
                                      max_programs=4000))
for difference in report.differences:
    print(difference.category, difference.premises,
          difference.rule_locations, difference.source)
print(report.equivalence_statement())
```

CLI:

```
python -m dlint.rule_diff \
    --old pkg.OldRule --new pkg.NewRule --json
```

Witnesses are deterministic and independently reproducible with `replay()`.
