# Cross-version scope audits

`dlint.scope` (also exported as `dlint.audit`) audits the same Dlint report
against several target Python versions without collapsing the results into
one shared set.

## Status values

* `eligible` - the source parses, the rule is enabled, the rule applies to
  the target version, and the report item can be signed off.
* `syntax_unsupported` - the target interpreter cannot parse the fragment,
  so absence of a warning is not evidence of safety.
* `rule_not_enabled` - the fragment parses but the report item rule was not
  selected for this maintenance group.
* `rule_not_applicable` - the rule is enabled, but its documented Python
  version range excludes this target. This is a target-environment skip, not
  a clean result.
* `no_findings` - the rule was enabled, applicable, actually ran on the
  fragment, and the report has no warning for it.
* `missing_source` - a report item could not be associated with any supplied
  source fragment, so it cannot be signed off.

`VersionAudit.skipped` combines syntax, disabled-rule, inapplicable-rule, and
missing-source entries. `summary()["skipped"]` exposes the same split without
forcing one shared result across versions.

## Main entry point

```python
from dlint.scope import audit_scope

audit = audit_scope(
    sources={"app.py": source},
    report=[{"filename": "app.py", "lineno": 4, "code": "DUO105"}],
    versions=["2.7", "3.8"],
    rules=["DUO105", "DUO108"],
)

audit.for_version("2.7").eligible_items
audit.for_version("3.8").to_dict()
audit.summary()["by_version"]["3.8"]["counts"]
```

`report` accepts dictionaries, objects, Dlint result tuples, flake8 text
lines, or a payload dictionary containing `sources` and `results`.

`versions` accepts `"2.7"`, `"py38"`, `"python 3.8"`, `38`, `(3, 8)`, and
other common spellings. The audit recognises Python 2 statement syntax and
Python 3 feature gates including `async`/`await`, f-strings, variable
annotations, `yield from`, matrix operators, and the walrus operator.

## Version-specific rules

The documented applicability of `DUO101` (`< 3.3`) and `DUO108` (Python 2)
is applied automatically. Linter classes may also declare
`_python_versions`, `_min_python_version`, or `_max_python_version`. A report
item for a rule outside its range is marked `rule_not_applicable`, not
`no_findings`.

## Shared results

By default each version has its own `eligible` list. Use
`audit.common_eligible()` only when a deliberate intersection is required;
a fragment skipped by one target version is kept out of that intersection.
