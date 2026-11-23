# Scope Audit

`dlint.audit` answers one question for maintenance groups that still run
different Python interpreters: **which report items is this group actually
eligible to sign off on, and which fragments did its target environment
simply skip?**

Everything is computed statically. A single Dlint report can be scoped
against any target Python version without executing the audited code or
re-running flake8 on that interpreter.

## Outcomes

Every source/rule pair resolves to exactly one of:

| Status | Meaning |
| --- | --- |
| `syntax_unsupported` | The target interpreter cannot parse the fragment, so no rule can run against it. |
| `rule_disabled` | The fragment parses, but the group's flake8-style configuration does not select this rule code. |
| `rule_inapplicable` | The rule exists, but its implementation is inert on the target Python version (for example `visit_Exec` under Python 3). |
| `unevaluable` | The target supports the syntax and the rule is enabled, but the interpreter running the audit cannot build an AST (for example auditing Python 2 syntax from a Python 3 process). It is never counted as a clean result. |
| `clean` | Syntax and rule selection are both satisfied and the rule genuinely produced no warnings. |
| `finding` | Syntax and rule selection are both satisfied and the rule fired. |

The first four are collected in `SKIP_STATUSES`; only `clean` and `finding`
are in `ELIGIBLE_STATUSES`. This keeps "syntax unsupported", "rule not
enabled", and a real "no warning" result in separate buckets instead of
merging them into one misleading zero.

## Auditing a fragment

```python
from dlint.audit import ScopeAuditor, RuleConfig

py38 = ScopeAuditor((3, 8))

verdict = py38.audit_fragment("exec('x')", code='DUO105')
verdict.outcomes[0].status  # 'finding'

# Python 2 print statement: skipped for the Python 3 group, not a clean run.
verdict = py38.audit_fragment("print 'legacy'", code='DUO105')
verdict.syntax_supported             # False
verdict.unsupported_features[0]      # {'name': 'print_statement', ...}
```

Call `audit_fragment` without a code to get one outcome per linter, or
`audit_source` for a whole file plus a `ScopeSummary` that counts each
bucket separately.

## Per-group rule configuration

`RuleConfig` mirrors flake8 prefix semantics without importing flake8, so
the audit works in environments where flake8 is not installed.

```python
config = RuleConfig(
    select=('DUO',),
    ignore=('DUO10',),          # disables the DUO10x family
    extended_default_select=(),
)
auditor = ScopeAuditor((3, 8), rule_config=config)
```

`RuleConfig.from_options(options)` accepts the same option namespace shape
that the flake8 extension uses (`select`, `ignore`,
`extended_default_select`, `extend_ignore`).

## Signing off a shared report

Each maintenance group builds its own auditor. A fragment skipped by one
target environment stays local to that group and is never forced into the
shared result.

```python
from dlint.audit import ScopeAuditor, parse_report

report = parse_report(
    "app/legacy.py:4:0: DUO105 use of \"exec\" is insecure\n"
    "app/eval.py:2:0: DUO104 use of \"eval\" is insecure\n"
)
sources = {
    'app/legacy.py': "exec 'legacy call'\n",
    'app/eval.py': "eval('1')\n",
}

py38 = ScopeAuditor((3, 8))
py27 = ScopeAuditor((2, 7))

# Each group asks for its own signable items independently.
py38.signable_report_items(report, sources)
py27.signable_report_items(report, sources)

# Per-item outcomes retain the skip reason for the audit trail.
for outcome in py38.report_item_outcomes(report, sources):
    print(outcome.code, outcome.status, outcome.reason)
```

## Version applicability

Most linters are plain AST visitors that apply on every supported
interpreter. A handful carry explicit `sys.version_info` gates and are
tracked in `dlint.audit._applicability`:

* `DUO101` only produces findings on Python 2 (early-return on Python 3.3+).
* `DUO108` only fires on Python 2.
* `DUO105` covers `exec()` calls everywhere; the bare Python 2 `exec`
  statement branch is uncovered on Python 3.

Applicability is evaluated against the **target** version, not the
interpreter running the audit, which is what lets one report serve both
maintenance groups.
