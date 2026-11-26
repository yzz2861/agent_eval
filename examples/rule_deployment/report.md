# Q4 Sigma Rule Deployment Review

Fill the highest-severity known detection blind spots in a single maintenance window. The corpus contains manually triaged attack drills and benign normal-operation drills. A plan is the post-change rule set; baseline rules only establish the old true-positive hits that must remain covered.

## Constraints

- Processing capacity: `4` cost units
- Rule slots: `3`
- Retain old true-positive hits: `True`
- Benign drill alert limit: `0`
- Mutual exclusion: candidates sharing a `group`, plus explicit pairs

Old true-positive hits to retain: `A1`, `A4`

## Coverage Matrix

| Case | Label | Severity | baseline:old_ps_encoded | baseline:old_ps_download | P | A | B | C | D | E |
|---|---|---|---|---|---|---|---|---|---|---|
| `A0` | malicious | critical | . | . | Y | . | . | . | . | . |
| `A1` | malicious | critical | Y | . | . | Y | Y | . | . | . |
| `A2` | malicious | critical | . | . | . | Y | . | . | . | . |
| `A3` | malicious | critical | . | . | . | . | Y | . | . | . |
| `A4` | malicious | high | . | Y | . | Y | Y | . | . | . |
| `A5` | malicious | high | . | . | . | . | . | Y | . | . |
| `A6` | malicious | critical | . | . | . | . | . | . | Y | . |
| `A7` | malicious | medium | . | . | . | . | . | . | . | Y |
| `A8` | malicious | critical | . | . | . | . | . | . | . | . |
| `A9` | malicious | high | . | . | . | . | . | . | . | . |
| `B1` | benign | low | . | . | . | . | . | . | . | . |
| `B2` | benign | low | . | . | . | . | . | . | . | . |
| `B3` | benign | low | . | . | . | . | . | . | . | . |
| `B4` | benign | low | . | . | . | . | . | . | . | . |
| `B5` | benign | low | . | . | . | . | . | . | . | . |
| `B6` | benign | low | . | . | . | . | . | . | . | . |

`baseline:*` columns are reference-only; a plan is the post-change rule set.

## Selected Deployment Plans

### Plan 1: P + A + C

- Cost: `4` / `4`
- Severity score: critical=3, high=2, medium=0, low=0
- Retention: `pass` (A1, A4)
- False positives on labelled benign drills: `0`

| Case | Label | Severity | Alert | Rules |
|---|---|---|---|---|
| `A0` | malicious | critical | Y | `P` |
| `A1` | malicious | critical | Y | `A` |
| `A2` | malicious | critical | Y | `A` |
| `A3` | malicious | critical | . | - |
| `A4` | malicious | high | Y | `A` |
| `A5` | malicious | high | Y | `C` |
| `A6` | malicious | critical | . | - |
| `A7` | malicious | medium | . | - |
| `A8` | malicious | critical | . | - |
| `A9` | malicious | high | . | - |
| `B1` | benign | low | . | - |
| `B2` | benign | low | . | - |
| `B3` | benign | low | . | - |
| `B4` | benign | low | . | - |
| `B5` | benign | low | . | - |
| `B6` | benign | low | . | - |

Replay check: `pass` (`SigmaMatcher` recomputation equals the cached alert rows).

| Uncovered case | Kind | Reason | Capable rules | Explanation |
|---|---|---|---|---|
| `A3` | constraint | mutual_exclusion | B | B matches but is exclusive (powershell-rewrite) with selected A; adding B needs 2 more capacity but only 0 remains; adding B exceeds the 3-rule slot limit (3 already selected) |
| `A6` | constraint | retention | D | D cannot be swapped in within capacity without dropping a rule that uniquely preserves a retained old hit; adding D needs 2 more capacity but only 0 remains; adding D exceeds the 3-rule slot limit (3 already selected) |
| `A7` | constraint | capacity | E | adding E needs 1 more capacity but only 0 remains; adding E exceeds the 3-rule slot limit (3 already selected) |
| `A8` | capability | no_rule_capability | - | no candidate rule's logsource/detection logic matches this event; this is a rule-capability gap |
| `A9` | capability | no_rule_capability | - | no candidate rule's logsource/detection logic matches this event; this is a rule-capability gap |

### Plan 2: P + B + C

- Cost: `4` / `4`
- Severity score: critical=3, high=2, medium=0, low=0
- Retention: `pass` (A1, A4)
- False positives on labelled benign drills: `0`

| Case | Label | Severity | Alert | Rules |
|---|---|---|---|---|
| `A0` | malicious | critical | Y | `P` |
| `A1` | malicious | critical | Y | `B` |
| `A2` | malicious | critical | . | - |
| `A3` | malicious | critical | Y | `B` |
| `A4` | malicious | high | Y | `B` |
| `A5` | malicious | high | Y | `C` |
| `A6` | malicious | critical | . | - |
| `A7` | malicious | medium | . | - |
| `A8` | malicious | critical | . | - |
| `A9` | malicious | high | . | - |
| `B1` | benign | low | . | - |
| `B2` | benign | low | . | - |
| `B3` | benign | low | . | - |
| `B4` | benign | low | . | - |
| `B5` | benign | low | . | - |
| `B6` | benign | low | . | - |

Replay check: `pass` (`SigmaMatcher` recomputation equals the cached alert rows).

| Uncovered case | Kind | Reason | Capable rules | Explanation |
|---|---|---|---|---|
| `A2` | constraint | mutual_exclusion | A | A matches but is exclusive (powershell-rewrite) with selected B; adding A needs 2 more capacity but only 0 remains; adding A exceeds the 3-rule slot limit (3 already selected) |
| `A6` | constraint | retention | D | D cannot be swapped in within capacity without dropping a rule that uniquely preserves a retained old hit; adding D needs 2 more capacity but only 0 remains; adding D exceeds the 3-rule slot limit (3 already selected) |
| `A7` | constraint | capacity | E | adding E needs 1 more capacity but only 0 remains; adding E exceeds the 3-rule slot limit (3 already selected) |
| `A8` | capability | no_rule_capability | - | no candidate rule's logsource/detection logic matches this event; this is a rule-capability gap |
| `A9` | capability | no_rule_capability | - | no candidate rule's logsource/detection logic matches this event; this is a rule-capability gap |

## Equal-Plan Tie

2 plans are tied on severity coverage, total cost, and rule count. Each plan above carries its own replayed alert rows; prefer the one whose uncovered-case explanation is operationally cheaper to accept.

## Reproduce

```bash
python -m sigma.matching.deployment examples/rule_deployment/scenario.yml \
  --coverage examples/rule_deployment/coverage_matrix.md \
  --json examples/rule_deployment/plans.json \
  --report examples/rule_deployment/report.md
```

