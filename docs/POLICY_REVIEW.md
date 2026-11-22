# Offline signing-policy review

`securesystemslib.policy_review` is a read-only, offline companion to the
DSSE signing code. It never loads private keys and never touches a network.
It answers two questions about a release policy after the real control-domain
ownership of each key has been established:

1. **Minimum satisfying domains** -- the fewest domains whose joint control
   can produce at least one complete, legal key combination. This measures
   *concentration*: a small number means few parties are enough to publish.
2. **Minimum blocking domains** -- the fewest domains whose simultaneous
   absence makes every legal combination impossible to complete. This
   measures *availability*: a small number means few outages stop a release.

Both numbers are produced by exhaustive subset search over the (small,
human-auditable) input and are reported together with the exact witness sets
and per-key domain mapping, so each result can be re-checked by hand.

## Inputs

### Policy document (`--policy`)

Lists every combination that makes a DSSE envelope a valid release. Three
rule shapes are supported and normalized into concrete key sets:

- `threshold`: any `threshold` distinct key ids from `keyids`;
- `slots`: one key id per slot, where a slot may list alternates;
- `combination`: one explicit list of required key ids.

The same key id may appear in multiple rules. Rules that expand to the same
key set are merged, and every originating rule id is retained.

```json
{
  "policy_id": "release-3of6",
  "rules": [
    {
      "rule_id": "three-of-six",
      "type": "threshold",
      "keyids": ["key-1", "key-2", "key-3", "key-4", "key-5", "key-6"],
      "threshold": 3
    }
  ]
}
```

### Roster document (`--roster`)

The frozen, authoritative statement of which control domain(s) actually hold
each key id. Every policy key id must appear exactly once. An owner is either
`confirmed` or `candidate`; candidate ownership is never silently treated as
confirmed.

```json
{
  "roster_id": "roster-shared-owner",
  "frozen_at": "2026-11-22T00:00:00+08:00",
  "keys": [
    {"keyid": "key-1", "owners": [{"domain": "domain-alpha", "status": "confirmed"}]},
    {
      "keyid": "key-2",
      "owners": [
        {"domain": "domain-bravo", "status": "candidate"},
        {"domain": "domain-charlie", "status": "candidate"}
      ]
    }
  ]
}
```

## Candidate ownership and pending ranges

When a key has candidate owners but no confirmed owner, its true home is
unknown. The tool then:

- evaluates both metrics on a *confirmed view*, using an explicit
  `UNASSIGNED-PENDING-CONFIRMATION` placeholder and emitting a warning; and
- enumerates every concrete assignment of candidate keys (up to a cap of
  100,000) and reports the min-to-max range each metric can take, keeping the
  single most concentrated and most dispersed assignments as the ranges that
  have to be confirmed or ruled out.

If the enumeration cap or the per-metric subset-search cap (1,000,000 checks)
is reached, the result is marked non-exhaustive rather than approximated.

## Running it

```bash
python -m securesystemslib.policy_review policy.json roster.json
python -m securesystemslib.policy_review policy.json roster.json --format json
python -m securesystemslib.policy_review policy.json roster.json --output report.md
```

A structural problem (unknown rule type, missing/extra roster entry, bad
JSON) exits with code `2`. Unconfirmed ownership is reported inside the
document and does not fail the run.

## Worked comparison: identical counts, different concentration

The files under `docs/policy_review_examples/` use one shared 3-of-6 policy
(`policy_3of6.json`) against two rosters with the same surface counts
(six keys, three domains, one threshold of three). Only the real ownership
differs.

| Roster | Key distribution | Min satisfying domains | Min blocking domains |
| --- | --- | --- | --- |
| `roster_balanced.json` | 2 keys per domain | 2 | 2 |
| `roster_shared_owner.json` | 4 keys on `domain-alpha`, 1 each elsewhere | 1 | 1 |

The shared-owner roster triggers an explicit finding:

> shared-owner concentration: domain `domain-alpha` alone holds every key of
> rule(s) three-of-six; one domain can satisfy the rule.

The head counts cannot distinguish the two policies; the ownership-aware
review shows that the second arrangement lets a single domain both publish a
release on its own and halt every release by being unavailable. The Markdown
report attaches the witness domains and a per-rule/per-key table so the claim
can be verified without trusting the tool.

`policy_candidate_range.json` plus `roster_candidates.json` demonstrate the
pending-confirmation range, and `policy_slots_alt.json` plus
`roster_slots.json` demonstrate slot alternates and a key reused by two rules.

## Library use

```python
from securesystemslib.policy_review import load_policy, load_roster, review
from securesystemslib.policy_review.report import report_to_dict

report = review(load_policy("policy.json"), load_roster("roster.json"))
print(report.confirmed_satisfying.value, report.confirmed_blocking.value)
data = report_to_dict(report)
```
