# Delegated role rotation windows

This example is offline: it parses two TUF `targets.json` snapshots, a
separately maintained approval-window file and already signed events.  It does
not publish metadata, create keys or verify signatures.

The sample rotates three delegated roles next month:

| role | old threshold | new threshold | approval window | requires |
| --- | ---: | ---: | --- | --- |
| `delegated-alpha` | 2 | 1 | 09:00-11:00 | - |
| `delegated-beta` | 1 | 2 | 09:20-10:35 | `delegated-alpha` |
| `delegated-gamma` | 2 | 2 | 09:10-09:50 | `delegated-alpha` |

The next version is accepted only when each role satisfies **both** contracts:
at least the old threshold and at least the new threshold.  Signatures outside
the role window are ignored.

Approval is sequential and each role needs ten minutes.  Two valid dependency
orders are evaluated:

1. `alpha -> beta -> gamma`
2. `alpha -> gamma -> beta`

Both finish with the base events.  The scenario then delays beta's signed slip
by 15 minutes.  In the first order gamma can no longer finish before 09:50, so
the report identifies `delegated-gamma` as the missing approval.  In the second
order gamma is approved before the delayed beta, so it remains feasible.

Run:

```console
python -m examples.rotation_windows.demo
```
