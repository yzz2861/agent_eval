# Offline allocation drill demo

This example demonstrates why remediation work must be assigned by atomic change combination rather than by vulnerability alert.

## Scenario

- `pylock.web.toml` and `pylock.worker.toml` are two consumers of one shared image, `base-python-runtime`.
- `audit-result.json` is an offline `pip-audit --format=json` result.
- `allocation-plan.toml` is the local scheduling table.
- Lin owns only the Django `4.2` version line.
- Chen owns only the `cryptography 44.0` version line.
- Riley is the only owner with `cross_environment = true` and has one slot.
- Two Django advisories are cleared together by one atomic combination.
- A separate `cryptography` combination also needs the sole cross-environment slot.

## Run

From the repository root:

```sh
python -m pip_audit \
  --audit-result examples/allocation-drill/audit-result.json \
  --allocation-plan examples/allocation-drill/allocation-plan.toml \
  --pylock examples/allocation-drill/pylock.web.toml \
  --pylock examples/allocation-drill/pylock.worker.toml
```

Use `--allocation-format json` for machine-readable output and `--allocation-check` to exit non-zero when unallocated conflict conditions remain. Use `-o FILE` to write either report to a file.

## What The Reviewer Should See

The coordinated plan assigns `django-4.2.27-shared-batch` to `cross-env-release`. That one slot covers both Django advisories in both environments because the combination is atomic and uses one shared image version decision.

The second combination, `cryptography-44.0.3-shared-batch`, cannot be assigned. The package-line group has spare capacity but cannot perform cross-environment work, while Riley's only slot is already used. The report emits a `capacity_exhausted` conflict with those details.

The alert-by-alert simulation grabs Riley for `ADV-2026-5101`, then immediately fails for `ADV-2026-5102` and `ADV-2026-5103`. It cannot infer that the first two alerts are one combination costing one slot. This is why per-alert slot grabbing understates capacity and can split a change that only works as a group.

## Plan Table Shape

The local table is TOML or JSON. The important fields are:

```toml
[[groups]]
name = "example-line"
capacity = 1
cross_environment = false
scopes = ["django@4.2"]

[[combinations]]
id = "atomic-batch"
findings = ["CVE-..."]
environments = ["web"]
slot_cost = 1

[[combinations.changes]]
package = "django"
line = "4.2"
to_version = "4.2.27"

[[shared_images]]
name = "base-image"
environments = ["web", "worker"]
packages = ["django"]
```

Shared image constraints reject different target package versions or different image tags selected for the same image. If one environment receives a managed package decision, the report also checks that all lockfile environments using that image receive the same decision.
