"""Reproducible report generator: writes audit and cross-version comparison artifacts."""

from __future__ import annotations

import json
import os

from policy_audit.compare import compare_versions
from policy_audit.policy import load_policy_file
from policy_audit.report import build_report


def main() -> None:
    os.makedirs("reports", exist_ok=True)

    full_policy = load_policy_file("examples/policy_full.json")
    with open("reports/audit_full.json", "w", encoding="utf-8") as handle:
        json.dump(build_report(full_policy), handle, indent=2, ensure_ascii=False)

    restricted_policy = load_policy_file("examples/policy_restricted.json")
    with open("reports/audit_restricted.json", "w", encoding="utf-8") as handle:
        json.dump(build_report(restricted_policy), handle, indent=2, ensure_ascii=False)

    with open("examples/compare_v2_v31.json", "r", encoding="utf-8") as handle:
        spec = json.load(handle)
    comparison = compare_versions(
        versions=spec["versions"],
        canonical_metrics=spec["canonical_metrics"],
        metric_mapping=spec["metric_mapping"],
        value_mapping=spec["value_mapping"],
        canonical_domains={
            metric: tuple(values) for metric, values in spec["canonical_domains"].items()
        },
        policy=full_policy,
        baseline=spec["baseline"],
    )
    with open("reports/compare_v2_v31.json", "w", encoding="utf-8") as handle:
        json.dump(comparison.as_dict(), handle, indent=2, ensure_ascii=False)

    print("artifacts written to reports/")


if __name__ == "__main__":
    main()
