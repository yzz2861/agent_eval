#
# SPDX-License-Identifier: Apache-2.0
"""Public attribution helpers for Bandit report consumers."""

from bandit.core.attribution import (  # noqa: F401
    DEFAULT_NEAR_MATCH_THRESHOLD,
    POLICY_VERSION,
    SCHEMA_VERSION,
    AttributionEngine,
    AttributionError,
    AttributionReport,
    Attributor,
    Evidence,
    attribute,
    attribute_bandit_report,
    attribute_findings,
    attribute_report,
    build_attribution,
    compute_attribution,
    load_manifest,
    load_release_manifest,
    load_manifests,
    load_release_manifests,
    main,
    resolve_attribution,
    resolve_ownership,
)

__all__ = [
    "DEFAULT_NEAR_MATCH_THRESHOLD",
    "POLICY_VERSION",
    "SCHEMA_VERSION",
    "AttributionEngine",
    "AttributionError",
    "AttributionReport",
    "Attributor",
    "Evidence",
    "attribute",
    "attribute_bandit_report",
    "attribute_findings",
    "attribute_report",
    "build_attribution",
    "compute_attribution",
    "load_manifest",
    "load_release_manifest",
    "load_manifests",
    "load_release_manifests",
    "main",
    "resolve_attribution",
    "resolve_ownership",
]


if __name__ == "__main__":
    raise SystemExit(main())
