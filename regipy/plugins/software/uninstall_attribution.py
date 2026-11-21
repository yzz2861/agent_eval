"""Cross-hive uninstall attribution plugin.

The normal regipy plugin contract receives a single hive.  This plugin keeps
that contract for ``regipy-plugins-run`` and exposes optional keyword arguments
for callers that have a baseline snapshot and/or user hives to join.  All
inputs are hive objects; nothing here touches the live registry.
"""

from typing import Any, Optional

from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.uninstall_attribution import (
    CollectionSnapshot,
    UserHive,
    analyze_uninstall_attribution,
)


class UninstallAttributionPlugin(Plugin):
    NAME = "uninstall_attribution"
    DESCRIPTION = "Attribute uninstall records across machine/user views and two collection snapshots"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def __init__(
        self,
        registry_hive,
        as_json=False,
        trim_values=False,
        baseline_hive=None,
        user_hives=None,
        baseline_user_hives=None,
        expected_user_ids=None,
        baseline_expected_user_ids=None,
        collection_id="current",
        baseline_collection_id="baseline",
        machine_id=None,
        captured_at=None,
        baseline_captured_at=None,
        **kwargs: Any,
    ):
        super().__init__(registry_hive, as_json=as_json, trim_values=trim_values)
        self.baseline_hive = baseline_hive
        self.user_hives = user_hives
        self.baseline_user_hives = baseline_user_hives
        self.expected_user_ids = expected_user_ids
        self.baseline_expected_user_ids = baseline_expected_user_ids
        self.collection_id = collection_id
        self.baseline_collection_id = baseline_collection_id
        self.machine_id = machine_id
        self.captured_at = captured_at
        self.baseline_captured_at = baseline_captured_at
        self.report: Optional[dict[str, Any]] = None

    def run(self):
        current = CollectionSnapshot(
            collection_id=self.collection_id,
            software_hive=self.registry_hive,
            user_hives=self.user_hives or [],
            expected_user_ids=self.expected_user_ids or set(),
            machine_id=self.machine_id or "machine",
            captured_at=self.captured_at,
        )

        baseline = None
        if self.baseline_hive is not None or self.baseline_user_hives:
            baseline = CollectionSnapshot(
                collection_id=self.baseline_collection_id,
                software_hive=self.baseline_hive,
                user_hives=self.baseline_user_hives or [],
                expected_user_ids=self.baseline_expected_user_ids or set(),
                machine_id=self.machine_id or "machine",
                captured_at=self.baseline_captured_at,
            )

        report = analyze_uninstall_attribution(
            current=current,
            baseline=baseline,
            machine_id=self.machine_id,
        )
        self.report = report
        self.entries = report["attributions"]


def build_plugin_snapshot(
    software_hive,
    user_hives=None,
    expected_user_ids=None,
    collection_id: str = "current",
    machine_id: str = "machine",
) -> CollectionSnapshot:
    """Small helper for callers that already have parsed hive objects."""

    normalized_users = []
    if isinstance(user_hives, dict):
        normalized_users = [UserHive(subject_id=str(subject_id), hive=hive) for subject_id, hive in user_hives.items()]
    elif user_hives:
        normalized_users = list(user_hives)

    return CollectionSnapshot(
        collection_id=collection_id,
        software_hive=software_hive,
        user_hives=normalized_users,
        expected_user_ids=expected_user_ids or set(),
        machine_id=machine_id,
    )
