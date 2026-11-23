import logging
from typing import Any, Optional, Union

from regipy.evidence import EvidenceTracker
from regipy.registry import RegistryHive

PLUGINS: set[type] = set()

logger = logging.getLogger(__name__)


class Plugin:
    NAME: Optional[str] = None
    DESCRIPTION: Optional[str] = None
    COMPATIBLE_HIVE: Optional[str] = None

    def __init_subclass__(cls) -> None:
        PLUGINS.add(cls)

    def __init__(self, registry_hive: RegistryHive, as_json=False, trim_values=False):
        self.registry_hive = registry_hive
        self.as_json = as_json
        self.trim_values = trim_values

        self.partial_hive_path = registry_hive.partial_hive_path

        # This variable should always hold the final result - in order to use it in anomaly detection and timeline gen.
        # Can be either a list of dicts (most plugins) or a dict (some plugins that organize by key path)
        self.entries: Union[list[dict[str, Any]], dict[str, Any]] = []

        # Records every key/value the conclusion of this run rests on, including
        # failed lookups ("absence evidence"). Used by the re-verification flow
        # (regipy.reverification) to decide whether a supplementary patch can
        # invalidate entries without re-running every plugin.
        self.evidence = EvidenceTracker(plugin_name=self.NAME or self.__class__.__name__)

    def evidence_key_read(self, key_path: str) -> int:
        """Declare that the key at ``key_path`` was read; returns its evidence index."""
        return self.evidence.record_key_read(key_path)

    def evidence_value_read(self, key_path: str, value_name: str) -> int:
        """Declare that ``value_name`` under ``key_path`` was read."""
        return self.evidence.record_value_read(key_path, value_name)

    def evidence_key_missing(self, key_path: str) -> int:
        """Declare that a key lookup failed and that absence fed the conclusion."""
        return self.evidence.record_key_missing(key_path)

    def evidence_value_missing(self, key_path: str, value_name: str) -> int:
        """Declare that a value lookup failed and that absence fed the conclusion."""
        return self.evidence.record_value_missing(key_path, value_name)

    def bind_evidence(self, entry_index: int, evidence_indices: Optional[list[int]] = None) -> None:
        """
        Attach the evidence supporting a single emitted entry. On
        re-verification, only entries whose evidence was invalidated need to
        be re-derived; without an explicit binding the whole plugin is scoped.
        """
        self.evidence.bind_entry(entry_index, evidence_indices)

    def evidence_scope(self):
        """Context manager collecting evidence consulted for a single entry."""
        return self.evidence.entry_scope()

    def can_run(self):
        """
        Whether the plugin can run or not, according to specific checks
        :return:
        """
        return self.registry_hive.hive_type == self.COMPATIBLE_HIVE

    def run(self):
        """
        Execute the plugin
        :return:
        """

    def generate_timeline_artifacts(self):
        """
        Run on the output of a plugin and generate timeline entries
        :return:
        """
        pass

    def detect_anomalies(self):
        """
        Run on the output of a plugin and detect possible anomalies
        :return:
        """
        pass
