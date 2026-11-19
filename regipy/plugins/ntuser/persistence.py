import logging

from regipy.certificate import key_evidence_id, value_evidence_id
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list

logger = logging.getLogger(__name__)

PERSISTENCE_ENTRIES = [
    r"\Software\Microsoft\Windows NT\CurrentVersion\Run",
    r"\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup",
    r"\Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup",
    r"\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
]


class NTUserPersistencePlugin(Plugin):
    NAME = "ntuser_persistence"
    DESCRIPTION = "Retrieve values from known persistence subkeys in NTUSER hive"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE
    CERTIFICATE_RULE_VERSION = "1"

    def certificate_rule(self):
        return {
            "kind": "known_persistence_subkeys",
            "paths": list(PERSISTENCE_ENTRIES),
        }

    def run(self):
        self.entries = get_subkey_values_from_list(
            self.registry_hive,
            PERSISTENCE_ENTRIES,
            as_json=self.as_json,
            trim_values=False,
        )

        recorder = getattr(self, "certificate_recorder", None)
        if recorder is None:
            return

        for path in PERSISTENCE_ENTRIES:
            entry = self.entries.get(path)
            key_id = key_evidence_id(path)
            if entry is None:
                recorder.record_decision(
                    step="persistence_path",
                    outcome={"path": path, "decision": "skip", "reason": "key_missing_or_empty"},
                    evidence_ids=[key_id],
                )
                continue

            value_ids = [value_evidence_id(path, value["name"]) for value in entry["values"]]
            recorder.record_decision(
                step="persistence_path",
                outcome={
                    "path": path,
                    "decision": "include",
                    "values_count": len(entry["values"]),
                },
                evidence_ids=[key_id, *value_ids],
            )
