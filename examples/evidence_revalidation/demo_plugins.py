"""Example evidence-aware plugins used by the supplemental-evidence demo.

The two plugins deliberately depend on disjoint registry facts, so that each
supplemental action (an edited value, then a previously missing key) only
revalidates the conclusion whose evidence actually moved.
"""

from __future__ import annotations

from typing import Any, Dict

from regipy.evidence.plugin import EvidenceAwarePlugin
from regipy.hive_types import NTUSER_HIVE_TYPE

RUN_KEY_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Run"
WINSCP_SESSIONS_PATH = r"\Software\Martin Prikryl\WinSCP 2\Sessions"


class PersistenceEvidencePlugin(EvidenceAwarePlugin):
    """One entry per Run value; each entry depends on that exact value."""

    NAME = "demo_persistence_evidence"
    DESCRIPTION = "Run-key persistence with per-value evidence dependencies"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self) -> None:
        if not self.evidence.key_exists(RUN_KEY_PATH):
            # The whole conclusion ("no Run persistence") rests on the absence.
            self.declare_key_absent(
                RUN_KEY_PATH,
                note="Run key missing at report time; absence supports the no-persistence conclusion",
            )
            return

        run_key = self.tracked.get_key(RUN_KEY_PATH)
        for value in run_key.iter_values():
            entry_id = f"{self.NAME}:{value.name}"
            with self.entry_scope(entry_id):
                self.tracked.get_value(RUN_KEY_PATH, value.name)
            self.add_evidenced_entry(
                {
                    "value_name": value.name,
                    "command": value.value,
                    "source_key": RUN_KEY_PATH,
                },
                entry_id=entry_id,
            )


class StoredCredentialEvidencePlugin(EvidenceAwarePlugin):
    """Concludes on stored WinSCP sessions, including the negative case."""

    NAME = "demo_stored_credential_evidence"
    DESCRIPTION = "Stored session findings whose absence itself is evidence"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self) -> None:
        if not self.evidence.key_exists(WINSCP_SESSIONS_PATH):
            entry_id = f"{self.NAME}:no_sessions"
            with self.entry_scope(entry_id):
                self.declare_key_absent(
                    WINSCP_SESSIONS_PATH,
                    note="No WinSCP Sessions key; absence participates in the no-stored-credential conclusion",
                )
            self.add_evidenced_entry(
                {
                    "finding": "no_stored_sessions",
                    "source_key": WINSCP_SESSIONS_PATH,
                },
                entry_id=entry_id,
            )
            return

        self.tracked.get_key(WINSCP_SESSIONS_PATH)
        for session_name in self.tracked.iter_subkey_names(WINSCP_SESSIONS_PATH):
            session_path = rf"{WINSCP_SESSIONS_PATH}\{session_name}"
            entry_id = f"{self.NAME}:{session_name}"
            with self.entry_scope(entry_id):
                self.declare_key_read(session_path)
            self.add_evidenced_entry(
                {
                    "finding": "stored_session",
                    "session_name": session_name,
                    "source_key": session_path,
                },
                entry_id=entry_id,
            )


DEMO_PLUGINS = [PersistenceEvidencePlugin, StoredCredentialEvidencePlugin]


def build_demo_hive() -> Dict[str, Dict[str, Any]]:
    """The baseline hive: one Run value, no WinSCP Sessions key."""
    return {
        RUN_KEY_PATH: {
            "timestamp": "2024-01-01T00:00:00+00:00",
            "subkeys": [],
            "values": {
                "Sidebar": {
                    "value": r"C:\Program Files\Windows Sidebar\sidebar.exe /autoRun",
                    "value_type": "REG_SZ",
                }
            },
        }
    }
