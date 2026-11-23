"""Tests for the plugin evidence-dependency interface and on-demand re-verification.

The scenario mirrors an investigator receiving a supplemental registry extract
in two steps:

1. An existing value under a persistence key is corrected. Only the conclusion
   that read that value may be re-verified; a plugin whose conclusion rests on a
   different (missing) key stays untouched.
2. The previously missing key is then supplied. Only the plugin that recorded
   the key's absence enters re-verification; the persistence plugin is no longer
   affected by this second patch.
"""

import lzma
import os
from tempfile import mktemp

import pytest

from regipy.evidence import EVIDENCE_KEY_MISSING, EVIDENCE_VALUE_READ
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.patching import AddedKeyPatch, ValueChangePatch
from regipy.plugins.ntuser.network_drives import NetworkDrivesPlugin
from regipy.plugins.ntuser.typed_urls import TypedUrlsPlugin
from regipy.plugins.plugin import Plugin
from regipy.reverification import ReverificationManager

RUN_KEY_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Run"
MISSING_EVIDENCE_PATH = r"\Software\RegipyEvidenceDemo\MissingArtifact"


class DemoPersistencePlugin(Plugin):
    """Reads a single value and declares exactly that value as evidence."""

    NAME = "demo_persistence"
    DESCRIPTION = "Evidence demo: one value-backed conclusion"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        subkey = self.registry_hive.get_key(RUN_KEY_PATH)
        with self.evidence_scope() as scope:
            self.evidence_key_read(RUN_KEY_PATH)
            sidebar = subkey.get_value("Sidebar", as_json=self.as_json)
            self.evidence_value_read(RUN_KEY_PATH, "Sidebar")
        self.entries.append({"value_name": "Sidebar", "command": sidebar})
        self.bind_evidence(len(self.entries) - 1, scope)


class DemoAbsencePlugin(Plugin):
    """Concludes "no artifact" and declares the failed lookup as evidence."""

    NAME = "demo_absence"
    DESCRIPTION = "Evidence demo: a conclusion resting on a missing key"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            self.registry_hive.get_key(MISSING_EVIDENCE_PATH)
        except Exception:
            self.evidence_key_missing(MISSING_EVIDENCE_PATH)
            self.entries.append({"artifact_present": False})
            self.bind_evidence(len(self.entries) - 1)
            return
        self.evidence_key_read(MISSING_EVIDENCE_PATH)
        self.entries.append({"artifact_present": True})
        self.bind_evidence(len(self.entries) - 1)


@pytest.fixture(scope="module")
def ntuser_path(test_data_dir):
    temp_path = mktemp()
    with open(temp_path, "wb") as tmp, lzma.open(os.path.join(test_data_dir, "NTUSER.DAT.xz")) as src:
        tmp.write(src.read())
    yield temp_path
    os.remove(temp_path)


def _run_initial(ntuser_path):
    from regipy.registry import RegistryHive

    hive = RegistryHive(ntuser_path)
    persistence = DemoPersistencePlugin(hive, as_json=True)
    absence = DemoAbsencePlugin(hive, as_json=True)
    persistence.run()
    absence.run()

    manager = ReverificationManager(hive, as_json=True)
    manager.register_run([persistence, absence])
    report = {persistence.NAME: persistence.entries, absence.NAME: absence.entries}
    return hive, manager, report, persistence, absence


def test_value_change_only_invalidates_value_dependency(ntuser_path):
    hive, manager, report, persistence, absence = _run_initial(ntuser_path)

    original_command = persistence.entries[0]["command"]
    assert original_command.startswith("%ProgramFiles%")
    assert absence.entries == [{"artifact_present": False}]

    value_patch = ValueChangePatch(
        RUN_KEY_PATH,
        "Sidebar",
        r"C:\Supplemental\Sidebar.exe /autoRun",
        value_type="REG_EXPAND_SZ",
    )

    scopes = manager.plan_invalidation([value_patch])
    assert list(scopes) == [DemoPersistencePlugin.NAME]
    scope = scopes[DemoPersistencePlugin.NAME]
    assert scope.entry_indices == [0]
    assert any("changed" in reason for reason in scope.reasons)

    result = manager.reverify([value_patch], report)
    assert result.affected_plugins == [DemoPersistencePlugin.NAME]
    assert result.unaffected_plugins == [DemoAbsencePlugin.NAME]
    assert result.new_report[DemoAbsencePlugin.NAME] == report[DemoAbsencePlugin.NAME]
    assert result.new_report[DemoPersistencePlugin.NAME][0]["command"] == r"C:\Supplemental\Sidebar.exe /autoRun"
    assert result.previous_report[DemoPersistencePlugin.NAME][0]["command"] == original_command

    bundle_path = mktemp(suffix=".json")
    try:
        result.save_report_bundle(bundle_path)
        import json

        with open(bundle_path, encoding="utf-8") as reader:
            bundle = json.load(reader)
        assert bundle["previous_report"][DemoPersistencePlugin.NAME] == report[DemoPersistencePlugin.NAME]
        assert bundle["invalidation_scopes"][DemoPersistencePlugin.NAME]["entry_indices"] == [0]
    finally:
        os.remove(bundle_path)


def test_added_key_only_invalidates_missing_key_dependency(ntuser_path):
    hive, manager, report, persistence, absence = _run_initial(ntuser_path)

    # First the value correction: only the value-backed plugin is affected.
    value_patch = ValueChangePatch(RUN_KEY_PATH, "Sidebar", "patched-command")
    first = manager.reverify([value_patch], report)
    assert first.affected_plugins == [DemoPersistencePlugin.NAME]

    # Then the previously missing key is supplied.
    added_patch = AddedKeyPatch(
        MISSING_EVIDENCE_PATH,
        values={"Indicator": "supplemental-artifact"},
        value_types={"Indicator": "REG_SZ"},
    )
    scopes = manager.plan_invalidation([added_patch])
    assert list(scopes) == [DemoAbsencePlugin.NAME]
    missing = [item for item in manager.recorded_evidence if item.kind == EVIDENCE_KEY_MISSING]
    assert len(missing) == 1
    assert missing[0].key_path == MISSING_EVIDENCE_PATH.upper()

    second = manager.reverify([added_patch], first.new_report)
    assert second.affected_plugins == [DemoAbsencePlugin.NAME]
    assert second.unaffected_plugins == [DemoPersistencePlugin.NAME]
    assert second.new_report[DemoAbsencePlugin.NAME] == [{"artifact_present": True}]
    assert second.new_report[DemoPersistencePlugin.NAME] == first.new_report[DemoPersistencePlugin.NAME]


def test_real_plugins_declare_evidence(ntuser_path):
    from regipy.registry import RegistryHive

    hive = RegistryHive(ntuser_path)

    typed_urls = TypedUrlsPlugin(hive, as_json=True)
    typed_urls.run()
    value_evidence = [item for item in typed_urls.evidence.evidence if item.kind == EVIDENCE_VALUE_READ]
    assert value_evidence, "typed_urls should declare every URL value it reads"
    assert {item.value_name for item in value_evidence} == {"URL1", "URL2"}

    network_drives = NetworkDrivesPlugin(hive, as_json=True)
    network_drives.run()
    # The test hive contains a mapped "p" drive; every emitted entry must be
    # bound to the value evidence it was derived from.
    assert network_drives.entries and network_drives.entries[0]["drive_letter"] == "p"
    value_evidence = [item for item in network_drives.evidence.evidence if item.kind == EVIDENCE_VALUE_READ]
    assert value_evidence and value_evidence[0].key_path == r"\NETWORK\P"
    assert value_evidence[0].value_name == "REMOTEPATH"
    assert value_evidence[0].entry_indices == [0]
