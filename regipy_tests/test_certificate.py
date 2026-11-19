import json

from regipy.certificate import (
    STATUS_INPUT_SUBSTITUTED,
    STATUS_RULE_CHANGED,
    STATUS_UNRECORDED_READ,
    STATUS_VERIFIED,
    run_plugin_with_certificate,
    verify_certificate,
)
from regipy.plugins.ntuser.persistence import NTUserPersistencePlugin
from regipy.registry import RegistryHive

RUN_KEY = r"\Software\Microsoft\Windows\CurrentVersion\Run"
SIDEBAR_COMMAND = r"%ProgramFiles%\Windows Sidebar\Sidebar.exe /autoRun"


def _run_certificate(hive_path):
    plugin = NTUserPersistencePlugin(RegistryHive(hive_path), as_json=True)
    certificate = run_plugin_with_certificate(plugin)
    return certificate, plugin.entries


def _issue_codes(result):
    return {issue["code"] for issue in result.issues}


def test_certificate_verifies_without_key_changes(ntuser_hive):
    certificate, entries = _run_certificate(ntuser_hive)

    result = verify_certificate(certificate, RegistryHive(ntuser_hive))

    assert result.verified is True
    assert result.status == STATUS_VERIFIED
    assert result.issues == []
    assert result.conclusion_sha256 == certificate["conclusion"]["sha256"]
    assert entries[RUN_KEY]["values"][0]["name"] == "Sidebar"


def test_certificate_diagnoses_deleted_dependency(ntuser_hive, second_hive_path):
    certificate, _ = _run_certificate(second_hive_path)
    assert any("not_a_malware" in item["id"] for item in certificate["evidence"])

    result = verify_certificate(certificate, RegistryHive(ntuser_hive))

    assert result.verified is False
    assert result.status == STATUS_INPUT_SUBSTITUTED
    assert "evidence_missing" in _issue_codes(result)
    assert any("not_a_malware" in (issue.get("evidence_id") or "") for issue in result.issues)


def test_certificate_diagnoses_same_path_value_replacement(ntuser_hive, tmp_path):
    certificate, _ = _run_certificate(ntuser_hive)
    altered_hive = tmp_path / "NTUSER_replaced.DAT"
    hive_bytes = open(ntuser_hive, "rb").read()
    original = SIDEBAR_COMMAND.encode("utf-16-le")
    replacement = SIDEBAR_COMMAND.replace("Sidebar.exe", "Evilbar.exe").encode("utf-16-le")
    assert len(original) == len(replacement)
    assert hive_bytes.count(original) == 1
    altered_hive.write_bytes(hive_bytes.replace(original, replacement))

    result = verify_certificate(certificate, RegistryHive(str(altered_hive)))

    assert result.verified is False
    assert result.status == STATUS_INPUT_SUBSTITUTED
    assert "evidence_modified" in _issue_codes(result)
    assert any("sidebar" in (issue.get("evidence_id") or "").lower() for issue in result.issues)


def test_certificate_does_not_embed_hive_or_unrelated_values(ntuser_hive):
    certificate, _ = _run_certificate(ntuser_hive)
    serialized = json.dumps(certificate)

    assert SIDEBAR_COMMAND not in serialized
    assert len(serialized) < 100_000


def test_rule_change_is_diagnosed_separately(ntuser_hive):
    certificate, _ = _run_certificate(ntuser_hive)

    class ChangedRulePlugin(NTUserPersistencePlugin):
        CERTIFICATE_RULE_VERSION = "2"

    result = verify_certificate(certificate, RegistryHive(ntuser_hive), plugin_class=ChangedRulePlugin)

    assert result.verified is False
    assert result.status == STATUS_RULE_CHANGED
    assert "rule_version_changed" in _issue_codes(result)


def test_unrecorded_read_fails_verification(ntuser_hive):
    certificate, _ = _run_certificate(ntuser_hive)

    class ExtraReadPlugin(NTUserPersistencePlugin):
        def run(self):
            self.registry_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Explorer")
            super().run()

    result = verify_certificate(certificate, RegistryHive(ntuser_hive), plugin_class=ExtraReadPlugin)

    assert result.verified is False
    assert result.status == STATUS_UNRECORDED_READ
    assert "read_not_in_certificate" in _issue_codes(result)
    assert result.unrecorded_reads
