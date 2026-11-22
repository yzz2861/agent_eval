"""Tests for the evidence dependency and targeted revalidation machinery."""

from __future__ import annotations

import json
import os
import sys

import pytest

from regipy.evidence import (
    ChangeSet,
    DictHive,
    EvidenceAwarePlugin,
    EvidenceKind,
    EvidenceRecorder,
    EvidenceRef,
    HiveSnapshot,
    KeyState,
    RegistryEvidenceSource,
    ValueState,
    build_evidence_report,
    build_snapshot,
    diff_snapshots,
    is_evidence_fresh,
    is_ref_stale,
    load_report,
    normalize_path,
    revalidate_report,
    save_report,
    stale_refs,
)
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "evidence_revalidation")
if EXAMPLES_DIR not in sys.path:
    sys.path.insert(0, EXAMPLES_DIR)

from demo_plugins import (  # noqa: E402
    DEMO_PLUGINS,
    RUN_KEY_PATH,
    WINSCP_SESSIONS_PATH,
    build_demo_hive,
)


def test_normalize_path_and_prefix_matching():
    assert normalize_path("software/microsoft") == r"\SOFTWARE\MICROSOFT"
    assert normalize_path(r"\A\B\\") == r"\A\B"
    from regipy.evidence.model import path_is_within

    assert path_is_within(r"\A\B\C", r"\A\B")
    assert path_is_within(r"\A\B", r"\A\B")
    assert not path_is_within(r"\A\BB", r"\A\B")


def test_evidence_ref_roundtrip_and_absence_flag():
    ref = EvidenceRef.missing_key(r"\Software\Missing")
    assert ref.is_absence
    payload = ref.to_dict()
    assert payload["kind"] == "missing_key"
    assert EvidenceRef.from_dict(payload) == ref

    value_ref = EvidenceRef.value(r"\A", "V", observed=1)
    assert not value_ref.is_absence
    assert EvidenceRef.from_dict(value_ref.to_dict()) == value_ref


def test_recorder_scopes_and_dedupe_merges_notes():
    recorder = EvidenceRecorder(plugin_name="p")
    recorder.declare_key_absent(r"\Missing")
    with recorder.entry_scope("entry-1"):
        recorder.declare_value_read(r"\A", "V", observed=1)
        recorder.declare_key_absent(r"\Missing", note="explained")

    entry_refs = recorder.evidence_for_entry("entry-1")
    missing = [ref for ref in entry_refs if ref.kind == EvidenceKind.MISSING_KEY]
    assert len(missing) == 1
    assert missing[0].note == "explained"
    assert any(ref.kind == EvidenceKind.VALUE for ref in entry_refs)

    restored = EvidenceRecorder.from_report_dict(recorder.to_report_dict())
    assert restored.entry_ids() == ["entry-1"]


def test_dict_hive_tracks_successful_and_failed_lookups():
    hive = DictHive({r"\A": {"values": {"V": {"value": 1}}}}, hive_type=NTUSER_HIVE_TYPE)
    recorder = EvidenceRecorder(plugin_name="p")
    from regipy.evidence import TrackingEvidenceSource

    source = TrackingEvidenceSource(hive, recorder)
    assert source.get_value(r"\A", "V") == 1
    with pytest.raises(RegistryKeyNotFoundException):
        source.get_key(r"\B")

    kinds = {(ref.kind, ref.key_path) for ref in recorder.all_refs}
    assert (EvidenceKind.VALUE, r"\A") in kinds
    assert (EvidenceKind.MISSING_KEY, r"\B") in kinds


def test_diff_snapshots_classifies_all_change_kinds():
    baseline = HiveSnapshot(
        {
            r"\A": KeyState(r"\A", "ts1", {"V": ValueState("V", 1, "REG_SZ")}),
            r"\Gone": KeyState(r"\Gone", "ts0", {}),
        }
    )
    supplemented = HiveSnapshot(
        {
            r"\A": KeyState(r"\A", "ts2", {"V": ValueState("V", 2, "REG_SZ"), "New": ValueState("New", 9)}),
            r"\Added": KeyState(r"\Added", "ts3", {}),
        }
    )
    change_set = diff_snapshots(baseline, supplemented)
    kinds = {change.kind for change in change_set.changes}
    assert {"key_deleted", "key_added", "key_modified", "value_added", "value_modified"} <= kinds


def test_staleness_rules_per_evidence_kind():
    change_set = ChangeSet.from_dict(
        {
            "changes": [
                {"kind": "value_modified", "key_path": r"\A", "value_name": "V"},
                {"kind": "key_added", "key_path": r"\Recovered"},
                {"kind": "key_added", "key_path": r"\Root\Child"},
            ]
        }
    )

    assert is_ref_stale(EvidenceRef.value(r"\A", "V"), change_set)
    assert not is_ref_stale(EvidenceRef.value(r"\A", "OTHER"), change_set)
    assert is_ref_stale(EvidenceRef.missing_value(r"\A", "V"), change_set)
    assert is_ref_stale(EvidenceRef.missing_key(r"\Recovered"), change_set)
    assert not is_ref_stale(EvidenceRef.missing_key(r"\Elsewhere"), change_set)
    assert is_ref_stale(EvidenceRef.subtree(r"\Root"), change_set)
    assert not is_ref_stale(EvidenceRef.subtree(r"\Other"), change_set)
    assert is_evidence_fresh([EvidenceRef.key(r"\Untouched")], change_set)
    assert stale_refs([EvidenceRef.key(r"\Untouched"), EvidenceRef.key(r"\A")], change_set)


def _baseline_report():
    hive = DictHive(build_demo_hive(), hive_type=NTUSER_HIVE_TYPE)
    return build_evidence_report(hive, DEMO_PLUGINS), hive


def test_baseline_report_carries_per_entry_evidence_and_snapshot():
    report, _ = _baseline_report()
    persistence = report["plugins"]["demo_persistence_evidence"]["entries"]
    credentials = report["plugins"]["demo_stored_credential_evidence"]["entries"]

    assert len(persistence) == 1
    refs = persistence[0]["_evidence_refs"]
    assert {ref["kind"] for ref in refs} == {"key", "value"}

    assert len(credentials) == 1
    assert credentials[0]["_evidence_refs"][0]["kind"] == "missing_key"
    assert HiveSnapshot.from_dict(report["baseline_snapshot"]).has_key(RUN_KEY_PATH)


def test_step_one_value_edit_only_revalidates_persistence_plugin(tmp_path):
    report, baseline_hive = _baseline_report()
    report_path = str(tmp_path / "report.json")
    save_report(report, report_path)

    edited = baseline_hive.apply_changes(value_changes={(RUN_KEY_PATH, "Sidebar"): "patched-command"})
    result = revalidate_report(load_report(report_path), edited, DEMO_PLUGINS, report_path=report_path)

    assert result.affected_plugins == ["demo_persistence_evidence"]
    persistence = result.plugin_results["demo_persistence_evidence"]
    credentials = result.plugin_results["demo_stored_credential_evidence"]

    assert persistence.reran is True
    assert len(persistence.revoked_entries) == 1
    assert len(persistence.refreshed_entries) == 1
    assert persistence.refreshed_entries[0]["command"] == "patched-command"
    assert credentials.reran is False
    assert len(credentials.retained_entries) == 1

    on_disk = load_report(report_path)
    assert len(on_disk["revalidation_history"]) == 1
    assert os.path.isdir(str(tmp_path / "archive"))
    archived = os.listdir(str(tmp_path / "archive"))
    assert len(archived) == 1
    archived_report = load_report(str(tmp_path / "archive" / archived[0]))
    assert "revalidation_history" not in archived_report


def test_step_two_missing_key_only_revalidates_credential_plugin(tmp_path):
    report, baseline_hive = _baseline_report()
    report_path = str(tmp_path / "report.json")
    save_report(report, report_path)

    edited = baseline_hive.apply_changes(value_changes={(RUN_KEY_PATH, "Sidebar"): "patched-command"})
    first = revalidate_report(load_report(report_path), edited, DEMO_PLUGINS, report_path=report_path)
    assert first.affected_plugins == ["demo_persistence_evidence"]

    recovered = edited.apply_changes(
        added_keys={
            WINSCP_SESSIONS_PATH: {"timestamp": "2024-02-02T00:00:00+00:00", "subkeys": ["s1"], "values": {}},
            rf"{WINSCP_SESSIONS_PATH}\s1": {"timestamp": "2024-02-02T00:00:00+00:00", "subkeys": [], "values": {}},
        }
    )
    second = revalidate_report(load_report(report_path), recovered, DEMO_PLUGINS, report_path=report_path)

    assert second.affected_plugins == ["demo_stored_credential_evidence"]
    credentials = second.plugin_results["demo_stored_credential_evidence"]
    persistence = second.plugin_results["demo_persistence_evidence"]

    assert persistence.reran is False
    assert len(persistence.retained_entries) == 1
    assert credentials.reran is True
    assert len(credentials.revoked_entries) == 1
    assert credentials.revoked_entries[0].stale_refs[0].kind == EvidenceKind.MISSING_KEY
    assert len(credentials.new_entries) == 1
    assert credentials.new_entries[0]["finding"] == "stored_session"

    final_report = load_report(report_path)
    assert len(final_report["revalidation_history"]) == 2
    assert len(os.listdir(str(tmp_path / "archive"))) == 2


def test_no_changes_means_no_revocation_and_no_reruns(tmp_path):
    report, baseline_hive = _baseline_report()
    result = revalidate_report(report, baseline_hive, DEMO_PLUGINS)
    assert result.affected_plugins == []
    assert result.revoked == []
    assert all(not plugin_result.reran for plugin_result in result.plugin_results.values())


def test_report_is_json_serializable_with_embedded_snapshot(tmp_path):
    report, _ = _baseline_report()
    path = tmp_path / "report.json"
    save_report(report, str(path))
    loaded = json.loads(path.read_text())
    assert loaded["report_version"] == 1
    assert loaded["plugins"]["demo_persistence_evidence"]["entries"][0]["_entry_id"]


def test_real_hive_adapter_snapshot_and_tracking(ntuser_hive):
    from regipy.registry import RegistryHive

    registry = RegistryHive(ntuser_hive)
    source = RegistryEvidenceSource(registry)
    snapshot = build_snapshot(source)
    assert snapshot.has_key(RUN_KEY_PATH)

    recorder = EvidenceRecorder(plugin_name="real")
    from regipy.evidence import TrackingEvidenceSource

    tracked = TrackingEvidenceSource(source, recorder)
    tracked.get_value(RUN_KEY_PATH, "Sidebar")
    assert any(ref.kind == EvidenceKind.VALUE and ref.value_name == "Sidebar" for ref in recorder.all_refs)

    with pytest.raises(RegistryKeyNotFoundException):
        tracked.get_key(r"\Definitely\Not\A\Real\Key")
    assert any(ref.kind == EvidenceKind.MISSING_KEY for ref in recorder.all_refs)


def test_real_hive_pair_diff_detects_supplemented_run_value(ntuser_hive, second_hive_path):
    from regipy.registry import RegistryHive

    baseline = build_snapshot(RegistryEvidenceSource(RegistryHive(ntuser_hive)))
    supplemented = build_snapshot(RegistryEvidenceSource(RegistryHive(second_hive_path)))
    change_set = diff_snapshots(baseline, supplemented)

    run_changes = [change for change in change_set.changes if normalize_path(change.key_path) == normalize_path(RUN_KEY_PATH)]
    assert any(change.kind == "value_added" and change.value_name == "not_a_malware" for change in run_changes)
    assert is_ref_stale(EvidenceRef.subtree(RUN_KEY_PATH), change_set)
    assert not is_ref_stale(
        EvidenceRef.value(r"\Software\Unrelated\Key", "Whatever"),
        change_set,
    )


class _LegacyPlugin(EvidenceAwarePlugin):
    NAME = "demo_legacy_compat"
    DESCRIPTION = "Accepts a plain RegistryHive-like object without an evidence source"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        self.add_evidenced_entry({"ok": True}, entry_id="legacy:1")


def test_evidence_aware_plugin_adapts_plain_dict_hive():
    hive = DictHive(build_demo_hive(), hive_type=NTUSER_HIVE_TYPE)
    plugin = _LegacyPlugin(hive)
    plugin.run()
    assert plugin.entries[0]["ok"] is True
    assert plugin.entries[0]["_entry_id"] == "legacy:1"
