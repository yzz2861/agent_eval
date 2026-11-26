# -*- coding: utf-8 -*-
import io
import json
import os

import pytest

from Registry import Registry
from Registry.StructuredComparison import (
    build_registry_snapshot,
    compare_snapshots,
    compare_firewall_rules,
    load_snapshot,
    parse_firewall_rule,
    resolve_field_alias,
    snapshot_from_registry_value,
    registry_value_raw_data_offset,
)
from Registry.SecurityDescriptor import parse_security_descriptor


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAPSHOT_DIR = os.path.join(ROOT, "acceptance", "snapshots")
REPORT_PATH = os.path.join(ROOT, "acceptance", "structured-comparison-report.md")
SUMMARY_PATH = os.path.join(ROOT, "acceptance", "acceptance-summary.json")
SYSTEM_HIVE = os.path.join(ROOT, "testing", "reg_samples", "new_log_1", "SYSTEM")
FIREWALL_KEY = r"ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
SERVICE_KEY = r"ControlSet001\Services\RasMan\Security"


def snapshot(name):
    return load_snapshot(os.path.join(SNAPSHOT_DIR, name))


@pytest.mark.parametrize("filename", [
    "firewall-rule-display-name.json",
    "firewall-rule-display-description.json",
])
def test_two_display_snapshots_are_not_permission_changes(filename):
    baseline = snapshot("firewall-rule-baseline.json")
    result = compare_snapshots(baseline, snapshot(filename))

    assert result["raw_changed"] is True
    assert result["display_only"] is True
    assert result["permission_change"] is False
    assert result["security_change"] is False
    assert result["verdict"] == "display_only"
    assert result["display_changes"]


def test_security_snapshot_is_permission_change():
    baseline = snapshot("firewall-rule-baseline.json")
    result = compare_snapshots(baseline, snapshot("firewall-rule-security-action.json"))

    assert result["raw_changed"] is True
    assert result["display_only"] is False
    assert result["permission_change"] is True
    assert result["security_change"] is True
    assert result["verdict"] == "security_change"
    action_change = result["security_changes"][0]
    assert action_change["canonical"] == "action"
    assert action_change["baseline_value"] == "Allow"
    assert action_change["candidate_value"] == "Block"


def test_firewall_offsets_point_to_raw_utf16_bytes():
    parsed = parse_firewall_rule(bytes.fromhex(snapshot("firewall-rule-baseline.json")["raw_hex"]))
    action = next(field for field in parsed["fields"] if field["token"] == "Action")
    raw = bytes.fromhex(parsed["raw_hex"])

    segment = raw[action["byte_offset"]:action["byte_offset"] + action["byte_length"]]
    assert segment.decode("utf-16-le") == "Action=Allow"
    value = raw[action["value_byte_offset"]:
                action["value_byte_offset"] + action["value_byte_length"]]
    assert value.decode("utf-16-le") == "Allow"
    assert any(item["token"] == "Action" for item in parsed["raw_byte_offsets"])


def test_unknown_version_is_tracked_but_not_escalated():
    baseline = parse_firewall_rule(bytes.fromhex(snapshot("firewall-rule-baseline.json")["raw_hex"]))
    text = bytes.fromhex(baseline["raw_hex"]).decode("utf-16-le").replace("v2.22", "v2.99", 1)
    candidate = parse_firewall_rule(text.encode("utf-16-le"))

    assert candidate["known_version"] is False
    assert candidate["unknown_versions"][0]["version"] == "2.99"
    result = compare_firewall_rules(baseline, candidate)
    assert result["verdict"] == "unknown_version_change"
    assert result["permission_change"] is False
    assert result["unknown_versions"]


def test_multiple_aliases_keep_sources():
    info = resolve_field_alias("LPort")
    names = {alias["name"] for alias in info["aliases"]}

    assert info["canonical"] == "local_port"
    assert "LocalPort" in names
    assert "localport" in names
    assert all(alias.get("source") for alias in info["aliases"])
    assert info["references"]


def test_build_snapshot_directly_from_python_registry():
    reg_snapshot = build_registry_snapshot(
        SYSTEM_HIVE, FIREWALL_KEY, "WirelessDisplay-In-TCP", snapshot_id="hive")
    parsed = parse_firewall_rule(bytes.fromhex(reg_snapshot["raw_hex"]),
                                 source=reg_snapshot["source"])

    assert parsed["version"] == "2.22"
    assert parsed["source"]["generator"] == "python-registry"
    assert reg_snapshot["source"]["raw_data_byte_offset"] > 0
    luauth = next(field for field in parsed["fields"] if field["token"] == "LUAuth")
    assert luauth["category"] == "security_descriptor"
    assert luauth["security_relevant"] is True


def test_binary_security_descriptor_tracks_offsets_and_real_change():
    registry = Registry.Registry(SYSTEM_HIVE)
    value = registry.open(SERVICE_KEY).value("Security")
    raw = value.raw_data()
    base = value._vkrecord.data_offset() + 4
    parsed = parse_security_descriptor(raw, base_offset=base)

    assert parsed["known_version"] is True
    assert parsed["owner"]["sid"] == "S-1-5-18"
    assert parsed["owner"]["description"] == "Local System"
    assert parsed["owner"]["byte_offset"] == base + parsed["owner_offset"]
    assert any(alias["name"] == "SY" and alias["source"] for alias in parsed["owner"]["aliases"])

    modified = bytearray(raw)
    modified[32] ^= 0x10
    result = compare_snapshots(
        {"kind": "self_relative_security_descriptor", "raw_hex": raw.hex(), "base_byte_offset": base},
        {"kind": "self_relative_security_descriptor", "raw_hex": bytes(modified).hex(), "base_byte_offset": base},
    )
    assert result["permission_change"] is True
    assert any(change["field"] == "dacl" for change in result["changes"])


def test_unknown_security_descriptor_revision_is_reported():
    registry = Registry.Registry(SYSTEM_HIVE)
    raw = bytearray(registry.open(SERVICE_KEY).value("Security").raw_data())
    raw[0] = 9
    parsed = parse_security_descriptor(bytes(raw))
    assert parsed["known_version"] is False
    assert parsed["unknown_versions"][0]["version"] == 9


@pytest.mark.parametrize("baseline_name,candidate_name", [
    ("service-rasman-baseline.json", "service-rasman-display-name.json"),
    ("service-rasman-baseline.json", "service-rasman-display-description.json"),
])
def test_service_display_snapshots_are_display_only(baseline_name, candidate_name):
    result = compare_snapshots(snapshot(baseline_name), snapshot(candidate_name))
    assert result["verdict"] == "display_only"
    assert result["display_only"] is True
    assert result["permission_change"] is False


def test_service_dacl_snapshot_is_permission_change():
    result = compare_snapshots(
        snapshot("service-rasman-baseline.json"),
        snapshot("service-rasman-security-dacl.json"),
    )
    assert result["verdict"] == "security_change"
    assert result["permission_change"] is True
    assert result["security_descriptor_comparison"]["changes"]


@pytest.mark.parametrize("old,new,expected_verdict", [
    ("-10200", "-10299", "display_only"),
    ("-10201", "-10298", "display_only"),
    ("Action=Allow", "Action=Block", "security_change"),
])
def test_in_memory_patched_hive_snapshots(old, new, expected_verdict):
    hive_bytes = open(SYSTEM_HIVE, "rb").read()
    registry = Registry.Registry(SYSTEM_HIVE)
    key = registry.open(FIREWALL_KEY)
    value = key.value("WirelessDisplay-In-TCP")
    raw = value.raw_data()
    raw_offset = registry_value_raw_data_offset(value)
    needle = old.encode("utf-16-le")
    patch_offset = raw.find(needle)
    assert patch_offset >= 0

    patched = bytearray(hive_bytes)
    replacement = new.encode("utf-16-le")
    assert len(needle) == len(replacement)
    start = raw_offset + patch_offset
    patched[start:start + len(replacement)] = replacement

    patched_registry = Registry.Registry(io.BytesIO(bytes(patched)))
    patched_value = patched_registry.open(FIREWALL_KEY).value("WirelessDisplay-In-TCP")
    baseline = snapshot_from_registry_value(value, key_path=FIREWALL_KEY)
    candidate = snapshot_from_registry_value(patched_value, key_path=FIREWALL_KEY)
    result = compare_snapshots(baseline, candidate)

    assert result["verdict"] == expected_verdict
    assert result["raw_changed"] is True
    assert result["permission_change"] == (expected_verdict == "security_change")


def test_report_and_summary_explain_three_acceptance_snapshots():
    with open(SUMMARY_PATH, "r", encoding="utf-8") as handle:
        summary = json.load(handle)

    verdicts = [item["verdict"] for item in summary["firewall"]]
    assert verdicts == ["display_only", "display_only", "security_change"]
    assert [item["permission_change"] for item in summary["firewall"]] == [False, False, True]

    with open(REPORT_PATH, "r", encoding="utf-8") as handle:
        report = handle.read()
    assert "结构化注册表对照验收报告" in report
    assert "firewall-display-name-only" in report
    assert "firewall-display-description-only" in report
    assert "firewall-security-action-block" in report
    assert "未知版本" in report
    assert "unknown_versions" in report
    assert "LPort" in report
