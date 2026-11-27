import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from tools.pcap_evidence import read_arp_bindings, read_dhcp_acks
from tools.retired_address_audit import build_report, main


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "retired_addresses"


def _fixture_paths():
    return {
        "ticket": "tests/fixtures/retired_addresses/ticket.json",
        "preservation": "tests/fixtures/retired_addresses/preservation.json",
        "handover": ["tests/fixtures/retired_addresses/handovers.jsonl"],
        "dhcp": ["tests/fixtures/retired_addresses/dhcp-east.pcap"],
        "arp": ["tests/fixtures/retired_addresses/arp-east.pcap"],
        "coverage": "tests/fixtures/retired_addresses/coverage.json",
    }


def _build_fixture_report(monkeypatch):
    monkeypatch.chdir(ROOT)
    paths = _fixture_paths()
    return build_report(
        ticket_path=paths["ticket"],
        preservation_path=paths["preservation"],
        handover_paths=paths["handover"],
        dhcp_paths=paths["dhcp"],
        arp_paths=paths["arp"],
        coverage_path=paths["coverage"],
    )


def _compact(report):
    compact = {
        "as_of": report["as_of"],
        "summary": report["summary"],
        "control_plane_gaps": report["control_plane_gaps"],
        "addresses": [],
    }
    for address in report["addresses"]:
        compact["addresses"].append(
            {
                "address": address["address"],
                "site": address["site"],
                "legacy_device": address["legacy_device"],
                "verdict": address["verdict"],
                "confidence": address["confidence"],
                "supporting_records": [
                    entry["record_id"] for entry in address["supporting_records"]
                ],
                "absent_records": [
                    {
                        "kind": entry["kind"],
                        "impact": entry["impact"],
                        "capture": entry["observation"]["status"],
                    }
                    for entry in address["absent_records"]
                ],
                "conflicts": [entry.get("kind", "") for entry in address["conflicting_records"]],
            }
        )
    return compact


def test_fixture_matches_frozen_verdicts(monkeypatch):
    report = _build_fixture_report(monkeypatch)
    expected = json.loads((FIXTURES / "expected_verdicts.json").read_text(encoding="utf-8"))
    assert _compact(report) == expected


def test_scenario_semantics(monkeypatch):
    report = _build_fixture_report(monkeypatch)
    by_address = {item["address"]: item for item in report["addresses"]}

    reused = by_address["10.20.0.10"]
    assert reused["verdict"] == "new_device"
    assert reused["confidence"] == "high"
    assert "dhcp:dhcp-east.pcap:1" in reused["basis"]
    assert "arp:arp-east.pcap:0:sender" in reused["basis"]
    assert any(item["kind"] == "lease_overlap" for item in reused["conflicting_records"])
    assert any(
        event["record_id"] == "dhcp:dhcp-east.pcap:0" for event in reused["context_records"]
    )

    still_old = by_address["10.20.0.11"]
    assert still_old["verdict"] == "old_device"
    assert still_old["confidence"] == "high"
    assert any(entry["kind"] == "handover" for entry in still_old["absent_records"])

    unknown = by_address["10.20.0.12"]
    assert unknown["verdict"] == "in_use_only"
    assert "00:aa:bb:cc:dd:ee" in " ".join(unknown["caveats"])
    assert any(entry["kind"] == "known_device_binding" for entry in unknown["absent_records"])

    lost_west = by_address["10.30.0.20"]
    assert lost_west["verdict"] == "new_device"
    assert lost_west["confidence"] == "low"
    assert lost_west["basis"] == ["HO-002"]
    lost_observations = [
        entry for entry in lost_west["absent_records"] if entry["observation"]["status"] == "lost"
    ]
    assert lost_observations
    assert all(entry["impact"] == "weakens_conclusion" for entry in lost_observations)
    assert any("west collector outage" in caveat for caveat in lost_west["caveats"])


def test_pcap_extraction_uses_lease_and_arp_semantics():
    dhcp = read_dhcp_acks([str(FIXTURES / "dhcp-east.pcap")])
    assert [record.address for record in dhcp] == ["10.20.0.10", "10.20.0.10", "10.20.0.11"]
    assert dhcp[0].client_mac == "00:1a:2b:3c:4d:01"
    assert dhcp[0].lease_seconds == 30 * 24 * 3600
    assert dhcp[1].client_mac == "00:1a:2b:3c:4d:11"
    assert dhcp[1].lease_end.isoformat() == "2026-12-03T02:00:00+00:00"

    bindings = read_arp_bindings([str(FIXTURES / "arp-east.pcap")])
    sender_bindings = [binding for binding in bindings if binding.role == "sender"]
    assert [(binding.ip, binding.mac) for binding in sender_bindings] == [
        ("10.20.0.10", "00:1a:2b:3c:4d:11"),
        ("10.20.0.11", "00:1a:2b:3c:4d:01"),
        ("10.20.0.12", "00:aa:bb:cc:dd:ee"),
    ]
    assert all(binding.ip == "10.20.0.1" for binding in bindings if binding.role == "target")


def test_inputs_are_not_modified(monkeypatch):
    root = ROOT
    paths = [
        root / "tests/fixtures/retired_addresses/ticket.json",
        root / "tests/fixtures/retired_addresses/preservation.json",
        root / "tests/fixtures/retired_addresses/handovers.jsonl",
        root / "tests/fixtures/retired_addresses/dhcp-east.pcap",
        root / "tests/fixtures/retired_addresses/arp-east.pcap",
        root / "tests/fixtures/retired_addresses/coverage.json",
    ]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    _build_fixture_report(monkeypatch)
    after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    assert before == after


def _load_fixture_builder():
    path = FIXTURES / "build_pcaps.py"
    spec = importlib.util.spec_from_file_location("fixture_build_pcaps", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_scenario(tmp_path, ticket, preservation, handovers, dhcp_packets=(), arp_packets=()):
    ticket_path = tmp_path / "ticket.json"
    preservation_path = tmp_path / "preservation.json"
    handover_path = tmp_path / "handovers.jsonl"
    ticket_path.write_text(json.dumps(ticket), encoding="utf-8")
    preservation_path.write_text(json.dumps(preservation), encoding="utf-8")
    handover_path.write_text(
        "\n".join(json.dumps(record) for record in handovers) + "\n", encoding="utf-8"
    )
    builder = _load_fixture_builder()
    dhcp_path = tmp_path / "dhcp.pcap"
    arp_path = tmp_path / "arp.pcap"
    builder.write_pcap(dhcp_path, dhcp_packets)
    builder.write_pcap(arp_path, arp_packets)
    return {
        "ticket": str(ticket_path),
        "preservation": str(preservation_path),
        "handover": [str(handover_path)],
        "dhcp": [str(dhcp_path)],
        "arp": [str(arp_path)],
    }


def _scenario_parts():
    old_mac = "00:1a:2b:3c:4d:01"
    new_mac = "00:1a:2b:3c:4d:11"
    ticket = {
        "ticket_id": "T-1",
        "devices": [
            {
                "device_id": "old",
                "name": "OLD",
                "site": "east",
                "mac": old_mac,
                "decommissioned_at": "2026-11-01T00:00:00Z",
                "role": "old",
            }
        ],
        "new_devices": [
            {"device_id": "new", "name": "NEW", "site": "east", "mac": new_mac, "role": "new"}
        ],
    }
    preservation = {
        "file_id": "P-1",
        "recorded_at": "2026-11-25T00:00:00Z",
        "addresses": [
            {
                "record_id": "P-001",
                "address": "10.0.0.10",
                "site": "east",
                "legacy_device": "old",
                "legacy_mac": old_mac,
            }
        ],
    }
    handover = [
        {
            "record_id": "HO-1",
            "at": "2026-11-03T00:00:00Z",
            "site": "east",
            "address": "10.0.0.10",
            "from_device": "old",
            "to_device": "new",
            "to_mac": new_mac,
        }
    ]
    return ticket, preservation, handover, old_mac, new_mac


def test_crossing_legacy_lease_without_new_ack_stays_old(tmp_path):
    ticket, preservation, handover, old_mac, _new_mac = _scenario_parts()
    builder = _load_fixture_builder()
    ack = (
        builder.ts("2026-10-29T00:00:00Z"),
        builder.dhcp_ack(old_mac, "10.0.0.10", 30 * 24 * 3600, 1, "10.0.0.1"),
    )
    paths = _write_scenario(tmp_path, ticket, preservation, handover, dhcp_packets=[ack])
    report = build_report(
        ticket_path=paths["ticket"],
        preservation_path=paths["preservation"],
        handover_paths=paths["handover"],
        dhcp_paths=paths["dhcp"],
        arp_paths=paths["arp"],
    )
    result = report["addresses"][0]
    assert result["verdict"] == "old_device"
    assert any("租期" in entry["why"] for entry in result["supporting_records"])


def test_unknown_mac_after_handover_downgrades_to_in_use_only(tmp_path):
    ticket, preservation, handover, _old_mac, _new_mac = _scenario_parts()
    builder = _load_fixture_builder()
    arp = (
        builder.ts("2026-11-04T00:00:00Z"),
        builder.arp_reply("00:aa:bb:cc:dd:ee", "10.0.0.10", "00:1a:2b:3c:4d:fe", "10.0.0.1"),
    )
    paths = _write_scenario(tmp_path, ticket, preservation, handover, arp_packets=[arp])
    report = build_report(
        ticket_path=paths["ticket"],
        preservation_path=paths["preservation"],
        handover_paths=paths["handover"],
        dhcp_paths=paths["dhcp"],
        arp_paths=paths["arp"],
    )
    result = report["addresses"][0]
    assert result["verdict"] == "in_use_only"
    assert any(item.get("role") == "conflict" for item in result["conflicting_records"])


def test_arp_request_target_is_not_a_binding(tmp_path):
    builder = _load_fixture_builder()
    pcap_path = tmp_path / "request.pcap"
    builder.write_pcap(
        pcap_path,
        [
            (
                builder.ts("2026-11-03T00:00:00Z"),
                builder.arp_request("00:1a:2b:3c:4d:fe", "10.0.0.1", "10.0.0.10"),
            )
        ],
    )
    bindings = read_arp_bindings([str(pcap_path)])
    assert [(binding.ip, binding.role) for binding in bindings] == [("10.0.0.1", "sender")]


def test_cli_json_output_and_fail_on_old(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    paths = _fixture_paths()
    argv = [
        "--ticket",
        paths["ticket"],
        "--preservation",
        paths["preservation"],
        "--handover",
        paths["handover"][0],
        "--dhcp-pcap",
        paths["dhcp"][0],
        "--arp-pcap",
        paths["arp"][0],
        "--coverage",
        paths["coverage"],
    ]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert json.loads(output)["summary"]["old_device"] == 1
    assert main(argv + ["--fail-on-old"]) == 2


def test_cli_refuses_to_overwrite_input(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    paths = _fixture_paths()
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--ticket",
                paths["ticket"],
                "--preservation",
                paths["preservation"],
                "--output",
                paths["ticket"],
            ]
        )
    assert excinfo.value.code == 2
