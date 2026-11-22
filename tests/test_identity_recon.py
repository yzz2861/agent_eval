import importlib.util
import json
import os
import subprocess
import sys

import pytest

import Evtx.Evtx as evtx


def _load_module():
    repo_root = os.path.dirname(os.path.dirname(__file__))
    module_path = os.path.join(repo_root, "evtx_scripts", "identity_recon.py")
    spec = importlib.util.spec_from_file_location("identity_recon", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


identity_recon = _load_module()

EVENT_TEMPLATE = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    "<System>"
    '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{00000000-0000-0000-0000-000000000000}}"/>'
    "<EventID>{event_id}</EventID>"
    '<TimeCreated SystemTime="{time_created}"></TimeCreated>'
    "<EventRecordID>{record_id}</EventRecordID>"
    "<Computer>{computer}</Computer>"
    "</System><EventData>{data}</EventData></Event>"
)


def _data_node(name, value):
    return '<Data Name="%s">%s</Data>' % (name, value)


def _event_xml(record_id, sid, username, domain, time_created, computer="HOST-01", event_id=4624):
    data = "".join(
        (
            _data_node("SubjectUserSid", "S-1-0-0"),
            _data_node("SubjectUserName", "-"),
            _data_node("SubjectDomainName", "-"),
            _data_node("TargetUserSid", sid if sid is not None else "-"),
            _data_node("TargetUserName", username if username is not None else "-"),
            _data_node("TargetDomainName", domain if domain is not None else "-"),
        )
    )
    return EVENT_TEMPLATE.format(
        event_id=event_id,
        time_created=time_created,
        record_id=record_id,
        computer=computer,
        data=data,
    )


@pytest.fixture
def dictionary(data_path):
    with open(os.path.join(data_path, "identity_dictionary_v1.json"), "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_parse_event_xml_reads_explicit_target_identity():
    claim = identity_recon.parse_event_xml(
        _event_xml(
            1,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "jdoe",
            "CORPNA",
            "2026-10-01T10:00:00+08:00",
        )
    )

    assert claim["sid"] == "S-1-5-21-1111111111-2222222222-3333333333-1001"
    assert claim["username"] == "jdoe"
    assert claim["domain"] == "CORPNA"
    assert claim["source_field_set"] == ("TargetUserSid", "TargetUserName", "TargetDomainName")
    assert claim["source_fields"]["TargetUserSid"].startswith("S-1-5-21-")


def test_identically_named_claims_resolve_to_distinct_domains(dictionary):
    north_america = identity_recon.parse_event_xml(
        _event_xml(
            10,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "jdoe",
            "CORPNA",
            "2026-10-01T10:00:00+08:00",
            computer="NA-DC-01",
        )
    )
    europe = identity_recon.parse_event_xml(
        _event_xml(
            11,
            "S-1-5-21-4444444444-5555555555-6666666666-1001",
            "jdoe",
            "CORPEU",
            "2026-10-02T10:00:00+08:00",
            computer="EU-DC-01",
        )
    )

    assert north_america["username"] == europe["username"] == "jdoe"
    assert north_america["sid"] != europe["sid"]

    review_na = identity_recon.reconcile_claim(north_america, dictionary)
    review_eu = identity_recon.reconcile_claim(europe, dictionary)

    assert review_na["status"] == identity_recon.STATUS_CONFIRMED
    assert review_eu["status"] == identity_recon.STATUS_CONFIRMED
    assert review_na["matched_registration"]["domain"] == "CORPNA"
    assert review_eu["matched_registration"]["domain"] == "CORPEU"
    assert review_na["matched_registration"]["sid"] != review_eu["matched_registration"]["sid"]


def test_claim_without_sid_stays_pending_and_keeps_source_fields(dictionary):
    claim = identity_recon.parse_event_xml(
        _event_xml(20, None, "jdoe", "CORPNA", "2026-10-01T10:00:00+08:00")
    )
    result = identity_recon.reconcile_claim(claim, dictionary)

    assert result["status"] == identity_recon.STATUS_NO_SID
    assert result["claimed_sid"] is None
    assert result["claimed_username"] == "jdoe"
    assert result["evidence"][0]["type"] == "username_only"
    assert result["source_fields"]["TargetUserName"] == "jdoe"


def test_event_newer_than_dictionary_is_stale(dictionary):
    claim = identity_recon.parse_event_xml(
        _event_xml(
            30,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "jdoe",
            "CORPNA",
            "2026-12-01T10:00:00+08:00",
        )
    )
    result = identity_recon.reconcile_claim(claim, dictionary)

    assert result["status"] == identity_recon.STATUS_DICTIONARY_STALE
    assert result["matched_registration"] is None
    assert result["evidence"][0]["dictionary_version"] == "v1"


def test_stale_dictionary_check_respects_timezone_offsets(dictionary):
    claim = identity_recon.parse_event_xml(
        _event_xml(
            31,
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "jdoe",
            "CORPNA",
            "2026-10-31T17:30:00+00:00",
        )
    )
    result = identity_recon.reconcile_claim(claim, dictionary)

    # 2026-10-31 17:30 UTC == 2026-11-01 01:30 +08:00, i.e. after the snapshot.
    assert result["status"] == identity_recon.STATUS_DICTIONARY_STALE


def test_conflicting_registrations_for_one_sid_remain_pending():
    dictionary = {
        "version": "v-conflict",
        "generated_at": "2026-11-01T00:00:00+08:00",
        "accounts": [
            {"sid": "S-1-5-21-9-9-9-1009", "username": "shared", "domain": "DOMA"},
            {"sid": "S-1-5-21-9-9-9-1009", "username": "shared", "domain": "DOMB"},
        ],
    }
    claim = identity_recon.parse_event_xml(
        _event_xml(40, "S-1-5-21-9-9-9-1009", "shared", "DOMA", "2026-10-01T10:00:00+08:00")
    )
    result = identity_recon.reconcile_claim(claim, dictionary)

    assert result["status"] == identity_recon.STATUS_CONFLICT
    assert len(result["candidate_registrations"]) == 2
    assert result["evidence"][0]["type"] == "conflicting_registrations"
    assert result["source_fields"]["TargetUserSid"] == "S-1-5-21-9-9-9-1009"


def test_expired_registration_does_not_match(dictionary):
    claim = identity_recon.parse_event_xml(
        _event_xml(
            50,
            "S-1-5-21-7777777777-8888888888-9999999999-1003",
            "archive",
            "CORPNA",
            "2026-10-01T10:00:00+08:00",
        )
    )
    result = identity_recon.reconcile_claim(claim, dictionary)

    assert result["status"] == identity_recon.STATUS_UNKNOWN_SID


def test_unregistered_sid_stays_pending(dictionary):
    claim = identity_recon.parse_event_xml(
        _event_xml(
            60,
            "S-1-5-21-0000000000-0000000000-0000000000-9999",
            "ghost",
            "CORPNA",
            "2026-10-01T10:00:00+08:00",
        )
    )
    result = identity_recon.reconcile_claim(claim, dictionary)

    assert result["status"] == identity_recon.STATUS_UNKNOWN_SID
    assert result["evidence"][0]["sid"] == claim["sid"]


def test_review_runs_on_real_security_evtx(data_path, dictionary):
    results = identity_recon.review(os.path.join(data_path, "security.evtx"), dictionary)
    summary = identity_recon.summarize(results)

    assert summary["total"] == len(results)
    expected_pending = sum(summary.get(status, 0) for status in identity_recon.PENDING_STATUSES)
    assert summary["pending_total"] == expected_pending
    for result in results:
        assert result["dictionary_version"] == "v1"
        assert "source_fields" in result


def test_security_evtx_contains_parseable_sid_claims(data_path):
    with evtx.Evtx(os.path.join(data_path, "security.evtx")) as log:
        record_count = sum(1 for _ in log.records())

    with evtx.Evtx(os.path.join(data_path, "security.evtx")) as log:
        claims = [identity_recon.parse_event_xml(record.xml()) for record in log.records()]

    assert len(claims) == record_count
    assert any(claim["sid"] is not None for claim in claims)


def test_cli_writes_json_report(data_path, tmp_path):
    evtx_path = os.path.join(data_path, "security.evtx")
    dictionary_path = os.path.join(data_path, "identity_dictionary_v1.json")
    output_path = tmp_path / "report.json"
    script_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "evtx_scripts", "identity_recon.py"
    )

    subprocess.run(
        [sys.executable, script_path, evtx_path, dictionary_path, "-o", str(output_path)],
        check=True,
    )

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["dictionary_version"] == "v1"
    assert report["summary"]["total"] == len(report["records"])
