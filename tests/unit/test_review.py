import json
import os

from cpe.cpe2_3_fs import CPE2_3_FS
from cpe.cpe2_3_uri import CPE2_3_URI
from cpe.cpe2_3_wfn import CPE2_3_WFN
from cpe.cpe2_2 import CPE2_2
from cpe.cpeset2_3 import CPESet2_3
from cpe.review import (
    ACTION_HOLD_UNKNOWN,
    ACTION_NO_REVIEW,
    ACTION_RE_REVIEW,
    CHANGE_COMPONENTS,
    CHANGE_REPRESENTATION_ONLY,
    STATUS_UNKNOWN,
    analyze,
    main,
)


SCENARIO = os.path.join(os.path.dirname(__file__), os.pardir, "rollback_review.json")


def _scenario():
    with open(SCENARIO) as stream:
        return json.load(stream)


def _device(report, device_id):
    return next(device for device in report["devices"] if device["id"] == device_id)


def _advisory(report, advisory_id):
    return next(advisory for advisory in report["advisories"]
                if advisory["id"] == advisory_id)


def test_name_match_accepts_all_cpe_2_3_bindings():
    """The name-match entry point must unbind URI/FS candidates."""

    uri = CPE2_3_URI("cpe:/a:acme:edge_agent:2.0")
    fs = CPE2_3_FS("cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*")
    wfn = CPE2_3_WFN('wfn:[part="a", vendor="acme", product="edge_agent", version="2\\.0"]')

    known = CPESet2_3()
    known.append(uri)

    assert known.name_match(fs) is True
    assert known.name_match(wfn) is True
    assert CPESet2_3.cpe_equal(uri, fs) is True
    assert CPESet2_3.cpe_equal(uri, CPE2_3_URI("cpe:/a:acme:edge_agent:1.5")) is False

    # A URI and formatted-string binding are one set member, not two.
    assert len(known) == 1
    known.append(fs)
    assert len(known) == 1


def test_cpe_2_2_to_2_3_binding_change_is_representation_only():
    report = analyze(
        approved=[CPE2_2("cpe:/a:acme:edge_agent:2.0")],
        devices=[{
            "id": "edge-legacy-binding",
            "before": [CPE2_2("cpe:/a:acme:edge_agent:2.0")],
            "after": [CPE2_3_FS("cpe:2.3:a:acme:edge_agent:2.0:*:*:*:*:*:*:*")],
        }],
        advisories=[{
            "id": "ADV-SAME",
            "type": "name",
            "cpe": CPE2_2("cpe:/a:acme:edge_agent:2.0"),
        }],
    )

    device = report["devices"][0]
    assert device["change"] == CHANGE_REPRESENTATION_ONLY
    assert device["recommendation"] == ACTION_NO_REVIEW
    assert device["approval_after"] == "approved"
    assert report["advisories"][0]["devices"]["edge-legacy-binding"]["after"] == "matched"


def test_representation_only_change_gets_no_review_ticket():
    report = analyze(_scenario())
    device = _device(report, "edge-nyc-01")

    assert device["change"] == CHANGE_REPRESENTATION_ONLY
    assert device["changed_attributes"] == []
    assert device["approved_before"] is True
    assert device["approved_after"] is True
    assert device["recommendation"] == ACTION_NO_REVIEW

    ticket = next(ticket for ticket in report["tickets"]
                  if ticket["device_id"] == "edge-nyc-01" and
                  ticket["advisory_id"] is None)
    assert ticket["action"] == ACTION_NO_REVIEW
    assert ticket["review_required"] is False


def test_real_rollback_gets_review_and_reopens_name_advisory():
    report = analyze(_scenario())
    device = _device(report, "edge-sfo-02")

    assert device["change"] == CHANGE_COMPONENTS
    assert "version" in device["changed_attributes"]
    assert device["approved_before"] is True
    assert device["approved_after"] is False
    assert device["recommendation"] == ACTION_RE_REVIEW

    advisory = _advisory(report, "ADV-EDGE-1.5")
    reentered = {entry["device_id"]: entry for entry in advisory["reentered_devices"]}
    assert "edge-sfo-02" in reentered
    assert reentered["edge-sfo-02"]["before"] == "not_matched"
    assert reentered["edge-sfo-02"]["after"] == "matched"
    assert reentered["edge-sfo-02"]["branch_sources"][0]["cpe"] == \
        "cpe:2.3:a:acme:edge_agent:1.5:*:*:*:*:*:*:*"

    assert "edge-nyc-01" not in reentered

    ticket = next(ticket for ticket in report["tickets"]
                  if ticket["device_id"] == "edge-sfo-02" and
                  ticket["advisory_id"] == "ADV-EDGE-1.5")
    assert ticket["action"] == "reopen_advisory_review"
    assert ticket["review_required"] is True


def test_language_advisory_reports_unknown_dependency_and_branch():
    report = analyze(_scenario())

    bridge = _advisory(report, "ADV-BRIDGE-AND")
    assert bridge["reentered_devices"] == []
    assert bridge["devices"]["edge-sfo-02"]["after"] == STATUS_UNKNOWN

    unknown = bridge["unknown_dependencies"]
    assert len(unknown) == 1
    assert unknown[0]["device_id"] == "edge-sfo-02"
    assert unknown[0]["stage"] == "after"
    assert unknown[0]["attributes"] == ["version"]
    assert unknown[0]["blocking"] is True

    hold_ticket = next(ticket for ticket in report["tickets"]
                       if ticket["device_id"] == "edge-sfo-02" and
                       ticket["advisory_id"] == "ADV-BRIDGE-AND")
    assert hold_ticket["action"] == ACTION_HOLD_UNKNOWN

    json_advisory = _advisory(report, "ADV-EDGE-JSON")
    branch = json_advisory["branch_sources"]["edge-sfo-02"][0]
    assert branch["vulnerable"] is True
    assert branch["operator"] == "OR"
    assert branch["path"].endswith("fact-ref[0]")


def test_cli_writes_a_report(tmp_path):
    output = tmp_path / "tickets.json"
    report = main(["--input", SCENARIO, "--output", str(output)])

    with open(str(output)) as stream:
        written = json.load(stream)

    assert written == json.loads(json.dumps(report))
    by_device = {}
    for ticket in written["tickets"]:
        if ticket["advisory_id"] is None:
            by_device[ticket["device_id"]] = ticket["action"]
    assert by_device["edge-nyc-01"] == ACTION_NO_REVIEW
    assert by_device["edge-sfo-02"] == ACTION_RE_REVIEW
