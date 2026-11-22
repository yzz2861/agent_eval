import json
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from detect_secrets.audit.audience import AudienceLedger
from detect_secrets.audit.audience import AudienceMismatchError
from detect_secrets.audit.audience import CrossAudienceLinkError
from detect_secrets.audit.audience import ReportLeakError
from detect_secrets.audit.audience import export_report
from detect_secrets.audit.audience import link_reports
from detect_secrets.audit.audience import renew_audience
from detect_secrets.audit.audience import transfer_audience_scope
from detect_secrets.audit.audience import verify_report


T0 = datetime(2026, 11, 20, tzinfo=timezone.utc)
WEEK = timedelta(days=7)
T1 = T0 + WEEK
T2 = T1 + WEEK

RAW_A = "raw-secret-a"
RAW_B = "raw-secret-b"
HASH_A = "a" * 40
HASH_B = "b" * 40
HASH_C = "c" * 40


@pytest.fixture
def source():
    return {
        "results": {
            "dept_a/app.py": [
                {
                    "type": "Secret Keyword",
                    "hashed_secret": HASH_A,
                    "is_secret": True,
                    "line_number": 3,
                    "secrets": RAW_A,
                    "lines": {3: "token = " + RAW_A},
                },
            ],
            "dept_a/config.py": [
                {
                    "type": "Secret Keyword",
                    "hashed_secret": HASH_B,
                    "is_secret": False,
                    "line_number": 2,
                    "secrets": RAW_B,
                },
            ],
            "dept_b/service.py": [
                {
                    "type": "AWS Access Key",
                    "hashed_secret": HASH_C,
                    "is_secret": True,
                    "line_number": 5,
                    "secrets": "AKIAEXAMPLE",
                },
            ],
            "dept_b/unverified.py": [
                {
                    "type": "Secret Keyword",
                    "hashed_secret": "d" * 40,
                    "is_secret": None,
                    "line_number": 1,
                },
            ],
        },
    }


def period(audience, name, start, end, files, **kwargs):
    if end is None:
        end = start + WEEK - timedelta(seconds=1)
    return {
        "audience": audience,
        "period": name,
        "not_before": start,
        "not_after": end,
        "filenames": files,
        **kwargs,
    }


def ledger_for(source, master_key=b"test-master-key"):
    return AudienceLedger(
        [
            period("partner-a", "p1", T0, T1, ["dept_a"]),
            period("partner-b", "p1", T0, T1, ["dept_b"]),
        ],
        master_key=master_key,
        clock=lambda: T0 + timedelta(days=1),
    )


def test_export_only_contains_the_audience_scope(source):
    ledger = ledger_for(source)
    report = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))

    assert {entry["filename"] for entry in report["results"]} == {
        "dept_a/app.py",
        "dept_a/config.py",
    }
    assert report["findings"] == report["results"]
    assert all("secrets" not in entry for entry in report["results"])
    assert all("hashed_secret" not in entry for entry in report["results"])
    assert all("line_numbers" in entry for entry in report["results"])


def test_export_never_leaks_secret_or_stable_digest(source):
    ledger = ledger_for(source)
    report = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    rendered = json.dumps(report, sort_keys=True)

    assert RAW_A not in rendered
    assert RAW_B not in rendered
    assert HASH_A not in rendered
    assert HASH_B not in rendered
    assert HASH_C not in rendered
    assert verify_report(report, ledger, source=source, at=T0 + timedelta(days=1))


def test_alias_is_stable_when_resent_inside_the_period(source):
    ledger = ledger_for(source)
    first = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    second = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=6))

    assert first == second
    assert {entry["alias"] for entry in first["results"]} == {
        entry["alias"] for entry in second["results"]
    }


def test_unverified_findings_are_not_exported_by_default(source):
    ledger = ledger_for(source)
    report = export_report(source, ledger, "partner-b", at=T0 + timedelta(days=1))
    assert [entry["filename"] for entry in report["results"]] == ["dept_b/service.py"]


def test_aliases_cannot_be_merged_across_audiences(source):
    ledger = ledger_for(source)
    report_a = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    report_b = export_report(source, ledger, "partner-b", at=T0 + timedelta(days=1))

    aliases_a = {entry["alias"] for entry in report_a["results"]}
    aliases_b = {entry["alias"] for entry in report_b["results"]}
    assert aliases_a.isdisjoint(aliases_b)
    assert link_reports(report_a, report_b, ledger) == {}


def test_renewal_links_to_previous_report_while_retained(source):
    ledger = ledger_for(source)
    first = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    renew_audience(ledger, "partner-a", "p2", not_before=T1, not_after=T2 - timedelta(seconds=1))

    renewed = export_report(
        source,
        ledger,
        "partner-a",
        at=T1 + timedelta(days=1),
        previous_report=first,
    )
    links = link_reports(first, renewed, ledger, "partner-a", at=T1 + timedelta(days=1))

    assert len(links) == len(renewed["results"])
    for entry in renewed["results"]:
        assert entry["previous_alias"] in {
            previous["alias"] for previous in first["results"]
        }
        assert links[entry["alias"]] == entry["previous_alias"]


def test_renewal_link_disappears_after_retention(source):
    ledger = ledger_for(source)
    first = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    renew_audience(ledger, "partner-a", "p2", not_before=T1, not_after=T2 + WEEK)

    renewed = export_report(
        source,
        ledger,
        "partner-a",
        at=T2 + timedelta(days=2),
        previous_report=first,
    )
    assert all("previous_alias" not in entry for entry in renewed["results"])
    assert link_reports(first, renewed, ledger, "partner-a", at=T2 + timedelta(days=2)) == {}


def test_audience_swap_retires_old_alias_and_rotates_target_alias(source):
    ledger = ledger_for(source)
    report_a = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    report_b = export_report(source, ledger, "partner-b", at=T0 + timedelta(days=1))

    transfer_audience_scope(
        ledger,
        "partner-a",
        "partner-b",
        ["dept_a/config.py"],
        new_period="p2",
        not_before=T1,
        not_after=T2 - timedelta(seconds=1),
        retention=WEEK,
    )

    moved_a = export_report(
        source, ledger, "partner-a", at=T1 + timedelta(days=1), previous_report=report_a,
    )
    moved_b = export_report(
        source, ledger, "partner-b", at=T1 + timedelta(days=1), previous_report=report_b,
    )

    old_alias = next(
        entry["alias"]
        for entry in report_a["results"]
        if entry["filename"] == "dept_a/config.py"
    )
    new_alias = next(
        entry["alias"]
        for entry in moved_b["results"]
        if entry["filename"] == "dept_a/config.py"
    )

    assert old_alias != new_alias
    assert old_alias in moved_a["retired_aliases"]
    assert all(entry["alias"] != old_alias for entry in moved_b["results"])
    assert all(
        "previous_alias" not in entry
        for entry in moved_b["results"]
        if entry["filename"] == "dept_a/config.py"
    )
    assert link_reports(report_a, moved_b, ledger, "partner-b") == {}


def test_finding_removed_from_scope_is_retired(source):
    ledger = ledger_for(source)
    report_a = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))

    ledger.add(
        period(
            "partner-a",
            "p2",
            T1,
            T2,
            ["dept_a/app.py"],
            previous_period="p1",
            previous_audience="partner-a",
        ),
    )
    reduced = export_report(
        source, ledger, "partner-a", at=T1 + timedelta(days=1), previous_report=report_a,
    )

    assert [entry["filename"] for entry in reduced["results"]] == ["dept_a/app.py"]
    assert len(reduced["retired"]) == 1
    assert reduced["retired"][0]["filename"] == "dept_a/config.py"


def test_verify_report_rejects_forbidden_fields(source):
    ledger = ledger_for(source)
    report = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    report["results"][0]["hashed_secret"] = HASH_A
    with pytest.raises(ReportLeakError):
        verify_report(report)


def test_renewed_report_is_stable_when_resent(source):
    ledger = ledger_for(source)
    first = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    renew_audience(ledger, "partner-a", "p2", not_before=T1, not_after=T2 - timedelta(seconds=1))
    renewed = export_report(
        source, ledger, "partner-a", at=T1 + timedelta(days=1), previous_report=first,
    )
    again = export_report(
        source, ledger, "partner-a", at=T1 + timedelta(days=2), previous_report=renewed,
    )

    assert renewed == again
    assert all(entry.get("previous_alias") for entry in again["results"])


def test_scope_change_within_period_keeps_retired_aliases_on_resend(source):
    ledger = ledger_for(source)
    first = export_report(source, ledger, "partner-a", at=T0 + timedelta(days=1))
    ledger.add(
        period(
            "partner-a",
            "p1b",
            T0,
            T1,
            ["dept_a/app.py"],
            previous_period="p1",
            previous_audience="partner-a",
        ),
    )
    reduced = export_report(
        source, ledger, "partner-a", at=T0 + timedelta(days=2), previous_report=first,
    )
    again = export_report(
        source, ledger, "partner-a", at=T0 + timedelta(days=3), previous_report=reduced,
    )

    assert reduced == again
    assert len(again["retired_aliases"]) == 1
