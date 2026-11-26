from __future__ import absolute_import, print_function

import json
import os

import pytest

import defusedxml.ElementTree as DefusedET
from defusedxml.common import DTDForbidden

import approval_quota as aq


FIXTURE = aq.parse_fixture()
HERE = os.path.dirname(os.path.abspath(__file__))


def test_nested_fixture_is_normal_offline_xml():
    document = aq.parse_approval(FIXTURE)

    assert document.job_id == "JOB-QUOTA-039"
    assert document.budget == 100
    assert [item.subtask_id for item in document.subtasks] == [
        "subtask-review",
        "subtask-verify",
        "subtask-release",
        "subtask-archive",
    ]
    assert all(item.quota == 25 for item in document.subtasks)
    assert document.declaration is not None


def test_xml_entry_rejects_dtd_and_keeps_parsing_offline():
    xml = """<?xml version="1.0"?>
    <!DOCTYPE approval [<!ENTITY offline "value">]>
    <approval job-id="j" quota="10"><subtask id="a" quota="1"/></approval>
    """
    with pytest.raises(DTDForbidden):
        aq.parse_approval(xml)


def test_two_entries_share_job_quota_and_retry_keeps_others_reserved():
    coordinator = aq.QuotaCoordinator()
    service = aq.ApprovalQuotaService(coordinator)

    parent_ledger = service.accept_approval(FIXTURE)
    declaration_document = aq.parse_declaration(
        DefusedET.tostring(aq.parse_approval(FIXTURE).declaration, encoding="unicode")
    )
    declaration_ledger = service.accept_document(declaration_document)

    assert declaration_ledger is parent_ledger
    assert parent_ledger.budget == 100
    assert parent_ledger.reserved == 100
    assert parent_ledger.available == 0
    assert len(parent_ledger.subtasks) == 4
    assert sum(event["action"] == "quota_reserved" for event in parent_ledger.events) == 4
    assert sum(event["action"] == "reservation_replayed" for event in parent_ledger.events) == 4

    rejected = parent_ledger.try_reserve("subtask-overflow", 1)
    assert rejected.ok is False
    assert rejected.status == aq.INSUFFICIENT_BUDGET
    assert "subtask-overflow" not in parent_ledger.subtasks
    with pytest.raises(aq.BudgetInsufficientError):
        parent_ledger.reserve("subtask-overflow", 1)

    # The first attempts have already consumed five units each.  Retrying them
    # must inherit that usage and the remaining hold instead of counting quota
    # from zero or reserving a second full slice.
    parent_ledger.spend("subtask-review", 5)
    parent_ledger.spend("subtask-verify", 5)
    parent_ledger.fail("subtask-review", "transient parser failure")
    parent_ledger.fail("subtask-verify", "transient adapter failure")
    review_retry = parent_ledger.retry("subtask-review")
    verify_retry = parent_ledger.retry("subtask-verify")

    assert review_retry.status == aq.RETRYING
    assert verify_retry.changes["inherited_used"] == 5
    assert parent_ledger.consumed == 10
    assert parent_ledger.reserved == 90
    assert parent_ledger.available == 0
    assert parent_ledger.reservation_for("subtask-review") == 25
    assert parent_ledger.quota_for("subtask-review") == 20
    assert parent_ledger.quota_for("subtask-verify") == 20
    assert parent_ledger.quota_for("subtask-release") == 25
    assert parent_ledger.quota_for("subtask-archive") == 25
    assert parent_ledger.quota_left_for_other_subtasks(["subtask-review", "subtask-verify"]) == 50

    # Normal completion settles the real total usage and closes the hold.
    completed = parent_ledger.complete("subtask-review", actual=25)
    assert completed.status == aq.COMPLETED
    assert parent_ledger.subtasks["subtask-review"].used == 25
    assert parent_ledger.quota_for("subtask-review") == 0

    # Cancellation closes the remaining hold; usage already incurred remains
    # auditable unless the caller explicitly restores it.
    cancelled = parent_ledger.cancel("subtask-verify")
    assert cancelled.status == aq.CANCELLED
    assert cancelled.changes["released"] == 20
    assert parent_ledger.consumed == 30
    assert parent_ledger.reserved == 50
    assert parent_ledger.available == 20
    assert parent_ledger.protected_quota_for_other_subtasks() == 50
    assert parent_ledger.quota_left_for_other_subtasks() == 70
    assert parent_ledger.quota_left_for_other_subtasks(include_available=False) == 50

    still_rejected = parent_ledger.try_reserve("subtask-too-large", 21)
    assert still_rejected.status == aq.BUDGET_INSUFFICIENT
    accepted = parent_ledger.try_reserve("subtask-fill-free-budget", 20)
    assert accepted.ok is True
    assert parent_ledger.available == 0
    assert parent_ledger.quota_for("subtask-release") == 25
    assert parent_ledger.quota_for("subtask-archive") == 25
    assert parent_ledger.quota_left_for_other_subtasks(["subtask-fill-free-budget"]) == 50

    snapshot = parent_ledger.snapshot()
    json.dumps(snapshot)
    restored = aq.QuotaLedger.from_snapshot(snapshot)
    assert restored.job_id == parent_ledger.job_id
    assert restored.available == 0
    assert restored.quota_for("subtask-release") == 25
    assert restored.quota_for("subtask-archive") == 25


def test_normal_completion_releases_unused_reservation():
    ledger = aq.QuotaLedger("job-complete", 50)
    ledger.reserve("a", 30)
    ledger.record_usage("a", total=12)

    result = ledger.complete("a")

    assert result.status == aq.COMPLETED
    assert result.changes["released"] == 18
    assert ledger.consumed == 12
    assert ledger.reserved == 0
    assert ledger.available == 38


def test_cancellation_restores_full_reservation_before_usage():
    ledger = aq.QuotaLedger("job-cancel", 40)
    ledger.reserve("a", 25)
    assert ledger.available == 15

    result = ledger.cancel("a")

    assert result.status == aq.CANCELLED
    assert ledger.reserved == 0
    assert ledger.consumed == 0
    assert ledger.available == 40


def test_cancellation_can_restore_incurred_usage():
    ledger = aq.QuotaLedger("job-cancel-refund", 40)
    ledger.reserve("a", 25)
    ledger.spend("a", 7)

    ledger.cancel("a", restore_used=True)

    assert ledger.consumed == 0
    assert ledger.reserved == 0
    assert ledger.available == 40


def test_budget_insufficient_is_distinct_from_terminal_states():
    ledger = aq.QuotaLedger("job-budget", 40)
    ledger.reserve("a", 25)

    result = ledger.try_reserve("b", 20)

    assert result.ok is False
    assert result.status == aq.INSUFFICIENT_BUDGET
    assert isinstance(result.error, aq.BudgetInsufficientError)
    assert ledger.available == 15

    accepted = ledger.try_reserve("b", 15)
    assert accepted.ok is True
    assert ledger.available == 0


def test_fair_integer_shares_are_deterministic():
    ledger = aq.QuotaLedger("job-fair", 101)
    assert ledger.fair_shares(4) == [26, 25, 25, 25]


def test_default_coordinator_supports_simple_two_entry_calls():
    aq.reset_default_coordinator()
    first = aq.accept_approval(FIXTURE)
    declaration_xml = """<declaration job-id="JOB-QUOTA-039" quota="100">
      <subtasks>
        <subtask id="subtask-review" quota="25"/>
      </subtasks>
    </declaration>"""
    second = aq.accept_declaration(declaration_xml)

    assert second is first
    assert first.reserved == 100
    aq.reset_default_coordinator()


def test_fixture_file_is_included_in_repository():
    assert os.path.exists(os.path.join(HERE, "xmltestdata", "approval_quota_nested.xml"))


if __name__ == "__main__":
    import traceback

    failures = 0
    for test_name in sorted(name for name in globals() if name.startswith("test_")):
        try:
            globals()[test_name]()
        except Exception:
            failures += 1
            traceback.print_exc()
    print("{} failure(s)".format(failures))
    raise SystemExit(1 if failures else 0)
