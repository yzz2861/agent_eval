import os
from datetime import datetime, timedelta, timezone

from Evtx.Ledger import CoverageLedger, FieldRequirements


BASE = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


class FakeRecord(object):
    def __init__(self, record_num, timestamp, offset, content=None, verify_ok=True, xml_error=None):
        self._record_num = record_num
        self._timestamp = timestamp
        self._offset = offset
        self._content = content or "record-{}".format(record_num)
        self._verify_ok = verify_ok
        self._xml_error = xml_error

    def record_num(self):
        return self._record_num

    def offset(self):
        return self._offset

    def timestamp(self):
        return self._timestamp

    def length(self):
        return 0x100

    def verify(self):
        return self._verify_ok

    def xml(self):
        if self._xml_error is not None:
            raise self._xml_error
        return "<Event><EventRecordID>{}</EventRecordID></Event>".format(self._record_num)

    def data(self):
        return self._content.encode("utf-8")


class FakeLog(object):
    def __init__(self, records):
        self._records = records

    def records(self):
        for record in self._records:
            yield record


def make_log(count, start_seconds=0, step_seconds=10, base_offset=0x1000, first_num=1, anomalies=None):
    anomalies = anomalies or {}
    records = []
    for index in range(count):
        record_num = first_num + index
        error = anomalies.get(record_num)
        records.append(
            FakeRecord(
                record_num,
                BASE + timedelta(seconds=start_seconds + index * step_seconds),
                base_offset + index * 0x100,
                xml_error=error,
            )
        )
    return FakeLog(records)


def test_partial_receipts_become_handoff_ready_and_each_receipt_traces():
    requirements = FieldRequirements("review-v1", ["EventID", "TimeCreated"])
    ledger = CoverageLedger(requirements, reuse_policy="compatible")
    ledger.scan_evidence("EX-1", make_log(5))

    assert ledger.summary()["evidence"]["EX-1"]["reviewed_records"] == 0
    assert ledger.is_handoff_ready("EX-1", 1, 5) is False

    first = ledger.issue_receipt("EX-1", "alice", 1, 3, note="partial spot check")
    assert first.receipt_id == "R0001"
    assert ledger.is_active(first)
    assert ledger.is_handoff_ready("EX-1", 1, 3) is True
    assert ledger.is_handoff_ready("EX-1", 1, 5) is False
    assert ledger.summary()["evidence"]["EX-1"]["reviewed_records"] == 3

    second = ledger.issue_receipt("EX-1", "bob", 4, 5, note="finish segment")
    assert second.receipt_id == "R0002"
    assert ledger.is_handoff_ready("EX-1", 1, 5) is True
    assert ledger.summary()["evidence"]["EX-1"]["reviewed_records"] == 5

    hits_one = ledger.trace("EX-1", record_num=1)
    assert [hit.receipt.receipt_id for hit in hits_one] == ["R0001"]
    hits_four = ledger.trace("EX-1", record_num=4)
    assert [hit.receipt.receipt_id for hit in hits_four] == ["R0002"]

    entry_four = [entry for entry in ledger.inventory("EX-1") if entry.record_num == 4][0]
    assert [hit.receipt.receipt_id for hit in ledger.trace("EX-1", offset=entry_four.offset)] == ["R0002"]

    traced = ledger.trace_receipt("R0002")
    assert traced["active"] is True
    assert [item["record_num"] for item in traced["bound_records"]] == [4, 5]

    window = ledger.reviewed_in_time_range(BASE, BASE + timedelta(seconds=20), "EX-1")
    assert [item["record_num"] for item in window] == [1, 2, 3]


def test_changed_requirements_make_receipts_stale_then_reusable_when_satisfied_again():
    original = FieldRequirements("review-v1", ["EventID", "TimeCreated"])
    ledger = CoverageLedger(original)
    ledger.scan_evidence("EX-1", make_log(4))
    receipt = ledger.issue_receipt("EX-1", "alice", 1, 4)

    ledger.set_requirements(FieldRequirements("review-v2", ["EventID", "TimeCreated", "Provider"]))
    reasons = ledger.receipt_status(receipt)
    assert not ledger.is_active(receipt)
    assert any(reason.startswith("requirements_changed") for reason in reasons)
    assert ledger.is_handoff_ready("EX-1", 1, 4) is False
    unreviewed = ledger.unreviewed("EX-1", 1, 4)
    assert all(any("only_stale_receipts" in reason for reason in item.reasons) for item in unreviewed)
    assert "requirements_changed" in ledger.trace("EX-1", record_num=1)[0].reasons[0]

    ledger.set_requirements(original)
    assert ledger.is_active(receipt)
    assert ledger.is_handoff_ready("EX-1", 1, 4) is True


def test_narrower_requirements_can_reuse_a_receipt_that_certified_more_fields():
    ledger = CoverageLedger(FieldRequirements("review-v1", ["EventID", "TimeCreated"]))
    ledger.scan_evidence("EX-1", make_log(3))
    receipt = ledger.issue_receipt("EX-1", "alice", 1, 3)

    ledger.set_requirements(FieldRequirements("review-thin", ["EventID"]))
    assert ledger.is_active(receipt)

    ledger.set_reuse_policy("exact")
    assert not ledger.is_active(receipt)


def test_overlapping_exhibits_are_merged_in_time_not_summed():
    ledger = CoverageLedger(FieldRequirements("review-v1", ["TimeCreated"]))
    ledger.scan_evidence("EX-A", make_log(5, start_seconds=0, step_seconds=10, first_num=1))
    ledger.scan_evidence("EX-B", make_log(3, start_seconds=10, step_seconds=10, base_offset=0x3000, first_num=101))

    receipt_a = ledger.issue_receipt("EX-A", "alice", 1, 5)
    receipt_b = ledger.issue_receipt("EX-B", "bob", 101, 103)
    assert ledger.is_active(receipt_a)
    assert ledger.is_active(receipt_b)

    assert ledger.reviewed_duration() == timedelta(seconds=40)
    assert ledger.overlap_time_seconds() == 20.0
    intervals = ledger.reviewed_time_intervals()
    assert len(intervals) == 1
    assert intervals[0][0] == BASE
    assert intervals[0][1] == BASE + timedelta(seconds=40)

    assert ledger.summary()["reviewed_records_total"] == 8
    assert ledger.summary()["evidence"]["EX-A"]["reviewed_records"] == 5
    assert ledger.summary()["evidence"]["EX-B"]["reviewed_records"] == 3


def test_anomalous_record_stays_unreviewed_as_a_reason_and_splits_intervals():
    anomalies = {3: RuntimeError("corrupt event body")}
    ledger = CoverageLedger(FieldRequirements("review-v1", ["EventID", "TimeCreated"]))
    ledger.scan_evidence("EX-1", make_log(5, anomalies=anomalies))
    receipt = ledger.issue_receipt("EX-1", "alice", 1, 5)

    assert ledger.is_active(receipt)
    report = ledger.summary()["evidence"]["EX-1"]
    assert report["anomalies"] == 1
    assert report["reviewed_records"] == 4
    assert report["reviewed_intervals"] == [(1, 2), (4, 5)]
    assert ledger.is_handoff_ready("EX-1", 1, 5) is False
    assert ledger.reviewed_duration("EX-1") == timedelta(seconds=20)
    assert ledger.coverage("EX-1")[2]["reviewed"] is False

    item = [entry for entry in ledger.unreviewed("EX-1") if entry.entry.record_num == 3][0]
    assert any("record_content_abnormal" in reason for reason in item.reasons)
    coverage = ledger.record_coverage("EX-1", 3)
    assert coverage["reviewed"] is False
    assert any("record_content_abnormal" in reason for reason in coverage["reasons"])


def test_receipt_bound_to_moved_record_position_is_not_reused():
    ledger = CoverageLedger(FieldRequirements("review-v1", ["EventID"]))
    ledger.scan_evidence("EX-1", make_log(3))
    receipt = ledger.issue_receipt("EX-1", "alice", 1, 3)

    moved_records = make_log(3)
    moved_records._records[1]._offset = moved_records._records[1]._offset + 0x20
    moved_records._records[1]._content = "changed-content"
    ledger.scan_evidence("EX-1", moved_records, append=False)

    assert not ledger.is_active(receipt)
    reasons = ledger.receipt_status(receipt)
    assert any("record_offset_changed" in reason for reason in reasons)
    assert any(reason.startswith("record_content_changed") for reason in reasons)
    assert [hit.active for hit in ledger.trace("EX-1", record_num=2)] == [False]


def test_receipt_json_round_trip_can_be_reloaded_and_traced():
    ledger = CoverageLedger(FieldRequirements("review-v1", ["EventID", "TimeCreated"]))
    ledger.scan_evidence("EX-1", make_log(4))
    receipt = ledger.issue_receipt("EX-1", "alice", 1, 2, note="first half")
    payload = ledger.to_dict()

    assert payload["receipts"][0]["receipt_id"] == receipt.receipt_id
    restored = CoverageLedger(FieldRequirements("review-v1", ["EventID", "TimeCreated"]))
    restored.scan_evidence("EX-1", make_log(4))
    restored.load_receipts(payload)
    restored_receipt = restored.get_receipt("R0001")

    assert restored_receipt is not None
    assert restored.is_active(restored_receipt)
    assert restored.is_handoff_ready("EX-1", 1, 2) is True
    assert [hit.receipt.receipt_id for hit in restored.trace("EX-1", record_num=1)] == ["R0001"]


def test_duplicate_overlapping_receipts_do_not_inflate_counts():
    ledger = CoverageLedger(FieldRequirements("review-v1", ["EventID"]))
    ledger.scan_evidence("EX-1", make_log(4))
    ledger.issue_receipt("EX-1", "alice", 1, 3)
    ledger.issue_receipt("EX-1", "bob", 2, 4)

    assert ledger.summary()["evidence"]["EX-1"]["reviewed_records"] == 4
    assert ledger.reviewed_intervals("EX-1") == [(1, 4)]
    assert ledger.covered_intervals("EX-1") == [(1, 4)]


def test_real_malformed_evtx_keeps_anomalies_as_unreviewed_reasons(data_path):
    path = os.path.join(data_path, "dns_log_malformed.evtx")
    ledger = CoverageLedger(FieldRequirements("review-v1", ["EventID", "TimeCreated"]))
    ledger.scan_file("DNS-malformed", path)

    entries = ledger.inventory("DNS-malformed")
    assert len(entries) == 5
    assert sum(1 for entry in entries if entry.anomaly is not None) == 4

    ledger.issue_receipt("DNS-malformed", "alice", 1, 5)
    report = ledger.summary()["evidence"]["DNS-malformed"]
    assert report["reviewed_records"] == 1
    assert ledger.is_handoff_ready("DNS-malformed", 1, 5) is False
    unreviewed = ledger.unreviewed("DNS-malformed", 1, 5)
    assert len(unreviewed) == 4
    assert all(any("abnormal" in reason or "invalid" in reason for reason in item.reasons) for item in unreviewed)
