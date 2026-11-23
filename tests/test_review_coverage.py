import os
from datetime import datetime, timedelta, timezone

import Evtx.Evtx as evtx
from Evtx.ReviewCoverage import RecordSnapshot, ReviewCoverageLedger


BASE = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)


def make_records(evidence_id, specs, digest_prefix=None):
    records = []
    for index, (minute, digest) in enumerate(specs, start=1):
        prefix = evidence_id if digest_prefix is None else digest_prefix
        records.append(
            RecordSnapshot(
                evidence_id=evidence_id,
                record_num=index,
                file_offset=0x1200 + (index - 1) * 0x100,
                chunk_offset=0x1000,
                record_offset=0x200 + (index - 1) * 0x100,
                timestamp=BASE + timedelta(minutes=minute),
                record_sha256=(prefix + ":" + digest) if prefix else digest,
                content_sha256=(prefix + ":" + digest) if prefix else digest,
                size=0x100,
            )
        )
    return records


def test_partial_receipt_becomes_handover_ready_and_receipts_trace():
    ledger = ReviewCoverageLedger()
    ledger.add_records("EX-A", make_records("EX-A", [(0, "one"), (30, "two")]))

    ledger.add_receipt(
        {
            "receipt_id": "R-1",
            "evidence_scope": "EX-A",
            "reviewer": "alice",
            "reviewed_at": BASE.isoformat(),
            "record_numbers": [1],
        }
    )
    assert ledger.summary["status"] == "partial"
    assert ledger.summary["reviewed_records"] == 1
    assert ledger.segments["EX-A"].status == "partial"

    ledger.add_receipt(
        {
            "receipt_id": "R-2",
            "evidence_scope": "EX-A",
            "reviewer": "bob",
            "reviewed_at": (BASE + timedelta(minutes=5)).isoformat(),
            "record_numbers": [2],
        }
    )
    summary = ledger.summary
    assert summary["status"] == "handover_ready"
    assert summary["reviewed_records"] == 2
    assert ledger.segments["EX-A"].status == "handover_ready"

    assert [record.review_ids for record in ledger.records()] == [["R-1"], ["R-2"]]
    assert ledger.trace_receipt("R-1")["reviewed_count"] == 1
    assert ledger.trace_receipt("R-2")["reviewed_count"] == 1
    assert ledger.trace_receipt("R-1")["segment_ids"] == ["EX-A"]


def test_overlapping_evidence_uses_union_and_distinct_locations():
    ledger = ReviewCoverageLedger()
    ledger.add_records("EX-A", make_records("EX-A", [(0, "a0"), (30, "a30")]))
    ledger.add_records("EX-B", make_records("EX-B", [(15, "b15"), (60, "b60")]))
    ledger.add_receipt({"receipt_id": "RA", "evidence_scope": "EX-A", "record_numbers": [1, 2]})
    ledger.add_receipt({"receipt_id": "RB", "evidence_scope": "EX-B", "record_numbers": [1, 2]})

    summary = ledger.summary
    assert summary["reviewed_records"] == 4
    assert summary["reviewed_record_instances"] == 4
    assert summary["covered_seconds"] == 3600
    assert summary["sum_evidence_covered_seconds"] == 4500
    assert summary["overlap_saved_seconds"] == 900
    assert len(summary["overlapping_evidence"]) == 1


def test_identical_overlapping_copy_is_not_counted_twice():
    ledger = ReviewCoverageLedger()
    original = make_records("EX-A", [(0, "same"), (30, "same")])
    copies = [
        RecordSnapshot(
            evidence_id="EX-B",
            record_num=record.record_num,
            file_offset=record.file_offset,
            chunk_offset=record.chunk_offset,
            timestamp=record.timestamp,
            record_sha256=record.record_sha256,
            size=record.size,
        )
        for record in original
    ]
    ledger.add_records("EX-A", original)
    ledger.add_records("EX-B", copies)
    ledger.add_receipt({"receipt_id": "RA", "evidence_scope": "EX-A", "record_numbers": [1, 2]})
    ledger.add_receipt({"receipt_id": "RB", "evidence_scope": "EX-B", "record_numbers": [1, 2]})

    assert ledger.summary["reviewed_records"] == 2
    assert ledger.summary["reviewed_record_instances"] == 4


def test_legacy_fields_are_reused_only_while_binding_matches():
    def old_receipt():
        return {
            "receipt_id": "R-LEGACY",
            "evidence_scope": "EX-A",
            "reviewer": "alice",
            "reviewed_at": BASE.isoformat(),
            "record_num": 1,
            "timestamp": BASE.isoformat(),
            "sha256": "match",
            "schema_version": 1,
        }

    ledger = ReviewCoverageLedger()
    ledger.add_records("EX-A", make_records("EX-A", [(0, "match")], digest_prefix=""))
    ledger.add_receipt(old_receipt())
    revision = ledger.add_receipt(
        {
            "receipt_id": "R-LEGACY",
            "evidence_scope": "EX-A",
            "record_num": 1,
            "timestamp": BASE.isoformat(),
            "sha256": "match",
            "schema_version": 2,
        }
    )
    assert revision.reviewer == "alice"
    assert revision.inherited_from["reviewer"] == "R-LEGACY"

    stale_ledger = ReviewCoverageLedger()
    stale_ledger.add_records("EX-A", make_records("EX-A", [(0, "changed")], digest_prefix=""))
    stale_ledger.add_receipt(old_receipt())
    stale_revision = stale_ledger.add_receipt(
        {
            "receipt_id": "R-LEGACY",
            "evidence_scope": "EX-A",
            "record_num": 1,
            "timestamp": BASE.isoformat(),
            "sha256": "changed",
            "schema_version": 2,
        }
    )
    assert stale_revision.reviewer is None
    assert "reviewer" not in stale_revision.inherited_from
    assert stale_revision.diagnostics[-1]["reason_code"] == "stale_receipt_binding"


def test_abnormal_record_content_remains_an_unreviewed_reason(data_path):
    ledger = ReviewCoverageLedger()
    ledger.add_evidence(os.path.join(data_path, "dns_log_malformed.evtx"), evidence_id="DNS")
    ledger.add_receipt(
        {
            "receipt_id": "R-DNS",
            "evidence_scope": "DNS",
            "record_numbers": [1, 2, 3, 4, 5],
        }
    )

    summary = ledger.summary
    assert summary["reviewed_records"] == 1
    assert summary["unreviewed_records"] == 4
    assert summary["invalid_record_count"] == 4
    assert any("record_content_error" in item["reason_code"] for item in summary["unreviewed"])
    assert ledger.trace_receipt("R-DNS")["status"] == "partial"


def test_evtx_reader_exposes_ledger_with_physical_locations():
    path = os.path.join(os.path.dirname(__file__), "data", "issue_38.evtx")
    with evtx.Evtx(path) as log:
        ledger = log.review_coverage({"receipt_id": "R", "record_numbers": [1]})

    assert ledger.summary["reviewed_records"] == 1
    record = ledger.records()[0]
    assert record.file_offset == 0x1200
    assert record.chunk_offset == 0x1000
    assert record.record_offset == 0x200
    assert record.receipt_ids == ["R"]


def test_explicit_timeline_segment_moves_from_partial_to_handover_ready():
    ledger = ReviewCoverageLedger(
        segments=[{"segment_id": "timeline-2026-11-23", "evidence_id": "EX-A"}]
    )
    ledger.add_records("EX-A", make_records("EX-A", [(0, "first"), (30, "second")]))
    ledger.add_receipt(
        {
            "receipt_id": "TRACE-1",
            "evidence_scope": "EX-A",
            "segment_id": "timeline-2026-11-23",
            "record_numbers": [1],
        }
    )
    assert ledger.segments["timeline-2026-11-23"].status == "partial"
    assert ledger.trace_receipt("TRACE-1")["segment_ids"] == ["timeline-2026-11-23"]

    ledger.add_receipt(
        {
            "receipt_id": "TRACE-2",
            "evidence_scope": "EX-A",
            "segment_id": "timeline-2026-11-23",
            "record_numbers": [2],
        }
    )
    segment = ledger.segments["timeline-2026-11-23"]
    assert segment.status == "handover_ready"
    assert segment.handover_ready is True
    assert ledger.summary["handover_ready_segments"] == ["timeline-2026-11-23"]
    assert {trace["receipt_id"] for trace in ledger.trace_receipts()} == {"TRACE-1", "TRACE-2"}
