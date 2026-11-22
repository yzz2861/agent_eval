"""Tests for the dual-sink upload recorder example.

The tests never open a socket: bodies are built in memory and streamed
through the recorder in deliberately small chunks.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from examples.dual_sink_upload.demo import BOUNDARY, build_body, run_demo
from examples.dual_sink_upload.recorder import AuditCallback, RecorderConfig, UploadRecorder
from examples.dual_sink_upload.records import PartStatus, RejectReason, RequestStatus, redact_label
from examples.dual_sink_upload.sinks import BusinessReceiptSink, CustomerServiceLogSink, JsonlSink
from python_multipart.exceptions import MultipartParseError


def make_part(
    name: bytes,
    value: bytes,
    *,
    content_type: bytes | None = None,
    filename: bytes | None = None,
    include_name: bool = True,
) -> bytes:
    lines = [b"--" + BOUNDARY]
    if include_name:
        disposition = b'Content-Disposition: form-data; name="' + name + b'"'
    else:
        disposition = b"Content-Disposition: form-data"
    if filename is not None:
        disposition += b'; filename="' + filename + b'"'
    lines.append(disposition)
    if content_type is not None:
        lines.append(b"Content-Type: " + content_type)
    lines.append(b"")
    lines.append(value)
    return b"\r\n".join(lines)


def wrap(parts: list[bytes]) -> bytes:
    return b"\r\n".join(parts) + b"\r\n--" + BOUNDARY + b"--\r\n"


def stream(recorder: UploadRecorder, body: bytes, chunk_size: int = 7) -> None:
    for offset in range(0, len(body), chunk_size):
        recorder.ingest(body[offset : offset + chunk_size])
    recorder.finish()


def make_recorder(**kwargs: object) -> tuple[UploadRecorder, BusinessReceiptSink, CustomerServiceLogSink]:
    business = BusinessReceiptSink()
    support = CustomerServiceLogSink()
    recorder = UploadRecorder(BOUNDARY, business_sink=business, support_sink=support, **kwargs)
    return recorder, business, support


def test_field_split_across_chunks_is_reassembled_by_hash() -> None:
    value = b"split-me-" * 11
    body = wrap([make_part(b"notes", value, content_type=b"text/plain")])
    recorder, business, support = make_recorder()
    stream(recorder, body, chunk_size=5)

    confirmed = [r for r in business.records if r["kind"] == "confirmed"]
    assert len(confirmed) == 1
    record = confirmed[0]
    assert record["bytes_received"] == len(value)
    assert record["chunk_count"] > 1
    assert record["content_hash"] == "sha256:" + hashlib.sha256(value).hexdigest()
    # The support view carries the same part reference but no field name.
    references = [r for r in support.records if r["kind"] == "reference"]
    assert len(references) == 1
    assert references[0]["part_ref"] == record["part_ref"]
    assert "field_name" not in references[0]
    assert "notes" not in json.dumps(support.records)
    assert value.decode() not in json.dumps(support.records)


def test_business_receipt_reconciles_to_request() -> None:
    value = b"reconcile-bytes"
    body = wrap([make_part(b"ledger_id", value, content_type=b"text/plain")])
    recorder, business, _ = make_recorder(request_ref="up_fixed_request")
    stream(recorder, body)

    record = next(r for r in business.records if r["kind"] == "confirmed")
    summary = next(r for r in business.records if r["kind"] == "summary")
    assert record["request_ref"] == "up_fixed_request" == summary["request_ref"]
    assert record["field_name"] == "ledger_id"
    assert record["content_hash"] == "sha256:" + hashlib.sha256(value).hexdigest()
    assert summary["status"] == RequestStatus.COMPLETED.value
    assert summary["accepted_parts"] == 1


def test_pii_filename_never_reaches_support_log() -> None:
    filename = b"Li Na - id card 990102.pdf"
    value = b"%PDF personal document"
    body = wrap([make_part(b"doc", value, content_type=b"application/pdf", filename=filename)])
    recorder, business, support = make_recorder()
    stream(recorder, body)

    confirmed = next(r for r in business.records if r["kind"] == "confirmed")
    assert "Li Na" not in confirmed["redacted_filename"]
    assert "990102" not in confirmed["redacted_filename"]
    support_blob = json.dumps(support.records, ensure_ascii=False)
    for token in ("Li Na", "990102", "id card", "doc", filename.decode()):
        assert token not in support_blob
    reference = next(r for r in support.records if r["kind"] == "reference")
    assert reference["status"] == PartStatus.ACCEPTED.value
    assert reference["is_file"] is True


def test_redact_label_is_non_reversible() -> None:
    assert redact_label(None) is None
    assert redact_label(b"") is None
    token = redact_label(b"../../etc/passwd user name.txt")
    assert token is not None
    assert "/" not in token and ".." not in token and "user name" not in token
    assert token == "file_redacted.txt"


def test_empty_name_is_rejected_with_minimum_info() -> None:
    body = wrap([make_part(b"", b"orphan value", include_name=False)])
    recorder, business, support = make_recorder()
    stream(recorder, body)

    rejection = next(r for r in business.records if r["kind"] == "rejection")
    assert rejection["reason"] == RejectReason.EMPTY_NAME.value
    assert rejection["status"] == PartStatus.REJECTED.value
    assert set(rejection) == {"kind", "part_ref", "status", "reason", "bytes_received", "detail"}
    support_rejection = next(r for r in support.records if r["kind"] == "rejection")
    assert support_rejection["reason"] == RejectReason.EMPTY_NAME.value
    assert "orphan value" not in json.dumps(support.records)
    assert "field_name" not in json.dumps(support.records)


def test_unknown_content_type_allowlist_rejection() -> None:
    config = RecorderConfig(allowed_content_types=frozenset({"application/pdf"}))
    body = wrap([make_part(b"blob", b"xyz", filename=b"blob.dat")])
    recorder, business, support = make_recorder(config=config)
    stream(recorder, body)
    rejection = next(r for r in business.records if r["kind"] == "rejection")
    assert rejection["reason"] == RejectReason.UNKNOWN_CONTENT_TYPE.value
    reference = next(r for r in support.records if r["kind"] == "reference")
    assert reference["reason"] == RejectReason.UNKNOWN_CONTENT_TYPE.value
    assert reference["is_file"] is True


def test_unknown_type_accepted_when_no_allowlist_configured() -> None:
    body = wrap([make_part(b"blob", b"xyz", filename=b"blob.dat")])
    recorder, business, support = make_recorder()
    stream(recorder, body)
    confirmed = [r for r in business.records if r["kind"] == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0]["content_type"] is None


def test_audit_callback_false_rejects_part() -> None:
    audit = AuditCallback(lambda metadata: False, reason="policy_block")
    body = wrap([make_part(b"field", b"data", content_type=b"text/plain")])
    recorder, business, support = make_recorder(audit=audit)
    stream(recorder, body)
    rejection = next(r for r in business.records if r["kind"] == "rejection")
    assert rejection["reason"] == RejectReason.AUDIT_CALLBACK_FAILED.value
    assert rejection["detail"] == "policy_block"
    support_blob = json.dumps(support.records)
    assert "policy_block" not in support_blob
    support_rejection = next(r for r in support.records if r["kind"] == "rejection")
    assert support_rejection["reason"] == "audit_callback_failed"


def test_audit_callback_exception_is_isolated() -> None:
    def explode(metadata: object) -> bool:
        if getattr(metadata, "field_name", "") == "doomed":
            raise RuntimeError("backend down")
        return True

    audit = AuditCallback(explode)
    good = make_part(b"kept", b"fine", content_type=b"text/plain")
    bad = make_part(b"doomed", b"boom", content_type=b"text/plain")
    body = wrap([good, bad])
    recorder, business, support = make_recorder(audit=audit)
    stream(recorder, body)

    confirmed = [r for r in business.records if r["kind"] == "confirmed"]
    assert [r["field_name"] for r in confirmed] == ["kept"]
    rejection = next(r for r in business.records if r["kind"] == "rejection")
    assert rejection["reason"] == RejectReason.AUDIT_CALLBACK_FAILED.value
    assert "backend down" not in json.dumps(support.records)
    summary = next(r for r in business.records if r["kind"] == "summary")
    assert summary["accepted_parts"] == 1
    assert summary["rejected_parts"] == 1
    assert summary["status"] == RequestStatus.REJECTED.value


def test_oversized_part_keeps_minimum_info_without_fingerprint() -> None:
    config = RecorderConfig(max_part_size=10)
    body = wrap([make_part(b"big", b"z" * 25, content_type=b"text/plain")])
    recorder, business, support = make_recorder(config=config)
    stream(recorder, body)
    rejection = next(r for r in business.records if r["kind"] == "rejection")
    assert rejection["reason"] == RejectReason.TOO_LARGE.value
    assert rejection["bytes_received"] == 25
    reference = next(r for r in support.records if r["kind"] == "reference")
    assert reference["fingerprint"] is None


def test_malformed_body_records_failure_and_propagates() -> None:
    recorder, business, support = make_recorder()
    with pytest.raises(MultipartParseError):
        recorder.ingest(b"this is not a multipart body at all")
    rejection = next(r for r in business.records if r["kind"] == "rejection")
    assert rejection["status"] == PartStatus.FAILED.value
    assert rejection["reason"] == RejectReason.MALFORMED_BODY.value
    support_rejection = next(r for r in support.records if r["kind"] == "rejection")
    assert support_rejection["reason"] == "malformed_body"


def test_fingerprints_are_salted_per_request() -> None:
    value = b"identical content"
    body = wrap([make_part(b"a", value, content_type=b"text/plain")])
    first_business = BusinessReceiptSink()
    first = UploadRecorder(BOUNDARY, business_sink=first_business)
    stream(first, body)
    second_business = BusinessReceiptSink()
    second = UploadRecorder(BOUNDARY, business_sink=second_business)
    stream(second, body)
    first_record = next(r for r in first_business.records if r["kind"] == "confirmed")
    second_record = next(r for r in second_business.records if r["kind"] == "confirmed")
    assert first_record["content_hash"] == second_record["content_hash"]
    assert first_record["fingerprint"] != second_record["fingerprint"]


def test_sinks_are_individually_optional() -> None:
    body = wrap([make_part(b"only", b"data", content_type=b"text/plain")])
    support = CustomerServiceLogSink()
    recorder = UploadRecorder(BOUNDARY, support_sink=support)
    stream(recorder, body)
    assert len(support.records) == 2
    recorder_no_sinks = UploadRecorder(BOUNDARY)
    stream(recorder_no_sinks, body)
    assert recorder_no_sinks.accepted_parts == 1


def test_jsonl_sink_writes_one_object_per_line(tmp_path: Path) -> None:
    stream_handle = io.StringIO()
    sink = JsonlSink(stream=stream_handle)
    sink.emit({"a": 1})
    sink.emit({"b": 2})
    lines = stream_handle.getvalue().splitlines()
    assert [json.loads(line) for line in lines] == [{"a": 1}, {"b": 2}]

    target = tmp_path / "support.jsonl"
    target.write_text(stream_handle.getvalue(), encoding="utf-8")
    reloaded = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert reloaded == [{"a": 1}, {"b": 2}]


def test_demo_covers_all_required_scenarios() -> None:
    business, support = run_demo()
    reasons = {r["reason"] for r in business.records if r["kind"] == "rejection"}
    assert {
        RejectReason.EMPTY_NAME.value,
        RejectReason.UNKNOWN_CONTENT_TYPE.value,
        RejectReason.AUDIT_CALLBACK_FAILED.value,
    }.issubset(reasons)
    summary = next(r for r in business.records if r["kind"] == "summary")
    assert summary["total_parts"] == 6
    assert summary["accepted_parts"] >= 1
    # The split field must span multiple transport chunks.
    split_field = next(r for r in business.records if r["kind"] == "confirmed" and r["field_name"] == "order_note")
    assert split_field["chunk_count"] > 1
    # No raw personal data or field names in the support log.
    support_blob = json.dumps(support.records, ensure_ascii=False)
    for token in ("Zhang", "passport", "12345678", "order_note", "id_scan"):
        assert token not in support_blob


def test_demo_body_is_wellformed_multipart() -> None:
    body = build_body()
    assert body.startswith(b"--" + BOUNDARY + b"\r\n")
    assert body.endswith(b"--" + BOUNDARY + b"--\r\n")
