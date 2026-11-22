"""Assertion tests for event-level completeness checking."""

import io

import ijson
import pytest

from audit_completeness import (
    CompletenessResult,
    audit_bytes,
    audit_chunks,
    audit_stream,
    compile_rules,
)
from audit_completeness.fixtures import (
    audit_rules,
    build_full_stream,
    build_truncated_stream,
)


def _summarize(result):
    return {
        name: sorted(
            (finding.rule_id, finding.status, repr(finding.position))
            for finding in getattr(result, name)
        )
        for name in ("complete", "type_mismatched", "missing")
    }


def test_rules_are_type_tagged_and_validated():
    rules = compile_rules([
        ("a.item.b", "string"),
        {"prefix": "a.item.c", "type": "int"},
    ])
    assert rules[0].expected_types == ("string",)
    assert rules[1].expected_types == ("number",)
    assert rules[0].container_prefix == "a.item"
    assert rules[0].key == "b"
    with pytest.raises(ValueError):
        compile_rules([("a.item.b", "map_key")])
    with pytest.raises(ValueError):
        compile_rules([])


def test_full_stream_is_intact_and_catalogues_every_record():
    result = audit_stream(io.BytesIO(build_full_stream()), audit_rules())
    assert result.intact is True
    assert result.stream_truncated is False
    assert result.truncated == []
    assert len(result.complete) == 15
    assert len(result.type_mismatched) == 1
    assert result.type_mismatched[0].actual_type == "number"
    assert result.missing == []




def test_closed_record_emits_definitive_missing_and_type_mismatch():
    import json
    payload = {"batches": [{"records": [
        {"risk_level": 9, "active": True, "flags": []}
    ]}]}
    data = json.dumps(payload).encode("utf-8")
    result = audit_stream(io.BytesIO(data), audit_rules())
    assert result.intact is True
    mismatch = [f for f in result.type_mismatched if f.rule_id.endswith("risk_level")]
    assert len(mismatch) == 1
    assert mismatch[0].actual_type == "number"
    missing_ids = {f.rule_id.split(".")[-1] for f in result.missing}
    assert missing_ids == {"amount"}
    assert result.missing[0].position["missing_key"] == "amount"


def test_truncated_tail_is_not_reported_as_missing():
    data = build_truncated_stream()
    result = audit_stream(io.BytesIO(data), audit_rules())
    assert result.intact is False
    assert result.stream_truncated is True
    assert isinstance(result.truncation_error, str)
    assert result.missing == []
    assert len(result.truncated) >= 1
    open_slot = result.truncated[-1]
    assert open_slot.position["unclosed_container"] == "map"
    pending = set(open_slot.position["pending_rules"])
    assert any(rule.endswith("risk_level") for rule in pending)
    completed = {f.rule_id.split(".")[-1] for f in result.completed_fields()}
    assert "record_id" not in completed
    assert len(result.completed_fields()) >= 3


def test_completed_fields_survive_truncation_and_are_individually_reviewable():
    full = audit_stream(io.BytesIO(build_full_stream()), audit_rules())
    cut = audit_stream(io.BytesIO(build_truncated_stream()), audit_rules())
    full_keys = {f.rule_id + repr(f.position) for f in full.completed_fields()}
    cut_keys = {f.rule_id + repr(f.position) for f in cut.completed_fields()}
    assert cut_keys
    assert cut_keys.issubset(full_keys)
    for finding in cut.completed_fields():
        assert finding.actual_type in finding.expected_types or finding.status == "type_mismatch"


def test_sync_short_read_and_push_chunks_observe_identical_results():
    full = build_full_stream()
    cut = build_truncated_stream()
    for data in (full, cut):
        sync_result = audit_stream(io.BytesIO(data), audit_rules(), buf_size=16)
        push_result = audit_bytes(data, audit_rules(), chunk_size=16)
        chunk_result = audit_chunks([data[:9], data[9:]], audit_rules())
        assert _summarize(sync_result) == _summarize(push_result)
        assert sync_result.stream_truncated == push_result.stream_truncated
        assert (
            [t.position for t in sync_result.truncated]
            == [t.position for t in push_result.truncated]
        )
        assert _summarize(push_result) == _summarize(chunk_result)
        assert push_result.stream_truncated == chunk_result.stream_truncated


def test_uncollected_later_batch_differs_from_closed_missing_field():
    import json
    closed_missing = json.dumps({"batches": [
        {"records": [{"active": True, "flags": [], "risk_level": "low"}]}
    ]}).encode("utf-8")
    complete = json.dumps({"batches": [
        {"records": [{"risk_level": "low", "amount": 1, "active": True, "flags": []}]}
    ]}).encode("utf-8")
    uncollected = complete[: complete.index(b"\"flags\"")]
    closed_result = audit_bytes(closed_missing, audit_rules())
    cut_result = audit_bytes(uncollected, audit_rules())
    assert closed_result.intact is True
    assert {f.rule_id.split(".")[-1] for f in closed_result.missing} == {"amount"}
    assert cut_result.intact is False
    assert cut_result.missing == []
    assert cut_result.truncated
    assert cut_result.open_slots


def test_empty_array_is_a_closed_negative_conclusion_not_truncation():
    import json
    rules = [("batches.item.records.item.tags.item", "string")]
    data = json.dumps({"batches": [{"records": [
        {"tags": []}, {"tags": ["kept"]}
    ]}]}).encode("utf-8")
    result = audit_stream(io.BytesIO(data), rules)
    assert result.intact is True
    assert result.stream_truncated is False
    assert len(result.complete) == 1
    assert len(result.missing) == 1
    assert result.missing[0].position["missing_key"] == "item"
    assert result.truncated == []
