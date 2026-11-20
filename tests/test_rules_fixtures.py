"""Rule verdicts on the conflicting minimal fixture pair."""

from __future__ import annotations

from elfharden import RuleId, Status, audit_bytes
from elfharden.builder import LAX_PROFILE, STRICT_PROFILE, build_elf


def _result(data: bytes, rule: RuleId):
    report = audit_bytes(data, rules=[rule])
    return report.results[0]


def test_strict_fixture_passes_all_three_rules() -> None:
    data = build_elf(STRICT_PROFILE)
    assert _result(data, RuleId.STACK_EXECUTABLE).status == Status.PASS
    assert _result(data, RuleId.RELRO).status == Status.PASS
    assert _result(data, RuleId.BIND_NOW).status == Status.PASS


def test_lax_fixture_reports_conflicts_not_guessed_pass() -> None:
    data = build_elf(LAX_PROFILE)
    stack = _result(data, RuleId.STACK_EXECUTABLE)
    assert stack.status == Status.CONFLICT
    assert stack.conflicts[0]["segment_verdict"] == Status.FAIL.value
    assert stack.conflicts[0]["section_verdict"] == Status.PASS.value
    bind = _result(data, RuleId.BIND_NOW)
    assert bind.status == Status.CONFLICT
    assert bind.conflicts[0]["segment_verdict"] == Status.FAIL.value
    assert bind.conflicts[0]["section_verdict"] == Status.PASS.value


def test_lax_fixture_relro_is_indeterminate_without_segment() -> None:
    data = build_elf(LAX_PROFILE)
    relro = _result(data, RuleId.RELRO)
    assert relro.status == Status.INDETERMINATE
    assert not any(e.kind == "program_header:PT_GNU_RELRO" for e in relro.evidence)


def test_every_verdict_cites_file_ranges() -> None:
    data = build_elf(LAX_PROFILE)
    report = audit_bytes(data).to_dict()
    for rule in report["results"]:
        located = [e for e in rule["evidence"] if e["file_range"] is not None]
        assert located, rule["rule_id"]
        for evidence in located:
            rng = evidence["file_range"]
            assert rng["end"] == rng["start"] + rng["size"]
            assert 0 <= rng["start"] < len(data)


def test_conflict_evidence_points_at_distinct_tables() -> None:
    data = build_elf(LAX_PROFILE)
    bind = _result(data, RuleId.BIND_NOW)
    ranges = {
        e.view.value: e.file_range.start for e in bind.evidence if e.file_range
    }
    assert ranges["segment"] != ranges["section"]


def test_gnu_stack_uses_program_header_entry_range() -> None:
    data = build_elf(LAX_PROFILE)
    stack = _result(data, RuleId.STACK_EXECUTABLE)
    segment_evidence = next(
        e for e in stack.evidence if e.view.value == "segment"
    )
    assert segment_evidence.file_range is not None
    assert segment_evidence.file_range.size == 56
    assert segment_evidence.file_range.start < len(data)
