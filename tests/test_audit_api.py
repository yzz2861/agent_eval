"""Public entry point and rule-selection behaviour."""

from __future__ import annotations

import io

import pytest

from elfharden import ALL_RULES, RuleId, Status, audit_bytes, audit_stream
from elfharden.builder import build_elf, STRICT_PROFILE


def test_default_runs_all_rules() -> None:
    report = audit_bytes(build_elf(STRICT_PROFILE))
    assert report.rules_selected == [rule.value for rule in ALL_RULES]
    assert len(report.results) == 3


def test_rule_selection_accepts_strings_and_enums() -> None:
    data = build_elf(STRICT_PROFILE)
    by_string = audit_bytes(data, rules=["relro"])
    by_enum = audit_bytes(data, rules=[RuleId.RELRO])
    assert by_string.results[0].rule_id == RuleId.RELRO
    assert by_enum.results[0].status == by_string.results[0].status


def test_rule_selection_deduplicates() -> None:
    report = audit_bytes(
        build_elf(STRICT_PROFILE), rules=["relro", RuleId.RELRO, "relro"]
    )
    assert report.rules_selected == ["relro"]


def test_unknown_rule_raises() -> None:
    with pytest.raises(ValueError):
        audit_bytes(build_elf(STRICT_PROFILE), rules=["does_not_exist"])


def test_audit_stream_accepts_open_file() -> None:
    data = build_elf(STRICT_PROFILE)
    report = audit_stream(io.BytesIO(data), rules=[RuleId.STACK_EXECUTABLE])
    assert report.results[0].status == Status.PASS
    assert report.elf_class == 64


def test_report_dict_contains_elf_metadata() -> None:
    payload = audit_bytes(build_elf(STRICT_PROFILE)).to_dict()
    elf = payload["elf"]
    assert elf["type"] == "ET_EXEC"
    assert elf["is_dynamic"] is True
    assert elf["section_headers_present"] is True
