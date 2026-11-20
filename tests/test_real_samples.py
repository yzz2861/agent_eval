"""Cross-checks against ELF samples shipped with the pyelftools corpus."""

from __future__ import annotations

from pathlib import Path


from elfharden import RuleId, Status, audit_elf

READELF = Path("test/testfiles_for_readelf")
UNITTESTS = Path("test/testfiles_for_unittests")


def _status(path: Path, rule: RuleId) -> Status:
    report = audit_elf(path, rules=[rule])
    return report.results[0].status


def test_full_relro_and_bind_now_shared_object() -> None:
    path = READELF / "tls64.so.elf"
    assert _status(path, RuleId.RELRO) == Status.PASS
    assert _status(path, RuleId.BIND_NOW) == Status.PASS
    assert _status(path, RuleId.STACK_EXECUTABLE) == Status.PASS


def test_partial_relro_dynamic_executable() -> None:
    path = READELF / "exe_stripped64.elf"
    assert _status(path, RuleId.RELRO) == Status.PARTIAL
    assert _status(path, RuleId.BIND_NOW) == Status.FAIL


def test_super_stripped_file_uses_program_headers_only() -> None:
    path = UNITTESTS / "aarch64_super_stripped.elf"
    report = audit_elf(path)
    assert report.section_headers_present is False
    stack = report.results[0]
    assert stack.rule_id == RuleId.STACK_EXECUTABLE
    assert stack.status == Status.INDETERMINATE
    assert any(e.view.value == "section" and
               e.kind == "section_header_table:absent" for e in stack.evidence)


def test_static_executable_marks_binding_not_applicable() -> None:
    path = UNITTESTS / "arm_reloc_relocated.elf"
    report = audit_elf(path)
    assert report.is_dynamic is False
    bind = next(r for r in report.results if r.rule_id == RuleId.BIND_NOW)
    assert bind.status == Status.NOT_APPLICABLE
    relro = next(r for r in report.results if r.rule_id == RuleId.RELRO)
    assert relro.status == Status.INDETERMINATE


def test_32bit_little_endian_is_supported() -> None:
    path = READELF / "exe_simple32.elf"
    report = audit_elf(path)
    assert report.elf_class == 32
    assert report.endianness == "little"
    assert _status(path, RuleId.STACK_EXECUTABLE) == Status.PASS


def test_report_is_json_serializable() -> None:
    import json
    report = audit_elf(READELF / "tls64.so.elf")
    text = json.dumps(report.to_dict())
    assert "PT_GNU_RELRO" in text
