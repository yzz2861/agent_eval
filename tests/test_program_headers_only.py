"""Samples whose section header table is removed (program headers only)."""

from __future__ import annotations

import io
import struct

from elftools.elf.elffile import ELFFile

from elfharden import RuleId, Status, audit_bytes, audit_elf
from elfharden.builder import STRICT_PROFILE, build_elf


def _strip_section_headers(data: bytes) -> bytes:
    # Zero e_shoff/e_shnum/e_shstrndx while leaving program headers intact.
    buf = bytearray(data)
    struct.pack_into("<Q", buf, 40, 0)  # e_shoff
    struct.pack_into("<HHH", buf, 60, 0, 0, 0)
    return bytes(buf)


def test_stripped_fixture_has_no_sections_but_keeps_segments() -> None:
    data = _strip_section_headers(build_elf(STRICT_PROFILE))
    elf = ELFFile(io.BytesIO(data))
    assert elf.num_sections() == 0
    assert list(elf.iter_segments())


def test_stripped_fixture_still_audits_from_program_headers() -> None:
    data = _strip_section_headers(build_elf(STRICT_PROFILE))
    report = audit_bytes(data)
    assert report.section_headers_present is False
    by_rule = {RuleId(r.rule_id): r.status for r in report.results}
    assert by_rule[RuleId.STACK_EXECUTABLE] == Status.PASS
    assert by_rule[RuleId.RELRO] == Status.PASS
    assert by_rule[RuleId.BIND_NOW] == Status.PASS
    for result in report.results:
        assert all(e.view.value != "section" or
                   e.kind == "section_header_table:absent"
                   for e in result.evidence)


def test_real_super_stripped_sample_round_trips() -> None:
    report = audit_elf(
        "test/testfiles_for_unittests/aarch64_super_stripped.elf",
        rules=[RuleId.BIND_NOW],
    )
    result = report.results[0]
    assert result.status == Status.FAIL
    segment_evidence = [e for e in result.evidence if e.view.value == "segment"]
    assert segment_evidence
    assert all(e.file_range is not None for e in segment_evidence)
