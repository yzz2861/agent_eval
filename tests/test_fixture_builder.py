"""The hand-built fixtures must be valid ELF and keep identical section views."""

from __future__ import annotations

import io
from pathlib import Path

from elftools.elf.elffile import ELFFile

from elfharden.builder import (
    LAX_PROFILE,
    STRICT_PROFILE,
    BuildLayout,
    _layout,
    build_elf,
    fixture_pair,
    section_declaration_signature,
)


def test_fixtures_parse_as_elf64() -> None:
    strict, lax = fixture_pair()
    for data in (strict, lax):
        elf = ELFFile(io.BytesIO(data))
        assert elf.elfclass == 64
        assert elf.little_endian is True
        assert elf["e_type"] == "ET_EXEC"
        assert elf.num_sections() == 6


def test_pair_has_identical_size_and_section_view() -> None:
    strict, lax = fixture_pair()
    assert len(strict) == len(lax)
    assert section_declaration_signature(strict) == section_declaration_signature(lax)
    layout = _layout(STRICT_PROFILE)
    differing = [i for i in range(len(strict)) if strict[i] != lax[i]]
    assert differing
    assert all(layout.phoff <= i < layout.dyn_full_offset for i in differing)


def test_pair_declares_same_sections_but_different_segments() -> None:
    strict, lax = fixture_pair()
    strict_elf = ELFFile(io.BytesIO(strict))
    lax_elf = ELFFile(io.BytesIO(lax))
    strict_sections = [(s.name, s["sh_type"], s["sh_offset"])
                        for s in strict_elf.iter_sections()]
    lax_sections = [(s.name, s["sh_type"], s["sh_offset"])
                    for s in lax_elf.iter_sections()]
    assert strict_sections == lax_sections
    strict_types = [s["p_type"] for s in strict_elf.iter_segments()]
    lax_types = [s["p_type"] for s in lax_elf.iter_segments()]
    assert "PT_GNU_RELRO" in strict_types
    assert "PT_GNU_RELRO" not in lax_types
    assert strict_types != lax_types


def test_layout_offsets_are_contained_in_fixture() -> None:
    for profile in (STRICT_PROFILE, LAX_PROFILE):
        layout: BuildLayout = _layout(profile)
        data = build_elf(profile)
        assert layout.shoff + 6 * 64 == len(data)
        assert layout.dyn_full_offset < layout.dyn_lax_offset
        assert layout.dyn_lax_offset < layout.shstr_offset
        assert layout.shstr_offset < layout.note_offset < layout.shoff
        assert len(data) < 1024


def test_fixture_files_on_disk_match_builder(tmp_path: Path) -> None:
    strict, lax = fixture_pair()
    strict_path = tmp_path / "strict.elf"
    strict_path.write_bytes(strict)
    assert strict_path.read_bytes() == strict
    assert len(lax) == len(strict)
