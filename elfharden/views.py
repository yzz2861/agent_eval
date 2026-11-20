"""Collectors for the three legal views of an ELF image.

Each hardening decision is derived from one of three independently parsed
views rather than convention:

* segment view - PT_* program headers (always present, survives stripping)
* dynamic view - PT_DYNAMIC / .dynamic entries (dynamic programs only)
* section view - SHT_* section headers (optional, removed by full strip)
"""

from __future__ import annotations

from dataclasses import dataclass

from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from .model import Range


PT_GNU_STACK = "PT_GNU_STACK"
PT_GNU_RELRO = "PT_GNU_RELRO"
PT_DYNAMIC = "PT_DYNAMIC"
SHT_NOBITS = "SHT_NOBITS"

# pyelftools resolves well-known tags to symbolic names; numeric aliases cover
# toolchain-specific tables and keep the audit independent of name tables.
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6FFFFFFB
_DF_BIND_NOW = 0x8
_DF_1_NOW = 0x1


@dataclass
class SegmentRecord:
    index: int
    p_type: str
    p_flags: int
    p_offset: int
    p_filesz: int
    p_vaddr: int
    p_memsz: int
    header_range: Range | None = None

    @property
    def executable(self) -> bool:
        return bool(self.p_flags & P_FLAGS.PF_X)

    @property
    def file_range(self) -> Range:
        return Range(start=self.p_offset, size=self.p_filesz)

    @property
    def memory_range(self) -> Range:
        return Range(start=self.p_vaddr, size=self.p_memsz)


@dataclass
class SectionRecord:
    index: int
    name: str
    sh_type: str
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int

    @property
    def allocatable(self) -> bool:
        return bool(self.sh_flags & SH_FLAGS.SHF_ALLOC)

    @property
    def writable(self) -> bool:
        return bool(self.sh_flags & SH_FLAGS.SHF_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.sh_flags & SH_FLAGS.SHF_EXECINSTR)

    @property
    def file_range(self) -> Range:
        # SHT_NOBITS occupies no bytes in the file; keep the logical span.
        size = 0 if self.sh_type == SHT_NOBITS else self.sh_size
        return Range(start=self.sh_offset, size=size)

    @property
    def memory_range(self) -> Range:
        return Range(start=self.sh_addr, size=self.sh_size)


@dataclass
class DynamicTagRecord:
    tag: str
    tag_value: int
    value: int
    entry_offset: int
    entry_size: int
    source: str
    section_index: int | None = None
    segment_index: int | None = None

    @property
    def range(self) -> Range:
        return Range(start=self.entry_offset, size=self.entry_size)

    def requests_now(self) -> bool:
        if self.tag_value == _DT_BIND_NOW or self.tag == "DT_BIND_NOW":
            return True
        if self.tag_value == _DT_FLAGS or self.tag == "DT_FLAGS":
            return bool(self.value & _DF_BIND_NOW)
        if self.tag_value == _DT_FLAGS_1 or self.tag == "DT_FLAGS_1":
            return bool(self.value & _DF_1_NOW)
        return False


@dataclass
class ELFViews:
    """Parsed evidence from the three legal ELF views."""

    elf: ELFFile
    segments: list[SegmentRecord]
    sections: list[SectionRecord]
    dynamic_tags: list[DynamicTagRecord]
    section_view_present: bool
    dynamic_present: bool

    @classmethod
    def collect(cls, elf: ELFFile) -> "ELFViews":
        phdr_size = elf.structs.Elf_Phdr.sizeof()
        phdr_offset = int(elf["e_phoff"])
        segments = [
            SegmentRecord(
                index=index,
                p_type=str(segment["p_type"]),
                p_flags=int(segment["p_flags"]),
                p_offset=int(segment["p_offset"]),
                p_filesz=int(segment["p_filesz"]),
                p_vaddr=int(segment["p_vaddr"]),
                p_memsz=int(segment["p_memsz"]),
                header_range=Range(
                    start=phdr_offset + index * phdr_size, size=phdr_size
                ),
            )
            for index, segment in enumerate(elf.iter_segments())
        ]
        section_view_present = elf.num_sections() > 0
        sections: list[SectionRecord] = []
        if section_view_present:
            for index, section in enumerate(elf.iter_sections()):
                sections.append(
                    SectionRecord(
                        index=index,
                        name=section.name,
                        sh_type=str(section["sh_type"]),
                        sh_flags=int(section["sh_flags"]),
                        sh_addr=int(section["sh_addr"]),
                        sh_offset=int(section["sh_offset"]),
                        sh_size=int(section["sh_size"]),
                    )
                )
        tags = _collect_dynamic_tags(elf)
        return cls(
            elf=elf,
            segments=segments,
            sections=sections,
            dynamic_tags=tags,
            section_view_present=section_view_present,
            dynamic_present=bool(tags),
        )

    def segment_by_type(self, p_type: str) -> list[SegmentRecord]:
        return [segment for segment in self.segments if segment.p_type == p_type]

    def section_by_name(self, name: str) -> list[SectionRecord]:
        return [section for section in self.sections if section.name == name]

    def sections_in_segment(self, segment: SegmentRecord) -> list[SectionRecord]:
        """Allocated sections whose memory span sits inside a segment."""
        if not segment.memory_range.size:
            return []
        result = []
        for section in self.sections:
            if not section.allocatable or not section.memory_range.size:
                continue
            if _range_inside(section.memory_range, segment.memory_range):
                result.append(section)
        return sorted(result, key=lambda item: item.sh_addr)


def _range_inside(inner: Range, outer: Range) -> bool:
    end = inner.start + inner.size
    outer_end = outer.start + outer.size
    return inner.start >= outer.start and end <= outer_end


def _collect_dynamic_tags(elf: ELFFile) -> list[DynamicTagRecord]:
    """Read dynamic entries from PT_DYNAMIC and any .dynamic section.

    The tables are parsed directly with the Elf_Dyn struct instead of
    pyelftools' higher-level Dynamic wrapper: that wrapper assumes the segment
    and section describe the same table, which is precisely the disagreement
    these audits must be able to report.
    """
    tags: list[DynamicTagRecord] = []
    dyn_struct = elf.structs.Elf_Dyn
    entry_size = dyn_struct.sizeof()
    stream = elf.stream
    for index, segment in enumerate(elf.iter_segments()):
        if str(segment["p_type"]) != PT_DYNAMIC or segment["p_filesz"] == 0:
            continue
        base = int(segment["p_offset"])
        count = int(segment["p_filesz"]) // entry_size
        for order in range(count):
            stream.seek(base + order * entry_size)
            entry = dyn_struct.parse_stream(stream)
            tags.append(
                DynamicTagRecord(
                    tag=str(entry.d_tag),
                    tag_value=_tag_value(entry.d_tag),
                    value=int(entry.d_val),
                    entry_offset=base + order * entry_size,
                    entry_size=entry_size,
                    source="segment:PT_DYNAMIC",
                    segment_index=index,
                )
            )
    if elf.num_sections() > 0:
        for index, section in enumerate(elf.iter_sections()):
            if not isinstance(section, DynamicSection) or section["sh_size"] == 0:
                continue
            base = int(section["sh_offset"])
            count = int(section["sh_size"]) // entry_size
            for order in range(count):
                stream.seek(base + order * entry_size)
                entry = dyn_struct.parse_stream(stream)
                tags.append(
                    DynamicTagRecord(
                        tag=str(entry.d_tag),
                        tag_value=_tag_value(entry.d_tag),
                        value=int(entry.d_val),
                        entry_offset=base + order * entry_size,
                        entry_size=entry_size,
                        source="section:.dynamic",
                        section_index=index,
                    )
                )
    return tags


def _tag_value(d_tag: object) -> int:
    if isinstance(d_tag, int):
        return int(d_tag)
    return _name_to_tag(d_tag)


_NAMED_TAGS = {
    "DT_BIND_NOW": _DT_BIND_NOW,
    "DT_FLAGS": _DT_FLAGS,
    "DT_FLAGS_1": _DT_FLAGS_1,
}


def _name_to_tag(name: object) -> int:
    return _NAMED_TAGS.get(str(name), -1)
