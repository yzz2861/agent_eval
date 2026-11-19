"""Core field attribution auditing on top of pyelftools.

The audit never applies relocations or loads code.  It reads section bytes,
symbol tables and relocation sections through pyelftools and explains every
field with the source evidence behind the verdict.
"""

from __future__ import annotations

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .arch import describe as get_arch_profile
from .model import (
    AuditResult,
    AuditTable,
    FieldVerdict,
    OverlapNote,
    RelocEvidence,
    RelocForm,
    VerdictKind,
)



def _struct_format(elf: ELFFile, width: int) -> str:
    if width not in (1, 2, 4, 8):
        raise ValueError(f"unsupported field width {width}; expected 1, 2, 4 or 8")
    if width == 1:
        return "B"
    prefix = "<" if elf.little_endian else ">"
    letter = {2: "H", 4: "I", 8: "Q"}[width]
    return prefix + letter


def _symbol_tables(elf: ELFFile) -> list[SymbolTableSection]:
    return [s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)]


def _resolve_symbol(elf: ELFFile, sym_index: int):
    for table in _symbol_tables(elf):
        if 0 <= sym_index < table.num_symbols():
            symbol = table.get_symbol(sym_index)
            return table, symbol
    return None, None


def _symbol_section_name(symbol) -> str | None:
    if symbol is None:
        return None
    shndx = symbol["st_shndx"]
    if isinstance(shndx, str):
        return shndx
    return f"section#{shndx}"


def _build_reloc_index(elf: ELFFile, section_name: str):
    """Map section-relative offsets to relocation evidence for one section."""
    by_offset: dict[int, list[RelocEvidence]] = {}
    forms: list[str] = []
    for reloc_section in elf.iter_sections():
        if not isinstance(reloc_section, RelocationSection):
            continue
        # SHT_REL(A): sh_info names the target section, sh_link the symtab.
        target_index = reloc_section["sh_info"]
        linked = elf.get_section(target_index) if target_index else None
        if linked is None or linked.name != section_name:
            continue
        form = RelocForm.RELA if reloc_section.is_RELA() else RelocForm.REL
        forms.append(form.value)
        for index, reloc in enumerate(reloc_section.iter_relocations()):
            sym_index = reloc["r_info_sym"]
            table, symbol = _resolve_symbol(elf, sym_index)
            sym_name = symbol.name if symbol is not None else None
            if form is RelocForm.RELA:
                addend = reloc["r_addend"]
                addend_source = "r_addend (RELA inline)"
            else:
                addend = None
                addend_source = "not available in REL; addend lives in the field bytes"
            note = None
            if symbol is None:
                note = "symbol index not present in any SHT_SYMTAB section"
            elif symbol["st_shndx"] == "SHN_UNDEF":
                note = "symbol is undefined in this object; resolution expected at link time"
            evidence = RelocEvidence(
                reloc_section=reloc_section.name,
                entry_index=index,
                form=form,
                r_offset=reloc["r_offset"],
                r_info_type=reloc["r_info_type"],
                r_info_type_name=str(reloc["r_info_type"]),
                r_info_sym=sym_index,
                symbol_name=sym_name,
                symbol_section=_symbol_section_name(symbol),
                symbol_index=sym_index,
                addend=addend,
                addend_source=addend_source,
                note=note,
            )
            by_offset.setdefault(reloc["r_offset"], []).append(evidence)
    return by_offset, forms

def _classify_field(width: int, raw_value: int, relocs: list[RelocEvidence],
                    arch_supported: bool) -> tuple[VerdictKind, list[str]]:
    if not relocs:
        if raw_value == 0:
            return VerdictKind.GAP, [
                "all field bytes are zero and no relocation references the field; genuinely empty"
            ]
        return VerdictKind.GAP, [
            "non-zero raw bytes without an explaining relocation; no attribution basis"
        ]
    reasons: list[str] = []
    candidate_only = False
    for evidence in relocs:
        head = f"{evidence.reloc_section}[{evidence.entry_index}]: {evidence.form.value}"
        if evidence.symbol_name:
            reasons.append(f"{head} -> named symbol {evidence.symbol_name!r} (symbol index {evidence.symbol_index})")
            if evidence.note is not None:
                # Named but e.g. SHN_UNDEF: the reference itself is provable, the
                # link-time resolution is a separate caveat, not a downgrade.
                reasons.append(f"{head}: {evidence.note}")
        else:
            candidate_only = True
            reasons.append(f"{head}: unnamed/special symbol index {evidence.symbol_index}; target cannot be proven here")
    if not arch_supported:
        candidate_only = True
        reasons.append("target architecture is outside the validated first-version set; relocation semantics not validated")
    if candidate_only:
        return VerdictKind.CANDIDATE, reasons
    return VerdictKind.PROVEN, reasons


def _read_raw(section, offset: int, width: int, struct_format: str) -> tuple[str, int]:
    import struct as _struct

    blob = section.data()
    chunk = blob[offset:offset + width]
    if len(chunk) != width:
        raise ValueError(f"field at section offset {offset} exceeds section size {section['sh_size']}")
    if width == 1:
        value = chunk[0]
    else:
        value = _struct.unpack(struct_format, chunk)[0]
    return chunk.hex(), value

def _detect_overlaps(tables: list[AuditTable]) -> list[OverlapNote]:
    notes: list[OverlapNote] = []
    for i, table_a in enumerate(tables):
        for table_b in tables[i + 1:]: 
            if table_a.section_name != table_b.section_name:
                continue
            shared_start = max(table_a.byte_start, table_b.byte_start)
            shared_end = min(table_a.byte_end, table_b.byte_end)
            if shared_start < shared_end:
                notes.append(OverlapNote(
                    range_a=table_a.range_name,
                    range_b=table_b.range_name,
                    section_name=table_a.section_name,
                    first_shared_offset=shared_start,
                    detail=(
                        f"ranges {table_a.range_name!r} and {table_b.range_name!r} both claim "
                        f"section bytes [{shared_start:#x}, {shared_end:#x}); the analyst-provided ranges overlap"
                    ),
                ))
    return notes


def _overlap_labels(tables: list[AuditTable], section_name: str,
                    byte_start: int, byte_end: int) -> list[str]:
    labels: list[str] = []
    for table in tables:
        if table.section_name != section_name:
            continue
        if max(byte_start, table.byte_start) < min(byte_end, table.byte_end):
            labels.append(table.range_name)
    return labels

def audit_member(elf: ELFFile, source: str, member_name: str | None,
                 tables: list[AuditTable]) -> AuditResult:
    profile = get_arch_profile(elf["e_machine"], elf.elfclass)
    result = AuditResult(
        source=source,
        member_name=member_name,
        machine=str(elf["e_machine"]),
        elf_class=elf.elfclass,
        endianness="little" if elf.little_endian else "big",
        arch_supported=profile is not None,
        tables=list(tables),
    )
    if profile is None:
        result.warnings.append(
            f"machine {elf['e_machine']} is not in the validated set; relocations stay candidates"
        )
    result.overlaps.extend(_detect_overlaps(tables))

    seen_reloc_forms: set[str] = set()
    for table in tables:
        section = elf.get_section_by_name(table.section_name)
        if section is None:
            result.warnings.append(f"{table.range_name}: section {table.section_name!r} not found")
            continue
        if table.byte_end > section["sh_size"]:
            result.warnings.append(
                f"{table.range_name}: range [{table.byte_start:#x},{table.byte_end:#x}) exceeds {table.section_name} size {section['sh_size']:#x}"
            )
            continue
        reloc_index, forms = _build_reloc_index(elf, table.section_name)
        seen_reloc_forms.update(forms)
        struct_format = _struct_format(elf, table.field_width)
        for slot in range(table.field_count):
            field_index = table.start_field + slot
            offset = field_index * table.field_width
            raw_hex, raw_value = _read_raw(section, offset, table.field_width, struct_format)
            relocs = list(reloc_index.get(offset, ()))
            kind, reasons = _classify_field(table.field_width, raw_value, relocs, profile is not None)
            labels = _overlap_labels(tables, table.section_name, offset, offset + table.field_width)
            result.fields.append(FieldVerdict(
                field_index=field_index,
                section_name=table.section_name,
                section_offset=offset,
                width=table.field_width,
                raw_bytes_hex=raw_hex,
                raw_value=raw_value,
                kind=kind,
                relocations=tuple(relocs),
                reasons=tuple(reasons),
                group_id=table.range_name,
                overlaps=tuple(label for label in labels if label != table.range_name),
            ))
    for form in sorted(seen_reloc_forms):
        result.warnings.append(f"relocation representation observed: {form}")
    return result

def classify_fields(path: str, tables: list[AuditTable]) -> list[AuditResult]:
    """Audit one relocatable object or every ELF member of an ar archive.

    ``tables`` are analyst-provided descriptions: section name, field width,
    start slot and slot count.  The function opens inputs read-only through
    pyelftools and never applies a relocation.
    """
    from .parser import open_elf_inputs

    results: list[AuditResult] = []
    for member_name, elf, source in open_elf_inputs(path):
        results.append(audit_member(elf, source=source, member_name=member_name, tables=tables))
    return results
