"""Load-config directory: read-only summary and guard table cross-refs."""

from __future__ import annotations

from .model import (
    Evidence,
    EvidenceKind,
    EvidenceLevel,
    LoadConfigSummary,
)


def _attr(struct, name, default=0):
    return getattr(struct, name, default)


def summarize(loaded):
    pe = loaded.pe
    if not hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        return None
    container = pe.DIRECTORY_ENTRY_LOAD_CONFIG
    struct = container.struct
    return LoadConfigSummary(
        rva=pe.get_rva_from_offset(struct.get_file_offset()),
        size=_attr(struct, "Size"),
        guard_flags=_attr(struct, "GuardFlags", None),
        guard_cf_check_slot=_attr(struct, "GuardCFCheckFunctionPointer", None) or None,
        guard_cf_dispatch_slot=_attr(struct, "GuardCFDispatchFunctionPointer", None) or None,
        guard_cf_table=_attr(struct, "GuardCFFunctionTable", None) or None,
        guard_cf_count=_attr(struct, "GuardCFFunctionCount", 0),
        guard_address_taken_iat_table=_attr(struct, "GuardAddressTakenIatEntryTable", None) or None,
        guard_address_taken_iat_count=_attr(struct, "GuardAddressTakenIatEntryCount", 0),
        guard_long_jump_table=_attr(struct, "GuardLongJumpTargetTable", None) or None,
        guard_long_jump_count=_attr(struct, "GuardLongJumpTargetCount", 0),
        guard_eh_continuation_table=_attr(struct, "GuardEHContinuationTable", None) or None,
        guard_eh_continuation_count=_attr(struct, "GuardEHContinuationCount", 0),
    )


def _guard_pointer_evidence(loaded, summary):
    """GuardCF check/dispatch pointers are indirect: RVA -> slot -> VA."""
    nodes = []
    mapping = (
        ("GuardCFCheckFunctionPointer", summary.guard_cf_check_slot),
        ("GuardCFDispatchFunctionPointer", summary.guard_cf_dispatch_slot),
    )
    for field_name, slot_rva in mapping:
        if not slot_rva:
            continue
        nodes.append(Evidence(
            level=EvidenceLevel.L8_LOAD_CONFIG,
            kind=EvidenceKind.FILE_POINTER,
            location=f"LOAD_CONFIG.{field_name}",
            rva=slot_rva,
            value=slot_rva,
            detail=("file-resident RVA naming the guard pointer slot; the slot"
                    " itself is filled by the loader"),
        ))
        if loaded.contains_rva(slot_rva):
            target = loaded.read_pointer(slot_rva)
            if target == 0:
                nodes.append(Evidence(
                    level=EvidenceLevel.L8_LOAD_CONFIG,
                    kind=EvidenceKind.RUNTIME_UNRESOLVED,
                    location=f"{field_name} target slot",
                    rva=slot_rva,
                    value=0,
                    detail="indirect guard pointer slot is empty on disk",
                ))
            else:
                nodes.append(Evidence(
                    level=EvidenceLevel.L8_LOAD_CONFIG,
                    kind=EvidenceKind.FILE_POINTER,
                    location=f"{field_name} target slot",
                    rva=slot_rva,
                    value=target,
                    detail=f"slot holds VA 0x{target:x} (image-base relative)",
                ))
    return nodes


def _guard_iat_table_evidence(loaded, summary, delay_iat_rvas):
    nodes = []
    table_rva = summary.guard_address_taken_iat_table
    count = summary.guard_address_taken_iat_count
    if not table_rva or not count:
        return nodes
    nodes.append(Evidence(
        level=EvidenceLevel.L8_LOAD_CONFIG,
        kind=EvidenceKind.FILE_POINTER,
        location="LOAD_CONFIG.GuardAddressTakenIatEntryTable",
        rva=table_rva,
        value=table_rva,
        detail=f"file-resident RVA of guard IAT table ({count} entries)",
    ))
    for index in range(min(count, 1024)):
        entry_rva = table_rva + index * (8 if loaded.is_64bit else 4)
        if not loaded.contains_rva(entry_rva):
            break
        target = loaded.read_pointer(entry_rva)
        linked = target in delay_iat_rvas
        nodes.append(Evidence(
            level=EvidenceLevel.L8_LOAD_CONFIG,
            kind=EvidenceKind.FILE_POINTER,
            location=f"GuardAddressTakenIatEntry[{index}]",
            rva=entry_rva,
            value=target,
            detail=("file-resident RVA to a delay IAT slot" if linked
                    else "file-resident RVA to an IAT slot"),
        ))
    return nodes


def build_load_config_evidence(loaded, summary, delay_iat_rvas):
    if summary is None:
        return []
    nodes = _guard_pointer_evidence(loaded, summary)
    nodes.extend(_guard_iat_table_evidence(loaded, summary, delay_iat_rvas))
    return nodes
