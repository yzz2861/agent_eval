"""Delay-import evidence chains for full PE images."""

from __future__ import annotations

from typing import List, Optional

import pefile

from .loader import LoadedInput
from .model import (
    Evidence,
    EvidenceKind,
    EvidenceLevel,
    ModuleEvidence,
    SymbolEvidence,
)


def _ev(level, kind, location, rva, value, detail):
    return Evidence(
        level=level,
        kind=kind,
        location=location,
        rva=rva,
        value=value,
        detail=detail,
    )


def _thunk_size(loaded):
    return 8 if loaded.is_64bit else 4


def _ordinal_flag(loaded):
    if loaded.is_64bit:
        return pefile.IMAGE_ORDINAL_FLAG64
    return pefile.IMAGE_ORDINAL_FLAG


def _module_level_evidence(loaded, desc, descriptor_rva):
    """L2/L6/L7 nodes that belong to the descriptor rather than a symbol."""
    nodes = []
    nodes.append(_ev(
        EvidenceLevel.L2_DESCRIPTOR, EvidenceKind.FILE_POINTER,
        "IMAGE_DELAYLOAD_DESCRIPTOR.szName", descriptor_rva + 4,
        desc.szName,
        "file-resident RVA of the DLL name string",
    ))
    nodes.append(_ev(
        EvidenceLevel.L7_MODULE_HANDLE, EvidenceKind.RUNTIME_UNRESOLVED,
        "IMAGE_DELAYLOAD_DESCRIPTOR.phmod", descriptor_rva + 8,
        desc.phmod,
        "phmod names a .data slot; the loader writes the module base at"
        " first load, no target is provable from the file",
    ))
    if desc.pUnloadIAT:
        nodes.append(_ev(
            EvidenceLevel.L6_UNLOAD_TABLE, EvidenceKind.FILE_POINTER,
            "IMAGE_DELAYLOAD_DESCRIPTOR.pUnloadIAT",
            descriptor_rva + 20, desc.pUnloadIAT,
            "file-resident RVA of the unload (clean copy) IAT",
        ))
    if desc.dwTimeStamp:
        nodes.append(_ev(
            EvidenceLevel.L5_BOUND_TABLE, EvidenceKind.FILE_POINTER,
            "IMAGE_DELAYLOAD_DESCRIPTOR.dwTimeStamp",
            descriptor_rva + 28, desc.dwTimeStamp,
            "non-zero timestamp marks a bound delay import",
        ))
    return nodes


def _int_node(loaded, symbol, int_rva, index):
    value = loaded.read_pointer(int_rva)
    if symbol.import_by_ordinal:
        return _ev(
            EvidenceLevel.L3_NAME_TABLE, EvidenceKind.INDEX_ONLY,
            f"INT[{index}]", int_rva, value,
            f"name table slot carries ordinal index {symbol.ordinal} only",
        )
    name = symbol.name
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="replace")
    return _ev(
        EvidenceLevel.L3_NAME_TABLE, EvidenceKind.FILE_POINTER,
        f"INT[{index}]", int_rva, value,
        f"file-resident RVA to hint/name blob (hint={symbol.hint}, name={name!r})",
    )


def _iat_node(loaded, symbol, iat_rva, index):
    value = loaded.read_pointer(iat_rva)
    if symbol.import_by_ordinal:
        return _ev(
            EvidenceLevel.L4_THUNK_TABLE, EvidenceKind.INDEX_ONLY,
            f"IAT[{index}]", iat_rva, value,
            f"thunk slot keeps ordinal index {symbol.ordinal} only; target unresolved",
        )
    if symbol.bound:
        return _ev(
            EvidenceLevel.L4_THUNK_TABLE, EvidenceKind.FILE_POINTER,
            f"IAT[{index}]", iat_rva, value,
            f"bound slot holds pre-resolved value 0x{value:x} from bind time",
        )
    if value == 0:
        return _ev(
            EvidenceLevel.L4_THUNK_TABLE, EvidenceKind.RUNTIME_UNRESOLVED,
            f"IAT[{index}]", iat_rva, 0,
            "empty slot; loader writes the target address on first call",
        )
    return _ev(
        EvidenceLevel.L4_THUNK_TABLE, EvidenceKind.FILE_POINTER,
        f"IAT[{index}]", iat_rva, value,
        "file-resident value (typically a copy of the INT hint/name RVA)",
    )


def _bound_iat_node(loaded, symbol, bound_rva, index):
    value = loaded.read_pointer(bound_rva)
    if symbol.import_by_ordinal:
        kind = EvidenceKind.INDEX_ONLY
        detail = f"bound slot for ordinal {symbol.ordinal}; index-only table entry"
    elif value == 0:
        kind = EvidenceKind.RUNTIME_UNRESOLVED
        detail = "bound table slot empty; no bind-time address recorded"
    else:
        kind = EvidenceKind.FILE_POINTER
        detail = f"bind-time address 0x{value:x} recorded in the file"
    return _ev(
        EvidenceLevel.L5_BOUND_TABLE, kind,
        f"BoundIAT[{index}]", bound_rva, value, detail,
    )


def _symbol_chain(loaded, desc, symbol, index):
    thunk_size = _thunk_size(loaded)
    iat_rva = desc.pIAT + index * thunk_size
    int_rva = desc.pINT + index * thunk_size
    name = symbol.name
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="replace")
    label = name if not symbol.import_by_ordinal else f"#{symbol.ordinal}"
    chain = [_int_node(loaded, symbol, int_rva, index)]
    chain.append(_iat_node(loaded, symbol, iat_rva, index))
    if desc.pBoundIAT:
        bound_rva = desc.pBoundIAT + index * thunk_size
        chain.append(_bound_iat_node(loaded, symbol, bound_rva, index))
    return SymbolEvidence(
        dll=None,
        symbol=label,
        by_ordinal=bool(symbol.import_by_ordinal),
        ordinal=symbol.ordinal,
        iat_rva=iat_rva,
        int_rva=int_rva,
        chain=chain,
    )


def build_module_evidence(loaded, entry):
    desc = entry.struct
    descriptor_rva = desc.get_file_offset()
    descriptor_rva = loaded.pe.get_rva_from_offset(descriptor_rva)
    dll = entry.dll
    if isinstance(dll, bytes):
        dll = dll.decode("ascii", errors="replace")
    module = ModuleEvidence(
        dll=dll,
        descriptor_rva=descriptor_rva,
        module_evidence=_module_level_evidence(loaded, desc, descriptor_rva),
    )
    for index, symbol in enumerate(entry.imports):
        symbol_evidence = _symbol_chain(loaded, desc, symbol, index)
        symbol_evidence.dll = dll
        module.symbols.append(symbol_evidence)
    return module
