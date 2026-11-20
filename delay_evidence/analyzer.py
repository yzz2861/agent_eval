"""Static evidence-chain analysis for delay-load transfer paths."""

from __future__ import annotations

from typing import List, Optional

from . import code_refs, fragment, load_config, pe_analysis
from .loader import LoadedInput
from .model import (
    AnalysisResult,
    Evidence,
    EvidenceKind,
    EvidenceLevel,
    ModuleEvidence,
)



def _safe_read_pointer(loaded, rva):
    if not loaded.contains_rva(rva):
        return None
    return loaded.read_pointer(rva)



def _scan_descriptors(loaded):
    """Locate delay descriptors inside a fragment by structural validation."""
    found = []
    span = len(loaded.data)
    for offset in range(0, span - 32 + 1):
        rva = loaded.base_rva + offset
        try:
            desc = fragment.read_descriptor(loaded, rva)
        except Exception:  # noqa: BLE001
            continue
        if desc["grAttrs"] not in (0, 1):
            continue
        if not desc["phmod"] or desc["pIAT"] == desc["pINT"]:
            continue
        if desc["pIAT"] == desc["szName"] or desc["pINT"] == desc["szName"]:
            continue
        pointers = (desc["szName"], desc["pIAT"], desc["pINT"], desc["pUnloadIAT"])
        if not all(loaded.contains_rva(value) for value in pointers if value):
            continue
        try:
            loaded.read_cstring(desc["szName"])
        except Exception:  # noqa: BLE001
            continue
        found.append((rva, desc))
    return found


def _analyze_fragment(loaded, warnings):
    modules = []
    thunk_size = 8 if loaded.is_64bit else 4
    for descriptor_rva, desc in _scan_descriptors(loaded):
        name_rva = desc["szName"]
        try:
            dll = loaded.read_cstring(name_rva)
        except Exception:  # noqa: BLE001
            dll = "<unresolved@0x%x>" % name_rva
            warnings.append("DLL name RVA 0x%x is outside the fragment" % name_rva)
        module = ModuleEvidence(dll=dll, descriptor_rva=descriptor_rva)
        module.module_evidence.append(Evidence(
            level=EvidenceLevel.L2_DESCRIPTOR,
            kind=EvidenceKind.FILE_POINTER,
            location="IMAGE_DELAYLOAD_DESCRIPTOR.szName",
            rva=descriptor_rva + 4,
            value=name_rva,
            detail="file-resident RVA of the DLL name string",
        ))
        module.module_evidence.append(Evidence(
            level=EvidenceLevel.L7_MODULE_HANDLE,
            kind=EvidenceKind.RUNTIME_UNRESOLVED,
            location="IMAGE_DELAYLOAD_DESCRIPTOR.phmod",
            rva=descriptor_rva + 8,
            value=desc["phmod"],
            detail="module handle slot filled by loader; not provable in a dump",
        ))
        index = 0
        while True:
            iat_rva = desc["pIAT"] + index * thunk_size
            int_rva = desc["pINT"] + index * thunk_size
            iat_value = _safe_read_pointer(loaded, iat_rva)
            if iat_value is None or (iat_value == 0 and index > 0):
                break
            try:
                nodes = fragment.describe_slot(loaded, iat_rva, int_rva, index)
            except Exception:  # noqa: BLE001
                break
            from .model import SymbolEvidence
            module.symbols.append(SymbolEvidence(
                dll=dll,
                symbol="slot[%d]" % index,
                by_ordinal=False,
                ordinal=None,
                iat_rva=iat_rva,
                int_rva=int_rva,
                chain=nodes,
            ))
            index += 1
            if index > 4096:
                break
        modules.append(module)
    return modules



def _delay_iat_rvas(result):
    rvas = set()
    for module in result.modules:
        for symbol in module.symbols:
            if symbol.iat_rva is not None:
                rvas.add(symbol.iat_rva)
    return rvas


def _analyze_pe(loaded, result):
    pe = loaded.pe
    result.load_config = load_config.summarize(loaded)
    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        return
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        module = pe_analysis.build_module_evidence(loaded, entry)
        result.modules.append(module)
    delay_iat_rvas = _delay_iat_rvas(result)
    guard_nodes = load_config.build_load_config_evidence(
        loaded, result.load_config, delay_iat_rvas
    )
    if guard_nodes and result.modules:
        target_module = result.modules[0]
        target_module.module_evidence.extend(guard_nodes)
    code_refs.build_code_references(loaded, result)


def analyze(loaded):
    """Build the full read-only evidence view for one input."""
    result = AnalysisResult(
        source=loaded.source,
        machine=loaded.machine,
        image_base=loaded.image_base,
        is_fragment=loaded.is_fragment,
        load_config=None,
        modules=[],
        warnings=[],
    )
    if loaded.is_fragment:
        result.modules = _analyze_fragment(loaded, result.warnings)
        return result
    _analyze_pe(loaded, result)
    return result
