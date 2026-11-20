"""Static code-reference scan: relocations pointing at delay IAT slots."""

from __future__ import annotations

from .model import Evidence, EvidenceKind, EvidenceLevel


def _relocation_rvas(loaded):
    pe = loaded.pe
    rvas = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return rvas
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.rva:
                rvas.add(entry.rva)
    return rvas


def build_code_references(loaded, result):
    """Attach L9 evidence where a relocation fixes up a delay IAT slot."""
    relocation_rvas = _relocation_rvas(loaded)
    slot_to_symbol = {}
    for module in result.modules:
        for symbol in module.symbols:
            if symbol.iat_rva is not None:
                slot_to_symbol[symbol.iat_rva] = (module, symbol)
    for slot_rva, (module, symbol) in sorted(slot_to_symbol.items()):
        if slot_rva in relocation_rvas:
            node = Evidence(
                level=EvidenceLevel.L9_CODE_REFERENCE,
                kind=EvidenceKind.FILE_POINTER,
                location=f"base relocation -> IAT slot 0x{slot_rva:x}",
                rva=slot_rva,
                value=slot_rva,
                detail=("file-resident relocation proves code/pointer data"
                        " references this delay IAT slot"),
            )
            symbol.chain.append(node)
        else:
            node = Evidence(
                level=EvidenceLevel.L9_CODE_REFERENCE,
                kind=EvidenceKind.RUNTIME_UNRESOLVED,
                location=f"no relocation for IAT slot 0x{slot_rva:x}",
                rva=slot_rva,
                value=None,
                detail=("no static relocation; the runtime helper resolves the"
                        " slot on demand, caller binding is not file-provable"),
            )
            symbol.chain.append(node)
