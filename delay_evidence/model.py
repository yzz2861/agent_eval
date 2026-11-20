"""Evidence model for the read-only delay-import / load-config view.

Every piece of evidence is classified into one of three buckets:

* ``FILE_POINTER`` - a target pointer that physically exists in the bytes
  of the file (an RVA/VA value stored in a directory entry, table slot or
  hint/name structure), i.e. something the static file can prove on its own.
* ``INDEX_ONLY`` - a table slot that keeps nothing but an ordinal/index;
  the file can prove the table position but not which target it resolves to.
* ``RUNTIME_UNRESOLVED`` - a slot whose meaningful content is produced by the
  loader at process start (module handle, patched IAT value, indirect guard
  function pointer target). The file only contains a placeholder or an
  indirect pointer, so the runtime target cannot be explained statically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class EvidenceKind(str, Enum):
    """How strongly the static file can prove a slot's target."""

    FILE_POINTER = "FILE_POINTER"
    INDEX_ONLY = "INDEX_ONLY"
    RUNTIME_UNRESOLVED = "RUNTIME_UNRESOLVED"


class EvidenceLevel(str, Enum):
    """Stages along the delay-load transfer path, outer to inner."""

    L1_DIRECTORY = "L1_DELAY_DIRECTORY"
    L2_DESCRIPTOR = "L2_DELAY_DESCRIPTOR"
    L3_NAME_TABLE = "L3_NAME_TABLE"
    L4_THUNK_TABLE = "L4_THUNK_TABLE"
    L5_BOUND_TABLE = "L5_BOUND_IAT"
    L6_UNLOAD_TABLE = "L6_UNLOAD_IAT"
    L7_MODULE_HANDLE = "L7_MODULE_HANDLE_SLOT"
    L8_LOAD_CONFIG = "L8_LOAD_CONFIG"
    L9_CODE_REFERENCE = "L9_CODE_REFERENCE"


LEVEL_DESCRIPTIONS = {
    EvidenceLevel.L1_DIRECTORY: "Data-directory entry pointing at the delay import directory",
    EvidenceLevel.L2_DESCRIPTOR: "IMAGE_DELAYLOAD_DESCRIPTOR for one delay-loaded DLL",
    EvidenceLevel.L3_NAME_TABLE: "Import Name Table (pINT): hint/name pointers or ordinals",
    EvidenceLevel.L4_THUNK_TABLE: "Import Address Table (pIAT): thunk slots patched at runtime",
    EvidenceLevel.L5_BOUND_TABLE: "Bound IAT (pBoundIAT): pre-resolved addresses from bind time",
    EvidenceLevel.L6_UNLOAD_TABLE: "Unload IAT (pUnloadIAT): clean copy used on unload",
    EvidenceLevel.L7_MODULE_HANDLE: "phmod slot: receives the loaded module base address",
    EvidenceLevel.L8_LOAD_CONFIG: "Load config cross-references (guard tables / guard pointers)",
    EvidenceLevel.L9_CODE_REFERENCE: "Code references (relocations / thunk scans) into the IAT",
}


@dataclass
class Evidence:
    """A single provable structure on the transfer path."""

    level: EvidenceLevel
    kind: EvidenceKind
    location: str
    rva: Optional[int]
    value: Optional[int]
    detail: str
    removed: bool = False

    def format_value(self) -> str:
        if self.value is None:
            return "-"
        return f"0x{self.value:x}"


@dataclass
class SymbolEvidence:
    """Evidence chain for one delay-imported symbol."""

    dll: str
    symbol: str
    by_ordinal: bool
    ordinal: Optional[int]
    iat_rva: Optional[int]
    int_rva: Optional[int]
    chain: List[Evidence] = field(default_factory=list)

    @property
    def broken_level(self) -> Optional[EvidenceLevel]:
        missing = [node for node in self.chain if node.removed]
        if not missing:
            return None
        order = list(EvidenceLevel)
        return sorted(missing, key=lambda node: order.index(node.level))[0].level

    @property
    def still_viable(self) -> bool:
        return self.broken_level is None


@dataclass
class ModuleEvidence:
    """Evidence collected for one delay-loaded DLL."""

    dll: str
    descriptor_rva: Optional[int]
    module_evidence: List[Evidence] = field(default_factory=list)
    symbols: List[SymbolEvidence] = field(default_factory=list)

    @property
    def broken_level(self) -> Optional[EvidenceLevel]:
        broken = [
            symbol.broken_level
            for symbol in self.symbols
            if symbol.broken_level is not None
        ]
        order = list(EvidenceLevel)
        if broken:
            return sorted(broken, key=lambda level: order.index(level))[0]
        module_broken = [node for node in self.module_evidence if node.removed]
        if module_broken:
            return sorted(
                module_broken, key=lambda node: order.index(node.level)
            )[0].level
        return None

    @property
    def viable_symbols(self) -> List[SymbolEvidence]:
        return [symbol for symbol in self.symbols if symbol.still_viable]


@dataclass
class LoadConfigSummary:
    """Read-only snapshot of the load-config structures relevant to the path."""

    rva: Optional[int]
    size: int
    guard_flags: Optional[int]
    guard_cf_check_slot: Optional[int]
    guard_cf_dispatch_slot: Optional[int]
    guard_cf_table: Optional[int]
    guard_cf_count: int
    guard_address_taken_iat_table: Optional[int]
    guard_address_taken_iat_count: int
    guard_long_jump_table: Optional[int]
    guard_long_jump_count: int
    guard_eh_continuation_table: Optional[int]
    guard_eh_continuation_count: int


@dataclass
class AnalysisResult:
    """Full analysis output for one input image or fragment."""

    source: str
    machine: str
    image_base: Optional[int]
    is_fragment: bool
    load_config: Optional[LoadConfigSummary]
    modules: List[ModuleEvidence]
    warnings: List[str] = field(default_factory=list)
    removed_targets: List[str] = field(default_factory=list)

    def walk_evidence(self):
        for module in self.modules:
            for node in module.module_evidence:
                yield module, None, node
            for symbol in module.symbols:
                for node in symbol.chain:
                    yield module, symbol, node
