"""Manual parser for raw delay-import byte fragments.

A fragment is a small dump whose first byte corresponds to
``base_rva``. The same structural rules as the on-disk PE apply, but no
section headers or data directories exist; the caller points the parser at
the delay directory RVA and it walks descriptors and thunks directly.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

from .loader import LoadedInput, LoaderError
from .model import Evidence, EvidenceKind, EvidenceLevel

DESCRIPTOR_FIELDS = 8
DESCRIPTOR_SIZE = 32


def _ev(level, kind, location, rva, value, detail):
    return Evidence(
        level=level, kind=kind, location=location,
        rva=rva, value=value, detail=detail,
    )


def read_descriptor(loaded: LoadedInput, rva: int) -> dict:
    raw = loaded.read(rva, DESCRIPTOR_SIZE)
    fields = ("grAttrs", "szName", "phmod", "pIAT", "pINT",
              "pBoundIAT", "pUnloadIAT", "dwTimeStamp")
    return dict(zip(fields, struct.unpack("<8I", raw)))


def walk_delay_directory(loaded: LoadedInput, directory_rva: int,
                         max_descriptors: int = 64) -> List[Tuple[int, dict]]:
    descriptors = []
    rva = directory_rva
    for _ in range(max_descriptors):
        desc = read_descriptor(loaded, rva)
        if all(value == 0 for value in desc.values()):
            break
        descriptors.append((rva, desc))
        rva += DESCRIPTOR_SIZE
    return descriptors


def read_thunk(loaded: LoadedInput, rva: int) -> int:
    return loaded.read_pointer(rva)


def is_ordinal(value: int, is_64bit: bool) -> bool:
    flag = 0x8000000000000000 if is_64bit else 0x80000000
    return bool(value & flag)


def ordinal_of(value: int) -> int:
    return value & 0xFFFF


def describe_slot(loaded, slot_rva, int_rva, index):
    """Classify one pIAT/pINT slot pair inside a fragment."""
    nodes = []
    iat_value = read_thunk(loaded, slot_rva)
    int_value = read_thunk(loaded, int_rva)
    if is_ordinal(iat_value, loaded.is_64bit) or is_ordinal(int_value, loaded.is_64bit):
        value = iat_value if is_ordinal(iat_value, loaded.is_64bit) else int_value
        level = (EvidenceLevel.L4_THUNK_TABLE
                 if is_ordinal(iat_value, loaded.is_64bit)
                 else EvidenceLevel.L3_NAME_TABLE)
        nodes.append(_ev(
            level, EvidenceKind.INDEX_ONLY,
            "thunk[%d]" % index, slot_rva, value,
            "ordinal-only slot, index %d" % ordinal_of(value),
        ))
        return nodes
    if iat_value == 0:
        nodes.append(_ev(
            EvidenceLevel.L4_THUNK_TABLE, EvidenceKind.RUNTIME_UNRESOLVED,
            "thunk[%d]" % index, slot_rva, 0,
            "empty slot; loader writes the target address at first call",
        ))
        return nodes
    if loaded.contains_rva(iat_value):
        detail = "file-resident hint/name RVA"
    else:
        detail = "bound VA 0x%x recorded at bind time" % iat_value
    nodes.append(_ev(
        EvidenceLevel.L4_THUNK_TABLE, EvidenceKind.FILE_POINTER,
        "thunk[%d]" % index, slot_rva, iat_value, detail,
    ))
    return nodes


