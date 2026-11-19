"""Deterministic, offline fuzzing harness with a fixed seed.

The harness applies a reproducible sequence of structure-preserving
mutations to a synthetic mini PE and yields every intermediate sample with
its :class:`~pefuzz.records.MutationRecord`.  No network access or external
corpus is required; the RNG seed makes the whole run replayable.
"""

import random

from .builder import build_mini_pe
from . import mutators


DEFAULT_SEED = 0x5EED1234


class FuzzCase:
    """One generated sample plus the transformation that produced it."""

    def __init__(self, label, data, record):
        self.label = label
        self.data = data
        self.record = record

    def __repr__(self):
        return "FuzzCase(" + self.label + ", " + str(len(self.data)) + "B)"


def _renames():
    return [
        b"CreateFileW",
        b"ReadFile",
        b"WriteFile",
        b"CloseHandle",
        b"HeapAlloc",
    ]


def generate_cases(seed=DEFAULT_SEED, base=None):
    """Yield a deterministic, finite list of fuzz cases."""
    rng = random.Random(seed)
    if base is None:
        base = build_mini_pe(seed=seed)

    cases = []
    cases.append(FuzzCase("baseline", bytes(base), None))

    moved_raw, record = mutators.move_section_raw(
        bytes(base), ".rdata", 0xA00
    )
    cases.append(FuzzCase("move_section_raw", moved_raw, record))

    moved_dir, record = mutators.move_directory_payload(
        bytes(base), 0, ".text"
    )
    cases.append(FuzzCase("move_export_payload", moved_dir, record))

    renamed, record = mutators.replace_import_name(
        bytes(base), 0, 0, _renames()[rng.randrange(5)]
    )
    cases.append(FuzzCase("rename_import", renamed, record))

    reordered_imports, record = mutators.reorder_import_descriptors(bytes(base))
    cases.append(
        FuzzCase("reorder_imports", reordered_imports, record)
    )

    reordered_resources, record = mutators.reorder_resource_entries(
        bytes(base), level=0
    )
    cases.append(
        FuzzCase("reorder_resources", reordered_resources, record)
    )

    reordered_debug, record = mutators.reorder_debug_entries(bytes(base))
    cases.append(FuzzCase("reorder_debug", reordered_debug, record))

    breakages = [
        ("break_dos_magic", lambda blob: mutators.break_dos_magic(blob)),
        (
            "break_raw_pointer",
            lambda blob: mutators.break_section_raw_pointer(blob, ".rdata"),
        ),
        (
            "break_directory_rva",
            lambda blob: mutators.break_directory_rva(blob, 1),
        ),
        (
            "break_import_name_rva",
            lambda blob: mutators.break_import_name_rva(blob, 0),
        ),
        (
            "break_resource_depth",
            lambda blob: mutators.break_resource_depth(blob),
        ),
    ]
    for label, operation in breakages:
        broken, record = operation(bytes(base))
        cases.append(FuzzCase(label, broken, record))

    return cases
