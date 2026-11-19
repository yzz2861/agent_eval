"""Architecture descriptions for the first supported set of targets.

Only a small, explicit set of architectures is supported in the first
version.  Objects built for other machines are still parsed read-only, but
their findings are reported with an ``unsupported_architecture`` evidence gap
instead of speculative pointer interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Architecture:
    """Static properties needed to interpret table fields."""

    machine: str
    elfclass: int
    little_endian: bool
    pointer_sizes: frozenset[int]

    def supports_width(self, width: int) -> bool:
        return width in self.pointer_sizes


_SUPPORTED: dict[tuple[str, int], Architecture] = {
    ("EM_386", 32): Architecture(
        machine="EM_386",
        elfclass=32,
        little_endian=True,
        pointer_sizes=frozenset({1, 2, 4}),
    ),
    ("EM_X86_64", 64): Architecture(
        machine="EM_X86_64",
        elfclass=64,
        little_endian=True,
        pointer_sizes=frozenset({1, 2, 4, 8}),
    ),
    ("EM_ARM", 32): Architecture(
        machine="EM_ARM",
        elfclass=32,
        little_endian=True,
        pointer_sizes=frozenset({1, 2, 4}),
    ),
    ("EM_AARCH64", 64): Architecture(
        machine="EM_AARCH64",
        elfclass=64,
        little_endian=True,
        pointer_sizes=frozenset({1, 2, 4, 8}),
    ),
    ("EM_RISCV", 32): Architecture(
        machine="EM_RISCV",
        elfclass=32,
        little_endian=True,
        pointer_sizes=frozenset({1, 2, 4}),
    ),
    ("EM_RISCV", 64): Architecture(
        machine="EM_RISCV",
        elfclass=64,
        little_endian=True,
        pointer_sizes=frozenset({1, 2, 4, 8}),
    ),
}


def describe(machine: str, elfclass: int) -> Architecture | None:
    """Return the supported architecture description, or ``None``."""
    return _SUPPORTED.get((machine, elfclass))
