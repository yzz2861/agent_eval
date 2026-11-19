"""Bytecode-level guard verification across nested code objects."""

from __future__ import annotations

import collections
import dis
import platform
import sys
import types
import typing

from RestrictedPython.audit import (
    KNOWN_GUARDS,
    SUPPORTED_BYTECODE_VERSIONS,
    _LOAD_NAME_OPCODES,
)


def bytecode_version_supported(
        version: tuple[int, int] | None = None) -> bool:
    """Whether audit rules are reviewed for this bytecode version."""
    if version is None:
        version = (sys.version_info.major, sys.version_info.minor)
    if platform.python_implementation() != "CPython":
        return False
    return version in SUPPORTED_BYTECODE_VERSIONS


def iter_code_objects(code: types.CodeType) -> typing.Iterator[types.CodeType]:
    """Yield ``code`` and every nested code object, recursively."""
    yield code
    for constant in code.co_consts:
        if isinstance(constant, types.CodeType):
            yield from iter_code_objects(constant)


def count_guard_loads(
        code: types.CodeType) -> tuple[collections.Counter[str], bool]:
    """Count guard-name loads in every code object.

    Returns the per-guard totals and whether all instructions were
    recognisable.  An unknown (opcode 0) instruction makes the result
    untrustworthy.
    """
    counts: collections.Counter[str] = collections.Counter()
    recognisable = True
    for nested in iter_code_objects(code):
        for instruction in dis.get_instructions(nested):
            if instruction.opname.startswith("<"):
                recognisable = False
            if (instruction.opname in _LOAD_NAME_OPCODES
                    and instruction.argval in KNOWN_GUARDS):
                counts[instruction.argval] += 1
    return counts, recognisable
