"""Read-only ELF function-table field attribution auditing.

Given a table section, field width and slot range, decide which slots hold
provable symbol references through relocations, which are only candidates,
and which remain evidence gaps.  Relocations are never applied and no code
is loaded; every conclusion carries its source evidence.
"""

from .arch import Architecture, describe
from .audit import AuditResult, AuditTable, FieldVerdict, classify_fields
from .model import RelocEvidence, RelocForm, VerdictKind
from .parser import ArchiveMember, ArchiveFormatError, iter_archive_members, open_elf_inputs

__all__ = [
    "Architecture",
    "ArchiveFormatError",
    "ArchiveMember",
    "AuditResult",
    "AuditTable",
    "FieldVerdict",
    "RelocEvidence",
    "RelocForm",
    "VerdictKind",
    "classify_fields",
    "describe",
    "iter_archive_members",
    "open_elf_inputs",
]

__version__ = "0.1.0"
