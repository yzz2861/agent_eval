"""Offline, evidence-preserving ELF hardening audit built on pyelftools.

The audit never executes the target binary. Every verdict is backed by
explicit byte ranges taken from one of three legal ELF views:

* segment view  - PT_* program headers (survives full strip)
* dynamic view  - PT_DYNAMIC / .dynamic entries (dynamic programs only)
* section view  - SHT_* section headers (optional)
"""

from .audit import ALL_RULES, audit_bytes, audit_elf, audit_stream, report_as_dict
from .model import AuditReport, Evidence, Range, RuleId, RuleResult, Status, ViewKind

__all__ = [
    "RuleId",
    "Status",
    "ViewKind",
    "AuditReport",
    "RuleResult",
    "Evidence",
    "Range",
    "ALL_RULES",
    "audit_stream",
    "audit_elf",
    "audit_bytes",
    "report_as_dict",
]
