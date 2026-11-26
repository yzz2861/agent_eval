"""
Public entrypoints for differential audit attribution.

The implementation lives in :mod:`pip_audit._diff`; this module keeps the
user-facing import stable and mirrors the CLI's ``pip-audit diff`` capability.
"""

from __future__ import annotations

from pip_audit._diff import (
    AuditDiff,
    AuditResult,
    Attribution,
    DiffError,
    Direction,
    audit_result_from_dict,
    audit_results_from_bundle,
    diff,
    diff_audit_results,
    diff_audits,
    diff_main,
    diff_saved_audits,
    load_audit_result,
    load_audit_results,
)
from pip_audit._service import FreezeFixtureError, FreezeService

__all__ = [
    "AuditDiff",
    "AuditResult",
    "Attribution",
    "DiffError",
    "Direction",
    "FreezeFixtureError",
    "FreezeService",
    "audit_result_from_dict",
    "audit_results_from_bundle",
    "diff",
    "diff_audit_results",
    "diff_audits",
    "diff_main",
    "diff_saved_audits",
    "load_audit_result",
    "load_audit_results",
]


if __name__ == "__main__":  # pragma: no cover
    diff_main()
