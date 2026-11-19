# SPDX-License-Identifier: Apache-2.0
"""Reusable takeover adjudication layer for Bandit scan results.

This package sits between raw Bandit scan output and the reports consumed by
CI gates. It combines four inputs:

* the legacy findings ("old debt") carried in previous reports,
* severity/confidence escalations between the legacy and current scans,
* the scope that this scan actually completed (including failed directories),
* the path-ownership policy plus explicit directory handoff records.

Public entry points are imported lazily so that partial installations (for
example PyYAML missing) do not break simple imports of helper modules.
"""
from __future__ import annotations

__all__ = [
    "AdjudicationEngine",
    "AdjudicationReport",
    "Adjudication",
    "Disposition",
    "CoverageStatus",
    "HandoffLedger",
    "OwnershipPolicy",
    "Finding",
]


def __getattr__(name):
    if name == "AdjudicationEngine":
        from bandit.takeover.engine import AdjudicationEngine

        return AdjudicationEngine
    if name in {"AdjudicationReport", "Adjudication", "Disposition"}:
        from bandit.takeover import engine

        return getattr(engine, name)
    if name == "CoverageStatus":
        from bandit.takeover.coverage import CoverageStatus

        return CoverageStatus
    if name == "HandoffLedger":
        from bandit.takeover.ledger import HandoffLedger

        return HandoffLedger
    if name == "OwnershipPolicy":
        from bandit.takeover.ownership import OwnershipPolicy

        return OwnershipPolicy
    if name == "Finding":
        from bandit.takeover.models import Finding

        return Finding
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
