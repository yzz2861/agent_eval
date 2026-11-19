# SPDX-License-Identifier: Apache-2.0
"""Scan coverage accounting.

The gate must distinguish "scanned and clean" from "never scanned".  This
module reconciles three things:

* the directories the team actually intended to scan (the scan manifest),
* the files that were successfully scanned in the current run,
* the errors/skips reported by Bandit for files that could not be scanned.

A directory whose scan failed, or that never appeared in the run, is surfaced
as :data: instead of being implicitly treated as
clean.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from bandit.takeover import paths as path_utils

LOG = logging.getLogger(__name__)


class CoverageStatus(str, Enum):
    """Coverage state of a single intended scan directory."""

    SCANNED = "scanned"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_SCANNED = "not_scanned"
    UNKNOWN_RISK = "unknown_risk"


@dataclass
class DirectoryCoverage:
    """Coverage outcome for one directory listed in the scan manifest."""

    directory: str
    status: CoverageStatus
    scanned_files: List[str] = field(default_factory=list)
    failed_files: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    @property
    def risk_unknown(self) -> bool:
        """True when the gate cannot make any claim about this directory."""
        return self.status in (
            CoverageStatus.FAILED,
            CoverageStatus.NOT_SCANNED,
            CoverageStatus.UNKNOWN_RISK,
            CoverageStatus.PARTIAL,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "directory": self.directory,
            "status": self.status.value,
            "risk_unknown": self.risk_unknown,
            "scanned_file_count": len(self.scanned_files),
            "failed_file_count": len(self.failed_files),
            "failed_files": list(self.failed_files),
            "reasons": list(self.reasons),
        }


class CoverageTracker:
    """Reconcile the scan manifest against what the run actually covered."""

    def __init__(self, manifest_directories=None) -> None:
        self.directories = [
            path_utils.normalize_path(d) for d in (manifest_directories or [])
        ]

    @classmethod
    def from_scan_report(
        cls, scan_report: Dict[str, Any], fallback_directories=None
    ) -> "CoverageTracker":
        """Build a tracker from a current Bandit JSON report.

        The manifest is taken from an explicit scan_manifest extension
        field when present, otherwise from the caller-supplied fallback list,
        and finally from the common prefix of the files seen in the run.
        """
        manifest = scan_report.get("scan_manifest") or list(
            fallback_directories or []
        )
        if not manifest:
            scanned = [
                r.get("filename", "")
                for r in scan_report.get("results", [])
            ]
            errored = [
                e.get("filename", "")
                for e in scan_report.get("errors", [])
            ]
            manifest = cls._common_directories(scanned + errored)
        return cls(manifest)

    @staticmethod
    def _common_directories(paths: List[str]) -> List[str]:
        dirs = set()
        for path in paths:
            normalized = path_utils.normalize_path(path)
            if normalized:
                dirs.add(normalized.rsplit("/", 1)[0] or normalized)
        return sorted(dirs)

    def evaluate(
        self,
        scanned_files: List[str],
        errors: Optional[List[Dict[str, str]]] = None,
    ) -> List[DirectoryCoverage]:
        """Classify every manifest directory using the run evidence.

        :param scanned_files: Files Bandit parsed successfully (their metrics
            appear in the report even when they have zero findings).
        :param errors: Entries from the report errors array, each with
            filename and reason.
        """
        errors = errors or []
        scanned_norm = {path_utils.normalize_path(f) for f in scanned_files}
        failed_norm = {
            path_utils.normalize_path(e.get("filename", "")): str(
                e.get("reason", "unknown error")
            )
            for e in errors
        }
        coverages = []
        for directory in self.directories:
            scanned_here = sorted(
                f for f in scanned_norm if path_utils.is_within(directory, f)
            )
            failed_here = sorted(
                f for f in failed_norm if path_utils.is_within(directory, f)
            )
            coverages.append(
                self._classify(
                    directory, scanned_here, failed_here, failed_norm
                )
            )
        return coverages

    @staticmethod
    def _classify(directory, scanned_here, failed_here, failed_reasons):
        reasons = [
            f"{fname}: {failed_reasons[fname]}" for fname in failed_here
        ]
        if scanned_here and not failed_here:
            status = CoverageStatus.SCANNED
        elif scanned_here and failed_here:
            status = CoverageStatus.PARTIAL
        elif failed_here:
            status = CoverageStatus.FAILED
        else:
            status = CoverageStatus.NOT_SCANNED
            reasons.append(
                "directory listed in scan manifest but absent from this run"
            )
        return DirectoryCoverage(
            directory=directory,
            status=status,
            scanned_files=scanned_here,
            failed_files=failed_here,
            reasons=reasons,
        )
