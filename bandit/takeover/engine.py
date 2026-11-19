# SPDX-License-Identifier: Apache-2.0
"""Takeover adjudication engine.

The engine combines raw Bandit results with the ownership policy, the handoff
ledger and the legacy report to decide, for every finding, whether it is:

* legacy debt that may remain exempt from the blocking gate,
* a legacy finding whose severity (or confidence) was escalated,
* a legacy finding that crossed an ownership boundary without a handoff
  record (treated as new debt for the current owner),
* a genuinely new finding that must be fixed now.

It also records which legacy findings disappeared and which manifest
directories still carry unknown risk because their scan did not complete.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from bandit.takeover import paths as path_utils
from bandit.takeover.coverage import CoverageTracker
from bandit.takeover.ledger import Handoff, HandoffLedger
from bandit.takeover.models import Finding, severity_rank
from bandit.takeover.ownership import UNOWNED

LOG = logging.getLogger(__name__)


class Disposition(str, Enum):
    """Final adjudication of a finding against policy and history."""

    LEGACY_DEBT = "legacy_debt"
    ESCALATED = "escalated"
    CROSS_BOUNDARY_UNACCEPTED = "cross_boundary_unaccepted"
    NEW_FINDING = "new_finding"
    RESOLVED_LEGACY = "resolved_legacy"

    @property
    def blocks(self) -> bool:
        """Whether the finding blocks the gate for its current owner."""
        return self in (
            Disposition.ESCALATED,
            Disposition.CROSS_BOUNDARY_UNACCEPTED,
            Disposition.NEW_FINDING,
        )


@dataclass
class Adjudication:
    """Decision attached to one current finding."""

    finding: Finding
    disposition: Disposition
    owner: str
    legacy_severity: Optional[str] = None
    legacy_confidence: Optional[str] = None
    legacy_filename: Optional[str] = None
    handoff: Optional[Handoff] = None
    reasons: List[str] = field(default_factory=list)

    @property
    def blocks(self) -> bool:
        return self.disposition.blocks

    def to_dict(self) -> Dict[str, Any]:
        data = self.finding.as_dict()
        data.update(
            {
                "disposition": self.disposition.value,
                "blocks_gate": self.blocks,
                "owner": self.owner,
                "legacy_severity": self.legacy_severity,
                "legacy_confidence": self.legacy_confidence,
                "legacy_filename": self.legacy_filename,
                "handoff_record": (
                    self.handoff.to_dict() if self.handoff else None
                ),
                "reasons": list(self.reasons),
            }
        )
        return data


@dataclass
class AdjudicationReport:
    """Full output of the adjudication layer for one scan."""

    adjudications: List[Adjudication] = field(default_factory=list)
    resolved_legacy: List[Dict[str, Any]] = field(default_factory=list)
    coverage: List[Any] = field(default_factory=list)
    generated_at: str = ""

    def blocking(self) -> List[Adjudication]:
        return [a for a in self.adjudications if a.blocks]

    def for_owner(self, team: str) -> List[Adjudication]:
        return [a for a in self.adjudications if a.owner == team]

    def unknown_risk_directories(self) -> List[Any]:
        return [c for c in self.coverage if c.risk_unknown]

    @property
    def gate_failed(self) -> bool:
        if any(a.blocks for a in self.adjudications):
            return True
        return any(c.risk_unknown for c in self.coverage)

    def summary(self) -> Dict[str, int]:
        counts = {d.value: 0 for d in Disposition}
        for adjudication in self.adjudications:
            counts[adjudication.disposition.value] += 1
        counts["resolved_legacy"] = len(self.resolved_legacy)
        counts["unknown_risk_directories"] = len(
            self.unknown_risk_directories()
        )
        counts["blocking"] = len(self.blocking())
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "gate_failed": self.gate_failed,
            "summary": self.summary(),
            "adjudications": [a.to_dict() for a in self.adjudications],
            "resolved_legacy": list(self.resolved_legacy),
            "coverage": [c.to_dict() for c in self.coverage],
        }


class AdjudicationEngine:
    """Reusable decision layer between scan results and rendered reports."""

    def __init__(
        self,
        ownership_policy,
        handoff_ledger: Optional[HandoffLedger] = None,
        path_map=None,
    ) -> None:
        self.ownership = ownership_policy
        self.ledger = handoff_ledger or HandoffLedger()
        self.path_map = path_map

    def adjudicate(
        self,
        current_scan: Dict[str, Any],
        legacy_report: Optional[Dict[str, Any]] = None,
        manifest_directories: Optional[List[str]] = None,
        generated_at: str = "",
    ) -> AdjudicationReport:
        """Run the full decision process for one current scan.

        :param current_scan: Bandit JSON report (``results`` + ``errors``)
            produced by this run.
        :param legacy_report: The previous Bandit JSON report whose findings
            represent the accepted backlog of old debt.
        :param manifest_directories: Directories this run intended to cover.
        :param generated_at: Timestamp to stamp on the output.
        """
        legacy_index = self._index_legacy(legacy_report or {})
        current_findings = [
            Finding.from_result(result)
            for result in current_scan.get("results", [])
        ]
        matched_legacy_keys: set = set()
        adjudications = [
            self._adjudicate_finding(
                finding, legacy_index, matched_legacy_keys
            )
            for finding in current_findings
        ]
        resolved = self._resolved_legacy(legacy_index, matched_legacy_keys)
        coverage = self._coverage(current_scan, manifest_directories)
        return AdjudicationReport(
            adjudications=adjudications,
            resolved_legacy=resolved,
            coverage=coverage,
            generated_at=generated_at,
        )

    def _index_legacy(
        self, legacy_report: Dict[str, Any]
    ) -> Dict[str, List[Finding]]:
        index: Dict[str, List[Finding]] = {}
        for result in legacy_report.get("results", []):
            finding = Finding.from_result(result)
            index.setdefault(finding.fingerprint, []).append(finding)
        return index

    def _adjudicate_finding(
        self,
        finding: Finding,
        legacy_index: Dict[str, List[Finding]],
        matched_legacy_keys: set,
    ) -> Adjudication:
        current_path = path_utils.normalize_path(finding.filename)
        owner = self.ownership.resolve(current_path)
        handoff = self.ledger.find(current_path)
        candidates = list(legacy_index.get(finding.fingerprint, []))
        legacy_match = self._match_legacy(
            finding, candidates, handoff, matched_legacy_keys
        )

        if legacy_match is None:
            return self._new_finding(finding, owner, handoff, current_path)

        matched_legacy_keys.add((finding.fingerprint, legacy_match.filename))
        reasons = [
            "matched legacy finding from previous report at "
            + legacy_match.filename
        ]
        if handoff is not None:
            reasons.append(
                "ownership moved via handoff record "
                + handoff.record_id
                + " ("
                + handoff.from_team
                + " -> "
                + handoff.to_team
                + ")"
            )
        legacy_owner = self._legacy_owner(legacy_match, handoff, current_path)
        crossed_boundary = bool(
            handoff is None and owner != UNOWNED and legacy_owner != owner
        )
        if crossed_boundary:
            reasons.append(
                "ownership changed from "
                + legacy_owner
                + " to "
                + owner
                + " without a handoff record; legacy debt cannot carry over"
            )
            return Adjudication(
                finding=finding,
                disposition=Disposition.CROSS_BOUNDARY_UNACCEPTED,
                owner=owner,
                legacy_severity=legacy_match.severity,
                legacy_confidence=legacy_match.confidence,
                legacy_filename=legacy_match.filename,
                reasons=reasons,
            )
        escalated = self._escalation(finding, legacy_match)
        if escalated:
            reasons.extend(escalated)
            return Adjudication(
                finding=finding,
                disposition=Disposition.ESCALATED,
                owner=owner,
                legacy_severity=legacy_match.severity,
                legacy_confidence=legacy_match.confidence,
                legacy_filename=legacy_match.filename,
                handoff=handoff,
                reasons=reasons,
            )
        return Adjudication(
            finding=finding,
            disposition=Disposition.LEGACY_DEBT,
            owner=owner,
            legacy_severity=legacy_match.severity,
            legacy_confidence=legacy_match.confidence,
            legacy_filename=legacy_match.filename,
            handoff=handoff,
            reasons=reasons,
        )

    def _match_legacy(self, finding, candidates, handoff, matched_legacy_keys):
        """Pick the legacy finding that the current finding continues.

        Preference order:
        1. same current path,
        2. the pre-handoff path translated from a handoff record,
        3. any remaining unmatched candidate (identical code identity).
        """
        if not candidates:
            return None
        current_path = path_utils.normalize_path(finding.filename)
        unmatched = [
            candidate
            for candidate in candidates
            if (finding.fingerprint, candidate.filename)
            not in matched_legacy_keys
        ]
        pool = unmatched or candidates
        for candidate in pool:
            legacy_path = path_utils.normalize_path(candidate.filename)
            if legacy_path == current_path:
                return candidate
        if handoff is not None:
            expected_old = handoff.moved_from(current_path)
            for candidate in pool:
                candidate_path = path_utils.normalize_path(
                    candidate.filename
                )
                if candidate_path == expected_old:
                    return candidate
        return pool[0]

    def _legacy_owner(self, legacy_match, handoff, current_path) -> str:
        if handoff is not None and handoff.covers(current_path):
            return handoff.from_team
        return self._resolve_owner(legacy_match.filename)

    def _resolve_owner(self, path: str) -> str:
        """Resolve ownership, rewriting historical paths via the PathMap."""
        normalized = path_utils.normalize_path(path)
        if self.path_map is not None:
            normalized = self.path_map.rewrite(normalized)
        return self.ownership.resolve(normalized)

    @staticmethod
    def _escalation(finding: Finding, legacy_match: Finding) -> List[str]:
        reasons: List[str] = []
        if severity_rank(finding.severity) > severity_rank(
            legacy_match.severity
        ):
            reasons.append(
                "severity escalated "
                + legacy_match.severity
                + " -> "
                + finding.severity
            )
        if severity_rank(finding.confidence) > severity_rank(
            legacy_match.confidence
        ):
            reasons.append(
                "confidence escalated "
                + legacy_match.confidence
                + " -> "
                + finding.confidence
            )
        return reasons

    def _new_finding(
        self, finding, owner, handoff, current_path
    ) -> Adjudication:
        reasons = ["no matching finding in the legacy report"]
        if handoff is not None:
            reasons.append(
                "directory moved under handoff "
                + handoff.record_id
                + " but the finding was not part of the accepted "
                + "legacy backlog"
            )
        return Adjudication(
            finding=finding,
            disposition=Disposition.NEW_FINDING,
            owner=owner,
            handoff=handoff,
            reasons=reasons,
        )

    def _resolved_legacy(self, legacy_index, matched_legacy_keys):
        resolved = []
        for fingerprint_id, candidates in legacy_index.items():
            for candidate in candidates:
                key = (fingerprint_id, candidate.filename)
                if key not in matched_legacy_keys:
                    data = candidate.as_dict()
                    data["owner"] = self._resolve_owner(candidate.filename)
                    data["note"] = (
                        "legacy finding absent from the current "
                        "scan; treat as "
                        "resolved or verify before closing"
                    )
                    resolved.append(data)
        return resolved

    def _coverage(self, current_scan, manifest_directories):
        tracker = CoverageTracker.from_scan_report(
            current_scan, fallback_directories=manifest_directories
        )
        scanned_files = self._scanned_files(current_scan)
        return tracker.evaluate(
            scanned_files=scanned_files, errors=current_scan.get("errors", [])
        )

    @staticmethod
    def _scanned_files(current_scan) -> List[str]:
        files = {
            path_utils.normalize_path(r.get("filename", ""))
            for r in current_scan.get("results", [])
        }
        metrics = current_scan.get("metrics") or {}
        for filename in metrics:
            if filename == "_totals":
                continue
            files.add(path_utils.normalize_path(filename))
        return sorted(f for f in files if f)
