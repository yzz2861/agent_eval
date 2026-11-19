#
# SPDX-License-Identifier: Apache-2.0
"""Data models for the takeover adjudication layer.

The layer deliberately works on plain dictionaries (the JSON shape produced by
``bandit -f json``) plus small dataclasses, so it can be reused without a
live :class:`~bandit.core.manager.BanditManager`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH")


def severity_rank(severity: str) -> int:
    """Return a comparable rank for a severity string."""
    try:
        return SEVERITY_ORDER.index((severity or "").upper())
    except ValueError:
        return -1


def fingerprint(result: Dict[str, Any]) -> str:
    """Stable identity of a finding, independent of line number and path.

    Line numbers move as code is edited and the path moves when a directory is
    handed over, so neither can be part of the identity used to match old
    findings against the current scan.
    """
    # Severity and confidence are deliberately excluded: they can be raised
    # between scans, and an escalated finding must still be recognisable as the
    # same piece of legacy debt so the escalation can be detected.
    material = "|".join(
        [
            str(result.get("test_id", "")),
            str(result.get("test_name", "")),
            str(result.get("issue_text", "")).strip(),
            str((result.get("issue_cwe") or {}).get("id", "")),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


@dataclass
class Finding:
    """A single scan finding normalized from a Bandit JSON result."""

    fingerprint: str
    test_id: str
    test_name: str
    filename: str
    line_number: Optional[int]
    severity: str
    confidence: str
    issue_text: str
    cwe_id: Optional[int]
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    @classmethod
    def from_result(cls, result: Dict[str, Any]) -> "Finding":
        cwe = result.get("issue_cwe") or {}
        return cls(
            fingerprint=fingerprint(result),
            test_id=str(result.get("test_id", "")),
            test_name=str(result.get("test_name", "")),
            filename=str(result.get("filename", "")),
            line_number=result.get("line_number"),
            severity=str(result.get("issue_severity", "")).upper(),
            confidence=str(result.get("issue_confidence", "")).upper(),
            issue_text=str(result.get("issue_text", "")),
            cwe_id=cwe.get("id"),
            raw=result,
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "test_id": self.test_id,
            "test_name": self.test_name,
            "filename": self.filename,
            "line_number": self.line_number,
            "issue_severity": self.severity,
            "issue_confidence": self.confidence,
            "issue_text": self.issue_text,
            "issue_cwe": {"id": self.cwe_id} if self.cwe_id else {},
        }
