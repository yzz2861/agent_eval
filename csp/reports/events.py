from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from csp.utils import REPORT_UNKNOWN, deduplication_key, normalize_violation_report


@dataclass
class CSPViolationEvent:
    """A normalized, auditable representation of a CSP violation report.

    Both the legacy ``report-uri`` (``{"csp-report": {...}}``) and the
    Reporting API (``{"type": "csp-violation", "body": {...}}``) report
    shapes are normalized into this structure, so missing fields never
    prevent a report from being recorded.
    """

    document_uri: str = REPORT_UNKNOWN
    referrer: str = REPORT_UNKNOWN
    violated_directive: str = REPORT_UNKNOWN
    effective_directive: str = REPORT_UNKNOWN
    original_policy: str = REPORT_UNKNOWN
    blocked_uri: str = REPORT_UNKNOWN
    source_file: str | None = None
    line_number: int | None = None
    column_number: int | None = None
    sample: str = ""
    disposition: str = ""
    status_code: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_report(cls, payload: Any) -> CSPViolationEvent:
        """Build an event from either supported report payload shape."""
        normalized = normalize_violation_report(payload)
        return cls(
            document_uri=normalized["document_uri"],
            referrer=normalized["referrer"],
            violated_directive=normalized["violated_directive"],
            effective_directive=normalized["effective_directive"],
            original_policy=normalized["original_policy"],
            blocked_uri=normalized["blocked_uri"],
            source_file=normalized["source_file"],
            line_number=normalized["line_number"],
            column_number=normalized["column_number"],
            sample=normalized["sample"],
            disposition=normalized["disposition"],
            status_code=normalized["status_code"],
            raw=normalized["raw"],
        )

    @property
    def deduplication_key(self) -> tuple[str, str, str]:
        """The source/directive/document-uri tuple used for dedup and throttling."""
        return deduplication_key(
            {
                "blocked_uri": self.blocked_uri,
                "violated_directive": self.violated_directive,
                "document_uri": self.document_uri,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_uri": self.document_uri,
            "referrer": self.referrer,
            "violated_directive": self.violated_directive,
            "effective_directive": self.effective_directive,
            "original_policy": self.original_policy,
            "blocked_uri": self.blocked_uri,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "sample": self.sample,
            "disposition": self.disposition,
            "status_code": self.status_code,
            "raw": self.raw,
            "deduplication_key": list(self.deduplication_key),
        }
