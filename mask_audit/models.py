"""Data structures returned by the mask consistency checker."""

from __future__ import annotations

from dataclasses import dataclass, field


#: A real semantic difference outside every permitted mask range.
SEVERITY_ERROR = 'error'
#: A masked token that is missing a permit, or a mask of the wrong kind.
SEVERITY_VIOLATION = 'mask_violation'
#: The checker cannot decide automatically; a human must review the item.
SEVERITY_MANUAL = 'manual'
#: Informational record of an allowed mask or a resolved object name.
SEVERITY_INFO = 'info'


@dataclass
class SourceLocation:
    """Half-open character span of a token inside one input document.

    ``line`` and ``column`` are 1-based and point at the first character of
    the span; ``start``/``end`` are 0-based character offsets.
    """

    start: int
    end: int
    line: int
    column: int

    def as_dict(self) -> dict:
        return {
            'start': self.start,
            'end': self.end,
            'line': self.line,
            'column': self.column,
        }


@dataclass
class AuditFinding:
    """A single observation produced while comparing two statements."""

    severity: str
    code: str
    message: str
    statement_index: int
    original_location: SourceLocation | None = None
    review_location: SourceLocation | None = None
    original_value: str | None = None
    review_value: str | None = None
    expected_zone: str | None = None
    actual_zone: str | None = None

    def as_dict(self) -> dict:
        data = {
            'severity': self.severity,
            'code': self.code,
            'message': self.message,
            'statement_index': self.statement_index,
            'original_location': (
                self.original_location.as_dict()
                if self.original_location is not None else None
            ),
            'review_location': (
                self.review_location.as_dict()
                if self.review_location is not None else None
            ),
        }
        for key in (
            'original_value',
            'review_value',
            'expected_zone',
            'actual_zone',
        ):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


@dataclass
class NameResolution:
    """Explanation of the target object named by a single statement.

    For ``ALTER TABLE zone_a.t_orders ...`` the database (schema) name is
    ``zone_a``, the object name is ``t_orders`` and ``masked`` records whether
    the database name itself was replaced by a mask placeholder.
    """

    statement_index: int
    statement_type: str
    database: str | None
    object_name: str | None
    zone: str | None
    masked: bool
    location: SourceLocation | None

    def as_dict(self) -> dict:
        return {
            'statement_index': self.statement_index,
            'statement_type': self.statement_type,
            'database': self.database,
            'object_name': self.object_name,
            'zone': self.zone,
            'masked': self.masked,
            'location': (
                self.location.as_dict()
                if self.location is not None else None
            ),
        }


@dataclass
class AuditReport:
    """Aggregate result of comparing an original with a review copy."""

    findings: list[AuditFinding] = field(default_factory=list)
    resolutions: list[NameResolution] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """True if any finding blocks automatic approval."""
        blocking = (SEVERITY_ERROR, SEVERITY_VIOLATION, SEVERITY_MANUAL)
        return any(item.severity in blocking for item in self.findings)

    @property
    def requires_manual_review(self) -> bool:
        return any(
            item.severity == SEVERITY_MANUAL for item in self.findings
        )

    def add(self, finding: AuditFinding) -> AuditFinding:
        self.findings.append(finding)
        return finding

    def as_dict(self) -> dict:
        return {
            'ok': not self.has_errors,
            'requires_manual_review': self.requires_manual_review,
            'findings': [item.as_dict() for item in self.findings],
            'resolutions': [item.as_dict() for item in self.resolutions],
        }
