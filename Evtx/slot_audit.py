"""Compatibility namespace for slot/activity auditing."""

from .activity import (
    ACTIVE,
    EMPTY,
    INDETERMINATE,
    RESIDUAL,
    ActivityReport,
    Conflict,
    RecordAssessment,
    SlotAssessment,
    audit_path,
    inspect_buffer,
    inspect_path,
    render_report,
)

audit_slots = inspect_buffer
inspect_activity = inspect_buffer
audit_file = inspect_path

__all__ = [
    "ACTIVE",
    "RESIDUAL",
    "INDETERMINATE",
    "EMPTY",
    "ActivityReport",
    "SlotAssessment",
    "RecordAssessment",
    "Conflict",
    "inspect_buffer",
    "inspect_path",
    "audit_path",
    "render_report",
    "audit_slots",
    "inspect_activity",
    "audit_file",
]
