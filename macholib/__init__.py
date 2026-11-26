"""
Enough Mach-O to make your head spin.

See the relevant header files in /usr/include/mach-o

And also Apple's documentation.
"""

__version__ = "1.16.4"

from .note_audit import (  # noqa: E402
    OwnerRegistry,
    audit_lc_notes,
    audit_notes,
    format_audit_report,
    format_audit_report_zh,
)

__all__ = [
    "OwnerRegistry",
    "audit_lc_notes",
    "audit_notes",
    "format_audit_report",
    "format_audit_report_zh",
]
