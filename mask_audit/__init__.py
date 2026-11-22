"""Offline consistency checks between original and masked SQL review copies.

The package answers a narrow question for on-call review workflows:
given an original SQL statement, a desensitized review copy, the token
ranges the caller is allowed to mask and a small session schema, does the
review copy still describe the same change in the same controlled zone?

The public entry point is :func:`mask_audit.checker.check_consistency`.
"""

from mask_audit.checker import (
    MaskRange,
    SessionSchema,
    check_consistency,
)
from mask_audit.models import (
    AuditFinding,
    AuditReport,
    NameResolution,
)

__all__ = [
    'AuditFinding',
    'AuditReport',
    'MaskRange',
    'NameResolution',
    'SessionSchema',
    'check_consistency',
]
