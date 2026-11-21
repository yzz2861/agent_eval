"""Offline pre-audit for user-supplied Jinja templates.

The package answers one question for a caller that maintains an allow-list of
templates a user may render: *before* any rendering happens, which references
(``extends`` / ``include`` / ``import`` / ``from ... import``) must be
reviewed, and can the entry template actually be published?

Three outcomes are possible for every reference expression:

* ``static``    - a single fixed template name, fully known without context;
* ``candidates``- a finite set of possible names (Jinja literal lists or host
                  declared variable domains), every value is checked;
* ``unknown``   - the name depends on data the host cannot bound, the host
                  must explicitly suspend the publication (a "hold").

Approvals are pinned to the content hashes of the whole transitive closure.
Editing any covered template invalidates the approval automatically.
"""

from .audit import AuditReport, audit_entry
from .models import (
    Approval,
    Decision,
    Reference,
    ReferenceKind,
    Resolution,
    Severity,
    TemplateRepository,
    build_approval,
)
from .references import extract_references, resolve_expression

__all__ = [
    "Approval",
    "AuditReport",
    "Decision",
    "Reference",
    "ReferenceKind",
    "Resolution",
    "Severity",
    "TemplateRepository",
    "audit_entry",
    "build_approval",
    "extract_references",
    "resolve_expression",
]
