"""
Read-only auditing of *active content* inside PDF documents.

Active content is anything a PDF viewer could execute or follow on its own,
such as JavaScript, launch or submit-form actions, rich media, embedded files
or form field trigger actions. Ordinary link annotations, static form values
and read-only comments are not considered active content.

The audit never executes an action, never resolves a URL or file path and
never opens an external resource. It only reads the object graph that pypdf
already parsed.

Example:

.. code-block:: python

    from pypdf import PdfReader
    from pypdf.security import ActiveContentScanner, ActiveContentPolicy

    reader = PdfReader("form.pdf")
    report = ActiveContentScanner(reader).scan()
    # report.entries contains one ActiveContentEntry per detected item.

    ActiveContentScanner(reader, policy=ActiveContentPolicy.REJECT).scan()
    # raises ActiveContentError when active content is present.
"""

from ._security import (
    ACTIVE_ACTION_TYPES,
    ActiveContentEntry,
    ActiveContentError,
    ActiveContentKind,
    ActiveContentLocation,
    ActiveContentPolicy,
    ActiveContentReport,
    ActiveContentScanner,
    AuditBudget,
    AuditBudgetExceededError,
    audit_active_content,
)

__all__ = [
    "ACTIVE_ACTION_TYPES",
    "ActiveContentEntry",
    "ActiveContentError",
    "ActiveContentKind",
    "ActiveContentLocation",
    "ActiveContentPolicy",
    "ActiveContentReport",
    "ActiveContentScanner",
    "AuditBudget",
    "AuditBudgetExceededError",
    "audit_active_content",
]
