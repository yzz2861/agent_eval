"""File-based offline signing handoff built on securesystemslib.

Implements an approval-form （单据） workflow:

* A form commits to a payload digest, a set of reviewers and a policy
*   revision.
* Reviewers sign offline and drop submissions into local directories.
* The importer enforces approval status (active/revoked/sealed), not just
*   signature validity, imports idempotently, and recovers from crashes
*   that happen in the middle of a write.
"""

from handoff.form import (
    STATUS_ACTIVE,
    STATUS_REVOKED,
    STATUS_SEALED,
    ApprovalForm,
)
from handoff.service import HandoffService, ImportResult
from handoff.store import FormStore

__all__ = [
    "ApprovalForm",
    "FormStore",
    "HandoffService",
    "ImportResult",
    "STATUS_ACTIVE",
    "STATUS_REVOKED",
    "STATUS_SEALED",
]
