# Offline comparator for historical TUF acceptance receipts.
#
# Answers the upgrade-review question which existing receipts can still be
# re-verified after historical delegation rules are removed, using only the
# retained acceptance evidence. Targets without a receipt are never risks.

from offline_receipt_compare.comparator import (
    ComparisonReport,
    ReceiptComparator,
    ReceiptOutcome,
)
from offline_receipt_compare.models import (
    EvidenceStore,
    Receipt,
    ReceiptSet,
    Verdict,
    VerdictCode,
)
from offline_receipt_compare.verifier import (
    MetadataBundle,
    RoleStep,
    TargetResolution,
    verify_chain,
)

__all__ = [
    "ComparisonReport",
    "EvidenceStore",
    "MetadataBundle",
    "Receipt",
    "ReceiptComparator",
    "ReceiptOutcome",
    "ReceiptSet",
    "RoleStep",
    "TargetResolution",
    "Verdict",
    "VerdictCode",
    "verify_chain",
]
