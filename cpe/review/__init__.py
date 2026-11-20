"""
Offline review layer built on top of the CPE parsing and name matching.

The review layer does not trust product names that happen to sit at the
same CPE layer.  Every relation between an advisory entry and an asset
record must be backed by an :class:`~cpe.review.model.Evidence` item and
is classified as one of three relation kinds:

- ``same``       identity, the only relation allowed to fold identifiers.
- ``contained``  a provable parent -> child containment chain.
- ``supplied``   a supplier declaration with no independently queryable
                  component record.
"""

from .model import (
    REL_SAME,
    REL_CONTAINED,
    REL_SUPPLIED,
    RELATION_KINDS,
    DISPOSITION_ACTIONABLE,
    DISPOSITION_REVIEW,
    DISPOSITION_EXCLUDED,
    Asset,
    AdvisoryEntry,
    Evidence,
    Relation,
    DispositionItem,
)
from .review import OfflineReview, ReviewResult
from .inventory import InventoryStore

__all__ = [
    "REL_SAME",
    "REL_CONTAINED",
    "REL_SUPPLIED",
    "RELATION_KINDS",
    "DISPOSITION_ACTIONABLE",
    "DISPOSITION_REVIEW",
    "DISPOSITION_EXCLUDED",
    "Asset",
    "AdvisoryEntry",
    "Evidence",
    "Relation",
    "DispositionItem",
    "OfflineReview",
    "ReviewResult",
    "InventoryStore",
]
