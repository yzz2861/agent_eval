"""Scoped maintenance review of updated TUF trusted targets.

Security operations can compare two ``Targets`` snapshots, attach each
change to a visibility scope, and generate maintenance notifications from
the resulting sealed review. Maintenance groups only receive a
``ScopedReviewView`` for their own scope: totals, deletion notes, and
evidence are all derived from the filtered change set.
"""

from tuf.maintenance._errors import (
    AbandonedNotificationError,
    BatchClosedError,
    DuplicateNotificationError,
    MaintenanceError,
    PolicyChangedError,
    ScopeNotVisibleError,
    StaleReviewError,
)
from tuf.maintenance.diff import (
    ArtifactRef,
    ChangeKind,
    ComponentIdentity,
    DeliveryChannel,
    Evidence,
    EvidenceKind,
    IdentitySource,
    ReviewTotals,
    ScopedDiffReview,
    ScopedReviewView,
    SharedDigest,
    TargetChange,
    digest_label,
)
from tuf.maintenance.notification import (
    AbandonmentBoundary,
    BatchState,
    DraftState,
    MaintenanceNotification,
    NotificationBatch,
    NotificationGenerator,
)
from tuf.maintenance.policy import PolicyControl, ScopePolicy

__all__ = [
    "AbandonedNotificationError",
    "AbandonmentBoundary",
    "ArtifactRef",
    "BatchClosedError",
    "BatchState",
    "ChangeKind",
    "ComponentIdentity",
    "DeliveryChannel",
    "DraftState",
    "DuplicateNotificationError",
    "Evidence",
    "EvidenceKind",
    "IdentitySource",
    "MaintenanceError",
    "MaintenanceNotification",
    "NotificationBatch",
    "NotificationGenerator",
    "PolicyChangedError",
    "PolicyControl",
    "ReviewTotals",
    "ScopeNotVisibleError",
    "ScopePolicy",
    "ScopedDiffReview",
    "ScopedReviewView",
    "SharedDigest",
    "StaleReviewError",
    "TargetChange",
    "digest_label",
]
