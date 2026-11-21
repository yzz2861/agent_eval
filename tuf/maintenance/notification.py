"""Maintenance notifications generated from a sealed scoped review.

Notifications are only created from :class:`ScopedDiffReview`. A batch is
bound to the review's policy version and registers for policy-change events.
Installing a different visibility policy abandons every draft in an open
batch, so a batch can never mix notifications built under different rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from tuf.maintenance._errors import (
    AbandonedNotificationError,
    BatchClosedError,
    DuplicateNotificationError,
    PolicyChangedError,
    StaleReviewError,
)
from tuf.maintenance.diff import ScopedDiffReview, ScopedReviewView
from tuf.maintenance.policy import PolicyControl  # noqa: TC001


class DraftState(StrEnum):
    """Delivery state of a generated notification."""

    ACTIVE = "active"
    ABANDONED = "abandoned"


class BatchState(StrEnum):
    """Lifecycle state of a notification batch."""

    OPEN = "open"
    CLOSED = "closed"
    DELIVERED = "delivered"
    ABANDONED = "abandoned"


@dataclass(frozen=True)
class AbandonmentBoundary:
    """Exact boundary at which a batch stopped being deliverable.

    ``policy_version`` is the version the abandoned drafts were generated
    under. Everything generated before the boundary is discarded together;
    nothing after it belongs to the batch.
    """

    policy_version: int
    reason: str
    draft_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation."""
        return {
            "policy_version": self.policy_version,
            "reason": self.reason,
            "draft_ids": list(self.draft_ids),
        }


@dataclass
class MaintenanceNotification:
    """A per-scope notification draft.

    ``body`` is a :class:`ScopedReviewView`, so rendering and serialization
    can only use changes visible to this scope.
    """

    draft_id: str
    scope: str
    policy_version: int
    body: ScopedReviewView
    _state: DraftState = field(default=DraftState.ACTIVE, init=False)
    _abandon_reason: str | None = field(default=None, init=False)

    @property
    def state(self) -> DraftState:
        """Return the current draft state."""
        return self._state

    @property
    def abandon_reason(self) -> str | None:
        """Return why this draft was abandoned, if it was."""
        return self._abandon_reason

    @property
    def deliverable(self) -> bool:
        """Return whether this draft may still be delivered."""
        return self._state is DraftState.ACTIVE

    def abandon(self, reason: str) -> None:
        """Abandon this draft. Idempotent."""
        if self._state is DraftState.ABANDONED:
            return
        self._state = DraftState.ABANDONED
        self._abandon_reason = reason

    def render(self) -> str:
        """Render the notification, refusing abandoned drafts."""
        if not self.deliverable:
            raise AbandonedNotificationError(
                f"draft {self.draft_id} was abandoned: {self._abandon_reason}"
            )
        return self.body.render_text()

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation of an active draft."""
        if not self.deliverable:
            raise AbandonedNotificationError(
                f"draft {self.draft_id} was abandoned: {self._abandon_reason}"
            )
        return {
            "draft_id": self.draft_id,
            "scope": self.scope,
            "policy_version": self.policy_version,
            "state": self._state.value,
            "body": self.body.as_dict(),
        }


class NotificationBatch:
    """A version-locked batch of notifications for one sealed review."""

    def __init__(
        self,
        control: PolicyControl,
        review: ScopedDiffReview,
        batch_seq: int = 0,
    ) -> None:
        self._control = control
        self._review = review
        self._batch_seq = batch_seq
        self._policy_version = review.policy.version
        self._drafts: list[MaintenanceNotification] = []
        self._state = BatchState.OPEN
        self._abandonment: AbandonmentBoundary | None = None
        self._unregister = control.register(self._on_policy_change)

    @property
    def state(self) -> BatchState:
        """Return the batch lifecycle state."""
        return self._state

    @property
    def policy_version(self) -> int:
        """Return the policy version this batch is locked to."""
        return self._policy_version

    @property
    def review_id(self) -> str:
        """Return the review id this batch was opened from."""
        return self._review.review_id

    @property
    def abandonment(self) -> AbandonmentBoundary | None:
        """Return the abandonment boundary, if the batch was abandoned."""
        return self._abandonment

    @property
    def drafts(self) -> tuple[MaintenanceNotification, ...]:
        """Return every generated draft, including abandoned ones."""
        return tuple(self._drafts)

    def generate(self, scope: str) -> MaintenanceNotification:
        """Generate the notification for ``scope``.

        The policy version is checked before and after building the draft.
        A change at either point abandons the whole batch and raises
        :class:`PolicyChangedError`.
        """
        if self._state is not BatchState.OPEN:
            raise BatchClosedError(
                f"batch {self._review.review_id} is {self._state.value}"
            )
        if any(draft.scope == scope for draft in self._drafts):
            raise DuplicateNotificationError(
                f"scope {scope} already has a notification"
            )

        self._control.assert_current(self._policy_version)
        body = self._review.for_scope(scope)
        draft = MaintenanceNotification(
            draft_id=(
                f"{body.view_id[:12]}-{self._batch_seq}-{len(self._drafts)}"
            ),
            scope=scope,
            policy_version=self._policy_version,
            body=body,
        )
        self._drafts.append(draft)

        if (
            self._state is not BatchState.OPEN
            or self._control.version != self._policy_version
        ):
            boundary = self.abandon(
                "visibility policy changed during generation"
            )
            draft.abandon(boundary.reason)
            raise PolicyChangedError(
                self._policy_version, self._control.version
            )
        return draft

    def abandon(self, reason: str) -> AbandonmentBoundary:
        """Abandon every draft in this batch at a single boundary."""
        if self._state is BatchState.DELIVERED:
            raise BatchClosedError("cannot abandon a delivered batch")
        if self._abandonment is None:
            boundary = AbandonmentBoundary(
                policy_version=self._policy_version,
                reason=reason,
                draft_ids=tuple(draft.draft_id for draft in self._drafts),
            )
            self._state = BatchState.ABANDONED
            self._abandonment = boundary
            self._unregister()
        else:
            boundary = self._abandonment
        for draft in self._drafts:
            draft.abandon(boundary.reason)
        return boundary

    def close(self) -> None:
        """Finish generation while keeping active drafts deliverable."""
        if self._state is BatchState.OPEN:
            self._state = BatchState.CLOSED

    def deliver(self) -> tuple[str, ...]:
        """Atomically render and deliver every active draft.

        The policy version is checked again at delivery time. A batch that
        was abandoned by a policy change raises instead of delivering
        notifications built under the previous visibility rules.
        """
        if self._state is BatchState.ABANDONED:
            raise AbandonedNotificationError(
                "cannot deliver an abandoned notification batch"
            )
        if self._state is not BatchState.CLOSED:
            raise BatchClosedError(
                f"batch must be closed before delivery, not {self._state.value}"
            )
        if self._control.version != self._policy_version:
            self.abandon("visibility policy changed before delivery")
            raise PolicyChangedError(
                self._policy_version, self._control.version
            )

        rendered = tuple(draft.render() for draft in self._drafts)
        self._state = BatchState.DELIVERED
        self._unregister()
        return rendered

    def deliverable(self) -> tuple[MaintenanceNotification, ...]:
        """Return only drafts that may still be delivered."""
        if self._state in (BatchState.ABANDONED, BatchState.DELIVERED):
            return ()
        return tuple(draft for draft in self._drafts if draft.deliverable)

    def _on_policy_change(self, old_version: int, new_version: int) -> None:
        if old_version != self._policy_version:
            return
        if self._state is BatchState.DELIVERED:
            return
        self.abandon(
            "visibility policy changed from version "
            f"{old_version} to {new_version}"
        )


class NotificationGenerator:
    """Create notification batches from sealed scoped reviews."""

    def __init__(self, control: PolicyControl) -> None:
        self._control = control
        self._batch_seq = 0

    def open_batch(self, review: ScopedDiffReview) -> NotificationBatch:
        """Open a batch for ``review``.

        Raises:
            StaleReviewError: If the review was built under a policy that is
                no longer current, or under a different policy with the same
                version.
        """
        if not isinstance(review, ScopedDiffReview):
            raise TypeError("notifications require a sealed scoped review")

        current = self._control.policy
        if (
            review.policy.version != current.version
            or review.policy_fingerprint != current.fingerprint
        ):
            raise StaleReviewError(
                "review is not valid for the current visibility policy"
            )
        self._batch_seq += 1
        return NotificationBatch(self._control, review, self._batch_seq)
