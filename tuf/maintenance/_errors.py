"""Exceptions for scoped maintenance diff review."""


class MaintenanceError(Exception):
    """Base class for maintenance review and notification errors."""


class PolicyChangedError(MaintenanceError):
    """The visibility policy changed while work was in progress."""

    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"visibility policy changed from version {expected} to {actual}"
        )
        self.expected = expected
        self.actual = actual


class StaleReviewError(MaintenanceError):
    """A review was built against a policy that is no longer current."""


class AbandonedNotificationError(MaintenanceError):
    """A notification belongs to an abandoned batch."""


class BatchClosedError(MaintenanceError):
    """A notification batch no longer accepts new notifications."""


class DuplicateNotificationError(MaintenanceError):
    """A notification was already generated for the requested scope."""


class ScopeNotVisibleError(MaintenanceError):
    """The requested scope is not part of the review's policy."""
