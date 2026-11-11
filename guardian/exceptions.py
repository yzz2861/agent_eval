"""
Exceptions used by django-guardian. All internal and guardian-specific errors
should extend GuardianError class.
"""


class GuardianError(Exception):
    """Base class for all guardian-specific exceptions."""

    pass


class NotUserNorGroup(GuardianError):
    """Raised when an object is neither User nor Group."""

    pass


class ObjectNotPersisted(GuardianError):
    """Raised when the object has not been saved to the database."""

    pass


class WrongAppError(GuardianError):
    """Raised when the app name for a permission is incorrect."""

    pass


class MixedContentTypeError(GuardianError):
    """Raised when content type for the provided permissions and/or class do not match."""

    pass


class MultipleIdentityAndObjectError(GuardianError):
    """Raised when an operation is attempted on both user/group and object."""

    pass


class BulkAssignmentError(GuardianError):
    """Raised when a bulk permission assignment fails its pre-validation.

    The original error that triggered the failure is preserved as the
    exception cause (see :pep:`3134`) and available via :attr:`original_error`,
    so callers never lose the underlying context when a whole batch is
    rejected and rolled back.
    """

    def __init__(self, message: str, original_error: BaseException | None = None) -> None:
        super().__init__(message)
        self.original_error = original_error
        if original_error is not None:
            self.__cause__ = original_error


class DuplicateBulkAssignmentError(BulkAssignmentError):
    """Raised in fail-on-duplicate mode when one of the target pairs already
    has an object permission (inside the batch or already persisted)."""

    pass
