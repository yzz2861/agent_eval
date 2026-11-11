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


class ObjectIdentityError(GuardianError):
    """Raised when an object's identity cannot be established unambiguously.

    Object identity is the combination of primary key, actual model and
    content type. A custom GUARDIAN_GET_CONTENT_TYPE that maps an object
    to the content type of an unrelated model would merge distinct primary
    key namespaces, letting same-pk objects of different models inherit each
    other's permissions; such writes are refused with this error.

    The code attribute is stable so monitoring can aggregate on it.
    """

    code = "object_identity_error"


class TenantMismatchError(GuardianError):
    """Raised when a cross-tenant object permission operation is denied.

    Only raised when a tenant resolver is configured via
    GUARDIAN_GET_TENANT. The message deliberately carries no object
    identifiers so the denial cannot be used to probe for the existence of
    another tenant's objects; the code attribute is stable so monitoring
    can aggregate on it.
    """

    code = "tenant_mismatch"
