from django.core.exceptions import BadRequest, SuspiciousOperation


class InvalidSessionKey(SuspiciousOperation):
    """Invalid characters in session key"""

    pass


class SuspiciousSession(SuspiciousOperation):
    """The session may be tampered with"""

    pass


class SessionInterrupted(BadRequest):
    """The session was interrupted."""

    pass


class SessionDataTooLarge(Exception):
    """The session data exceeds the configured session cookie budget."""

    pass
