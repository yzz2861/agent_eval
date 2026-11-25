"""Exception hierarchy for the progressive custody inspection backend.

All errors raised by the custody package derive from :class:`CustodyError`
so callers can catch the whole family at once.
"""


class CustodyError(Exception):
    """Base class for every error raised by the custody backend."""


class ManifestError(CustodyError):
    """The custody manifest is missing, malformed or inconsistent."""


class ApprovalRevokedError(CustodyError):
    """A previously granted approval is no longer valid.

    Raised when an object whose content was handed out in an earlier round
    can no longer be authenticated: the original document was replaced, or
    the same-named object moved to different byte positions.
    """

    def __init__(self, object_id, reason, detail=None):
        self.object_id = object_id
        self.reason = reason
        message = 'approval for object {0!r} revoked: {1}'.format(
            object_id, reason)
        if detail:
            message += ' ({0})'.format(detail)
        super(ApprovalRevokedError, self).__init__(message)


class AccessDeniedError(CustodyError):
    """An automatic inspection tried to read content that was not approved.

    The first inspection round may only look at structure; reading the full
    payload of an embedded object requires an explicit approval recorded in
    the custody manifest.
    """

    def __init__(self, object_id, tried_range=None, allowed=None):
        self.object_id = object_id
        self.tried_range = tried_range
        self.allowed = list(allowed) if allowed is not None else []
        message = ('access to content of object {0!r} has not been granted'
                   .format(object_id))
        if tried_range is not None:
            message += '; tried to read {0[0]}..{0[1]}'.format(tried_range)
        super(AccessDeniedError, self).__init__(message)


class CustodyScanError(CustodyError):
    """Container structure could not be parsed for a structural observation."""


# Alternate spellings kept as aliases for callers using either name.
RevokedApprovalError = ApprovalRevokedError
AccessNotGrantedError = AccessDeniedError
