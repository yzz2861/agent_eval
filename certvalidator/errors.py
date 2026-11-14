# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function


class PathError(Exception):

    pass


class PathBuildingError(PathError):

    pass


class DuplicateCertificateError(PathError):

    pass


class CRLValidationError(Exception):

    pass


class CRLNoMatchesError(CRLValidationError):

    pass


class CRLValidationIndeterminateError(CRLValidationError):

    @property
    def failures(self):
        return self.args[1]


class FetchPolicyError(Exception):

    # A unicode string of a machine-readable reason code for the rejection,
    # such as "loopback_address" or "response_too_large"
    reason = None

    def __init__(self, message, reason=None):
        """
        :param message:
            A unicode string of the error message. Must not contain a full
            URL (only a scheme://host[:port] origin) or any key material.

        :param reason:
            A unicode string of a machine-readable reason code
        """

        super(FetchPolicyError, self).__init__(message)
        self.reason = reason


class CRLFetchError(CRLValidationIndeterminateError):

    # A unicode string of a machine-readable reason code from the HTTP fetch
    # policy, such as "loopback_address" or "cross_origin_redirect"
    reason = None

    def __init__(self, message, reason=None):
        """
        :param message:
            A unicode string of the error message

        :param reason:
            A unicode string of a machine-readable reason code
        """

        super(CRLFetchError, self).__init__(message, [(message,)])
        self.reason = reason


class OCSPValidationError(Exception):

    pass


class OCSPNoMatchesError(OCSPValidationError):

    pass


class OCSPValidationIndeterminateError(OCSPValidationError):

    @property
    def failures(self):
        return self.args[1]


class OCSPFetchError(OCSPValidationIndeterminateError):

    # A unicode string of a machine-readable reason code from the HTTP fetch
    # policy, such as "loopback_address" or "cross_origin_redirect"
    reason = None

    def __init__(self, message, reason=None):
        """
        :param message:
            A unicode string of the error message

        :param reason:
            A unicode string of a machine-readable reason code
        """

        super(OCSPFetchError, self).__init__(message, [(message,)])
        self.reason = reason


class SoftFailError(Exception):

    pass


class ValidationError(Exception):

    pass


class PathValidationError(ValidationError):

    pass


class RevokedError(PathValidationError):

    pass


class InvalidCertificateError(PathValidationError):

    pass
