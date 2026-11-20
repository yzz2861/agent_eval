# Copyright (c) 2016 Red Hat, Inc.
# Author: Stanislav Kontar, Red Hat Product Security
# License: LGPLv3+

"""
All exceptions needed by CVSS library.
"""


class CVSSError(Exception):
    """
    General CVSS exception.
    """

    pass


class CVSS2Error(CVSSError):
    """
    General CVSS2 exception.
    """

    pass


class CVSS2MalformedError(CVSS2Error):
    """
    Exception for malformed input CVSS2 vectors.
    """

    pass


class CVSS2MandatoryError(CVSS2Error):
    """
    Exception for missing mandatory fields.
    """

    pass


class CVSS2RHScoreDoesNotMatch(CVSS2Error):
    """
    Exception when parsing CVSS2 vectors in Red Hat notation, which have score not matching the
    computed score.
    """

    pass


class CVSS2RHMalformedError(CVSS2Error):
    """
    Exception for malformed input CVSS2 vectors in Red Hat notation.
    """

    pass


class CVSS3Error(CVSSError):
    """
    General CVSS3 exception.
    """

    pass


class CVSS3MalformedError(CVSS3Error):
    """
    Exception for malformed input CVSS3 vectors.
    """

    pass


class CVSS3MandatoryError(CVSS3Error):
    """
    Exception for missing mandatory fields.
    """

    pass


class CVSS3RHScoreDoesNotMatch(CVSS3Error):
    """
    Exception when parsing CVSS3 vectors in Red Hat notation, which have score not matching the
    computed score.
    """

    pass


class CVSS3RHMalformedError(CVSS3Error):
    """
    Exception for malformed input CVSS3 vectors in Red Hat notation.
    """

    pass


class CVSS4Error(CVSSError):
    """
    General CVSS4 exception.
    """

    pass


class CVSS4MalformedError(CVSS4Error):
    """
    Exception for malformed input CVSS4 vectors.
    """

    pass


class CVSS4MandatoryError(CVSS4Error):
    """
    Exception for missing mandatory fields.
    """

    pass


class CVSS4RHScoreDoesNotMatch(CVSS4Error):
    """
    Exception when parsing CVSS4 vectors in Red Hat notation, which have score not matching the
    computed score.
    """

    pass


class CVSS4RHMalformedError(CVSS4Error):
    """
    Exception for malformed input CVSS4 vectors in Red Hat notation.
    """

    pass


class CVSSHistoryError(CVSSError):
    """
    General exception for the scoring-history layer.
    """

    pass


class CVSSHistoryValidationError(CVSSHistoryError):
    """
    Exception for an invalid scoring-history event, e.g. an erratum changing a metric which is
    not allowed to be updated or carrying an illegal metric value.
    """

    pass


class CVSSHistoryReferenceError(CVSSHistoryError):
    """
    Exception for an illegal cross-version reference. The offending event can be traced back
    through the ``event_id``, ``advisory_id`` and ``referenced_prefix`` attributes.
    """

    def __init__(self, message, event_id=None, advisory_id=None, referenced_prefix=None):
        super(CVSSHistoryReferenceError, self).__init__(message)
        self.event_id = event_id
        self.advisory_id = advisory_id
        self.referenced_prefix = referenced_prefix


class CVSSHistoryRevocationError(CVSSHistoryError):
    """
    Exception for a revocation event which does not reference an existing, still-active erratum.
    """

    pass
