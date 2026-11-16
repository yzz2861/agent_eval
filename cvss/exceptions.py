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


class CVSSParserError(CVSSError):
    """
    General exception for ambiguous or unsupported CVSS vectors found in text.
    """

    pass


class CVSSPrefixConfusionError(CVSSParserError):
    """
    Exception for a CVSS vector candidate whose version prefix and metric set do
    not belong to the same CVSS version, for example a 'CVSS:4.0' prefix combined
    with CVSS3 metrics. Such a candidate is never scored with another version.
    """

    pass


class CVSSUnknownPrefixError(CVSSParserError):
    """
    Exception for a CVSS vector candidate using a 'CVSS:x.y' version prefix whose
    version is not supported by this library.
    """

    pass


class CVSSVersionMismatchError(CVSSParserError):
    """
    Exception for a CVSS vector candidate whose detected version does not match
    the target version explicitly requested by the caller. The parser never
    silently downgrades or upgrades such a vector.
    """

    pass


class CVSSMultipleVectorsError(CVSSParserError):
    """
    Exception for text containing more than one distinct CVSS vector candidate
    when the caller asked for a single vector.
    """

    pass
