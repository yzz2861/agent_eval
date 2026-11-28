"""
SignXML exception types.
"""

import cryptography.exceptions


class SignXMLException(Exception):
    pass


class InvalidSignature(cryptography.exceptions.InvalidSignature, SignXMLException):
    """
    Raised when signature validation fails.
    """


class InvalidDigest(InvalidSignature):
    """
    Raised when digest validation fails (causing the signature to be untrusted).
    """


class InvalidCertificate(InvalidSignature):
    """
    Raised when certificate validation fails.
    """


class InvalidInput(ValueError, SignXMLException):
    pass


class RedundantCert(SignXMLException):
    pass


class InsufficientEndorsement(SignXMLException):
    """
    Raised when one or more cryptographically verified references lack the required number of independent
    endorsements. This is deliberately not a subclass of :class:`InvalidSignature`: the signature itself is
    valid, but the caller-supplied endorsement quorum is not met for every reference in scope.
    """
