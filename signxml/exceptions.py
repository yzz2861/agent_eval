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


class AlgorithmPolicyViolation(InvalidInput):
    """
    Raised when a signature algorithm combination is not permitted by the configured purpose policy.
    """


class UnsupportedAlgorithm(InvalidInput):
    """
    Raised when SignXML or its cryptographic backend does not implement an algorithm or combination.
    """


class RedundantCert(SignXMLException):
    pass
