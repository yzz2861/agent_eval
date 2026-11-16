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


class _AlgorithmPolicyViolation(InvalidSignature, InvalidInput):
    """
    Raised when a signature uses an algorithm forbidden by the configured algorithm policy.

    This inherits from InvalidInput for compatibility with configurations that previously reported
    algorithm whitelist violations as input errors. Callers that catch InvalidSignature will also
    handle this exception.
    """


class RedundantCert(SignXMLException):
    pass
