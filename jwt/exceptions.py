class PyJWTError(Exception):
    """
    Base class for all exceptions
    """

    pass


class InvalidTokenError(PyJWTError):
    """Base exception when ``decode()`` fails on a token"""

    pass


class DecodeError(InvalidTokenError):
    """Raised when a token cannot be decoded because it failed validation"""

    pass


class InvalidSignatureError(DecodeError):
    """Raised when a token's signature doesn't match the one provided as part of
    the token."""

    pass


class ExpiredSignatureError(InvalidTokenError):
    """Raised when a token's ``exp`` claim indicates that it has expired"""

    pass


class InvalidAudienceError(InvalidTokenError):
    """Raised when a token's ``aud`` claim does not match one of the expected
    audience values"""

    pass


class InvalidIssuerError(InvalidTokenError):
    """Raised when a token's ``iss`` claim does not match the expected issuer"""

    pass


class InvalidIssuedAtError(InvalidTokenError):
    """Raised when a token's ``iat`` claim is non-numeric"""

    pass


class ImmatureSignatureError(InvalidTokenError):
    """Raised when a token's ``nbf`` or ``iat`` claims represent a time in the future"""

    pass


class InvalidKeyError(PyJWTError):
    """Raised when the specified key is not in the proper format"""

    pass


class InvalidAlgorithmError(InvalidTokenError):
    """Raised when the specified algorithm is not recognized by PyJWT"""

    pass


class MissingRequiredClaimError(InvalidTokenError):
    """Raised when a claim that is required to be present is not contained
    in the claimset"""

    def __init__(self, claim: str) -> None:
        self.claim = claim

    def __str__(self) -> str:
        return f'Token is missing the "{self.claim}" claim'


class PyJWKError(PyJWTError):
    pass


class MissingCryptographyError(PyJWKError):
    """Raised if the algorithm requires ``cryptography`` to be installed and it is not available."""

    pass


class PyJWKSetError(PyJWTError):
    pass


class PyJWKClientError(PyJWTError):
    pass


class PyJWKClientConnectionError(PyJWKClientError):
    pass


class InvalidSubjectError(InvalidTokenError):
    """Raised when a token's ``sub`` claim is not a string or doesn't match the expected ``subject``"""

    pass


class InvalidJTIError(InvalidTokenError):
    """Raised when a token's ``jti`` claim is not a string"""

    pass


class TrustDomainError(InvalidTokenError):
    """Base exception for trust-domain mismatches.

    Raised when a token cannot be associated with a configured trust
    domain (validation profile) at all, as opposed to tokens that belong
    to a known domain but fail validation within it.
    """

    pass


class UnknownIssuerError(TrustDomainError):
    """Raised when a token's ``iss`` claim does not match any registered
    validation profile, so no trust domain can be selected for it"""

    pass


class UnknownKeyError(InvalidTokenError):
    """Raised when a token's ``kid`` header does not match any key
    configured in the selected validation profile"""

    pass


class InvalidTypError(InvalidTokenError):
    """Raised when a token's ``typ`` header does not match the value
    required by the selected validation profile"""

    pass


class TokenTooOldError(InvalidTokenError):
    """Raised when a token's age (based on its ``iat`` claim) exceeds the
    maximum age allowed by the selected validation profile"""

    pass
