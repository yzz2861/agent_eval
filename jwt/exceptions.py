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


class CompressionError(DecodeError):
    """Base class for failures while decompressing a compressed JWT payload.

    Every subclass is a :class:`DecodeError`, so existing callers that catch
    ``DecodeError`` keep working, while the concrete subclass distinguishes
    budget violations from malformed streams.
    """

    pass


class UnsupportedCompressionAlgorithmError(CompressionError):
    """Raised when the JWT ``zip`` header names a compression algorithm that
    the decoder does not support or has not been configured to allow."""

    pass


class CompressedPayloadSizeError(CompressionError):
    """Raised when a compressed payload exceeds the configured compressed or
    decompressed byte budget. The check happens before a large buffer is
    allocated, so an oversized token cannot exhaust worker memory."""

    pass


class CompressionRatioError(CompressionError):
    """Raised when the ratio between decompressed and compressed bytes would
    exceed the configured budget, i.e. a decompression bomb."""

    pass


class TruncatedCompressedPayloadError(CompressionError):
    """Raised when a compressed payload ends before the compression stream's
    own end-of-stream marker."""

    pass


class TrailingCompressedDataError(CompressionError):
    """Raised when bytes remain after the compression stream's end-of-stream
    marker."""

    pass


class InvalidCompressedPayloadError(CompressionError):
    """Raised when a compressed payload cannot be decompressed because the
    stream itself is corrupt."""

    pass


class ClaimLimitExceededError(DecodeError):
    """Base class for claim structure budget violations discovered while
    parsing a decompressed payload."""

    pass


class ClaimNodeLimitExceededError(ClaimLimitExceededError):
    """Raised when a decompressed payload contains more JSON value nodes than
    the per-decode budget allows."""

    pass


class ClaimDepthLimitExceededError(ClaimLimitExceededError):
    """Raised when a decompressed payload nests JSON containers more deeply
    than the per-decode budget allows."""

    pass
