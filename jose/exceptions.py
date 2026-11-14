class JOSEError(Exception):
    pass


class JWSError(JOSEError):
    pass


class JWSSignatureError(JWSError):
    pass


class JWSAlgorithmError(JWSError):
    pass


class JWTError(JOSEError):
    pass


class JWTClaimsError(JWTError):
    pass


class ExpiredSignatureError(JWTError):
    pass


class JWKError(JOSEError):
    pass


class JWEError(JOSEError):
    """Base error for all JWE errors"""

    pass


class JWEParseError(JWEError):
    """Could not parse the JWE string provided"""

    pass


class JWEInvalidAuth(JWEError):
    """
    The authentication tag did not match the protected sections of the
    JWE string provided
    """

    pass


class JWEAlgorithmUnsupportedError(JWEError):
    """
    The JWE algorithm is not supported by the backend
    """

    pass


class JWEPolicyError(JWEError):
    """A configured resource budget or header policy was exceeded.

    Raised for oversized tokens or payloads, excessive compression ratios,
    too deeply nested JSON or too many JSON containers. Error messages only
    describe numeric limits, never the decrypted content.
    """

    pass


class JWEDecompressError(JWEError):
    """The compressed JWE payload could not be decompressed.

    Raised for unknown compression algorithms, truncated streams and trailing
    bytes after the end of the compressed stream.
    """

    pass


class JWEPayloadError(JWEError):
    """The decompressed JWE payload is not valid for the requested format."""

    pass
