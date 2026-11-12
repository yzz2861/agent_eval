from .api_jwk import PyJWK, PyJWKSet
from .api_jws import (
    PyJWS,
    get_algorithm_by_name,
    get_unverified_header,
    register_algorithm,
    unregister_algorithm,
)
from .api_jwt import CompressedPyJWT, PyJWT, decode, decode_complete, encode
from .compression import (
    COMPRESSION_ALGORITHMS,
    CompressionAlgorithm,
    CompressionBudget,
)
from .exceptions import (
    ClaimDepthLimitExceededError,
    ClaimLimitExceededError,
    ClaimNodeLimitExceededError,
    CompressedPayloadSizeError,
    CompressionError,
    CompressionRatioError,
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidCompressedPayloadError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
    TrailingCompressedDataError,
    TruncatedCompressedPayloadError,
    UnsupportedCompressionAlgorithmError,
)
from .jwks_client import PyJWKClient
from .warnings import InsecureKeyLengthWarning

__version__ = "2.15.1"

__title__ = "PyJWT"
__description__ = "JSON Web Token implementation in Python"
__url__ = "https://pyjwt.readthedocs.io"
__uri__ = __url__
__doc__ = f"{__description__} <{__uri__}>"

__author__ = "José Padilla"
__email__ = "hello@jpadilla.com"

__license__ = "MIT"
__copyright__ = "Copyright 2015-2026 José Padilla"


__all__ = [
    "PyJWS",
    "PyJWT",
    "CompressedPyJWT",
    "PyJWKClient",
    "PyJWK",
    "PyJWKSet",
    "CompressionBudget",
    "CompressionAlgorithm",
    "COMPRESSION_ALGORITHMS",
    "decode",
    "decode_complete",
    "encode",
    "get_unverified_header",
    "register_algorithm",
    "unregister_algorithm",
    "get_algorithm_by_name",
    # Warnings
    "InsecureKeyLengthWarning",
    # Exceptions
    "CompressionError",
    "UnsupportedCompressionAlgorithmError",
    "CompressedPayloadSizeError",
    "CompressionRatioError",
    "TruncatedCompressedPayloadError",
    "TrailingCompressedDataError",
    "InvalidCompressedPayloadError",
    "ClaimLimitExceededError",
    "ClaimNodeLimitExceededError",
    "ClaimDepthLimitExceededError",
    "DecodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAlgorithmError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "MissingRequiredClaimError",
    "PyJWKClientConnectionError",
    "PyJWKClientError",
    "PyJWKError",
    "PyJWKSetError",
    "PyJWTError",
]
