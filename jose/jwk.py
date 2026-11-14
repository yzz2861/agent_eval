from jose.backends.base import Key
from jose.constants import ALGORITHMS
from jose.exceptions import JWKError
from jose.utils import base64url_decode

try:
    from jose.backends import RSAKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import ECKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import AESKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import DIRKey  # noqa: F401
except ImportError:
    pass

try:
    from jose.backends import HMACKey  # noqa: F401
except ImportError:
    pass


def get_key(algorithm):
    if algorithm in ALGORITHMS.KEYS:
        return ALGORITHMS.KEYS[algorithm]
    elif algorithm in ALGORITHMS.HMAC:  # noqa: F811
        return HMACKey
    elif algorithm in ALGORITHMS.RSA:
        from jose.backends import RSAKey  # noqa: F811

        return RSAKey
    elif algorithm in ALGORITHMS.EC:
        from jose.backends import ECKey  # noqa: F811

        return ECKey
    elif algorithm in ALGORITHMS.AES:
        from jose.backends import AESKey  # noqa: F811

        return AESKey
    elif algorithm == ALGORITHMS.DIR:
        from jose.backends import DIRKey  # noqa: F811

        return DIRKey
    return None


# Mapping of JWS/JWE algorithm families (as named by the ``kty`` JWK member)
# to the algorithm sets implemented by the corresponding backend.
_ALGORITHM_FAMILIES = {
    "oct": ALGORITHMS.HMAC,
    "RSA": ALGORITHMS.RSA,
    "EC": ALGORITHMS.EC,
    "OKP": set(),
}

# Required key type (JWK ``kty``) for each supported algorithm.
_ALGORITHM_KTY = {
    **{algorithm: "oct" for algorithm in ALGORITHMS.HMAC},
    **{algorithm: "RSA" for algorithm in ALGORITHMS.RSA},
    **{algorithm: "EC" for algorithm in ALGORITHMS.EC},
}

# RFC 7518 section 3.2/3.3/3.4 minimum key sizes for signature algorithms.
_HMAC_MIN_KEY_SIZES = {
    ALGORITHMS.HS256: 256,
    ALGORITHMS.HS384: 384,
    ALGORITHMS.HS512: 512,
}

_RSA_MIN_KEY_SIZE = 2048

_EC_REQUIRED_CURVES = {
    ALGORITHMS.ES256: "P-256",
    ALGORITHMS.ES384: "P-384",
    ALGORITHMS.ES512: "P-521",
}

# Operations required for each key usage, per RFC 7517 section 4.3.
_OPERATION_KEY_OPS = {
    "sign": "sign",
    "verify": "verify",
}

# Cache of constructed JWK keys. The cache key only carries the algorithm
# family and the JWK ``kid``; it never contains key material.
_jwk_cache = {}


def get_algorithm_family(algorithm):
    """Return the JWK key type (``kty``) associated with an algorithm.

    Returns ``None`` for algorithms that do not map to a JWK key type.
    """
    return _ALGORITHM_KTY.get(algorithm)


def clear_jwk_cache():
    """Drop every cached JWK key. Intended for tests and key rotation."""
    _jwk_cache.clear()


def _jwk_cache_key(algorithm, kid):
    return (get_algorithm_family(algorithm), kid, algorithm)


def _ensure_expected_kty(jwk_data, algorithm):
    kty = jwk_data.get("kty")
    expected_kty = get_algorithm_family(algorithm)
    if expected_kty is None:
        raise JWKError("Algorithm %s does not support JWK keys" % algorithm)
    if kty not in _ALGORITHM_FAMILIES:
        raise JWKError("Unknown JWK key type for algorithm %s" % algorithm)
    if kty != expected_kty:
        raise JWKError(
            "JWK key type %s cannot be used with algorithm %s, expected %s"
            % (kty, algorithm, expected_kty)
        )
    if algorithm not in _ALGORITHM_FAMILIES[kty]:
        raise JWKError("Algorithm %s is not valid for JWK key type %s" % (algorithm, kty))


def _validate_alg_member(jwk_data, algorithm):
    jwk_alg = jwk_data.get("alg")
    if jwk_alg is not None and jwk_alg != algorithm:
        raise JWKError("JWK alg does not match the requested algorithm")


def _validate_use_and_key_ops(jwk_data, operation):
    use = jwk_data.get("use")
    if use is not None and use != "sig":
        raise JWKError("JWK use %s does not permit signature operations" % use)

    key_ops = jwk_data.get("key_ops")
    if key_ops is None:
        return
    if not isinstance(key_ops, (list, tuple)) or not key_ops:
        raise JWKError("JWK key_ops must be a non-empty list")
    required_op = _OPERATION_KEY_OPS.get(operation)
    if required_op is not None and required_op not in key_ops:
        raise JWKError("JWK key_ops do not permit the %s operation" % required_op)


def _decode_oct_key(jwk_data):
    encoded_key = jwk_data.get("k")
    if not isinstance(encoded_key, str):
        raise JWKError("JWK oct key is missing the 'k' member")
    try:
        return base64url_decode(encoded_key.encode("utf-8"))
    except Exception:
        raise JWKError("JWK oct key contains an invalid 'k' member")


def _validate_oct_size(jwk_data, algorithm):
    key_material = _decode_oct_key(jwk_data)
    min_bits = _HMAC_MIN_KEY_SIZES.get(algorithm)
    if min_bits is not None and len(key_material) * 8 < min_bits:
        raise JWKError(
            "JWK oct key is too short for algorithm %s, expected at least %d bits" % (algorithm, min_bits)
        )


def _base64url_uint(member):
    if not isinstance(member, str):
        return None
    try:
        padding = b"=" * (-len(member) % 4)
        return int.from_bytes(base64url_decode(member.encode("utf-8") + padding), "big")
    except Exception:
        return None


def _validate_rsa_size(jwk_data):
    modulus = _base64url_uint(jwk_data.get("n"))
    if modulus is None:
        raise JWKError("RSA JWK is missing a valid 'n' member")
    if modulus.bit_length() < _RSA_MIN_KEY_SIZE:
        raise JWKError("RSA JWK modulus must be at least %d bits" % _RSA_MIN_KEY_SIZE)


def _validate_ec_curve(jwk_data, algorithm):
    expected_curve = _EC_REQUIRED_CURVES.get(algorithm)
    curve = jwk_data.get("crv")
    if curve != expected_curve:
        raise JWKError(
            "EC JWK curve %s does not match algorithm %s, expected %s" % (curve, algorithm, expected_curve)
        )
    if not isinstance(jwk_data.get("x"), str) or not isinstance(jwk_data.get("y"), str):
        raise JWKError("EC JWK is missing the 'x' or 'y' member")


def validate_jwk(jwk_data, algorithm, operation="verify"):
    """Validate a JWK dict against a requested algorithm and operation.

    The checks cover the JWK key type (``kty``), explicit ``alg`` member,
    ``use``/``key_ops`` and the minimum key sizes and curves required by the
    JWS signature algorithms. Key material is never included in errors.
    """
    if not isinstance(jwk_data, dict):
        raise JWKError("A JWK must be a JSON object")

    _ensure_expected_kty(jwk_data, algorithm)
    _validate_alg_member(jwk_data, algorithm)
    _validate_use_and_key_ops(jwk_data, operation)

    kty = jwk_data["kty"]
    if kty == "oct":
        _validate_oct_size(jwk_data, algorithm)
    elif kty == "RSA":
        _validate_rsa_size(jwk_data)
    elif kty == "EC":
        _validate_ec_curve(jwk_data, algorithm)

    return jwk_data


def construct_from_jwk(jwk_data, algorithm, operation="verify"):
    """Validate and construct a JWK key, caching by family, kid and algorithm."""
    validate_jwk(jwk_data, algorithm, operation)
    kid = jwk_data.get("kid")
    if kid is None:
        # Without a kid there is no stable cache identity; never reuse a key
        # constructed for a different, kid-less JWK.
        return construct(jwk_data, algorithm)
    cache_key = _jwk_cache_key(algorithm, kid)
    if cache_key in _jwk_cache:
        return _jwk_cache[cache_key]

    constructed_key = construct(jwk_data, algorithm)
    _jwk_cache[cache_key] = constructed_key
    return constructed_key


def register_key(algorithm, key_class):
    if not issubclass(key_class, Key):
        raise TypeError("Key class is not a subclass of jwk.Key")
    ALGORITHMS.KEYS[algorithm] = key_class
    ALGORITHMS.SUPPORTED.add(algorithm)
    return True


def construct(key_data, algorithm=None):
    """
    Construct a Key object for the given algorithm with the given
    key_data.
    """

    # Allow for pulling the algorithm off of the passed in jwk.
    if not algorithm and isinstance(key_data, dict):
        algorithm = key_data.get("alg", None)

    if not algorithm:
        raise JWKError("Unable to find an algorithm for key")

    key_class = get_key(algorithm)
    if not key_class:
        raise JWKError("Unable to find an algorithm for key")
    return key_class(key_data, algorithm)
