"""
RFC 6979:
    Deterministic Usage of the Digital Signature Algorithm (DSA) and
    Elliptic Curve Digital Signature Algorithm (ECDSA)

    http://tools.ietf.org/html/rfc6979

Many thanks to Coda Hale for his implementation in Go language:
    https://github.com/codahale/rfc6979
"""

import hmac
from binascii import hexlify
from .util import number_to_string, number_to_string_crop, bit_length
from ._compat import hmac_compat, normalise_bytes


# bit_length was defined in this module previously so keep it for backwards
# compatibility, will need to deprecate and remove it later
__all__ = [
    "bit_length",
    "bits2int",
    "bits2octets",
    "generate_k",
    "validate_extra_entropy",
    "MAX_EXTRA_ENTROPY_LENGTH",
    "MAX_RETRY_GENERATION",
    "Rfc6979Error",
    "NonceGenerationError",
]

#: Maximum accepted length of the ``extra_entropy`` parameter, in bytes.
#: RFC 6979 section 3.6 suggests at most 32 bytes of additional entropy,
#: but we allow a more generous bound to accommodate callers that mix in
#: tenant or instance identifiers. Anything larger is rejected to avoid
#: unbounded work and accidental misuse.
MAX_EXTRA_ENTROPY_LENGTH = 1024

#: Maximum number of retries when generating a nonce or a deterministic
#: signature. Retries only happen when the generated value is not valid
#: (not in the 1..order-1 range or producing a zero r/s). The bound makes
#: the failure observable instead of looping forever.
MAX_RETRY_GENERATION = 1024


class Rfc6979Error(Exception):
    """Base class for errors raised by the RFC6979 nonce generation."""

    pass


class NonceGenerationError(Rfc6979Error):
    """
    Raised when a valid nonce could not be generated within the retry
    limit.

    This error is distinguishable from transient signature failures so
    that callers can alert on it instead of retrying indefinitely.
    """

    pass


def validate_extra_entropy(extra_entropy):
    """
    Check the type and length of ``extra_entropy`` and return it
    normalised to ``bytes``.

    :param extra_entropy: additional data for the RFC6979 process
    :type extra_entropy: :term:`bytes-like object`
    :raises TypeError: if the value is not a bytes-like object
    :raises ValueError: if the value is longer than
        ``MAX_EXTRA_ENTROPY_LENGTH`` bytes
    :rtype: bytes
    """
    try:
        entropy = bytes(normalise_bytes(extra_entropy))
    except TypeError:
        raise TypeError(
            "extra_entropy must be a bytes-like object, got {0}".format(
                type(extra_entropy).__name__
            )
        )
    if len(entropy) > MAX_EXTRA_ENTROPY_LENGTH:
        raise ValueError(
            "extra_entropy too long: {0} bytes, maximum is {1} bytes".format(
                len(entropy), MAX_EXTRA_ENTROPY_LENGTH
            )
        )
    return entropy


def bits2int(data, qlen):
    x = int(hexlify(data), 16)
    l = len(data) * 8

    if l > qlen:
        return x >> (l - qlen)
    return x


def bits2octets(data, order):
    z1 = bits2int(data, bit_length(order))
    z2 = z1 - order

    if z2 < 0:
        z2 = z1

    return number_to_string_crop(z2, order)


# https://tools.ietf.org/html/rfc6979#section-3.2
def generate_k(
    order,
    secexp,
    hash_func,
    data,
    retry_gen=0,
    extra_entropy=b"",
    max_retries=None,
):
    """
    Generate the ``k`` value - the nonce for DSA.

    :param int order: order of the DSA generator used in the signature
    :param int secexp: secure exponent (private key) in numeric form
    :param hash_func: reference to the same hash function used for generating
        hash, like :py:class:`hashlib.sha1`
    :param bytes data: hash in binary form of the signing data
    :param int retry_gen: how many good 'k' values to skip before returning
    :param bytes extra_entropy: additional added data in binary form as per
        section-3.6 of rfc6979. Must be a bytes-like object of at most
        ``MAX_EXTRA_ENTROPY_LENGTH`` bytes, it will be normalised to
        ``bytes`` before use.
    :param int max_retries: maximum number of retries when the generated
        value is not a valid nonce (not in the 1..order-1 range) before
        giving up, ``MAX_RETRY_GENERATION`` by default
    :rtype: int
    :raises TypeError: if ``extra_entropy`` is not a bytes-like object
    :raises ValueError: if ``extra_entropy`` is longer than
        ``MAX_EXTRA_ENTROPY_LENGTH`` bytes
    :raises NonceGenerationError: if no valid nonce was found within
        ``max_retries`` retries
    """

    extra_entropy = validate_extra_entropy(extra_entropy)
    if max_retries is None:
        max_retries = MAX_RETRY_GENERATION

    qlen = bit_length(order)
    holen = hash_func().digest_size
    rolen = (qlen + 7) // 8
    bx = (
        hmac_compat(number_to_string(secexp, order)),
        hmac_compat(bits2octets(data, order)),
        hmac_compat(extra_entropy),
    )

    # Step B
    v = b"\x01" * holen

    # Step C
    k = b"\x00" * holen

    # Step D

    k = hmac.new(k, digestmod=hash_func)
    k.update(v + b"\x00")
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step E
    v = hmac.new(k, v, hash_func).digest()

    # Step F
    k = hmac.new(k, digestmod=hash_func)
    k.update(v + b"\x01")
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step G
    v = hmac.new(k, v, hash_func).digest()

    # Step H
    retries = 0
    while True:
        # Step H1
        t = b""

        # Step H2
        while len(t) < rolen:
            v = hmac.new(k, v, hash_func).digest()
            t += v

        # Step H3
        secret = bits2int(t, qlen)

        if 1 <= secret < order:
            if retry_gen <= 0:
                return secret
            retry_gen -= 1
        else:
            retries += 1
            if retries > max_retries:
                raise NonceGenerationError(
                    "no valid nonce found after {0} retries".format(
                        max_retries
                    )
                )

        k = hmac.new(k, v + b"\x00", hash_func).digest()
        v = hmac.new(k, v, hash_func).digest()
