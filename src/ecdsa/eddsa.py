"""Implementation of Edwards Digital Signature Algorithm."""

import hashlib
from ._sha3 import shake_256
from . import ellipticcurve
from ._compat import (
    remove_whitespace,
    bit_length,
    bytes_to_int,
    int_to_bytes,
    compat26_str,
    normalise_bytes,
)

# edwards25519, defined in RFC7748
_p = 2**255 - 19
_a = -1
_d = int(
    remove_whitespace(
        "370957059346694393431380835087545651895421138798432190163887855330"
        "85940283555"
    )
)
_h = 8

_Gx = int(
    remove_whitespace(
        "151122213495354007725011514095885315114540126930418572060461132"
        "83949847762202"
    )
)
_Gy = int(
    remove_whitespace(
        "463168356949264781694283940034751631413079938662562256157830336"
        "03165251855960"
    )
)
_r = 2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED


def _sha512(data):
    return hashlib.new("sha512", compat26_str(data)).digest()


curve_ed25519 = ellipticcurve.CurveEdTw(_p, _a, _d, _h, _sha512)
generator_ed25519 = ellipticcurve.PointEdwards(
    curve_ed25519, _Gx, _Gy, 1, _Gx * _Gy % _p, _r, generator=True
)


# edwards448, defined in RFC7748
_p = 2**448 - 2**224 - 1
_a = 1
_d = -39081 % _p
_h = 4

_Gx = int(
    remove_whitespace(
        "224580040295924300187604334099896036246789641632564134246125461"
        "686950415467406032909029192869357953282578032075146446173674602635"
        "247710"
    )
)
_Gy = int(
    remove_whitespace(
        "298819210078481492676017930443930673437544040154080242095928241"
        "372331506189835876003536878655418784733982303233503462500531545062"
        "832660"
    )
)
_r = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D


def _shake256(data):
    return shake_256(data, 114)


curve_ed448 = ellipticcurve.CurveEdTw(_p, _a, _d, _h, _shake256)
generator_ed448 = ellipticcurve.PointEdwards(
    curve_ed448, _Gx, _Gy, 1, _Gx * _Gy % _p, _r, generator=True
)

# Signature modes as defined by RFC 8032. The mode is an explicit parameter
# of every signing and verification call, it is never folded into the data
# that gets signed, so a signature produced in one mode can't be accepted
# while verifying it in a different one.
PURE = "pure"
PREHASH = "prehash"
CONTEXT = "context"

# RFC 8032 limits the context string to a single octet length.
MAX_CONTEXT_LENGTH = 255

_MODES = frozenset((PURE, PREHASH, CONTEXT))


def _normalise_context(context):
    """Validate and normalise an EdDSA context string."""
    if context is None:
        return None
    context = normalise_bytes(context)
    if not isinstance(context, (bytes, bytearray, memoryview)):
        raise TypeError("context must be a bytes-like object")
    if len(context) > MAX_CONTEXT_LENGTH:
        raise ValueError(
            "context is too long, at most {0} bytes are allowed".format(
                MAX_CONTEXT_LENGTH
            )
        )
    return bytes(context)


def _check_mode(mode, context):
    """Validate the mode/context combination and return the normalised ctx."""
    if mode not in _MODES:
        raise ValueError(
            "invalid mode, allowed values are: {0}, {1} and {2}".format(
                PURE, PREHASH, CONTEXT
            )
        )
    context = _normalise_context(context)
    if mode != CONTEXT and context is not None:
        raise ValueError(
            "a context is only allowed together with the '{0}' mode".format(
                CONTEXT
            )
        )
    return context


def _domain_separation(curve, mode, context):
    """Build the dom2/dom4 prefix for an EdDSA signing operation.

    Ed25519 (RFC 8032 section 5.1) has no prefix for PureEdDSA, while
    Ed448 (section 5.2) always uses one. The prehash flag and the context
    length are part of the prefix, so the three modes are not interchangeable.
    """
    if curve == curve_ed25519:
        if mode == PURE:
            return bytearray()
        prefix = b"SigEd25519 no Ed25519 collisions"
    else:
        prefix = b"SigEd448"

    if mode == PREHASH:
        flag = 1
    else:
        flag = 0

    if context is None:
        context = b""

    return bytearray(prefix + bytearray((flag, len(context))) + bytes(context))


def _prepare_message(curve, mode, data):
    """Apply prehashing when the caller selected the prehash mode."""
    if mode == PREHASH:
        if curve == curve_ed25519:
            # Ed25519ph: SHA-512, 64 octets (RFC 8032 section 5.1)
            return bytes(curve.hash_func(data))
        # Ed448ph: SHAKE256 with a fixed 512-bit output (section 5.2);
        # the curve hash function itself produces the 114-octet digest
        # used inside the signature, so it can't be reused here
        return bytes(shake_256(data, 64))
    return data


class PublicKey(object):
    """Public key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, public_key, public_point=None):
        self.generator = generator
        self.curve = generator.curve()
        self.__encoded = public_key
        # plus one for the sign bit and round up
        self.baselen = (bit_length(self.curve.p()) + 1 + 7) // 8
        if len(public_key) != self.baselen:
            raise ValueError(
                "Incorrect size of the public key, expected: {0} bytes".format(
                    self.baselen
                )
            )
        if public_point:
            self.__point = public_point
        else:
            self.__point = ellipticcurve.PointEdwards.from_bytes(
                self.curve, public_key
            )

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return (
                self.curve == other.curve and self.__encoded == other.__encoded
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    @property
    def point(self):
        return self.__point

    @point.setter
    def point(self, other):
        if self.__point != other:
            raise ValueError("Can't change the coordinates of the point")
        self.__point = other

    def public_point(self):
        return self.__point

    def public_key(self):
        return self.__encoded

    def verify(self, data, signature, mode=PURE, context=None):
        """Verify an EdDSA signature over data.

        :param data: the message that was signed
        :type data: :term:`bytes-like object`
        :param bytes signature: the signature to verify
        :param str mode: one of :data:`PURE`, :data:`PREHASH` or
            :data:`CONTEXT`. The same mode (and, for :data:`CONTEXT`, the
            same context) has to be provided as when signing; a mismatch
            makes the verification fail instead of being treated as a
            pure signature.
        :param context: optional context string, only accepted together
            with the :data:`CONTEXT` mode, at most
            :data:`MAX_CONTEXT_LENGTH` bytes long
        :type context: :term:`bytes-like object`

        :raises ValueError: if the signature is malformed, the parameters
            are invalid or the signature does not verify
        """
        context = _check_mode(mode, context)
        data = compat26_str(data)
        if len(signature) != 2 * self.baselen:
            raise ValueError(
                "Invalid signature length, expected: {0} bytes".format(
                    2 * self.baselen
                )
            )
        R = ellipticcurve.PointEdwards.from_bytes(
            self.curve, signature[: self.baselen]
        )
        S = bytes_to_int(signature[self.baselen :], "little")
        if S >= self.generator.order():
            raise ValueError("Invalid signature")

        dom = _domain_separation(self.curve, mode, context)
        data = _prepare_message(self.curve, mode, data)

        k = bytes_to_int(
            self.curve.hash_func(dom + R.to_bytes() + self.__encoded + data),
            "little",
        )

        if self.generator * S != self.__point * k + R:
            raise ValueError("Invalid signature")

        return True


class PrivateKey(object):
    """Private key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, private_key):
        self.generator = generator
        self.curve = generator.curve()
        # plus one for the sign bit and round up
        self.baselen = (bit_length(self.curve.p()) + 1 + 7) // 8
        if len(private_key) != self.baselen:
            raise ValueError(
                "Incorrect size of private key, expected: {0} bytes".format(
                    self.baselen
                )
            )
        self.__private_key = bytes(private_key)
        self.__h = bytearray(self.curve.hash_func(private_key))
        self.__public_key = None

        a = self.__h[: self.baselen]
        a = self._key_prune(a)
        scalar = bytes_to_int(a, "little")
        self.__s = scalar

    @property
    def private_key(self):
        return self.__private_key

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            return (
                self.curve == other.curve
                and self.__private_key == other.__private_key
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    def _key_prune(self, key):
        # make sure the key is not in a small subgroup
        h = self.curve.cofactor()
        if h == 4:
            h_log = 2
        elif h == 8:
            h_log = 3
        else:
            raise ValueError("Only cofactor 4 and 8 curves supported")
        key[0] &= ~((1 << h_log) - 1)

        # ensure the highest bit is set but no higher
        l = bit_length(self.curve.p())
        if l % 8 == 0:
            key[-1] = 0
            key[-2] |= 0x80
        else:
            key[-1] = key[-1] & (1 << (l % 8)) - 1 | 1 << (l % 8) - 1
        return key

    def public_key(self):
        """Generate the public key based on the included private key"""
        if self.__public_key:
            return self.__public_key

        public_point = self.generator * self.__s

        self.__public_key = PublicKey(
            self.generator, public_point.to_bytes(), public_point
        )

        return self.__public_key

    def sign(self, data, mode=PURE, context=None):
        """Perform an EdDSA signature over data.

        :param data: the message to sign
        :type data: :term:`bytes-like object`
        :param str mode: one of :data:`PURE`, :data:`PREHASH` or
            :data:`CONTEXT`. Prehashing is applied only when
            :data:`PREHASH` is selected explicitly.
        :param context: optional context string, only accepted together
            with the :data:`CONTEXT` mode, at most
            :data:`MAX_CONTEXT_LENGTH` bytes long
        :type context: :term:`bytes-like object`

        :return: the encoded signature
        :rtype: bytes
        """
        context = _check_mode(mode, context)
        data = compat26_str(data)
        A = self.public_key().public_key()

        prefix = self.__h[self.baselen :]

        dom = _domain_separation(self.curve, mode, context)
        data = _prepare_message(self.curve, mode, data)

        r = bytes_to_int(self.curve.hash_func(dom + prefix + data), "little")
        R = (self.generator * r).to_bytes()

        k = bytes_to_int(self.curve.hash_func(dom + R + A + data), "little")
        k %= self.generator.order()

        S = (r + k * self.__s) % self.generator.order()

        return R + int_to_bytes(S, self.baselen, "little")
