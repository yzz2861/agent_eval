"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

from .errors import MalformedPointError
from .util import number_to_string, orderlen
from .ellipticcurve import INFINITY, Point, PointJacobi
from .keys import SigningKey, VerifyingKey


__all__ = [
    "ECDH",
    "NoKeyError",
    "NoCurveError",
    "InvalidCurveError",
    "InvalidPointError",
    "InvalidSubgroupError",
    "InvalidSharedSecretError",
]


class NoKeyError(Exception):
    """ECDH. Key not found but it is needed for operation."""

    pass


class NoCurveError(Exception):
    """ECDH. Curve not set but it is needed for operation."""

    pass


class InvalidCurveError(Exception):
    """
    ECDH. Raised in case the public and private keys use different curves.
    """

    pass


class InvalidPointError(MalformedPointError):
    """
    ECDH. Raised when a received public point is invalid.

    This covers points at infinity, points outside the field, points not on
    the selected curve, and malformed public key encodings.
    """

    pass


class InvalidSubgroupError(Exception):
    """
    ECDH. Raised when a received public point is not in the required subgroup.
    """

    pass


class InvalidSharedSecretError(Exception):
    """
    ECDH. Raised when the shared secret is degenerate.

    This covers a point at infinity or an all-zero secret, as well as an
    invalid local private scalar.
    """

    pass


def _curve_field(curve):
    return getattr(curve, "curve", None)


def _curve_cofactor(curve):
    field = _curve_field(curve)
    if field is None or not hasattr(field, "cofactor"):
        return None
    return field.cofactor()


def _curve_field_matches(left, right):
    if left is right:
        return True
    if left is None or right is None:
        return False
    try:
        if not all(
            hasattr(curve, attr)
            for curve in (left, right)
            for attr in ("p", "a", "b")
        ):
            return False
        lp, rp = int(left.p()), int(right.p())
        if lp != rp:
            return False
        if int(left.a()) % lp != int(right.a()) % rp:
            return False
        if int(left.b()) % lp != int(right.b()) % rp:
            return False
        if hasattr(left, "cofactor") and hasattr(right, "cofactor"):
            lco, rco = left.cofactor(), right.cofactor()
            if lco is not None and rco is not None and int(lco) != int(rco):
                return False
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _curve_matches(left, right):
    """Compare complete public curve parameters, not just object identity."""
    if left is right:
        return True
    if left is None or right is None:
        return False
    try:
        lf, rf = _curve_field(left), _curve_field(right)
        if not _curve_field_matches(lf, rf):
            return False

        lgen = getattr(left, "generator", None)
        rgen = getattr(right, "generator", None)
        if lgen is None or rgen is None:
            return False
        if lgen.curve() is None or rgen.curve() is None:
            return False
        if not _curve_field_matches(lgen.curve(), rgen.curve()):
            return False
        if int(lgen.x()) != int(rgen.x()):
            return False
        if int(lgen.y()) != int(rgen.y()):
            return False
        if lgen.order() != rgen.order():
            return False

        lorder = getattr(left, "order", None)
        rorder = getattr(right, "order", None)
        if lorder != rorder:
            return False

        lco, rco = _curve_cofactor(left), _curve_cofactor(right)
        if lco is not None and rco is not None and int(lco) != int(rco):
            return False
    except (AttributeError, TypeError, ValueError):
        return False
    return True


class ECDH(object):
    """
    Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.

    Allows two parties, each having an elliptic-curve public-private key
    pair, to establish a shared secret over an insecure channel
    """

    def __init__(
        self,
        curve=None,
        private_key=None,
        public_key=None,
        strict=False,
        check_subgroup=None,
    ):
        """
        ECDH init.

        Call can be initialised without parameters, then the first operation
        (loading either key) will set the used curve.
        All parameters must be ultimately set before shared secret
        calculation will be allowed.

        :param curve: curve for operations
        :type curve: Curve
        :param private_key: `my` private key for ECDH
        :type private_key: SigningKey
        :param public_key:  `their` public key for ECDH
        :type public_key: VerifyingKey
        :param strict: enable full received-public-point validation, including
            subgroup validation, defaults to False for compatibility
        :type strict: bool
        :param check_subgroup: explicitly require the received point to be in
            the subgroup generated by the curve generator. If ``None``,
            subgroup validation is enabled by ``strict`` or by a curve with a
            non-unit cofactor.
        :type check_subgroup: bool
        """
        self.curve = curve
        self.strict = bool(strict)
        self.check_subgroup = (
            None if check_subgroup is None else bool(check_subgroup)
        )
        self.private_key = None
        self.public_key = None
        self._validated_public_point = None
        if private_key:
            self.load_private_key(private_key)
        if public_key:
            self.load_received_public_key(public_key, strict=strict)

    def _subgroup_validation_required(self, strict, check_subgroup):
        if check_subgroup is not None:
            return bool(check_subgroup) or bool(strict)
        if self.check_subgroup is not None:
            return self.check_subgroup or bool(strict)
        if strict or self.strict:
            return True
        cofactor = _curve_cofactor(self.curve)
        return cofactor is not None and int(cofactor) != 1

    def _validate_received_public_key(
        self, public_key, strict=None, check_subgroup=None
    ):
        if not hasattr(public_key, "curve") or not hasattr(
            public_key, "pubkey"
        ):
            raise InvalidPointError("Invalid public key object.")
        if public_key.curve is None:
            raise InvalidCurveError("Curve mismatch.")
        if self.curve is None:
            self.curve = public_key.curve
        if _curve_field(self.curve) is None:
            raise InvalidCurveError("Curve mismatch.")
        if not _curve_matches(self.curve, public_key.curve):
            raise InvalidCurveError("Curve mismatch.")

        point = getattr(public_key.pubkey, "point", None)
        if point is None or point == INFINITY:
            raise InvalidPointError(
                "Invalid public point (point at infinity)."
            )
        if not hasattr(point, "curve") or not _curve_field_matches(
            point.curve(), _curve_field(self.curve)
        ):
            raise InvalidPointError(
                "Invalid public point (point is on a different curve)."
            )

        try:
            x, y = int(point.x()), int(point.y())
        except (TypeError, ValueError, AttributeError):
            raise InvalidPointError("Invalid public point coordinates.")

        prime = self.curve.curve.p()
        if not (0 <= x < prime) or not (0 <= y < prime):
            raise InvalidPointError(
                "Invalid public point (coordinates out of range)."
            )
        if not self.curve.curve.contains_point(x, y):
            raise InvalidPointError(
                "Invalid public point (point is not on the curve)."
            )

        validated_point = PointJacobi(
            self.curve.curve, x, y, 1, self.curve.order
        )
        effective_strict = self.strict if strict is None else bool(strict)
        if self._subgroup_validation_required(
            effective_strict, check_subgroup
        ):
            subgroup_point = Point(self.curve.curve, x, y)
            if self.curve.order * subgroup_point != INFINITY:
                raise InvalidSubgroupError(
                    "Invalid public point (subgroup validation failed)."
                )

        # Keep a private copy so later mutation of the caller's key cannot
        # change the point used in the actual key agreement.
        return validated_point

    def _get_shared_secret(self, remote_public_key):
        if not self.private_key:
            raise NoKeyError(
                "Private key needs to be set to create shared secret"
            )
        if not self.public_key:
            raise NoKeyError(
                "Public key needs to be set to create shared secret"
            )
        if not _curve_matches(self.private_key.curve, self.curve):
            raise InvalidCurveError(
                "Curves for public key and private key are not equal."
            )

        try:
            secret_multiplier = int(
                self.private_key.privkey.secret_multiplier
            )
        except (TypeError, ValueError, AttributeError):
            raise InvalidSharedSecretError(
                "Invalid private key scalar."
            )
        if not 1 <= secret_multiplier < self.curve.order:
            raise InvalidSharedSecretError(
                "Invalid private key scalar."
            )

        validated_point = self._validate_received_public_key(
            remote_public_key
        )

        # shared secret = PUBKEYtheirs * PRIVATEKEYours
        result = validated_point * secret_multiplier
        if result == INFINITY:
            raise InvalidSharedSecretError("Invalid shared secret (INFINITY).")

        secret = int(result.x())
        if secret == 0:
            raise InvalidSharedSecretError("Invalid shared secret (zero).")
        return secret

    def set_curve(self, key_curve):
        """
        Set the working curve for ecdh operations.

        :param key_curve: curve from `curves` module
        :type key_curve: Curve
        """
        self.curve = key_curve
        self._validated_public_point = None

    def generate_private_key(self):
        """
        Generate local private key for ecdh operation with curve that was set.

        :raises NoCurveError: Curve must be set before key generation.

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        if not self.curve:
            raise NoCurveError("Curve must be set prior to key generation.")
        return self.load_private_key(SigningKey.generate(curve=self.curve))

    def load_private_key(self, private_key):
        """
        Load private key from SigningKey (keys.py) object.

        Needs to have the same curve as was set with set_curve method.
        If curve is not set - it sets from this SigningKey

        :param private_key: Initialised SigningKey class
        :type private_key: SigningKey

        :raises InvalidCurveError: private_key curve not the same as self.curve

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        if not hasattr(private_key, "curve") or not hasattr(
            private_key, "get_verifying_key"
        ):
            raise TypeError("private_key must be a SigningKey")
        if private_key.curve is None:
            raise InvalidCurveError("Curve mismatch.")
        if not self.curve:
            self.curve = private_key.curve
        if _curve_field(self.curve) is None:
            raise InvalidCurveError("Curve mismatch.")
        if not _curve_matches(self.curve, private_key.curve):
            raise InvalidCurveError("Curve mismatch.")
        self.private_key = private_key
        self._validated_public_point = None
        return self.private_key.get_verifying_key()

    def load_private_key_bytes(self, private_key):
        """
        Load private key from byte string.

        Uses current curve and checks if the provided key matches
        the curve of ECDH key agreement.
        Key loads via from_string method of SigningKey class

        :param private_key: private key in bytes string format
        :type private_key: :term:`bytes-like object`

        :raises NoCurveError: Curve must be set before loading.

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        if not self.curve:
            raise NoCurveError("Curve must be set prior to key load.")
        return self.load_private_key(
            SigningKey.from_string(private_key, curve=self.curve)
        )

    def load_private_key_der(self, private_key_der):
        """
        Load private key from DER byte string.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only DER format supported is the RFC5915
        Look at keys.py:SigningKey.from_der()

        :param private_key_der: string with the DER encoding of private ECDSA
            key
        :type private_key_der: string

        :raises InvalidCurveError: private_key curve not the same as self.curve

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        return self.load_private_key(SigningKey.from_der(private_key_der))

    def load_private_key_pem(self, private_key_pem):
        """
        Load private key from PEM string.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only PEM format supported is the RFC5915
        Look at keys.py:SigningKey.from_pem()
        it needs to have `EC PRIVATE KEY` section

        :param private_key_pem: string with PEM-encoded private ECDSA key
        :type private_key_pem: string

        :raises InvalidCurveError: private_key curve not the same as self.curve

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        return self.load_private_key(SigningKey.from_pem(private_key_pem))

    def get_public_key(self):
        """
        Provides a public key that matches the local private key.

        Needs to be sent to the remote party.

        :return: public (verifying) key from local private key.
        :rtype: VerifyingKey
        """
        return self.private_key.get_verifying_key()

    def load_received_public_key(
        self, public_key, strict=None, check_subgroup=None
    ):
        """
        Load public key from VerifyingKey (keys.py) object.

        Needs to have the same curve as set as current for ecdh operation.
        If curve is not set - it sets it from VerifyingKey.

        :param public_key: Initialised VerifyingKey class
        :type public_key: VerifyingKey
        :param strict: enable full point validation for this key, defaults to
            the mode configured on the ECDH object
        :type strict: bool
        :param check_subgroup: require the point to be in the curve's subgroup,
            defaults to the mode configured on the ECDH object
        :type check_subgroup: bool

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises InvalidPointError: public point is infinite, off curve or
            otherwise malformed
        :raises InvalidSubgroupError: public point failed subgroup validation
        """
        validated_point = self._validate_received_public_key(
            public_key, strict=strict, check_subgroup=check_subgroup
        )
        self.public_key = public_key
        self._validated_public_point = validated_point

    def load_received_public_key_bytes(
        self,
        public_key_str,
        valid_encodings=None,
        curve=None,
        strict=None,
        check_subgroup=None,
    ):
        """
        Load public key from byte string.

        Uses the current curve to decode the point, then validates the curve,
        point coordinates, and subgroup according to the configured mode.
        Key loads via from_string method of VerifyingKey class

        :param public_key_str: public key in bytes string format
        :type public_key_str: :term:`bytes-like object`
        :param valid_encodings: list of acceptable point encoding formats,
            supported ones are: :term:`uncompressed`, :term:`compressed`,
            :term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
            name). All formats by default (specified with ``None``).
        :type valid_encodings: :term:`set-like object`
        :param curve: curve associated with the encoded point. This lets the
            caller verify the peer's declared curve before decoding. Defaults
            to the curve configured on this ECDH object.
        :type curve: Curve
        :param strict: enable full point validation for this key
        :type strict: bool
        :param check_subgroup: require the point to be in the curve's subgroup
        :type check_subgroup: bool

        :raises NoCurveError: no curve is configured
        :raises InvalidCurveError: the declared peer curve differs from the
            local curve
        :raises InvalidPointError: the encoded point is malformed or invalid
        """
        if curve is not None:
            if self.curve is not None and not _curve_matches(
                self.curve, curve
            ):
                raise InvalidCurveError("Curve mismatch.")
            decode_curve = self.curve if self.curve is not None else curve
        else:
            decode_curve = self.curve
        if decode_curve is None:
            raise NoCurveError("Curve must be set prior to key load.")
        try:
            public_key = VerifyingKey.from_string(
                public_key_str,
                decode_curve,
                valid_encodings=valid_encodings,
            )
        except MalformedPointError:
            raise InvalidPointError(
                "Invalid public point encoding."
            )
        return self.load_received_public_key(
            public_key, strict=strict, check_subgroup=check_subgroup
        )

    def load_received_public_key_der(
        self, public_key_der, strict=None, check_subgroup=None
    ):
        """
        Load public key from DER byte string.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only DER format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_der()

        :param public_key_der: string with the DER encoding of public ECDSA key
        :type public_key_der: string
        :param strict: enable full point validation for this key
        :type strict: bool
        :param check_subgroup: require the point to be in the curve's subgroup
        :type check_subgroup: bool

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises InvalidPointError: the encoded point is malformed or invalid
        """
        try:
            public_key = VerifyingKey.from_der(public_key_der)
        except MalformedPointError:
            raise InvalidPointError(
                "Invalid public point encoding."
            )
        return self.load_received_public_key(
            public_key, strict=strict, check_subgroup=check_subgroup
        )

    def load_received_public_key_pem(
        self, public_key_pem, strict=None, check_subgroup=None
    ):
        """
        Load public key from PEM string.

        Compares the curve of the PEM-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only PEM format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_pem()

        :param public_key_pem: string with PEM-encoded public ECDSA key
        :type public_key_pem: string
        :param strict: enable full point validation for this key
        :type strict: bool
        :param check_subgroup: require the point to be in the curve's subgroup
        :type check_subgroup: bool

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises InvalidPointError: the encoded point is malformed or invalid
        """
        try:
            public_key = VerifyingKey.from_pem(public_key_pem)
        except MalformedPointError:
            raise InvalidPointError(
                "Invalid public point encoding."
            )
        return self.load_received_public_key(
            public_key, strict=strict, check_subgroup=check_subgroup
        )

    def generate_sharedsecret_bytes(self):
        """
        Generate shared secret from local private key and remote public key.

        The objects needs to have both private key and received public key
        before generation is allowed.

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises InvalidPointError: public point is invalid
        :raises InvalidSubgroupError: public point failed subgroup validation
        :raises InvalidSharedSecretError: shared secret is degenerate
        :raises NoKeyError: public_key or private_key is not set

        :return: shared secret
        :rtype: bytes
        """
        shared_secret = self.generate_sharedsecret()
        prime = self.curve.curve.p()
        encoded = number_to_string(shared_secret, prime)
        if len(encoded) != orderlen(prime):
            raise InvalidSharedSecretError(
                "Invalid shared secret encoding length."
            )
        return encoded

    def generate_sharedsecret(self):
        """
        Generate shared secret from local private key and remote public key.

        The objects needs to have both private key and received public key
        before generation is allowed.

        It's the same for local and remote party,
        shared secret(local private key, remote public key) ==
        shared secret(local public key, remote private key)

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises NoKeyError: public_key or private_key is not set

        :return: shared secret
        :rtype: int
        """
        return self._get_shared_secret(self.public_key)
