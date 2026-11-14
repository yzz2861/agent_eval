# coding: utf-8

"""
Centralized policy checks that bind an algorithm identity (an OID) to the
parameters and key material it is paired with.

The regular ASN.1 type classes in ``asn1crypto.algos``, ``asn1crypto.keys``
and ``asn1crypto.x509`` intentionally stay permissive so that unknown
algorithms can still be parsed. The functions in this module are only invoked
when a caller explicitly asks for validation ("strict mode") or reaches an
entry point that is going to act on the algorithm, such as verifying a
signature. Default parsing behavior is therefore unchanged.

Every error message includes the offending OID (and, when relevant, the ASN.1
type name of the parameters), but never any key material. The OID and
parameter type are also exposed as attributes on the raised exception.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._errors import unwrap
from ._types import int_types
from .core import Null, Void


# Minimum RSA modulus size, in bits, accepted in strict mode. Legacy 1024-bit
# keys still parse and validate outside of strict mode.
MIN_RSA_KEY_SIZE = 2048

# Public exponents considered safe for RSA verification.
SAFE_RSA_PUBLIC_EXPONENTS = set([65537, 3])

# keyUsage bits (RFC 5280 4.2.1.3) that permit each operation. The names
# match asn1crypto.x509.KeyUsage._map.
_KEY_USAGE_SIGN = set(['digital_signature', 'non_repudiation'])
_KEY_USAGE_CERT_SIGN = set(['key_cert_sign'])
_KEY_USAGE_CRL_SIGN = set(['crl_sign'])
_KEY_USAGE_KEY_ENCIPHER = set(['key_encipherment'])
_KEY_USAGE_DATA_ENCIPHER = set(['data_encipherment'])
_KEY_USAGE_AGREEMENT = set(['key_agreement'])

# RFC 5480 section 2.1.1.1 mandates the namedCurve choice for EC keys in
# PKIX profiles, restricted to the curves registered for certificates.
# Non-PKIX curves such as secp256k1, and explicitly specified domain
# parameters, are still parsed but rejected at the verification boundary.
_RFC5480_NAMED_CURVES = set([
    '1.3.132.0.33',  # secp224r1
    '1.2.840.10045.3.1.7',  # prime256v1 / secp256r1
    '1.3.132.0.34',  # secp384r1
    '1.3.132.0.35',  # secp521r1
    '1.3.132.0.26',  # sect233k1
    '1.3.132.0.27',  # sect233r1
    '1.3.132.0.16',  # sect283k1
    '1.3.132.0.17',  # sect283r1
    '1.3.132.0.36',  # sect409k1
    '1.3.132.0.37',  # sect409r1
    '1.3.132.0.38',  # sect571k1
    '1.3.132.0.39',  # sect571r1
])


class AlgorithmValidationError(ValueError):
    """
    Base class for all algorithm/parameter/key policy failures. Subclasses let
    callers distinguish the category of problem without parsing the message.
    """

    def __init__(self, message, oid=None, parameter_type=None):
        self.oid = oid
        self.parameter_type = parameter_type
        super(AlgorithmValidationError, self).__init__(message)


class UnknownAlgorithmError(AlgorithmValidationError):
    """
    Raised when an AlgorithmIdentifier references an OID that has no policy.
    Unknown algorithms remain parseable, but may not be used for verification.
    """


class MissingParametersError(AlgorithmValidationError):
    """
    Raised when required parameters are omitted, or when a key lacks the
    domain parameters its algorithm requires.
    """


class DuplicateParametersError(AlgorithmValidationError):
    """
    Raised when a parameter that may only appear once is present more than
    once, or when a required and a defaulted value conflict.
    """


class ParameterConflictError(AlgorithmValidationError):
    """
    Raised when an algorithm requires NULL (or absent) parameters but a
    non-NULL value was supplied, or when the parameter type does not match
    the OID. Covers NULL vs non-NULL conflicts.
    """


class InvalidParametersError(AlgorithmValidationError):
    """
    Raised when parameters are present with the correct ASN.1 type, but their
    contents violate the algorithm policy (unsupported named curve, malformed
    PSS/OAEP params, wrong EC point encoding, ...).
    """


class KeySizeError(AlgorithmValidationError):
    """
    Raised when a key is too small (or otherwise invalid in size) for the
    algorithm it is paired with in strict mode.
    """


class KeyUsageMismatchError(AlgorithmValidationError):
    """
    Raised when a keyUsage extension does not permit the requested operation.
    """


def _oid_of(algorithm_identifier):
    return algorithm_identifier['algorithm'].dotted


def _name_of(algorithm_identifier):
    return algorithm_identifier['algorithm'].native


def _is_known(identifier_class, oid):
    return oid in identifier_class._map


def _parameter_type_name(parameters):
    if parameters is None or parameters.__class__ == Void:
        return 'Void'
    # An unparsed Any value still knows the real type of its parsed contents.
    if parameters.__class__.__name__ == 'Any':
        try:
            return type(parameters.parsed).__name__
        except (ValueError, TypeError):
            return 'Any'
    return type(parameters).__name__


def _is_absent(parameters):
    return parameters is None or parameters.__class__ == Void


def _is_null(parameters):
    if parameters.__class__ == Null:
        return True
    # Some BER-encoded inputs expose a NULL parameter as an unparsed Any
    # value rather than a core.Null instance; parse it lazily to check.
    if parameters.__class__.__name__ == 'Any':
        try:
            parsed = parameters.parsed
        except (ValueError, TypeError):
            return False
        return parsed.__class__ == Null
    return False


def _raise(exc, message, oid, parameters=None, *extra):
    """
    Raises ``exc`` with a formatted message. The OID is always the first
    format value; callers pass additional non-sensitive values via ``extra``.
    The parameter type name is attached as an exception attribute rather than
    being interpolated by every call site.
    """

    parameter_type = _parameter_type_name(parameters) if parameters is not None else None
    raise exc(
        unwrap(message, oid, *extra),
        oid=oid,
        parameter_type=parameter_type
    )


def _check_null_required(algorithm_identifier, strict):
    """
    Validates an OID whose AlgorithmIdentifier must carry NULL parameters
    (or, outside strict mode, no parameters).
    """

    oid = _oid_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if _is_absent(parameters):
        if strict:
            _raise(
                MissingParametersError,
                '''
                Algorithm identifier %s is missing the required NULL
                parameters
                ''',
                oid,
                parameters
            )
        return

    if not _is_null(parameters):
        _raise(
            ParameterConflictError,
            '''
            Algorithm identifier %s requires NULL parameters, but received
            parameters of type %s
            ''',
            oid,
            parameters,
            _parameter_type_name(parameters)
        )


def validate_algorithm_identifier(algorithm_identifier, identifier_class=None, strict=False):
    """
    Validates the algorithm/parameters pairing of an AlgorithmIdentifier-like
    structure (DigestAlgorithm, SignedDigestAlgorithm, PublicKeyAlgorithm,
    ...). Unknown OIDs are always rejected here since an identifier must be
    understood before it can be acted upon.

    :param algorithm_identifier:
        A Sequence with an ``algorithm`` ObjectIdentifier and an optional
        ``parameters`` Any field
    :param identifier_class:
        The ObjectIdentifier subclass defining legal OIDs; defaults to the
        class of the contained algorithm field
    :param strict:
        A bool - when True, missing required parameters are rejected

    :raises:
        A subclass of AlgorithmValidationError
    """

    from .algos import DigestAlgorithmId, EncryptionAlgorithmId, SignedDigestAlgorithmId
    from .keys import PrivateKeyAlgorithmId, PublicKeyAlgorithmId

    oid = _oid_of(algorithm_identifier)
    if identifier_class is None:
        identifier_class = algorithm_identifier['algorithm'].__class__

    if not _is_known(identifier_class, oid):
        _raise(UnknownAlgorithmError, 'Unknown algorithm identifier %s', oid)

    name = _name_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if identifier_class is DigestAlgorithmId:
        _check_null_required(algorithm_identifier, strict)
        return

    if identifier_class is SignedDigestAlgorithmId:
        _validate_signed_digest_algorithm(algorithm_identifier, strict)
        return

    if identifier_class in (PublicKeyAlgorithmId, PrivateKeyAlgorithmId):
        # Key identifiers are validated together with their key material via
        # validate_public_key()/validate_private_key().
        return

    if identifier_class is EncryptionAlgorithmId and name == 'rsaes_pkcs1v15':
        _check_null_required(algorithm_identifier, strict)
        return

    # Generic fallback: absent/NULL parameters are always acceptable.
    if _is_absent(parameters) or _is_null(parameters):
        return


def _validate_signed_digest_algorithm(algorithm_identifier, strict):
    from .algos import RSASSAPSSParams, SignedDigestAlgorithmId

    oid = _oid_of(algorithm_identifier)
    name = _name_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if not _is_known(SignedDigestAlgorithmId, oid):
        _raise(UnknownAlgorithmError, 'Unknown signature algorithm %s', oid)

    if name == 'rsassa_pss':
        if _is_absent(parameters) or _is_null(parameters):
            if strict:
                _raise(
                    MissingParametersError,
                    '''
                    RSASSA-PSS algorithm identifier %s is missing explicit
                    RSASSA-PSS parameters
                    ''',
                    oid,
                    parameters
                )
            return
        if parameters.__class__ != RSASSAPSSParams:
            _raise(
                ParameterConflictError,
                '''
                RSASSA-PSS algorithm identifier %s requires RSASSAPSSParams,
                but received parameters of type %s
                ''',
                oid,
                parameters,
                _parameter_type_name(parameters)
            )
        _validate_pss_params(parameters, oid)
        return

    if name in ('ed25519', 'ed448'):
        # RFC 8410: EdDSA AlgorithmIdentifiers MUST omit parameters.
        if not _is_absent(parameters):
            if _is_null(parameters) and not strict:
                return
            _raise(
                ParameterConflictError,
                '''
                EdDSA algorithm identifier %s must not include parameters, but
                received parameters of type %s
                ''',
                oid,
                parameters,
                _parameter_type_name(parameters)
            )
        return

    # All other signature OIDs (PKCS#1 v1.5 RSA, DSA, ECDSA, ...) take NULL.
    _check_null_required(algorithm_identifier, strict)


def _validate_pss_params(params, oid):
    hash_algorithm = params['hash_algorithm']
    mask_gen = params['mask_gen_algorithm']
    salt_length = params['salt_length'].native
    trailer = params['trailer_field'].native

    validate_algorithm_identifier(hash_algorithm, strict=False)

    if mask_gen['algorithm'].dotted != '1.2.840.113549.1.1.8':
        _raise(
            InvalidParametersError,
            'RSASSA-PSS parameters for %s contain an unsupported mask generation algorithm',
            oid,
            params
        )
    mgf_params = mask_gen['parameters']
    if not _is_absent(mgf_params):
        validate_algorithm_identifier(mgf_params, strict=False)
        # The same digest is expressed twice (once directly and once inside
        # MGF1); a disagreement is a duplicate-parameter conflict rather than
        # a missing value.
        if mgf_params['algorithm'].dotted != hash_algorithm['algorithm'].dotted:
            _raise(
                DuplicateParametersError,
                '''
                RSASSA-PSS parameters for %s disagree on the digest: the
                hash algorithm and the MGF1 digest must be identical
                ''',
                oid,
                params
            )

    if not isinstance(salt_length, int_types) or salt_length < 0:
        _raise(
            InvalidParametersError,
            'RSASSA-PSS parameters for %s contain an invalid salt length',
            oid,
            params
        )

    if trailer != 1 and trailer != 'trailer_field_bc':
        _raise(
            InvalidParametersError,
            'RSASSA-PSS parameters for %s contain an unsupported trailer field',
            oid,
            params
        )


def _validate_oaep_params(params, oid):
    hash_algorithm = params['hash_algorithm']
    mask_gen = params['mask_gen_algorithm']
    p_source = params['p_source_algorithm']

    validate_algorithm_identifier(hash_algorithm, strict=False)

    if mask_gen['algorithm'].dotted != '1.2.840.113549.1.1.8':
        _raise(
            InvalidParametersError,
            'RSAES-OAEP parameters for %s contain an unsupported mask generation algorithm',
            oid,
            params
        )
    mgf_params = mask_gen['parameters']
    if not _is_absent(mgf_params):
        validate_algorithm_identifier(mgf_params, strict=False)
        if mgf_params['algorithm'].dotted != hash_algorithm['algorithm'].dotted:
            _raise(
                DuplicateParametersError,
                '''
                RSAES-OAEP parameters for %s disagree on the digest: the hash
                algorithm and the MGF1 digest must be identical
                ''',
                oid,
                params
            )

    if p_source['algorithm'].dotted != '1.2.840.113549.1.1.9':
        _raise(
            InvalidParametersError,
            'RSAES-OAEP parameters for %s contain an unsupported PSource algorithm',
            oid,
            params
        )


def _validate_rsa_key(key_info, key_field, algorithm_identifier, strict):
    """
    Binds an RSA-family identifier to the modulus/exponent of the contained
    key, checking PKCS#1 NULL parameters, PSS/OAEP parameter contents and, in
    strict mode, key size and exponent.
    """

    from .algos import RSAESOAEPParams, RSASSAPSSParams
    from .keys import RSAPrivateKey, RSAPublicKey

    oid = _oid_of(algorithm_identifier)
    name = _name_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if name == 'rsa':
        if not _is_absent(parameters) and not _is_null(parameters):
            _raise(
                ParameterConflictError,
                '''
                RSA algorithm identifier %s requires NULL parameters, but
                received parameters of type %s
                ''',
                oid,
                parameters,
                _parameter_type_name(parameters)
            )
        if strict and _is_absent(parameters):
            _raise(
                MissingParametersError,
                'RSA algorithm identifier %s is missing the required NULL parameters',
                oid,
                parameters
            )
    elif name == 'rsassa_pss':
        if not _is_absent(parameters) and not _is_null(parameters):
            if parameters.__class__ != RSASSAPSSParams:
                _raise(
                    ParameterConflictError,
                    '''
                    RSASSA-PSS algorithm identifier %s requires
                    RSASSAPSSParams, but received parameters of type %s
                    ''',
                    oid,
                    parameters,
                    _parameter_type_name(parameters)
                )
            _validate_pss_params(parameters, oid)
        elif strict and _is_absent(parameters):
            _raise(
                MissingParametersError,
                'RSASSA-PSS algorithm identifier %s is missing explicit parameters',
                oid,
                parameters
            )
    elif name == 'rsaes_oaep':
        if not _is_absent(parameters) and not _is_null(parameters):
            if parameters.__class__ != RSAESOAEPParams:
                _raise(
                    ParameterConflictError,
                    '''
                    RSAES-OAEP algorithm identifier %s requires
                    RSAESOAEPParams, but received parameters of type %s
                    ''',
                    oid,
                    parameters,
                    _parameter_type_name(parameters)
                )
            _validate_oaep_params(parameters, oid)
        elif strict and _is_absent(parameters):
            _raise(
                MissingParametersError,
                'RSAES-OAEP algorithm identifier %s is missing explicit parameters',
                oid,
                parameters
            )

    parsed = key_info[key_field].parsed
    if not isinstance(parsed, (RSAPublicKey, RSAPrivateKey)):
        _raise(
            InvalidParametersError,
            '''
            Algorithm identifier %s requires an RSA key, but the key material
            parsed as a different type
            ''',
            oid,
            parameters
        )

    modulus = parsed['modulus'].native
    exponent = parsed['public_exponent'].native

    if modulus is None or modulus <= 0:
        _raise(
            InvalidParametersError,
            'RSA key paired with %s has an invalid modulus',
            oid,
            parameters
        )
    if exponent is None or exponent <= 2:
        _raise(
            InvalidParametersError,
            'RSA key paired with %s has an invalid public exponent',
            oid,
            parameters
        )

    bit_size = modulus.bit_length()
    if strict and bit_size < MIN_RSA_KEY_SIZE:
        _raise(
            KeySizeError,
            '''
            RSA key paired with %s is %d bits, below the minimum allowed size
            of %d bits
            ''',
            oid,
            parameters,
            bit_size,
            MIN_RSA_KEY_SIZE
        )

    if strict and exponent not in SAFE_RSA_PUBLIC_EXPONENTS:
        _raise(
            InvalidParametersError,
            '''
            RSA key paired with %s uses a public exponent that is not in the
            allowed set
            ''',
            oid,
            parameters
        )


def _validate_dsa_key(key_info, key_field, algorithm_identifier, strict):
    """
    Validates that a DSA identifier carries complete Dss-Parms (p, q, g) and
    that the key material is an integer value. Absent parameters are never
    silently defaulted.
    """

    from .keys import DSAParams

    oid = _oid_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if _is_absent(parameters):
        # Absent parameters are inherited from the CA in some legacy PKIX
        # profiles. They are parseable, but strict verification rejects them
        # so a backend can never silently fall back to a default parameter set.
        if strict:
            _raise(
                MissingParametersError,
                '''
                DSA algorithm identifier %s is missing domain parameters
                (p, q, g); implicit default parameters are not allowed in
                strict mode
                ''',
                oid,
                parameters
            )
        return

    if parameters.__class__ != DSAParams:
        _raise(
            ParameterConflictError,
            '''
            DSA algorithm identifier %s requires DSAParams, but received
            parameters of type %s
            ''',
            oid,
            parameters,
            _parameter_type_name(parameters)
        )

    for field_name in ('p', 'q', 'g'):
        value = parameters[field_name].native
        if value is None or value <= 0:
            _raise(
                InvalidParametersError,
                'DSA parameters for %s are missing a valid %s value',
                oid,
                parameters,
                field_name
            )

    if strict:
        q_contents = parameters['q'].contents
        if q_contents[0:1] == b'\x00':
            q_contents = q_contents[1:]
        if len(q_contents) < 20:
            _raise(
                KeySizeError,
                '''
                DSA key paired with %s uses a subgroup order q smaller than
                160 bits
                ''',
                oid,
                parameters
            )

    value = key_info[key_field].parsed.native
    if value is None or value <= 0:
        _raise(
            InvalidParametersError,
            'DSA key paired with %s has an invalid public value',
            oid,
            parameters
        )


def _validate_ec_key(key_info, key_field, algorithm_identifier, strict):
    """
    Binds the ecPublicKey OID to its ECDomainParameters and validates the EC
    point encoding and length against the declared curve.
    """

    from .core import ParsableOctetString
    from .keys import ECDomainParameters, ECPointBitString, ECPrivateKey, NamedCurve

    oid = _oid_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if _is_absent(parameters):
        # RFC 5480 requires a namedCurve; a verifier must never assume one.
        _raise(
            MissingParametersError,
            '''
            EC algorithm identifier %s is missing domain parameters; a
            default curve must not be assumed
            ''',
            oid,
            parameters
        )

    if parameters.__class__ != ECDomainParameters:
        _raise(
            ParameterConflictError,
            '''
            EC algorithm identifier %s requires ECDomainParameters, but
            received parameters of type %s
            ''',
            oid,
            parameters,
            _parameter_type_name(parameters)
        )

    choice_name = parameters.name
    if choice_name == 'implicit_ca':
        _raise(
            MissingParametersError,
            '''
            EC algorithm identifier %s uses implicitlyCA domain parameters;
            the curve can not be determined from the key
            ''',
            oid,
            parameters
        )

    if choice_name == 'named':
        curve_oid = parameters.chosen.dotted
        if curve_oid not in NamedCurve._map:
            _raise(
                UnknownAlgorithmError,
                'EC key uses unknown named curve OID %s',
                curve_oid,
                parameters
            )
        if curve_oid not in _RFC5480_NAMED_CURVES:
            _raise(
                InvalidParametersError,
                '''
                EC key uses named curve %s, which is not permitted for PKIX
                certificates (RFC 5480)
                ''',
                curve_oid,
                parameters
            )
        try:
            field_size = parameters.key_size
        except (ValueError, ZeroDivisionError):
            _raise(
                InvalidParametersError,
                'EC key uses named curve %s without a registered key length',
                curve_oid,
                parameters
            )
    else:
        # Explicitly specified domain parameters are parseable, but RFC 5480
        # requires a named curve in PKIX profiles.
        if strict:
            _raise(
                InvalidParametersError,
                '''
                EC algorithm identifier %s uses explicitly specified domain
                parameters; PKIX requires a named curve
                ''',
                oid,
                parameters
            )
        field_size = parameters.key_size

    point = key_info[key_field]
    if isinstance(point, ParsableOctetString) and hasattr(point, 'parsed') \
            and isinstance(point.parsed, ECPrivateKey):
        # PKCS#8 EC private keys embed the optional public point inside the
        # ECPrivateKey structure; validate it when present.
        embedded = point.parsed['public_key']
        if embedded.native is None:
            return
        point = embedded
    if not isinstance(point, ECPointBitString):
        _raise(
            InvalidParametersError,
            '''
            EC algorithm identifier %s requires an ECPoint bit string, but
            received a different type
            ''',
            oid,
            parameters
        )

    data = point.native
    if not data or len(data) < 1:
        _raise(
            InvalidParametersError,
            'EC key paired with %s contains an empty point',
            oid,
            parameters
        )

    first = data[0:1]
    if first == b'\x04':
        expected_len = 1 + 2 * field_size
        if len(data) != expected_len:
            _raise(
                InvalidParametersError,
                '''
                EC point for %s is %d bytes, but the declared curve requires
                %d bytes for an uncompressed point
                ''',
                oid,
                parameters,
                len(data),
                expected_len
            )
    elif first in (b'\x02', b'\x03'):
        _raise(
            InvalidParametersError,
            '''
            EC key paired with %s uses a compressed point encoding, which is
            not supported for verification
            ''',
            oid,
            parameters
        )
    else:
        first_byte = data[0] if isinstance(data[0], int_types) else ord(data[0])
        _raise(
            InvalidParametersError,
            'EC key paired with %s has an unrecognized point encoding 0x%02x',
            oid,
            parameters,
            first_byte
        )


def _validate_eddsa_key(key_info, key_field, algorithm_identifier):
    """
    Validates an RFC 8410 EdDSA/XDH identifier (no parameters) and the opaque
    key bit string length.
    """

    from .core import OctetBitString, OctetString

    oid = _oid_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if not _is_absent(parameters):
        _raise(
            ParameterConflictError,
            '''
            Algorithm identifier %s must not include parameters, but received
            parameters of type %s
            ''',
            oid,
            parameters,
            _parameter_type_name(parameters)
        )

    # RFC 8410 public keys are opaque bit strings (tag 3); PKCS#8 private
    # keys are opaque octet strings (tag 4). Parsable variants share the same
    # tags but are not Python subclasses, so match on the tag instead.
    point = key_info[key_field]
    if getattr(point, 'tag', None) not in (OctetBitString.tag, OctetString.tag):
        _raise(
            InvalidParametersError,
            '''
            Algorithm identifier %s requires an opaque key string, but
            received a different type
            ''',
            oid,
            parameters
        )

    expected_sizes = {
        'ed25519': 32,
        'x25519': 32,
        'ed448': 57,
        'x448': 56,
    }
    expected = expected_sizes.get(_name_of(algorithm_identifier))
    if expected is not None and len(point.native) != expected:
        _raise(
            InvalidParametersError,
            'The %s key paired with algorithm identifier %s has the wrong encoded length',
            oid,
            parameters,
            _name_of(algorithm_identifier),
        )


def _validate_dh_key(key_info, key_field, algorithm_identifier, strict):
    from .keys import DomainParameters

    oid = _oid_of(algorithm_identifier)
    parameters = algorithm_identifier['parameters']

    if _is_absent(parameters):
        if strict:
            _raise(
                MissingParametersError,
                'DH algorithm identifier %s is missing domain parameters',
                oid,
                parameters
            )
        return

    if parameters.__class__ != DomainParameters:
        _raise(
            ParameterConflictError,
            '''
            DH algorithm identifier %s requires DomainParameters, but
            received parameters of type %s
            ''',
            oid,
            parameters,
            _parameter_type_name(parameters)
        )

    for field_name in ('p', 'q', 'g'):
        if parameters[field_name].native is None:
            _raise(
                InvalidParametersError,
                'DH parameters for %s are missing the %s value',
                oid,
                parameters,
                field_name
            )


def _dispatch_key(key_info, strict):
    """
    Runs the binding checks for a SubjectPublicKeyInfo or PrivateKeyInfo.
    """

    from .keys import (
        PrivateKeyAlgorithmId,
        PrivateKeyInfo,
        PublicKeyAlgorithmId,
        PublicKeyInfo,
    )

    if isinstance(key_info, PublicKeyInfo):
        algorithm_identifier = key_info['algorithm']
        key_field = 'public_key'
    elif isinstance(key_info, PrivateKeyInfo):
        algorithm_identifier = key_info['private_key_algorithm']
        key_field = 'private_key'
    else:
        raise TypeError(
            'key_info must be a PublicKeyInfo or PrivateKeyInfo, not %s'
            % type(key_info).__name__
        )

    oid = _oid_of(algorithm_identifier)
    if oid not in PublicKeyAlgorithmId._map and oid not in PrivateKeyAlgorithmId._map:
        _raise(UnknownAlgorithmError, 'Unknown key algorithm %s', oid)

    name = _name_of(algorithm_identifier)

    if name in ('rsa', 'rsaes_oaep', 'rsassa_pss'):
        _validate_rsa_key(key_info, key_field, algorithm_identifier, strict)
    elif name == 'dsa':
        _validate_dsa_key(key_info, key_field, algorithm_identifier, strict)
    elif name == 'ec':
        _validate_ec_key(key_info, key_field, algorithm_identifier, strict)
    elif name in ('ed25519', 'ed448', 'x25519', 'x448'):
        _validate_eddsa_key(key_info, key_field, algorithm_identifier)
    elif name == 'dh':
        _validate_dh_key(key_info, key_field, algorithm_identifier, strict)
    else:  # pragma: no cover - guarded by the known-map check above
        _raise(UnknownAlgorithmError, 'Unsupported key algorithm %s', oid)


def validate_public_key(public_key_info, strict=False):
    """
    Validates that the algorithm identifier of a SubjectPublicKeyInfo is
    bound to parameters and key material that are consistent and safe to act
    on. Default parsing is unaffected: this must be called explicitly.

    Even with ``strict=False``, structural binding errors, unknown OIDs at the
    verification boundary, missing EC/DSA parameters and invalid point
    encodings are rejected, since a verification backend must never guess a
    curve or parameter set.

    :param public_key_info:
        An asn1crypto.keys.PublicKeyInfo object
    :param strict:
        A bool - when True, RFC profile requirements are enforced (RFC 5480
        named curves, minimum RSA key size/exponent, required NULL params)

    :raises:
        A subclass of AlgorithmValidationError
    """

    _dispatch_key(public_key_info, strict)
    return public_key_info


def validate_private_key(private_key_info, strict=False):
    """
    Validates the algorithm/parameter/key binding of a PKCS#8 PrivateKeyInfo.
    Mirrors validate_public_key().

    :param private_key_info:
        An asn1crypto.keys.PrivateKeyInfo object
    :param strict:
        A bool, see validate_public_key()

    :raises:
        A subclass of AlgorithmValidationError
    """

    _dispatch_key(private_key_info, strict)
    return private_key_info


def validate_key_usage(key_usage, operation):
    """
    Checks that a keyUsage value permits the requested operation.

    :param key_usage:
        An asn1crypto.x509.KeyUsage object, the native set it returns, or
        None. None means the certificate has no keyUsage extension, in which
        case RFC 5280 permits every operation.
    :param operation:
        A unicode string of "sign", "cert_sign", "crl_sign",
        "key_encipherment", "data_encipherment" or "key_agreement"

    :raises:
        KeyUsageMismatchError - when the operation is not permitted
    """

    operation_map = {
        'sign': _KEY_USAGE_SIGN,
        'cert_sign': _KEY_USAGE_CERT_SIGN,
        'crl_sign': _KEY_USAGE_CRL_SIGN,
        'key_encipherment': _KEY_USAGE_KEY_ENCIPHER,
        'data_encipherment': _KEY_USAGE_DATA_ENCIPHER,
        'key_agreement': _KEY_USAGE_AGREEMENT,
    }

    if operation not in operation_map:
        raise ValueError(unwrap(
            '''
            operation must be one of %s, not %s
            ''',
            ', '.join(sorted(operation_map)),
            repr(operation)
        ))

    if key_usage is None:
        return

    usages = key_usage.native if hasattr(key_usage, 'native') else key_usage

    required = operation_map[operation]
    if usages is not None and required.isdisjoint(usages):
        raise KeyUsageMismatchError(
            unwrap(
                '''
                keyUsage %s does not permit the operation "%s"; one of %s is
                required
                ''',
                ', '.join(sorted(usages)) if usages else '(empty)',
                operation,
                ', '.join(sorted(required))
            ),
            oid=None,
            parameter_type='KeyUsage'
        )


def validate_signed_digest_algorithm(signed_digest_algorithm, strict=False):
    """
    Validates a signature AlgorithmIdentifier. Unknown OIDs are always
    rejected since no verification can occur for an unrecognized algorithm.

    :param signed_digest_algorithm:
        An asn1crypto.algos.SignedDigestAlgorithm object
    :param strict:
        A bool - when True, missing required NULL/explicit parameters are
        rejected

    :raises:
        A subclass of AlgorithmValidationError
    """

    from .algos import SignedDigestAlgorithmId

    validate_algorithm_identifier(
        signed_digest_algorithm,
        identifier_class=SignedDigestAlgorithmId,
        strict=strict
    )
    return signed_digest_algorithm


def _check_signature_algorithm_pair(tbs_algorithm, outer_algorithm):
    """
    RFC 5280 4.1.1.2: the TBS signature algorithm and the outer
    signatureAlgorithm must be identical, including parameters.
    """

    if tbs_algorithm.dump() != outer_algorithm.dump():
        oid = outer_algorithm['algorithm'].dotted
        _raise(
            ParameterConflictError,
            '''
            The inner and outer signature algorithm identifiers for %s do not
            match
            ''',
            oid
        )


def validate_certificate(certificate, strict=False, usage=None):
    """
    Validates the algorithm/parameter/key bindings in an X.509 certificate.
    No cryptographic verification is performed; instead every value a
    verification backend would consume is checked for a safe, unambiguous
    interpretation.

    :param certificate:
        An asn1crypto.x509.Certificate object
    :param strict:
        A bool - enables RFC profile enforcement when True
    :param usage:
        An optional operation validated against the keyUsage extension

    :raises:
        A subclass of AlgorithmValidationError
    """

    tbs = certificate['tbs_certificate']

    _check_signature_algorithm_pair(
        tbs['signature'],
        certificate['signature_algorithm']
    )
    validate_signed_digest_algorithm(
        certificate['signature_algorithm'],
        strict=strict
    )
    validate_public_key(tbs['subject_public_key_info'], strict=strict)

    if usage is not None:
        validate_key_usage(certificate.key_usage_value, usage)

    return certificate


def _csr_requested_key_usage(certification_request):
    attributes = certification_request['certification_request_info']['attributes']
    if not attributes.native or not len(attributes):
        return None

    for attribute in attributes:
        if attribute['type'].native != 'extension_request':
            continue
        for extension in attribute['values']:
            if extension['extn_id'].native == 'key_usage':
                return extension['extn_value'].parsed
    return None


def validate_csr(certification_request, strict=False, usage=None):
    """
    Validates the algorithm/parameter/key bindings in a PKCS#10 CSR.

    :param certification_request:
        An asn1crypto.csr.CertificationRequest object
    :param strict:
        A bool - enables RFC profile enforcement when True
    :param usage:
        An optional operation validated against a keyUsage extension requested
        through the extensionRequest attribute

    :raises:
        A subclass of AlgorithmValidationError
    """

    request_info = certification_request['certification_request_info']
    validate_signed_digest_algorithm(
        certification_request['signature_algorithm'],
        strict=strict
    )
    validate_public_key(request_info['subject_pk_info'], strict=strict)

    if usage is not None:
        validate_key_usage(
            _csr_requested_key_usage(certification_request),
            usage
        )

    return certification_request
