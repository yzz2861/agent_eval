"""X.509 certificate chain validation and CoseKey binding checks.

The helpers in this module bind an X.509 certificate chain to a COSE key:
they verify that the leaf certificate carries the public key of the given
CoseKey, that the chain is anchored at a trusted certificate, that every
certificate is within its validity period, and that the asserted COSE key
operations are consistent with both the CoseKey ``key_ops`` parameter and
the leaf certificate's X.509 key usage extension.
"""

from datetime import datetime, timezone
from typing import Optional, Sequence, Set, Type

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, x448, x25519

from pycose.exceptions import CoseIllegalKeyOps, CoseInvalidCertificate
from pycose.keys.cosekey import CoseKey
from pycose.keys.curves import CoseCurve
from pycose.keys.keyops import (
    DecryptOp,
    DeriveBitsOp,
    DeriveKeyOp,
    EncryptOp,
    KeyOps,
    SignOp,
    UnwrapOp,
    VerifyOp,
    WrapOp,
)
from pycose.keys.keyparam import EC2KpX, EC2KpY, OKPKpX, RSAKpE, RSAKpN
from pycose.keys.keytype import KtyEC2, KtyOKP, KtyRSA


# COSE key operations mapped to the X.509 key usage bits that authorize them.
# Symmetric-only operations (MAC_*) have no X.509 counterpart and are omitted.
_KEY_OPS_TO_KEY_USAGE = {
    SignOp: "digital_signature",
    VerifyOp: "digital_signature",
    EncryptOp: "key_encipherment",
    DecryptOp: "decipher_only",
    WrapOp: "key_encipherment",
    UnwrapOp: "decipher_only",
    DeriveKeyOp: "key_agreement",
    DeriveBitsOp: "key_agreement",
}

_EC_CURVE_TYPES = {
    type(curve.curve_obj): curve for curve in CoseCurve.get_registered_classes().values()
    if curve.key_type == KtyEC2
}

# Backend-specific subclasses (e.g. the Rust OpenSSL backend) require
# isinstance checks rather than exact type equality.
_OKP_CURVE_TYPES = (
    (ed25519.Ed25519PublicKey, "ED25519"),
    (ed448.Ed448PublicKey, "ED448"),
    (x25519.X25519PublicKey, "X25519"),
    (x448.X448PublicKey, "X448"),
)


def load_certificate(encoded_cert: bytes) -> x509.Certificate:
    """Load a DER or PEM-encoded X.509 certificate."""

    try:
        return x509.load_der_x509_certificate(encoded_cert)
    except ValueError:
        try:
            return x509.load_pem_x509_certificate(encoded_cert)
        except ValueError as exc:
            raise CoseInvalidCertificate(
                "Could not parse X.509 certificate (expected DER or PEM)."
            ) from exc


def public_key_matches(cose_key: CoseKey, certificate: x509.Certificate) -> bool:
    """Check whether the certificate's public key matches the CoseKey."""

    cert_pub = certificate.public_key()

    if cose_key.kty == KtyEC2 and isinstance(cert_pub, ec.EllipticCurvePublicKey):
        expected_curve = _EC_CURVE_TYPES.get(type(cert_pub.curve))
        if expected_curve is None or cose_key.crv != expected_curve:
            return False
        numbers = cert_pub.public_numbers()
        size = expected_curve.size
        if numbers.x.to_bytes(size, "big") != cose_key[EC2KpX]:
            return False
        # An EC2 CoseKey in compact mode may omit the y coordinate.
        return not cose_key[EC2KpY] or numbers.y.to_bytes(size, "big") == cose_key[EC2KpY]

    if cose_key.kty == KtyRSA and isinstance(cert_pub, rsa.RSAPublicKey):
        numbers = cert_pub.public_numbers()
        return numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big") == cose_key[RSAKpN] and \
            numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big") == cose_key[RSAKpE]

    if cose_key.kty == KtyOKP:
        expected_curve = next(
            (name for key_type, name in _OKP_CURVE_TYPES
             if isinstance(cert_pub, key_type)),
            None,
        )
        if expected_curve is None or getattr(cose_key.crv, "fullname", None) != expected_curve:
            return False
        return cert_pub.public_bytes_raw() == cose_key[OKPKpX]

    return False


def _verify_signature(certificate: x509.Certificate, issuer_public_key) -> None:
    """Verify that ``certificate`` was signed by the holder of ``issuer_public_key``."""

    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm),
            )
        elif isinstance(issuer_public_key,
                        (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            raise CoseInvalidCertificate(
                f"Unsupported issuer public key type: {type(issuer_public_key).__name__}."
            )
    except InvalidSignature as exc:
        raise CoseInvalidCertificate(
            f"Certificate '{certificate.subject.rfc4514_string()}' has an invalid signature."
        ) from exc


def _check_validity(certificate: x509.Certificate, moment: datetime) -> None:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    try:
        certificate.not_valid_before_utc
    except AttributeError:  # cryptography < 42
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    else:
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc

    if moment < not_before:
        raise CoseInvalidCertificate(
            f"Certificate '{certificate.subject.rfc4514_string()}' is not yet valid."
        )
    if moment > not_after:
        raise CoseInvalidCertificate(
            f"Certificate '{certificate.subject.rfc4514_string()}' is expired."
        )


def _check_certificate_key_usage(certificate: x509.Certificate, key_usage: Set[str]) -> None:
    if not key_usage:
        return
    try:
        extension = certificate.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        # A certificate without a key usage extension does not restrict usage.
        return
    for usage in key_usage:
        if not getattr(extension.value, usage, False):
            raise CoseInvalidCertificate(
                f"Certificate '{certificate.subject.rfc4514_string()}' does not allow "
                f"the X.509 key usage '{usage}'."
            )


def key_ops_to_key_usage(key_ops: Sequence[Type[KeyOps]]) -> Set[str]:
    """Translate COSE key operations into the required X.509 key usage bits."""

    return {
        usage
        for key_op in key_ops
        for usage in [_KEY_OPS_TO_KEY_USAGE.get(key_op)]
        if usage is not None
    }


def validate_certificate_chain(
    encoded_chain: Sequence[bytes],
    cose_key: CoseKey,
    trust_roots: Optional[Sequence[bytes]] = None,
    key_ops: Optional[Sequence[Type[KeyOps]]] = None,
    moment: Optional[datetime] = None,
) -> None:
    """Validate an X.509 chain against a CoseKey.

    :param encoded_chain: DER/PEM-encoded certificates, leaf first, intermediates after.
    :param cose_key: The COSE key whose public key must match the leaf certificate.
    :param trust_roots: Trust anchor certificates (DER/PEM). Required to establish trust.
    :param key_ops: COSE key operations that must be permitted. Defaults to the
        ``key_ops`` set on the CoseKey itself.
    :param moment: Validation time (defaults to the current time).
    :raises CoseInvalidCertificate: on parse, binding, path or validity failures.
    :raises CoseIllegalKeyOps: when the CoseKey does not allow a required key op.
    """

    if not encoded_chain:
        raise CoseInvalidCertificate("The certificate chain is empty.")

    chain = [load_certificate(encoded) for encoded in encoded_chain]
    anchors = [load_certificate(encoded) for encoded in (trust_roots or [])]
    moment = moment or datetime.now(timezone.utc)

    leaf = chain[0]
    if not public_key_matches(cose_key, leaf):
        raise CoseInvalidCertificate(
            "The public key in the leaf certificate does not match the CoseKey."
        )

    if key_ops is None:
        key_ops = list(cose_key.key_ops)
    key_ops = list(key_ops)

    if key_ops:
        for required_op in key_ops:
            if required_op not in cose_key.key_ops:
                raise CoseIllegalKeyOps(
                    f"The CoseKey does not permit key operation "
                    f"'{getattr(required_op, 'fullname', required_op)}'."
                )
        _check_certificate_key_usage(leaf, key_ops_to_key_usage(key_ops))

    for certificate in chain:
        _check_validity(certificate, moment)

    current = leaf
    for issuer_certificate in chain[1:]:
        if current.issuer != issuer_certificate.subject:
            raise CoseInvalidCertificate(
                f"Certificate '{current.subject.rfc4514_string()}' was not issued by "
                f"'{issuer_certificate.subject.rfc4514_string()}'."
            )
        _check_validity(issuer_certificate, moment)
        _verify_signature(current, issuer_certificate.public_key())
        current = issuer_certificate

    anchor = next(
        (candidate for candidate in anchors if candidate.subject == current.issuer),
        None,
    )
    if anchor is None:
        raise CoseInvalidCertificate("The certificate chain is not anchored at a trusted certificate.")
    _check_validity(anchor, moment)
    _verify_signature(current, anchor.public_key())
