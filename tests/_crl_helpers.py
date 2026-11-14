# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import datetime

from cryptography import x509 as cx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from asn1crypto import crl, x509


class GeneratedCertificate(object):
    """
    Holds both the cryptography certificate (used for building other objects)
    and the asn1crypto certificate (used by certvalidator itself).
    """

    def __init__(self, crypto_cert, asn1_cert):
        self._crypto_cert = crypto_cert
        self.asn1 = asn1_cert

    @property
    def subject(self):
        return self._crypto_cert.subject


def _name(common_name):
    return cx.Name([cx.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(common_name, key=None, issuer_ca=None):
    """
    Builds a self-signed CA certificate and private key, or a CA issued by
    issuer_ca when one is provided.
    """

    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _name(common_name)
    issuer_name = issuer_ca.subject if issuer_ca is not None else subject

    builder = (
        cx.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(cx.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            cx.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(cx.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    )
    signed = builder.sign(key, hashes.SHA256())
    asn1_cert = x509.Certificate.load(signed.public_bytes(serialization.Encoding.DER))
    return key, GeneratedCertificate(signed, asn1_cert)


def make_end_entity(ca_key, ca_cert, common_name, serial_number, moment=None):
    if moment is None:
        moment = datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        cx.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(moment - datetime.timedelta(days=30))
        .not_valid_after(moment + datetime.timedelta(days=365))
        .add_extension(cx.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(cx.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(cx.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .add_extension(
            cx.CRLDistributionPoints([
                cx.DistributionPoint(
                    full_name=[cx.UniformResourceIdentifier('http://crl.example/root.crl')],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None,
                )
            ]),
            False
        )
    )
    signed = builder.sign(ca_key, hashes.SHA256())
    asn1_cert = x509.Certificate.load(signed.public_bytes(serialization.Encoding.DER))
    return key, GeneratedCertificate(signed, asn1_cert)


def make_issued_certificate(issuer_key, issuer_cert, common_name, serial_number=2):
    """
    Builds a CA-capable certificate (e.g. an indirect CRL issuer) issued by
    another CA.
    """

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _name(common_name)
    builder = (
        cx.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(cx.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            cx.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(cx.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(cx.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
    )
    signed = builder.sign(issuer_key, hashes.SHA256())
    asn1_cert = x509.Certificate.load(signed.public_bytes(serialization.Encoding.DER))
    return key, GeneratedCertificate(signed, asn1_cert)


def build_crl(
    signer_key,
    signer_cert,
    revoked_entries,
    crl_number,
    this_update,
    next_update,
    delta_indicator=None,
    issuing_distribution_point=None,
    unknown_critical_oid=None,
    freshest_url=None,
):
    """
    Builds a signed asn1crypto.crl.CertificateList. revoked_entries is a list
    of (serial_number, cryptography.x509.ReasonFlags, datetime) tuples.
    """

    builder = (
        cx.CertificateRevocationListBuilder()
        .issuer_name(signer_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
        .add_extension(cx.CRLNumber(crl_number), False)
        .add_extension(
            cx.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key()),
            False
        )
    )
    if delta_indicator is not None:
        builder = builder.add_extension(cx.DeltaCRLIndicator(delta_indicator), False)
    if issuing_distribution_point is not None:
        builder = builder.add_extension(issuing_distribution_point, True)
    if unknown_critical_oid is not None:
        builder = builder.add_extension(
            cx.UnrecognizedExtension(unknown_critical_oid, b'\x04\x03\x01\x02\x03'),
            True
        )
    if freshest_url is not None:
        distribution_point = cx.DistributionPoint(
            full_name=[cx.UniformResourceIdentifier(freshest_url)],
            relative_name=None,
            crl_issuer=None,
            reasons=None,
        )
        builder = builder.add_extension(cx.FreshestCRL([distribution_point]), False)

    for serial_number, reason, revocation_date in revoked_entries:
        revoked_builder = (
            cx.RevokedCertificateBuilder()
            .serial_number(serial_number)
            .revocation_date(revocation_date)
            .add_extension(cx.CRLReason(reason), False)
        )
        builder = builder.add_revoked_certificate(revoked_builder.build())

    signed = builder.sign(signer_key, hashes.SHA256())
    return crl.CertificateList.load(signed.public_bytes(serialization.Encoding.DER))
