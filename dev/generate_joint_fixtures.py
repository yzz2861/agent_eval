# coding: utf-8
"""
Generates the small local PKI used by tests/test_joint_validation.py.

The two service certificates have the same subject and public key, but are
issued by different intermediate CAs. This allows one service identity to have
more than one valid chain, which is what the joint path selection tests need.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import os
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'tests',
    'fixtures',
    'joint'
)

NOT_BEFORE = datetime(2020, 1, 1)
NOT_AFTER = datetime(2040, 1, 1)


def _name(common_name, organization):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _write_cert(filename, cert):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _certificate(subject, issuer, public_key, signing_key, serial, extensions):
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical)
    return builder.sign(signing_key, hashes.SHA256())


def main():
    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    root_a_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_b_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_a_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_b_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    service_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    root_a_name = _name('Joint Root A', 'Joint Test PKI')
    root_b_name = _name('Joint Root B', 'Joint Test PKI')
    intermediate_a_name = _name('Joint Intermediate A', 'Joint Test PKI')
    intermediate_b_name = _name('Joint Intermediate B', 'Joint Test PKI')
    service_name = _name('joint-service.example.com', 'Joint Service')

    root_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    )
    intermediate_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    )
    service_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    service_eku = x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.EMAIL_PROTECTION,
    ])

    root_a = _certificate(
        root_a_name,
        root_a_name,
        root_a_key.public_key(),
        root_a_key,
        0x1001,
        [
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (root_usage, True),
            (x509.SubjectKeyIdentifier.from_public_key(root_a_key.public_key()), False),
        ]
    )
    root_b = _certificate(
        root_b_name,
        root_b_name,
        root_b_key.public_key(),
        root_b_key,
        0x1002,
        [
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (root_usage, True),
            (x509.SubjectKeyIdentifier.from_public_key(root_b_key.public_key()), False),
        ]
    )

    intermediate_a = _certificate(
        intermediate_a_name,
        root_a_name,
        intermediate_a_key.public_key(),
        root_a_key,
        0x2001,
        [
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (intermediate_usage, True),
            (x509.SubjectKeyIdentifier.from_public_key(intermediate_a_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(root_a_key.public_key()), False),
        ]
    )
    intermediate_b = _certificate(
        intermediate_b_name,
        root_b_name,
        intermediate_b_key.public_key(),
        root_b_key,
        0x2002,
        [
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (intermediate_usage, True),
            (x509.SubjectKeyIdentifier.from_public_key(intermediate_b_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(root_b_key.public_key()), False),
        ]
    )

    service_a = _certificate(
        service_name,
        intermediate_a_name,
        service_key.public_key(),
        intermediate_a_key,
        0x3001,
        [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (service_usage, True),
            (service_eku, False),
            (x509.SubjectKeyIdentifier.from_public_key(service_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_a_key.public_key()), False),
        ]
    )
    service_b = _certificate(
        service_name,
        intermediate_b_name,
        service_key.public_key(),
        intermediate_b_key,
        0x3002,
        [
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (service_usage, True),
            (service_eku, False),
            (x509.SubjectKeyIdentifier.from_public_key(service_key.public_key()), False),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_b_key.public_key()), False),
        ]
    )

    _write_cert('root-a.crt', root_a)
    _write_cert('root-b.crt', root_b)
    _write_cert('intermediate-a.crt', intermediate_a)
    _write_cert('intermediate-b.crt', intermediate_b)
    _write_cert('service-a.crt', service_a)
    _write_cert('service-b.crt', service_b)


if __name__ == '__main__':
    main()
