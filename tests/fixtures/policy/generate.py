# coding: utf-8
"""
Generates two local offline certificate samples that share the same policy
OID but carry different policy qualifiers.

Run from the repository root (requires the "cryptography" package, which is
not part of the regular test dependencies - the generated .der files are
committed and used directly by the test suite):

    python tests/fixtures/policy/generate.py

The certificates are real, self-signed RSA certificates so the signature and
chain verification path is untouched; only the certificate policies extension
differs between the two samples.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import os
from datetime import datetime

from asn1crypto.util import timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from asn1crypto import algos, core, keys, x509


POLICY_OID = '1.2.3.4.5.6.7.8.1'
UNKNOWN_QUALIFIER_OID = '1.2.3.4.5.6.7.99.1'

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))


def _public_key_info(private_key):
    rsa_public = private_key.public_key().public_numbers()
    return keys.PublicKeyInfo({
        'algorithm': keys.PublicKeyAlgorithm({'algorithm': 'rsa'}),
        'public_key': core.ParsableOctetBitString(
            keys.RSAPublicKey({
                'modulus': rsa_public.n,
                'public_exponent': rsa_public.e,
            }).dump()
        ),
    })


def _extension(ext_value):
    return x509.Extension({
        'extn_id': 'certificate_policies',
        'critical': False,
        'extn_value': core.ParsableOctetString(ext_value.dump()),
    })


def _policies_with_cps():
    # An implemented qualifier (CPS URI): a reader that understands the
    # certification_practice_statement qualifier has an approval basis.
    return x509.CertificatePolicies([
        x509.PolicyInformation({
            'policy_identifier': POLICY_OID,
            'policy_qualifiers': [
                x509.PolicyQualifierInfo({
                    'policy_qualifier_id': 'certification_practice_statement',
                    'qualifier': core.IA5String('https://example.com/cps.pdf'),
                }),
            ],
        }),
    ])


def _policies_with_unknown_qualifier():
    # The same policy OID, but a qualifier syntax that asn1crypto does not
    # implement. The raw qualifier stays visible, but it must never be treated
    # as an understandable approval basis.
    return x509.CertificatePolicies([
        x509.PolicyInformation({
            'policy_identifier': POLICY_OID,
            'policy_qualifiers': [
                x509.PolicyQualifierInfo({
                    'policy_qualifier_id': x509.PolicyQualifierId(
                        UNKNOWN_QUALIFIER_OID
                    ),
                    'qualifier': core.UTF8String('local offline attestation token'),
                }),
            ],
        }),
    ])


def _build_certificate(common_name, policies, private_key):
    name = x509.Name.build({'common_name': common_name})
    tbs = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': 1,
        'signature': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'issuer': name,
        'validity': x509.Validity({
            'not_before': x509.Time('utc_time', datetime(2026, 1, 1, tzinfo=timezone.utc)),
            'not_after': x509.Time('general_time', datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
        }),
        'subject': name,
        'subject_public_key_info': _public_key_info(private_key),
        'extensions': x509.Extensions([_extension(policies)]),
    })

    signature = private_key.sign(
        tbs.dump(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    return x509.Certificate({
        'tbs_certificate': tbs,
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'}),
        'signature_value': core.OctetBitString(signature),
    })


def main():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    samples = [
        ('policy-qualifier-cps.der', 'offline-cps.example', _policies_with_cps()),
        (
            'policy-qualifier-unknown.der',
            'offline-unknown.example',
            _policies_with_unknown_qualifier(),
        ),
    ]

    for filename, common_name, policies in samples:
        certificate = _build_certificate(common_name, policies, private_key)
        path = os.path.join(FIXTURES_DIR, filename)
        with open(path, 'wb') as f:
            f.write(certificate.dump())
        print('wrote %s' % path)


if __name__ == '__main__':
    main()
