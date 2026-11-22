# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from asn1crypto import algos, cms, core, keys, pkcs12, util, x509


UTC = util.timezone.utc


def synthetic_certificate(serial_number, common_name, modulus):
    name = x509.Name.build({
        'organization_name': 'Synthetic Archive',
        'common_name': common_name,
    })
    signature_algorithm = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
    public_key = keys.PublicKeyInfo.wrap(keys.RSAPublicKey({
        'modulus': modulus,
        'public_exponent': 65537,
    }), 'rsa')
    tbs_certificate = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': serial_number,
        'signature': signature_algorithm,
        'issuer': name,
        'validity': {
            'not_before': x509.Time({'utc_time': datetime(2020, 1, 1, tzinfo=UTC)}),
            'not_after': x509.Time({'utc_time': datetime(2030, 1, 1, tzinfo=UTC)}),
        },
        'subject': name,
        'subject_public_key_info': public_key,
    })
    return x509.Certificate({
        'tbs_certificate': tbs_certificate,
        'signature_algorithm': signature_algorithm,
        'signature_value': b'\x00' * 8,
    })


def _attributes(friendly_name, local_key_id):
    return pkcs12.Attributes([
        pkcs12.Attribute({
            'type': 'friendly_name',
            'values': [friendly_name],
        }),
        pkcs12.Attribute({
            'type': 'local_key_id',
            'values': [local_key_id],
        }),
    ])


def _cert_bag(certificate, friendly_name, local_key_id):
    cert_bag = pkcs12.CertBag({
        'cert_id': 'x509',
        'cert_value': certificate,
    })
    return pkcs12.SafeBag({
        'bag_id': 'cert_bag',
        'bag_value': cert_bag,
        'bag_attributes': _attributes(friendly_name, local_key_id),
    })


def _encrypted_key_bag(friendly_name, local_key_id):
    encrypted = keys.EncryptedPrivateKeyInfo({
        'encryption_algorithm': {
            'algorithm': 'aes256_cbc',
            'parameters': b'\x00' * 16,
        },
        'encrypted_data': b'SYNTHETIC-PLACEHOLDER-NOT-A-PRIVATE-KEY',
    })
    return pkcs12.SafeBag({
        'bag_id': 'pkcs8_shrouded_key_bag',
        'bag_value': encrypted,
        'bag_attributes': _attributes(friendly_name, local_key_id),
    })


def build_synthetic_directory():
    certificate_a = synthetic_certificate(0x2001, 'shared.example', 0xA001)
    certificate_b = synthetic_certificate(0x2002, 'shared.example', 0xB002)
    certificate_c = synthetic_certificate(0x2003, 'visible.example', 0xC003)

    safe_contents = pkcs12.SafeContents([
        _cert_bag(certificate_a, 'Shared Legacy', b'\xa1\x01'),
        _cert_bag(certificate_b, 'Shared Legacy', b'\xb2\x02'),
        _cert_bag(certificate_c, 'Visible Only', b'\xc3\x03'),
        _encrypted_key_bag('Visible Only', b'\xd4\x04'),
    ])
    data_content = cms.ContentInfo({
        'content_type': 'data',
        'content': core.OctetString(safe_contents.dump()),
    })

    encrypted_contents = cms.EncryptedData({
        'version': 'v0',
        'encrypted_content_info': {
            'content_type': 'data',
            'content_encryption_algorithm': {
                'algorithm': 'aes256_cbc',
                'parameters': b'\x00' * 16,
            },
            'encrypted_content': b'SYNTHETIC-ENCRYPTED-SAFE-PLACEHOLDER',
        },
    })
    encrypted_content = cms.ContentInfo({
        'content_type': 'encrypted_data',
        'content': encrypted_contents,
    })

    authenticated_safe = pkcs12.AuthenticatedSafe([data_content, encrypted_content])
    auth_safe = cms.ContentInfo({
        'content_type': 'data',
        'content': core.OctetString(authenticated_safe.dump()),
    })
    pfx = pkcs12.Pfx({
        'version': 'v3',
        'auth_safe': auth_safe,
    })

    registry = [
        {
            'record_id': 'REG-001',
            'friendly_name': 'Shared Legacy',
            'sha256': certificate_a.sha256,
        },
        {
            'record_id': 'REG-002',
            'friendly_name': 'Visible Only',
        },
    ]
    return pfx.dump(), registry, certificate_a, certificate_b, certificate_c
