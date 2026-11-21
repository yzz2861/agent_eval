# coding: utf-8
"""
Deterministic synthetic CMS time-stamp fixtures for timestamp_audit tests.

Real arbitration exhibits cannot be checked into the repository, so this
module constructs minimal but structurally valid RFC 3161 TimeStampToken
ContentInfo structures with asn1crypto. The signatures are placeholder octet
strings on purpose: timestamp_audit must never verify them itself, and the
caller-supplied verdict path is exercised separately in the tests.
"""
from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os

from asn1crypto import cms, core, pem, tsp, x509


SAME_GEN_TIME = '20260310093000Z'
UNKNOWN_ALGORITHM_OID = '1.2.999.42.7'


def make_tst_token(algorithm, imprint_digest, gen_time, serial_number,
                   unsigned_attrs=None, policy_oid='1.2.3.4.5'):
    """Build a self-contained CMS ContentInfo wrapping one TSTInfo."""
    tst_info = tsp.TSTInfo({
        'version': 'v1',
        'policy': core.ObjectIdentifier(policy_oid),
        'message_imprint': tsp.MessageImprint({
            'hash_algorithm': cms.DigestAlgorithm({'algorithm': algorithm}),
            'hashed_message': core.OctetString(imprint_digest),
        }),
        'serial_number': core.Integer(serial_number),
        'gen_time': core.GeneralizedTime(gen_time),
    })

    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': x509.Name.build({'common_name': 'Synthetic Test TSA'}),
                'serial_number': core.Integer(serial_number),
            }),
        }),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': core.OctetString(b'\x00\x01\x02\x03'),
    })
    if unsigned_attrs is not None:
        signer_info['unsigned_attrs'] = unsigned_attrs

    signed_data = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': cms.DigestAlgorithms([{'algorithm': 'sha256'}]),
        'encap_content_info': cms.EncapsulatedContentInfo({
            'content_type': 'tst_info',
            'content': core.ParsableOctetString(tst_info.dump()),
        }),
        'signer_infos': cms.SignerInfos([signer_info]),
    })
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })


def make_nested_attribute(nested_token, attribute_type='signature_time_stamp_token'):
    return cms.CMSAttributes([cms.CMSAttribute({
        'type': attribute_type,
        'values': cms.SetOfContentInfo([nested_token]),
    })])


def make_timestamp_response(token):
    """Wrap a token the way an RFC 3161 responder would."""
    return tsp.TimeStampResp({
        'status': tsp.PKIStatusInfo({'status': 'granted'}),
        'time_stamp_token': token,
    })


def write_fixtures(base_dir):
    """
    Create the byte-level scenario under ``base_dir`` and return a descriptor
    dict so tests can assert against the same declared digests.
    """
    receipt_dir = os.path.join(base_dir, 'receipts')
    exhibit_dir = os.path.join(base_dir, 'exhibits')
    os.makedirs(receipt_dir)
    os.makedirs(exhibit_dir)

    exhibit_a = os.path.join(exhibit_dir, 'summary_page_a.pdf')
    exhibit_b = os.path.join(exhibit_dir, 'summary_page_b.pdf')
    exhibit_c = os.path.join(exhibit_dir, 'nested_target.bin')
    missing_exhibit = os.path.join(exhibit_dir, 'not_delivered.pdf')

    payload_a = b'%PDF-1.7 arbitration summary page A - printed 09:30:00\n'
    payload_b = b'%PDF-1.7 arbitration summary page B - printed 09:30:00\n'
    payload_c = b'bytes covered by the inner nested receipt\n'
    with open(exhibit_a, 'wb') as f:
        f.write(payload_a)
    with open(exhibit_b, 'wb') as f:
        f.write(payload_b)
    with open(exhibit_c, 'wb') as f:
        f.write(payload_c)

    digest_a_sha256 = hashlib.sha256(payload_a).digest()
    digest_b_sha256 = hashlib.sha256(payload_b).digest()
    digest_c_sha256 = hashlib.sha256(payload_c).digest()

    # Receipt A and B declare the same gen_time (identical print timestamp on
    # the summary pages) but protect different content digests. Only A and B
    # have their own receipts; the missing exhibit never receives one.
    token_a = make_tst_token('sha256', digest_a_sha256, SAME_GEN_TIME, 1001)
    token_b = make_tst_token('sha256', digest_b_sha256, SAME_GEN_TIME, 1002)

    receipt_a = os.path.join(receipt_dir, 'summary_a.tsr')
    receipt_b = os.path.join(receipt_dir, 'summary_b.tsr')
    with open(receipt_a, 'wb') as f:
        f.write(token_a.dump())
    with open(receipt_b, 'wb') as f:
        f.write(pem.armor('CMS', token_b.dump()))

    # An outer receipt whose signer carries an inner RFC 3161 receipt in the
    # signature_time_stamp_token unsigned attribute.
    inner_token = make_tst_token('sha256', digest_c_sha256, SAME_GEN_TIME, 2001)
    outer_signature = b'\x99' * 16
    outer_token = make_tst_token(
        'sha1', hashlib.sha1(outer_signature).digest(), SAME_GEN_TIME, 2002,
        unsigned_attrs=make_nested_attribute(inner_token),
    )
    nested_receipt = os.path.join(receipt_dir, 'nested.tsr')
    with open(nested_receipt, 'wb') as f:
        f.write(outer_token.dump())

    # A TimeStampResp wrapper around the exact token_a bytes, instead of a
    # bare ContentInfo. The parser must surface the same receipt id.
    response_receipt = os.path.join(receipt_dir, 'wrapped_resp.tsr')
    with open(response_receipt, 'wb') as f:
        f.write(make_timestamp_response(
            cms.ContentInfo.load(token_a.dump())
        ).dump())

    # A receipt declaring a digest algorithm OID the local build cannot map.
    unknown_token = make_tst_token(
        UNKNOWN_ALGORITHM_OID, b'\xde\xad' * 16, SAME_GEN_TIME, 3001
    )
    unknown_receipt = os.path.join(receipt_dir, 'unknown_algorithm.tsr')
    with open(unknown_receipt, 'wb') as f:
        f.write(unknown_token.dump())

    # Deliberately broken bytes to exercise the parse-error path.
    broken_receipt = os.path.join(receipt_dir, 'broken.tsr')
    with open(broken_receipt, 'wb') as f:
        f.write(b'\x30\x09\x02\x01\x01not-really-der')

    return {
        'receipt_files': [
            receipt_a, receipt_b, nested_receipt,
            response_receipt, unknown_receipt, broken_receipt,
        ],
        'exhibits': [
            ('EX-A', exhibit_a),
            ('EX-B', exhibit_b),
            ('EX-C', exhibit_c),
            ('EX-MISSING', missing_exhibit),
        ],
        'expected': {
            'gen_time': '2026-03-10T09:30:00+00:00',
            'exhibit_a_digest_sha256_hex': digest_a_sha256.hex(),
            'exhibit_b_digest_sha256_hex': digest_b_sha256.hex(),
            'exhibit_c_digest_sha256_hex': digest_c_sha256.hex(),
            'unknown_algorithm_oid': UNKNOWN_ALGORITHM_OID,
        },
        'token_a_der': token_a.dump(),
    }
