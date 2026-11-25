"""Synthetic CMS / time-stamp receipt sample builder.

Everything here is fabricated test material: signature OCTET STRINGS hold
plain marker bytes instead of real signatures, and "trust" is decided by the
caller rather than this package. The DER structures themselves are valid CMS
SignedData / TSTInfo so that asn1crypto can parse them end to end.

The chain models an archive receiving renewed receipts every few years:

* stage 1 - the original signed CMS; its signature value carries a 2018
  RFC 3161 signature time-stamp token.
* stage 2 - a 2021 archive-style receipt whose imprint covers the whole
  stage-1 record DER, carried in a chain attribute.
* stage 3 - a 2024 archive-style receipt whose imprint covers the whole
  stage-2 record DER.

Replacing the stage-2 bytes (e.g. dropping the middle record) therefore
removes exactly one provable history segment, which the analyzer reports
without guessing what the missing original looked like.
"""

from __future__ import unicode_literals

import hashlib

from asn1crypto import algos, cms, core, tsp

from .analyzer import (
    ARCHIVE_CHAIN_ATTR,
    SIGNATURE_TST_ATTR_OID,
)

POLICY_OID = '1.2.840.113549.1.9.16.6.100.0'
DIGEST_ALGORITHM = 'sha256'
REPACKAGED_WRAPPER_OID = '1.2.840.113549.1.9.16.6.200.1'

# Register the synthetic wrapper content type so asn1crypto parses the outer
# ContentInfo as a regular explicit-tagged structure instead of a bare Any.
cms.ContentType._map[REPACKAGED_WRAPPER_OID] = 'evidence_repackaged_wrapper'
cms.ContentInfo._oid_specs['evidence_repackaged_wrapper'] = cms.ContentInfo

STAGE_SPECS = (
    ('stage1-2018', '2018-06-01T08:00:00+00:00', b'TSA-2018-key'),
    ('stage2-2021', '2021-06-01T08:00:00+00:00', b'TSA-2021-key'),
    ('stage3-2024', '2024-06-01T08:00:00+00:00', b'TSA-2024-key'),
)

ORIGINAL_PAYLOAD = (
    b'Archive case file 2018-A-17: original signed submission.\n'
    b'This payload stands in for the original signature material.\n'
)


def build_three_stage_sample(extra_payload=b''):
    """Return ``(records, trust_inputs)`` for the canonical three-stage chain."""

    payload = ORIGINAL_PAYLOAD + extra_payload
    stage1 = build_stage_one(payload)
    stage2 = build_followup_stage(stage1, STAGE_SPECS[1])
    stage3 = build_followup_stage(stage2, STAGE_SPECS[2])
    records = [stage1, stage2, stage3]
    trust_inputs = {
        'tst-serial-1': 'trusted',
        'tst-serial-2': 'trusted',
        'tst-serial-3': 'trusted',
    }
    return records, trust_inputs


def build_stage_one(payload):
    """The original CMS SignedData plus its first signature time-stamp."""

    signature_marker = b'ORIGINAL-CMS-SIGNATURE-MARKER'
    signer_info = _signer_info(b'ORIGINAL-SIGNER-KEY', signature_marker)
    token = build_tst_token(
        serial=1,
        gen_time=STAGE_SPECS[0][1],
        tsa_key=STAGE_SPECS[0][2],
        imprinted=signature_marker,
    )
    _attach_unsigned(signer_info, SIGNATURE_TST_ATTR_OID, token)
    record = _signed_data_record(
        signer_info,
        payload,
        content_type='data',
    )
    return SampleRecord(STAGE_SPECS[0][0], record.dump())


def build_followup_stage(previous_record, stage_spec):
    """Build an archive-renewal record over the whole previous record DER."""

    record_id, gen_time, tsa_key = stage_spec
    serial = int(record_id.split('-')[0].replace('stage', ''))
    signature_marker = b'RENEWAL-SIGNATURE-' + record_id.encode('ascii')
    signer_info = _signer_info(
        b'RENEWAL-SIGNER-KEY-' + str(serial).encode('ascii'),
        signature_marker,
    )
    token = build_tst_token(
        serial=serial,
        gen_time=gen_time,
        tsa_key=tsa_key,
        imprinted=previous_record.blob,
    )
    _attach_unsigned(signer_info, ARCHIVE_CHAIN_ATTR, token)
    record = _signed_data_record(
        signer_info,
        previous_record.blob,
        content_type='signed_data',
    )
    return SampleRecord(record_id, record.dump())


def build_tst_token(serial, gen_time, tsa_key, imprinted):
    """Construct a synthetic but structurally valid RFC 3161 TST token."""

    digest = hashlib.new(DIGEST_ALGORITHM, imprinted).digest()
    tst_info = tsp.TSTInfo({
        'version': 1,
        'policy': core.ObjectIdentifier(POLICY_OID),
        'message_imprint': tsp.MessageImprint({
            'hash_algorithm': algos.DigestAlgorithm({
                'algorithm': DIGEST_ALGORITHM,
            }),
            'hashed_message': core.OctetString(digest),
        }),
        'serial_number': core.Integer(serial),
        'gen_time': core.GeneralizedTime(
            gen_time[:19].replace('-', '').replace(':', '').replace('T', '') + 'Z'
        ),
    })
    signer_info = _signer_info(
        tsa_key,
        b'TSA-SIGNATURE-MARKER-%d' % serial,
    )
    signed_data = cms.SignedData({
        'version': 3,
        'digest_algorithms': cms.DigestAlgorithms([
            algos.DigestAlgorithm({'algorithm': DIGEST_ALGORITHM}),
        ]),
        'encap_content_info': cms.EncapsulatedContentInfo({
            'content_type': 'tst_info',
            'content': cms.ParsableOctetString(parsed=tst_info),
        }),
        'signer_infos': cms.SignerInfos([signer_info]),
    })
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })


def build_repackaged_record(record, wrapper_oid=REPACKAGED_WRAPPER_OID):
    """Put an existing record inside a different outer ContentInfo wrapper."""

    inner = cms.ContentInfo.load(record.blob)
    wrapper = cms.ContentInfo({
        'content_type': cms.ContentType(value=wrapper_oid),
        'content': inner,
    })
    return SampleRecord(record.record_id + '-repackaged', wrapper.dump())


def build_replacement_middle_record():
    """A structurally valid but unrelated record used to swap out stage 2."""

    signer_info = _signer_info(
        b'INTRUDER-SIGNER-KEY', b'REPLACEMENT-SIGNATURE-MARKER',
    )
    record = _signed_data_record(
        signer_info,
        b'foreign record with no time-stamp receipts',
        content_type='data',
    )
    return SampleRecord('stage2-2021-replaced', record.dump())


def _signer_info(signer_key, signature_marker):
    return cms.SignerInfo({
        'version': 3,
        'sid': cms.SignerIdentifier(
            name='subject_key_identifier',
            value=core.OctetString(hashlib.sha256(signer_key).digest()),
        ),
        'digest_algorithm': algos.DigestAlgorithm({
            'algorithm': DIGEST_ALGORITHM,
        }),
        'signed_attrs': cms.CMSAttributes([]),
        'signature_algorithm': algos.SignedDigestAlgorithm({
            'algorithm': 'sha256_rsa',
        }),
        'signature': core.OctetString(signature_marker),
    })


def _attach_unsigned(signer_info, attribute_oid, token):
    if attribute_oid == SIGNATURE_TST_ATTR_OID or attribute_oid == 'signature_time_stamp_token':
        attribute = cms.CMSAttribute({
            'type': 'signature_time_stamp_token',
            'values': cms.SetOfContentInfo([token]),
        })
    else:
        attribute = cms.CMSAttribute({
            'type': cms.CMSAttributeType(value=attribute_oid),
            'values': cms.SetOfAny([token]),
        })
    existing = signer_info['unsigned_attrs']
    attributes = list(existing) if existing is not None else []
    attributes.append(attribute)
    signer_info['unsigned_attrs'] = cms.CMSAttributes(attributes)


RENEWAL_ENCAPSULATION_OID = '1.2.840.113549.1.9.16.6.100.9'


def _signed_data_record(signer_info, payload, content_type):
    if content_type == 'signed_data':
        # An unregistered encapsulation OID keeps the predecessor record as
        # opaque OCTET STRING contents instead of letting asn1crypto try to
        # reinterpret it; the analyzer re-parses it explicitly as ContentInfo.
        encap_type = cms.ContentType(value=RENEWAL_ENCAPSULATION_OID)
    else:
        encap_type = content_type
    encap_content = cms.ParsableOctetString(value=payload)
    signed_data = cms.SignedData({
        'version': 3,
        'digest_algorithms': cms.DigestAlgorithms([
            algos.DigestAlgorithm({'algorithm': DIGEST_ALGORITHM}),
        ]),
        'encap_content_info': cms.EncapsulatedContentInfo({
            'content_type': encap_type,
            'content': encap_content,
        }),
        'signer_infos': cms.SignerInfos([signer_info]),
    })
    return cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data,
    })


class SampleRecord(object):
    """A named synthetic record blob ready to be handed to the analyzer."""

    def __init__(self, record_id, blob):
        self.record_id = record_id
        self.blob = blob
