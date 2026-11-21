# coding: utf-8
"""
Offline extraction of RFC 3161 time-stamp receipts from CMS containers.

Only the local bytes of the supplied files are inspected. The module never
fetches revocation information, never contacts a time-stamp authority and
never draws conclusions from the displayed ``genTime`` value. Every receipt
is returned together with a provenance chain so that an arbitrator can retrace
which byte sequence, which CMS attribute and which nesting level it came from.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib

from asn1crypto import cms, pem, tsp


# CMS unsigned attributes that carry RFC 3161 TimeStampToken ContentInfo
# structures. "counter_signature" and "microsoft_nested_signature" hold
# SignerInfo/SignedData structures rather than time-stamp tokens, so they are
# not traversed as receipt containers.
TIMESTAMP_ATTR_TYPES = (
    'signature_time_stamp_token',
    'microsoft_time_stamp_token',
)

MAX_NESTING_DEPTH = 100


class ReceiptParseError(Exception):
    """Raised when a byte sequence cannot be decoded into a CMS container."""


def _read_bytes(file_path):
    with open(file_path, 'rb') as f:
        return f.read()


def _dearmor(data):
    if pem.detect(data):
        _, _, der_bytes = pem.unarmor(data)
        return der_bytes
    return data


def _load_container(der_bytes):
    """
    Accept either a bare CMS ContentInfo (the usual on-disk .tsr/.p7m form)
    or a full RFC 3161 TimeStampResp that wraps the token under
    ``time_stamp_token``.
    """
    try:
        content_info = cms.ContentInfo.load(der_bytes)
        # asn1crypto parses lazily, so touching the fields is required to
        # reject a TimeStampResp that merely shares the SEQUENCE outer tag.
        if content_info['content_type'].native == 'signed_data':
            return [content_info]
    except (ValueError, TypeError):
        pass

    response = tsp.TimeStampResp.load(der_bytes)
    token = response['time_stamp_token']
    if token.native is None:
        return []
    return [token]


def _tst_info(signed_data):
    encap = signed_data['encap_content_info']
    if encap['content_type'].native != 'tst_info':
        return None
    parsed = encap['content'].parsed
    return parsed if isinstance(parsed, tsp.TSTInfo) else None


def _algorithm_description(digest_algorithm):
    algorithm = digest_algorithm['algorithm']
    oid = algorithm.dotted
    name = algorithm.native
    # For an unregistered OID asn1crypto echoes the dotted OID back as the
    # native value, which is indistinguishable from a real name here.
    name_known = name != oid
    hashlib_name = name if name_known and name in hashlib.algorithms_available else None
    parameters = digest_algorithm['parameters']
    parameter_tag = None if parameters.native is None else parameters.tag
    return {
        'algorithm_oid': oid,
        'algorithm_name': name if name_known else None,
        'hashlib_name': hashlib_name,
        'algorithm_interpretable': bool(hashlib_name),
        'parameters_tag': parameter_tag,
    }


def _build_record(token, origin_path, token_index, depth, chain):
    der_bytes = token.dump()
    signed_data = token['content']
    tst_info = _tst_info(signed_data)

    record = {
        'receipt_id': hashlib.sha256(der_bytes).hexdigest(),
        'origin_path': origin_path,
        'token_index': token_index,
        'depth': depth,
        'provenance_chain': list(chain),
        'token_der_sha256': hashlib.sha256(der_bytes).hexdigest(),
        'token_der_length': len(der_bytes),
        'content_type_oid': token['content_type'].dotted,
        'is_time_stamp_token': tst_info is not None,
        'gen_time': None,
        'serial_number': None,
        'policy_oid': None,
        'digest_algorithm_oid': None,
        'digest_algorithm_name': None,
        'hashlib_name': None,
        'algorithm_interpretable': False,
        'algorithm_parameters_tag': None,
        'message_imprint_digest_hex': None,
        'message_imprint_digest_length': None,
        'nested_receipt_ids': [],
        'matched_exhibits': [],
        'match_status': 'not_evaluated',
        'signature_verdict': 'unprovided',
        'signature_verdict_note': None,
    }

    if tst_info is not None:
        imprint = tst_info['message_imprint']
        algorithm_info = _algorithm_description(imprint['hash_algorithm'])
        digest_value = imprint['hashed_message'].native
        record.update({
            'gen_time': tst_info['gen_time'].native.isoformat()
            if tst_info['gen_time'].native is not None else None,
            'serial_number': tst_info['serial_number'].native,
            'policy_oid': tst_info['policy'].dotted,
            'digest_algorithm_oid': algorithm_info['algorithm_oid'],
            'digest_algorithm_name': algorithm_info['algorithm_name'],
            'hashlib_name': algorithm_info['hashlib_name'],
            'algorithm_interpretable': algorithm_info['algorithm_interpretable'],
            'algorithm_parameters_tag': algorithm_info['parameters_tag'],
            'message_imprint_digest_hex': digest_value.hex(),
            'message_imprint_digest_length': len(digest_value),
        })

    return record


def _unsigned_timestamp_attributes(signer_info):
    unsigned_attrs = signer_info['unsigned_attrs']
    if unsigned_attrs.native is None:
        return
    for attr_index, attribute in enumerate(unsigned_attrs):
        attr_type = attribute['type'].native
        if attr_type not in TIMESTAMP_ATTR_TYPES:
            continue
        for value_index, nested_token in enumerate(attribute['values']):
            yield attr_type, attr_index, value_index, nested_token


def _walk(token, origin_path, token_index, depth, chain, records):
    if depth > MAX_NESTING_DEPTH:
        raise ReceiptParseError(
            'time-stamp nesting exceeds %d levels in %s' % (MAX_NESTING_DEPTH, origin_path)
        )

    record = _build_record(token, origin_path, token_index, depth, chain)
    records.append(record)

    if not record['is_time_stamp_token']:
        return record

    signed_data = token['content']
    for signer_index, signer_info in enumerate(signed_data['signer_infos']):
        for attr_type, attr_index, value_index, nested_token in \
                _unsigned_timestamp_attributes(signer_info):
            nested_chain = chain + [{
                'parent_receipt_id': record['receipt_id'],
                'signer_info_index': signer_index,
                'attribute_type': attr_type,
                'attribute_index': attr_index,
                'attribute_value_index': value_index,
            }]
            nested_record = _walk(
                nested_token,
                origin_path,
                value_index,
                depth + 1,
                nested_chain,
                records,
            )
            record['nested_receipt_ids'].append(nested_record['receipt_id'])

    return record


def parse_receipt_file(file_path):
    """
    Parse one local CMS file into flat receipt records plus parse errors.

    :param file_path:
        A filesystem path to a DER or PEM CMS ContentInfo / TimeStampResp

    :return:
        A two-element tuple ``(records, errors)``. ``records`` is a list of
        plain dicts in traversal (outer-to-inner) order; ``errors`` is a list
        of dicts describing files that could not be decoded.
    """
    records = []
    errors = []
    try:
        data = _read_bytes(file_path)
        root_tokens = _load_container(_dearmor(data))
    except (ValueError, OSError, IOError, TypeError) as exc:
        errors.append({
            'origin_path': file_path,
            'error': 'unparseable_container',
            'detail': '%s: %s' % (type(exc).__name__, str(exc)),
        })
        return records, errors

    for token_index, token in enumerate(root_tokens):
        try:
            _walk(token, file_path, token_index, 0, [], records)
        except (ValueError, TypeError, ReceiptParseError) as exc:
            errors.append({
                'origin_path': file_path,
                'error': 'malformed_nested_token',
                'detail': '%s: %s' % (type(exc).__name__, str(exc)),
            })
    return records, errors
