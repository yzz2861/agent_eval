# coding: utf-8
"""
Local-byte comparison between time-stamp message imprints and exhibits.

Identity is established exclusively by the digest algorithm OID declared
inside the TSTInfo message imprint plus the digest bytes. The displayed
``gen_time`` is never consulted: two receipts printed at the same instant are
only equivalent when their declared algorithm and imprint digest coincide.
Missing exhibit bytes and algorithms the local hashlib build cannot compute
are reported as separate, explicit statuses instead of being silently treated
as mismatches.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import hashlib
import os


MATCHED = 'matched'
NO_LOCAL_MATCH = 'no_local_match'
ALGORITHM_UNINTERPRETABLE = 'algorithm_uninterpretable'
NOT_A_TIME_STAMP_TOKEN = 'not_a_time_stamp_token'

EXHIBIT_OK = 'ok'
EXHIBIT_BYTES_MISSING = 'bytes_missing'

SIGNATURE_VERDICTS = ('valid', 'invalid', 'inconclusive', 'unprovided')

_STREAM_CHUNK_SIZE = 1024 * 1024


def _stream_digest(file_path, algorithm_name):
    digest = hashlib.new(algorithm_name)
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(_STREAM_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_exhibit_index(exhibits, required_algorithms):
    """
    Hash every locally available exhibit with every algorithm that at least
    one receipt declared. Missing files are kept as explicit records rather
    than dropped, so the report can distinguish "no bytes" from "no match".

    :param exhibits:
        A list of ``(exhibit_id, file_path)`` tuples
    :param required_algorithms:
        An iterable of hashlib algorithm names that receipts require

 :return:
        A dict of exhibit records keyed by ``exhibit_id``
    """
    algorithm_names = sorted(set(required_algorithms))
    index = {}
    for exhibit_id, file_path in exhibits:
        record = {
            'exhibit_id': exhibit_id,
            'path': file_path,
            'status': EXHIBIT_OK,
            'bytes_sha256': None,
            'bytes_length': None,
            'digests': {},
            'matched_receipt_ids': [],
        }
        if not os.path.isfile(file_path):
            record['status'] = EXHIBIT_BYTES_MISSING
            index[exhibit_id] = record
            continue

        record['bytes_sha256'] = _stream_digest(file_path, 'sha256')
        record['bytes_length'] = os.path.getsize(file_path)
        for algorithm_name in algorithm_names:
            if algorithm_name == 'sha256':
                record['digests'][algorithm_name] = record['bytes_sha256']
            else:
                record['digests'][algorithm_name] = _stream_digest(
                    file_path, algorithm_name
                )
        index[exhibit_id] = record
    return index


def match_receipts(records, exhibit_index):
    """
    Match receipt message imprints against the exhibit index in place.

    A match requires both the declared digest algorithm OID and the imprint
    digest bytes to be equal. ``gen_time`` is deliberately excluded from the
    comparison so identical print times cannot create a false association.
    """
    for record in records:
        if not record['is_time_stamp_token']:
            record['match_status'] = NOT_A_TIME_STAMP_TOKEN
            continue
        if not record['algorithm_interpretable']:
            record['match_status'] = ALGORITHM_UNINTERPRETABLE
            continue

        algorithm_name = record['hashlib_name']
        imprint_digest = record['message_imprint_digest_hex']
        for exhibit_id, exhibit in exhibit_index.items():
            if exhibit['status'] != EXHIBIT_OK:
                continue
            local_digest = exhibit['digests'].get(algorithm_name)
            if local_digest is None:
                continue
            if local_digest == imprint_digest:
                record['matched_exhibits'].append({
                    'exhibit_id': exhibit_id,
                    'path': exhibit['path'],
                    'digest_algorithm_oid': record['digest_algorithm_oid'],
                    'digest_algorithm_name': algorithm_name,
                    'digest_hex': local_digest,
                })
                exhibit['matched_receipt_ids'].append(record['receipt_id'])

        record['match_status'] = MATCHED if record['matched_exhibits'] else NO_LOCAL_MATCH


def apply_signature_verdicts(records, verdicts):
    """
    Attach caller-supplied signature authenticity conclusions.

    This module never verifies signatures itself. The caller passes a mapping
    of ``receipt_id`` (the SHA-256 of the TimeStampToken DER bytes) to
    ``{"verdict": ..., "note": ...}``. Unknown verdict values and unknown
    receipt ids are returned for the report instead of being silently dropped.

    :return:
        A dict with ``unresolved_keys`` and ``invalid_verdicts`` lists
    """
    by_id = {}
    for record in records:
        by_id.setdefault(record['receipt_id'], []).append(record)
    unresolved_keys = []
    invalid_verdicts = []

    for receipt_id, verdict_info in (verdicts or {}).items():
        matching_records = by_id.get(receipt_id)
        if matching_records is None:
            unresolved_keys.append(receipt_id)
            continue
        verdict = verdict_info.get('verdict', 'unprovided')
        if verdict not in SIGNATURE_VERDICTS:
            invalid_verdicts.append({'receipt_id': receipt_id, 'verdict': verdict})
            continue
        for record in matching_records:
            record['signature_verdict'] = verdict
            record['signature_verdict_note'] = verdict_info.get('note')

    return {
        'unresolved_keys': unresolved_keys,
        'invalid_verdicts': invalid_verdicts,
    }
