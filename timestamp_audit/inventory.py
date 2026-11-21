# coding: utf-8
"""
Offline exhibit inventory built from CMS time-stamp receipts.

The inventory is fully reproducible from local bytes. It records, for every
receipt, the digest algorithm and message-imprint digest declared by the
TSTInfo, the provenance chain of any nested receipts, and the caller-supplied
signature authenticity verdict. Exhibits are associated with receipts solely
by recomputing digests over their local bytes; the displayed ``genTime`` is
reported for readability but never used to infer identity.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from .matching import (
    ALGORITHM_UNINTERPRETABLE,
    EXHIBIT_BYTES_MISSING,
    MATCHED,
    NO_LOCAL_MATCH,
    apply_signature_verdicts,
    build_exhibit_index,
    match_receipts,
)
from .receipts import parse_receipt_file


MATCHING_BASIS = (
    'Receipt-to-exhibit identity is established only by equality of the '
    'TSTInfo-declared digest algorithm OID and message-imprint digest bytes '
    'against digests recomputed from local exhibit bytes. genTime is recorded '
    'as metadata and never participates in matching.'
)


def _normalise_exhibits(exhibits):
    normalised = []
    for exhibit in exhibits:
        if isinstance(exhibit, dict):
            normalised.append((exhibit['exhibit_id'], exhibit['path']))
        else:
            normalised.append((exhibit[0], exhibit[1]))
    return normalised


def _imprint_key(record):
    if not record['is_time_stamp_token']:
        return None
    return record['digest_algorithm_oid'], record['message_imprint_digest_hex']


def _group_by(values, key_function):
    groups = {}
    for value in values:
        key = key_function(value)
        if key is None:
            continue
        groups.setdefault(key, []).append(value)
    return groups


def _same_gen_time_groups(records):
    token_records = [r for r in records if r['is_time_stamp_token']]
    groups = _group_by(token_records, lambda r: r['gen_time'])
    result = []
    for gen_time, members in sorted(groups.items(), key=lambda item: item[0] or ''):
        if len(members) < 2:
            continue
        result.append({
            'gen_time': gen_time,
            'receipt_ids': [member['receipt_id'] for member in members],
            'imprint_keys': sorted(set(
                '%s:%s' % _imprint_key(member) for member in members
            )),
            'match_statuses': sorted(set(member['match_status'] for member in members)),
        })
    return result


def _imprint_groups(records):
    token_records = [r for r in records if r['is_time_stamp_token']]
    groups = _group_by(token_records, _imprint_key)
    return [
        {
            'digest_algorithm_oid': key[0],
            'message_imprint_digest_hex': key[1],
            'receipt_ids': [member['receipt_id'] for member in members],
            'match_statuses': sorted(set(member['match_status'] for member in members)),
        }
        for key, members in sorted(groups.items())
    ]


def build_inventory(receipt_files, exhibits, signature_verdicts=None):
    """
    Produce the full offline inventory report.

    :param receipt_files:
        A list of local paths to DER/PEM CMS ContentInfo or TimeStampResp files
    :param exhibits:
        A list of ``(exhibit_id, path)`` tuples or dicts with those keys
    :param signature_verdicts:
        Optional caller mapping of receipt id to verdict info; see
        :func:`timestamp_audit.matching.apply_signature_verdicts`

    :return:
        A plain-dict report suitable for JSON serialisation
    """
    exhibits = _normalise_exhibits(exhibits)

    records = []
    parse_errors = []
    for receipt_file in receipt_files:
        file_records, file_errors = parse_receipt_file(receipt_file)
        records.extend(file_records)
        parse_errors.extend(file_errors)

    required_algorithms = {
        record['hashlib_name']
        for record in records
        if record['is_time_stamp_token'] and record['algorithm_interpretable']
    }
    exhibit_index = build_exhibit_index(exhibits, required_algorithms)
    match_receipts(records, exhibit_index)
    verdict_warnings = apply_signature_verdicts(records, signature_verdicts)

    token_records = [r for r in records if r['is_time_stamp_token']]
    exhibit_records = list(exhibit_index.values())
    exhibits_without_receipt = [
        {
            'exhibit_id': exhibit['exhibit_id'],
            'path': exhibit['path'],
            'status': exhibit['status'],
        }
        for exhibit in exhibit_records
        if not exhibit['matched_receipt_ids']
    ]

    summary = {
        'receipt_files_total': len(receipt_files),
        'receipt_files_with_parse_errors': len({
            error['origin_path'] for error in parse_errors
        }),
        'tokens_total': len(records),
        'time_stamp_tokens_total': len(token_records),
        'nested_tokens_total': sum(1 for r in records if r['depth'] > 0),
        'matched_tokens_total': sum(1 for r in token_records if r['match_status'] == MATCHED),
        'unmatched_tokens_total': sum(
            1 for r in token_records if r['match_status'] == NO_LOCAL_MATCH
        ),
        'uninterpretable_algorithm_tokens_total': sum(
            1 for r in token_records
            if r['match_status'] == ALGORITHM_UNINTERPRETABLE
        ),
        'exhibits_total': len(exhibit_records),
        'exhibits_missing_bytes_total': sum(
            1 for exhibit in exhibit_records
            if exhibit['status'] == EXHIBIT_BYTES_MISSING
        ),
        'exhibits_without_receipt_total': len(exhibits_without_receipt),
        'same_gen_time_groups_total': len(_same_gen_time_groups(records)),
    }

    return {
        'matching_basis': MATCHING_BASIS,
        'summary': summary,
        'receipts': records,
        'exhibits': exhibit_records,
        'exhibits_without_receipt': exhibits_without_receipt,
        'imprint_groups': _imprint_groups(records),
        'same_gen_time_groups': _same_gen_time_groups(records),
        'parse_errors': parse_errors,
        'verdict_warnings': verdict_warnings,
    }
