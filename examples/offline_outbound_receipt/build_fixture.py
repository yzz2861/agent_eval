#!/usr/bin/env python3
"""Build the offline outbound receipt example from PGPy test keys."""

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CREATED = datetime(2026, 11, 28, 0, 0, tzinfo=timezone.utc)
HANDOFF_ID = 'HO-2026-11-28-001'

ORIGINAL = b'''Delivery-Marker: signature-valid
Notice-ID: N-2026-11-28-001
Audience: internal
Subject: Scheduled platform maintenance

The platform maintenance window is 02:00-03:00 UTC on 2026-11-30.
Internal contact: operations-desk@example.invalid
Runbook: https://intranet.example.invalid/runbooks/maintenance-1138
Rollback owner: Internal Platform Team
'''

DERIVATIVE = b'''Delivery-Marker: signature-valid
Notice-ID: N-2026-11-28-001
Audience: external
Subject: Scheduled platform maintenance

The platform maintenance window is 02:00-03:00 UTC on 2026-11-30.
Public status page: https://status.example.invalid
Internal contact, runbook, and rollback details have been removed.
'''

ALTERED_DERIVATIVE = b'''Delivery-Marker: signature-valid
Notice-ID: N-2026-11-28-001
Audience: external
Subject: Scheduled platform maintenance

The platform maintenance window is 02:00-03:30 UTC on 2026-11-30.
Public status page: https://status.example.invalid
Internal contact, runbook, and rollback details have been removed.
'''


def _write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _write_json(path, document):
    from pgpy.handoff import canonical_json_bytes
    _write_bytes(path, canonical_json_bytes(document))


def _sign_file(key, path, signature_path):
    from pgpy.handoff import sign_bytes
    from pgpy.handoff import write_detached_signature
    signature = sign_bytes(key, path.read_bytes(), created=CREATED)
    write_detached_signature(signature, signature_path)
    return signature


def main():
    from pgpy import PGPKey
    from pgpy.handoff import DERIVATION_SCHEMA
    from pgpy.handoff import RELEASE_APPROVAL_SCHEMA
    from pgpy.handoff import RECEIPT_SCHEMA
    from pgpy.handoff import sha256_bytes
    from pgpy.handoff import verify_outbound_receipt
    from pgpy.handoff import write_public_key

    source_keys = ROOT / 'tests' / 'testdata' / 'keys'
    original_key = PGPKey.from_file(str(source_keys / 'targette.sec.rsa.asc'))[0]
    derivation_key = PGPKey.from_file(str(source_keys / 'rsa.1.sec.asc'))[0]
    approval_key = PGPKey.from_file(str(source_keys / 'dsa.1.sec.asc'))[0]
    receipt_key = PGPKey.from_file(str(source_keys / 'ecc.2.sec.asc'))[0]

    archive = HERE / 'archive'
    negative = HERE / 'negative'
    expected = HERE / 'expected'
    for directory in (archive, negative, expected):
        if directory.exists():
            shutil.rmtree(str(directory))
        directory.mkdir(parents=True)

    _write_bytes(archive / 'notice-original.txt', ORIGINAL)
    _write_bytes(archive / 'notice-external.txt', DERIVATIVE)
    _write_bytes(negative / 'notice-external.txt', ALTERED_DERIVATIVE)

    keys = archive / 'keys'
    keys.mkdir()
    write_public_key(original_key, keys / 'original-signer.pub.asc')
    write_public_key(derivation_key, keys / 'derivation-authority.pub.asc')
    write_public_key(approval_key, keys / 'release-approver.pub.asc')
    write_public_key(receipt_key, keys / 'receipt-issuer.pub.asc')

    _sign_file(original_key, archive / 'notice-original.txt', archive / 'notice-original.txt.asc')

    original_sha256 = sha256_bytes(ORIGINAL)
    derivative_sha256 = sha256_bytes(DERIVATIVE)
    derivation_document = {
        'schema': DERIVATION_SCHEMA,
        'handoff_id': HANDOFF_ID,
        'created': '2026-11-28T00:05:00Z',
        'issuer': 'Independent Desensitization Desk',
        'source': {
            'name': 'notice-original.txt',
            'sha256': original_sha256,
        },
        'derivative': {
            'name': 'notice-external.txt',
            'sha256': derivative_sha256,
            'transformation': 'remove-internal-fields',
        },
    }
    _write_json(archive / 'derivation.json', derivation_document)
    _sign_file(derivation_key, archive / 'derivation.json', archive / 'derivation.json.asc')

    derivation_sha256 = sha256_bytes((archive / 'derivation.json').read_bytes())
    approval_document = {
        'schema': RELEASE_APPROVAL_SCHEMA,
        'handoff_id': HANDOFF_ID,
        'created': '2026-11-28T00:10:00Z',
        'approval_id': 'RA-2026-11-28-001',
        'decision': 'approved',
        'approved_derivation_sha256': derivation_sha256,
        'approver': 'Release Approver',
    }
    _write_json(archive / 'release-approval.json', approval_document)
    _sign_file(approval_key, archive / 'release-approval.json', archive / 'release-approval.json.asc')

    receipt = {
        'schema': RECEIPT_SCHEMA,
        'handoff_id': HANDOFF_ID,
        'created': '2026-11-28T00:15:00Z',
        'issued_by': {
            'name': 'Dispatch Desk',
            'role': 'offline outbound receipt issuer',
            'key': 'keys/receipt-issuer.pub.asc',
            'fingerprint': str(receipt_key.fingerprint),
        },
        'signed_object': {
            'name': 'notice-original.txt',
            'path': 'notice-original.txt',
            'sha256': original_sha256,
            'signature': 'notice-original.txt.asc',
            'signer_key': 'keys/original-signer.pub.asc',
            'signer_fingerprint': str(original_key.fingerprint),
        },
        'derivative': {
            'name': 'notice-external.txt',
            'path': 'notice-external.txt',
            'inherited_delivery_marker': 'signature-valid',
            'own_signature': None,
        },
        'derivation': {
            'path': 'derivation.json',
            'sha256': derivation_sha256,
            'signature': 'derivation.json.asc',
            'signer_key': 'keys/derivation-authority.pub.asc',
            'signer_fingerprint': str(derivation_key.fingerprint),
        },
        'release_approval': {
            'path': 'release-approval.json',
            'sha256': sha256_bytes((archive / 'release-approval.json').read_bytes()),
            'signature': 'release-approval.json.asc',
            'signer_key': 'keys/release-approver.pub.asc',
            'signer_fingerprint': str(approval_key.fingerprint),
        },
        'receipt_signature': 'outbound-receipt.json.asc',
    }
    _write_json(archive / 'outbound-receipt.json', receipt)
    _sign_file(receipt_key, archive / 'outbound-receipt.json', archive / 'outbound-receipt.json.asc')

    valid = verify_outbound_receipt(str(archive))
    mismatch = verify_outbound_receipt(str(archive), derivative_path=str(negative / 'notice-external.txt'))
    _write_json(expected / 'valid.json', valid)
    _write_json(expected / 'mismatch.json', mismatch)

    print(json.dumps({'archive': str(archive),
                      'valid': {key: valid[key] for key in ('original_signature_valid',
                                                           'derivative_deliverable',
                                                           'simplified_has_own_signature')},
                      'mismatch': {key: mismatch[key] for key in ('original_signature_valid',
                                                                 'derivative_deliverable',
                                                                 'simplified_has_own_signature')},
                      'mismatch_claim': mismatch['failures'][0]['claim'] if mismatch['failures'] else None},
                     ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
