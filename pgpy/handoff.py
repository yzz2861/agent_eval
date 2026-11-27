"""Verification helpers for offline handoffs signed with PGPy.

The handoff receipt is deliberately separate from the signed source and the
derivative.  A valid signature on the source says nothing about a derivative
that was produced later, so the receipt records three independent pieces of
evidence: the signed source, an independently issued derivation statement, and
a release approval.  The receipt itself is detached-signed as well.
"""

import argparse
import hashlib
import json
import os
import sys
import warnings

from .pgp import PGPKey, PGPMessage, PGPSignature


__all__ = ['HandoffVerificationError',
           'canonical_json_bytes',
           'sha256_bytes',
           'sha256_file',
           'sign_bytes',
           'write_detached_signature',
           'write_public_key',
           'verify_outbound_receipt']


RECEIPT_SCHEMA = 'pgpy.handoff.outbound-receipt/v1'
DERIVATION_SCHEMA = 'pgpy.handoff.derivation/v1'
RELEASE_APPROVAL_SCHEMA = 'pgpy.handoff.release-approval/v1'


class HandoffVerificationError(Exception):
    """Raised when a handoff document cannot be evaluated."""


def sha256_bytes(data):
    """Return the lowercase SHA-256 digest of *data*."""
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_file(path):
    """Return the lowercase SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_bytes(document):
    """Serialize *document* in the stable form used by bundled evidence."""
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')


def sign_bytes(private_key, subject, **prefs):
    """Create a detached binary-document signature over *subject*."""
    if isinstance(private_key, (str, bytes, os.PathLike)):
        private_key = PGPKey.from_file(private_key)[0]
    if isinstance(subject, str):
        subject = subject.encode('utf-8')
    return private_key.sign(bytes(subject), **prefs)


def write_detached_signature(signature, path):
    """Write an ASCII-armored detached signature to *path*."""
    with open(path, 'w', encoding='utf-8', newline='\n') as output:
        output.write(str(signature))
        if not str(signature).endswith('\n'):
            output.write('\n')


def write_public_key(key, path):
    """Write the public half of *key* in ASCII-armored form."""
    if isinstance(key, (str, bytes, os.PathLike)):
        key = PGPKey.from_file(key)[0]
    with open(path, 'w', encoding='utf-8', newline='\n') as output:
        output.write(str(key.pubkey))
        if not str(key.pubkey).endswith('\n'):
            output.write('\n')


def _read_bytes(path):
    with open(path, 'rb') as source:
        return source.read()


def _safe_path(root, relative_path, description):
    if not isinstance(relative_path, str) or relative_path == '':
        raise HandoffVerificationError('{:s} must be a non-empty relative path'.format(description))
    if os.path.isabs(relative_path):
        raise HandoffVerificationError('{:s} must be relative to the archive'.format(description))
    root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root, relative_path))
    try:
        inside = os.path.commonpath([root, candidate]) == root
    except ValueError:
        inside = False
    if not inside:
        raise HandoffVerificationError('{:s} escapes the archive: {:s}'.format(description, relative_path))
    return candidate


def _load_key(path):
    key = PGPKey.from_file(path)[0]
    return key


def _load_signature(path):
    signature = PGPSignature.from_file(path)
    if isinstance(signature, tuple):
        signature = signature[0]
    return signature


def _signature_verifies(key, subject, signature):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return bool(key.verify(subject, signature))
    except Exception:
        return False


def _public_keys(root, receipt):
    keys = []
    key_dir = os.path.join(root, 'keys')
    if os.path.isdir(key_dir):
        for name in sorted(os.listdir(key_dir)):
            if name.endswith('.asc'):
                try:
                    keys.append(_load_key(os.path.join(key_dir, name)))
                except Exception:
                    pass

    for relative_path in receipt.get('derivative', {}).get('verification_keys', []):
        try:
            keys.append(_load_key(_safe_path(root, relative_path, 'derivative verification key')))
        except Exception:
            pass
    return keys


def _detached_signature_candidates(root, actual_path, derivative_claim):
    candidates = [actual_path + '.asc', actual_path + '.sig']
    declared = derivative_claim.get('own_signature')
    if isinstance(declared, str) and declared:
        candidates.insert(0, _safe_path(root, declared, 'derivative signature'))

    seen = set()
    for candidate in candidates:
        candidate = os.path.realpath(candidate)
        if candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate):
            yield candidate


def _own_signature_status(root, actual_path, data, receipt):
    status = {'present': False, 'valid': False, 'validated_by': []}
    keys = _public_keys(root, receipt)

    for signature_path in _detached_signature_candidates(root, actual_path, receipt.get('derivative', {})):
        try:
            signature = _load_signature(signature_path)
            status['present'] = True
        except Exception:
            continue

        for key in keys:
            if _signature_verifies(key, data, signature):
                status['valid'] = True
                status['validated_by'].append(str(key.fingerprint))

    if data.lstrip().startswith(b'-----BEGIN PGP SIGNED MESSAGE-----'):
        try:
            message = PGPMessage.from_blob(data)
            if isinstance(message, tuple):
                message = message[0]
            status['present'] = status['present'] or bool(message.signatures)
            for signature in message.signatures:
                for key in keys:
                    if _signature_verifies(key, message, signature):
                        status['valid'] = True
                        status['validated_by'].append(str(key.fingerprint))
        except Exception:
            pass

    status['validated_by'] = sorted(set(status['validated_by']))
    return status


def _delivery_marker(data):
    for raw_line in data.splitlines():
        line = raw_line.strip()
        if line.lower().startswith(b'delivery-marker:'):
            return line.split(b':', 1)[1].strip().decode('utf-8', 'replace')
    return None


def _add_failure(failures, code, claim, evidence, message, **details):
    failure = {'code': code,
               'claim': claim,
               'evidence': evidence,
               'message': message}
    failure.update(details)
    failures.append(failure)


def verify_outbound_receipt(archive, derivative_path=None, receipt_path='outbound-receipt.json',
                            receipt_signature_path=None, require_receipt_signature=True):
    """Verify an offline outbound receipt and its handoff evidence.

    :param archive: Directory containing the receipt and its evidence.
    :param derivative_path: Optional replacement attachment to check against the
                            evidence.  Its basename must still match the name in
                            the receipt.  This is how a receiver tests a same-name
                            attachment that arrived through a different channel.
    :param receipt_path: Receipt path relative to *archive*.
    :param receipt_signature_path: Optional receipt signature path relative to
                                   *archive*.
    :param require_receipt_signature: Whether an unsigned receipt is acceptable.
    :returns: A JSON-serializable result with the three requested facts and
              claim-level failures.
    """
    root = os.path.realpath(archive)
    result = {'handoff_id': None,
              'receipt_signature_valid': False,
              'original_signature_valid': False,
              'derivation_evidence_valid': False,
              'release_approval_valid': False,
              'derivative_deliverable': False,
              'simplified_has_own_signature': False,
              'simplified_signature_evidence': 'none',
              'delivery_basis': [],
              'delivery_marker': None,
              'missing_evidence': [],
              'failures': []}
    failures = result['failures']

    try:
        receipt_file = _safe_path(root, receipt_path, 'receipt path')
        receipt_bytes = _read_bytes(receipt_file)
        receipt = json.loads(receipt_bytes.decode('utf-8'))
        if not isinstance(receipt, dict):
            raise ValueError('receipt must be a JSON object')
    except Exception as exc:
        _add_failure(failures, 'RECEIPT_UNREADABLE', 'handoff.receipt', receipt_path,
                     'receipt could not be read as a JSON object', error=str(exc))
        result['missing_evidence'] = ['handoff.receipt']
        return result

    result['handoff_id'] = receipt.get('handoff_id')
    if receipt.get('schema') != RECEIPT_SCHEMA:
        _add_failure(failures, 'RECEIPT_SCHEMA_MISMATCH', 'handoff.schema', receipt_path,
                     'unexpected receipt schema', expected=RECEIPT_SCHEMA, actual=receipt.get('schema'))

    receipt_signature = receipt_signature_path or receipt.get('receipt_signature') or receipt_path + '.asc'
    receipt_key_path = receipt.get('issued_by', {}).get('key')
    try:
        receipt_key = _load_key(_safe_path(root, receipt_key_path, 'receipt signer key'))
        receipt_signature_obj = _load_signature(_safe_path(root, receipt_signature, 'receipt signature'))
        result['receipt_signature_valid'] = _signature_verifies(receipt_key, receipt_bytes, receipt_signature_obj)
    except Exception as exc:
        result['receipt_signature_valid'] = False
        _add_failure(failures, 'RECEIPT_SIGNATURE_UNREADABLE', 'handoff.receipt_signature',
                     receipt_signature, 'receipt signature evidence could not be loaded', error=str(exc))
    if require_receipt_signature and not result['receipt_signature_valid'] and \
            not any(f['code'].startswith('RECEIPT_SIGNATURE') for f in failures):
        _add_failure(failures, 'RECEIPT_SIGNATURE_INVALID', 'handoff.receipt_signature',
                     receipt_signature, 'the outbound receipt is not signed by its declared issuer')

    signed_object = receipt.get('signed_object', {})
    original_data = None
    original_sha256 = None
    original_path = None
    original_digest_ok = False
    try:
        original_path = _safe_path(root, signed_object.get('path'), 'signed object path')
        original_data = _read_bytes(original_path)
        original_sha256 = sha256_bytes(original_data)
        original_digest_ok = original_sha256 == signed_object.get('sha256')
        if not original_digest_ok:
            _add_failure(failures, 'ORIGINAL_DIGEST_MISMATCH', 'handoff.signed_object.sha256',
                         signed_object.get('path'), 'the signed object does not match the receipt digest',
                         expected_sha256=signed_object.get('sha256'), actual_sha256=original_sha256)

        original_key = _load_key(_safe_path(root, signed_object.get('signer_key'), 'signed object key'))
        original_signature = _load_signature(_safe_path(root, signed_object.get('signature'), 'signed object signature'))
        original_verified = _signature_verifies(original_key, original_data, original_signature)
        result['original_signature_valid'] = bool(original_digest_ok and original_verified)
        if not original_verified:
            _add_failure(failures, 'ORIGINAL_SIGNATURE_INVALID', 'handoff.signed_object.signature',
                         signed_object.get('signature'), 'the original detached signature does not verify')
    except Exception as exc:
        _add_failure(failures, 'ORIGINAL_EVIDENCE_UNREADABLE', 'handoff.signed_object',
                     signed_object.get('path'), 'original signature evidence could not be loaded', error=str(exc))

    derivative = receipt.get('derivative', {})
    derivative_name = derivative.get('name')
    derivative_claim_path = derivative.get('path', derivative_name)
    derivative_data = None
    derivative_sha256 = None
    derivative_actual_path = None
    try:
        if derivative_path is None:
            derivative_actual_path = _safe_path(root, derivative_claim_path, 'derivative path')
        else:
            derivative_actual_path = os.path.realpath(derivative_path)
        derivative_data = _read_bytes(derivative_actual_path)
        derivative_sha256 = sha256_bytes(derivative_data)
        if os.path.basename(derivative_actual_path) != derivative_name:
            _add_failure(failures, 'DERIVATIVE_NAME_MISMATCH', 'handoff.derivative.name',
                         os.path.basename(derivative_actual_path), 'the supplied attachment has a different name',
                         expected=derivative_name, actual=os.path.basename(derivative_actual_path))
        signature_status = _own_signature_status(root, derivative_actual_path, derivative_data, receipt)
        result['simplified_has_own_signature'] = signature_status['valid']
        if signature_status['valid']:
            result['simplified_signature_evidence'] = 'valid'
        elif signature_status['present']:
            result['simplified_signature_evidence'] = 'invalid'
    except Exception as exc:
        _add_failure(failures, 'DERIVATIVE_UNREADABLE', 'handoff.derivative',
                     derivative_claim_path, 'the derivative attachment could not be read', error=str(exc))

    derivation = receipt.get('derivation', {})
    derivation_failures_before = len(failures)
    derivation_bytes = None
    derivation_record = None
    derivation_sha256 = None
    try:
        derivation_file = _safe_path(root, derivation.get('path'), 'derivation record path')
        derivation_bytes = _read_bytes(derivation_file)
        derivation_sha256 = sha256_bytes(derivation_bytes)
        if derivation_sha256 != derivation.get('sha256'):
            _add_failure(failures, 'DERIVATION_RECORD_DIGEST_MISMATCH', 'handoff.derivation.sha256',
                         derivation.get('path'), 'the derivation record does not match the receipt digest',
                         expected_sha256=derivation.get('sha256'), actual_sha256=derivation_sha256)

        derivation_key = _load_key(_safe_path(root, derivation.get('signer_key'), 'derivation signer key'))
        derivation_signature = _load_signature(_safe_path(root, derivation.get('signature'), 'derivation signature'))
        if not _signature_verifies(derivation_key, derivation_bytes, derivation_signature):
            _add_failure(failures, 'DERIVATION_SIGNATURE_INVALID', 'handoff.derivation.signature',
                         derivation.get('signature'), 'the independent derivation statement is not signed by its declared authority')

        derivation_record = json.loads(derivation_bytes.decode('utf-8'))
        if derivation_record.get('schema') != DERIVATION_SCHEMA:
            _add_failure(failures, 'DERIVATION_SCHEMA_MISMATCH', 'handoff.derivation.schema',
                         derivation.get('path'), 'unexpected derivation schema',
                         expected=DERIVATION_SCHEMA, actual=derivation_record.get('schema'))
        if derivation_record.get('handoff_id') != result['handoff_id']:
            _add_failure(failures, 'DERIVATION_HANDOFF_MISMATCH', 'handoff.derivation.handoff_id',
                         derivation.get('path'), 'the derivation statement belongs to another handoff',
                         expected=result['handoff_id'], actual=derivation_record.get('handoff_id'))

        source = derivation_record.get('source', {})
        if source.get('sha256') != original_sha256:
            _add_failure(failures, 'DERIVATION_SOURCE_DIGEST_MISMATCH', 'handoff.derivation.source.sha256',
                         derivation.get('path'), 'the independent statement does not cover the verified original',
                         expected_sha256=source.get('sha256'), actual_sha256=original_sha256)
        if source.get('name') != os.path.basename(original_path or ''):
            _add_failure(failures, 'DERIVATION_SOURCE_NAME_MISMATCH', 'handoff.derivation.source.name',
                         derivation.get('path'), 'the independent statement names another source',
                         expected=source.get('name'), actual=os.path.basename(original_path or ''))

        target = derivation_record.get('derivative', {})
        if target.get('name') != derivative_name:
            _add_failure(failures, 'DERIVATION_DERIVATIVE_NAME_MISMATCH', 'handoff.derivation.derivative.name',
                         derivation.get('path'), 'the independent statement names another derivative',
                         expected=target.get('name'), actual=derivative_name)
        if target.get('sha256') != derivative_sha256:
            _add_failure(failures, 'DERIVATION_DERIVATIVE_DIGEST_MISMATCH',
                         'handoff.derivation.derivative.sha256', derivation.get('path'),
                         'the independent derivation statement does not cover the supplied attachment',
                         expected_sha256=target.get('sha256'), actual_sha256=derivative_sha256)
    except Exception as exc:
        _add_failure(failures, 'DERIVATION_EVIDENCE_UNREADABLE', 'handoff.derivation',
                     derivation.get('path'), 'derivation evidence could not be loaded', error=str(exc))

    result['derivation_evidence_valid'] = len(failures) == derivation_failures_before

    approval = receipt.get('release_approval', {})
    approval_failures_before = len(failures)
    try:
        approval_file = _safe_path(root, approval.get('path'), 'release approval path')
        approval_bytes = _read_bytes(approval_file)
        approval_sha256 = sha256_bytes(approval_bytes)
        if approval_sha256 != approval.get('sha256'):
            _add_failure(failures, 'RELEASE_APPROVAL_DIGEST_MISMATCH', 'handoff.release_approval.sha256',
                         approval.get('path'), 'the release approval does not match the receipt digest',
                         expected_sha256=approval.get('sha256'), actual_sha256=approval_sha256)

        approval_key = _load_key(_safe_path(root, approval.get('signer_key'), 'release approver key'))
        approval_signature = _load_signature(_safe_path(root, approval.get('signature'), 'release approval signature'))
        if not _signature_verifies(approval_key, approval_bytes, approval_signature):
            _add_failure(failures, 'RELEASE_APPROVAL_SIGNATURE_INVALID', 'handoff.release_approval.signature',
                         approval.get('signature'), 'the release approval is not signed by its declared approver')

        approval_record = json.loads(approval_bytes.decode('utf-8'))
        if approval_record.get('schema') != RELEASE_APPROVAL_SCHEMA:
            _add_failure(failures, 'RELEASE_APPROVAL_SCHEMA_MISMATCH', 'handoff.release_approval.schema',
                         approval.get('path'), 'unexpected release approval schema',
                         expected=RELEASE_APPROVAL_SCHEMA, actual=approval_record.get('schema'))
        if approval_record.get('handoff_id') != result['handoff_id']:
            _add_failure(failures, 'RELEASE_APPROVAL_HANDOFF_MISMATCH', 'handoff.release_approval.handoff_id',
                         approval.get('path'), 'the release approval belongs to another handoff',
                         expected=result['handoff_id'], actual=approval_record.get('handoff_id'))
        if approval_record.get('decision') != 'approved':
            _add_failure(failures, 'RELEASE_NOT_APPROVED', 'handoff.release_approval.decision',
                         approval.get('path'), 'the release was not approved',
                         actual=approval_record.get('decision'))
        if approval_record.get('approved_derivation_sha256') != derivation_sha256:
            _add_failure(failures, 'RELEASE_APPROVAL_DERIVATION_DIGEST_MISMATCH',
                         'handoff.release_approval.approved_derivation_sha256', approval.get('path'),
                         'the approval does not cover the independently signed derivation statement',
                         expected_sha256=approval_record.get('approved_derivation_sha256'),
                         actual_sha256=derivation_sha256)
    except Exception as exc:
        _add_failure(failures, 'RELEASE_APPROVAL_UNREADABLE', 'handoff.release_approval',
                     approval.get('path'), 'release approval evidence could not be loaded', error=str(exc))

    result['release_approval_valid'] = len(failures) == approval_failures_before

    if original_data is not None and derivative_data is not None:
        original_marker = _delivery_marker(original_data)
        derivative_marker = _delivery_marker(derivative_data)
        result['delivery_marker'] = {'value': derivative_marker,
                                     'inherited_from_original': bool(derivative_marker and
                                                                     derivative_marker == original_marker),
                                     'used_as_signature_evidence': False}

    evidence_ok = (result['original_signature_valid'] and
                   result['derivation_evidence_valid'] and
                   result['release_approval_valid'])
    result['derivative_deliverable'] = bool(result['receipt_signature_valid'] and evidence_ok and not failures)
    if result['derivative_deliverable']:
        result['delivery_basis'] = ['original-detached-signature',
                                    'independent-derivation',
                                    'release-approval',
                                    'signed-outbound-receipt']
    result['missing_evidence'] = sorted({failure['claim'] for failure in failures if failure.get('claim')})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify an offline PGPy handoff receipt')
    parser.add_argument('archive', help='directory containing the receipt and evidence')
    parser.add_argument('--derivative', help='same-name attachment to verify instead of the archived one')
    parser.add_argument('--receipt', default='outbound-receipt.json', help='receipt path relative to archive')
    parser.add_argument('--signature', help='receipt signature path relative to archive')
    parser.add_argument('--allow-unsigned-receipt', action='store_true',
                        help='do not require a receipt signature')
    args = parser.parse_args(argv)

    result = verify_outbound_receipt(args.archive,
                                     derivative_path=args.derivative,
                                     receipt_path=args.receipt,
                                     receipt_signature_path=args.signature,
                                     require_receipt_signature=not args.allow_unsigned_receipt)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write('\n')
    return 0 if result['derivative_deliverable'] else 1


if __name__ == '__main__':
    sys.exit(main())
