import json
import shutil
from pathlib import Path

from pgpy import PGPKey
from pgpy.handoff import verify_outbound_receipt
from pgpy.handoff import sign_bytes
from pgpy.handoff import write_detached_signature


EXAMPLE = Path('examples') / 'offline_outbound_receipt'
ARCHIVE = EXAMPLE / 'archive'
NEGATIVE = EXAMPLE / 'negative' / 'notice-external.txt'


def test_valid_handoff_keeps_three_facts_separate():
    result = verify_outbound_receipt(str(ARCHIVE))

    assert result['receipt_signature_valid'] is True
    assert result['original_signature_valid'] is True
    assert result['derivation_evidence_valid'] is True
    assert result['release_approval_valid'] is True
    assert result['derivative_deliverable'] is True
    assert result['simplified_has_own_signature'] is False
    assert result['delivery_marker'] == {'value': 'signature-valid',
                                         'inherited_from_original': True,
                                         'used_as_signature_evidence': False}
    assert result['missing_evidence'] == []
    assert result['failures'] == []


def test_same_name_attachment_mismatch_locates_derivation_claim():
    result = verify_outbound_receipt(str(ARCHIVE), derivative_path=str(NEGATIVE))

    assert NEGATIVE.name == 'notice-external.txt'
    assert result['original_signature_valid'] is True
    assert result['derivative_deliverable'] is False
    assert result['simplified_has_own_signature'] is False
    assert len(result['failures']) == 1
    failure = result['failures'][0]
    assert failure['code'] == 'DERIVATION_DERIVATIVE_DIGEST_MISMATCH'
    assert failure['claim'] == 'handoff.derivation.derivative.sha256'
    assert failure['evidence'] == 'derivation.json'
    assert result['missing_evidence'] == ['handoff.derivation.derivative.sha256']


def test_receipt_signature_covers_receipt_bytes(tmp_path):
    archive = tmp_path / 'archive'
    shutil.copytree(str(ARCHIVE), str(archive))
    receipt = archive / 'outbound-receipt.json'
    receipt.write_bytes(receipt.read_bytes() + b' ')

    result = verify_outbound_receipt(str(archive))

    assert result['receipt_signature_valid'] is False
    assert result['derivative_deliverable'] is False
    assert any(failure['code'] == 'RECEIPT_SIGNATURE_INVALID'
               for failure in result['failures'])


def test_derivative_can_have_its_own_detached_signature(tmp_path):
    archive = tmp_path / 'archive'
    shutil.copytree(str(ARCHIVE), str(archive))
    derivative = archive / 'notice-external.txt'
    key = PGPKey.from_file('tests/testdata/keys/rsa.1.sec.asc')[0]
    signature = sign_bytes(key, derivative.read_bytes())
    write_detached_signature(signature, archive / 'notice-external.txt.asc')

    result = verify_outbound_receipt(str(archive))

    assert result['simplified_has_own_signature'] is True
    assert result['simplified_signature_evidence'] == 'valid'
    assert result['derivative_deliverable'] is True


def test_expected_reports_are_reproducible():
    valid = json.loads((EXAMPLE / 'expected' / 'valid.json').read_text(encoding='utf-8'))
    mismatch = json.loads((EXAMPLE / 'expected' / 'mismatch.json').read_text(encoding='utf-8'))

    assert verify_outbound_receipt(str(ARCHIVE)) == valid
    assert verify_outbound_receipt(str(ARCHIVE), derivative_path=str(NEGATIVE)) == mismatch
