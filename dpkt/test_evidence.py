# -*- coding: utf-8 -*-
"""Tests for the offline evidence projection."""
from __future__ import absolute_import
from __future__ import print_function

import copy
import gzip
import hashlib
import json
import os

import pytest

from . import evidence


_FIXTURE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'examples', 'data', 'evidence_projection.pcap.gz',
)
_SALT = b'\x00' * 16


def _record(projection, index):
    return next(record for record in projection['records'] if record['index'] == index)


def _field(projection, index, name):
    return next(field for field in _record(projection, index)['fields']
                if field['name'] == name)


def _projection():
    return evidence.project(_FIXTURE, salt=_SALT)


def test_projection_covers_vlan_ihl_and_truncation():
    projection = _projection()
    assert evidence.verify(projection).ok

    vlan_frame = _record(projection, 0)
    assert vlan_frame['encapsulation'] == {
        'link_layer': 'ethernet', 'vlan_tags': 1, 'ip_offset': 18,
    }
    assert _field(projection, 0, 'eth.dst')['source']['offset'] == 0
    vlan_id = _field(projection, 0, 'vlan.id')
    assert vlan_id['source']['offset'] == 14
    assert vlan_id['source']['bit_offset'] == 4
    assert vlan_id['source']['bit_length'] == 12
    assert vlan_id['representation']['value'] == 100
    assert _field(projection, 0, 'ip.hl')['representation']['value'] == 5
    assert _field(projection, 0, 'ip.ttl')['source']['offset'] == 26
    assert _field(projection, 0, 'ip.ttl')['source']['file_offset'] == (
        vlan_frame['packet_offset'] + 26
    )

    options_frame = _record(projection, 1)
    assert _field(projection, 1, 'ip.hl')['representation']['value'] == 6
    opts = _field(projection, 1, 'ip.opts')
    assert opts['source']['offset'] == 38
    assert opts['source']['length'] == 4
    assert opts['representation'] == {
        'kind': 'verbatim', 'encoding': 'hex', 'value': '01010100',
    }
    assert _field(projection, 1, 'ip.src')['source']['offset'] == 30
    assert _field(projection, 1, 'ip.src')['source']['file_offset'] == (
        options_frame['packet_offset'] + 30
    )

    truncated = _record(projection, 2)
    assert truncated['truncated']
    assert truncated['captured_length'] == 28
    assert _field(projection, 2, 'ip.ttl')['status'] == 'located'
    assert _field(projection, 2, 'ip.p')['status'] == 'located'
    assert _field(projection, 2, 'ip.src')['status'] == 'unlocated'
    assert _field(projection, 2, 'ip.src')['reason'] == 'truncated'

    untagged = _record(projection, 4)
    assert untagged['encapsulation']['ip_offset'] == 14
    assert _field(projection, 4, 'vlan.id')['status'] == 'unlocated'
    assert _field(projection, 4, 'ip.ttl')['source']['offset'] == 22


def test_addresses_are_redacted_and_other_values_are_verbatim():
    projection = _projection()
    text = evidence.dumps_projection(projection)
    assert '10.1.2.3' not in text
    assert '0a010203' not in text
    assert '02:00:00:00:00:01' not in text
    assert '020000000001' not in text

    for name in ('eth.dst', 'eth.src', 'ip.src', 'ip.dst'):
        representation = _field(projection, 0, name)['representation']
        assert representation['kind'] == 'redacted'
        assert representation['value'].startswith('hmac-sha256:')

    ttl = _field(projection, 0, 'ip.ttl')['representation']
    assert ttl == {'kind': 'verbatim', 'encoding': 'uint', 'value': 64}


def test_unknown_encapsulation_has_only_unlocated_ip_fields():
    projection = _projection()
    record = _record(projection, 3)
    assert record['encapsulation']['ip_offset'] is None
    for field in record['fields']:
        if field['name'].startswith('ip.'):
            assert field['status'] == 'unlocated'
            assert field['reason'] == 'unknown_encapsulation'
            assert field['source'] is None
            assert field['representation'] is None


def test_verify_rejects_changed_value_or_source_position():
    projection = _projection()
    assert evidence.verify(projection).ok

    changed_value = copy.deepcopy(projection)
    _field(changed_value, 0, 'ip.ttl')['representation']['value'] = 1
    result = evidence.verify(changed_value)
    assert not result
    assert any(error['code'] == 'field_commitment_mismatch'
               for error in result.errors)

    changed_offset = copy.deepcopy(projection)
    _field(changed_offset, 0, 'ip.ttl')['source']['offset'] += 1
    result = evidence.verify(changed_offset)
    assert not result
    assert any(error['code'] == 'field_commitment_mismatch'
               for error in result.errors)

    changed_file_offset = copy.deepcopy(projection)
    _field(changed_file_offset, 0, 'ip.ttl')['source']['file_offset'] += 1
    result = evidence.verify(changed_file_offset)
    assert not result
    assert any(error['code'] == 'field_commitment_mismatch'
               for error in result.errors)

    changed_record_offset = copy.deepcopy(projection)
    _record(changed_record_offset, 0)['packet_offset'] += 1
    result = evidence.verify(changed_record_offset)
    assert not result
    assert any(error['code'] == 'manifest_commitment_mismatch'
               for error in result.errors)


def test_verify_against_source_and_reject_changed_source(tmp_path):
    projection = _projection()
    result = evidence.verify(projection, source=_FIXTURE)
    assert result.ok
    assert result.checked['source_digest_match'] is True

    with gzip.open(_FIXTURE, 'rb') as stream:
        raw = bytearray(stream.read())
    # Record 0 starts at file offset 24, its frame at 40; offset 66 is ip.ttl.
    assert raw[66] == 64
    raw[66] = 63
    changed = tmp_path / 'changed.pcap.gz'
    with open(str(changed), 'wb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
            compressed.write(bytes(raw))

    result = evidence.verify(projection, source=str(changed))
    assert not result
    assert any(error['code'] == 'source_digest_mismatch' for error in result.errors)


def test_field_policy_and_record_selection_are_enforced():
    projection = evidence.project(
        _FIXTURE, fields='ip.ttl,ip.src', records='2',
    )
    assert projection['policy']['fields'] == ['ip.ttl', 'ip.src']
    assert projection['policy']['records'] == [2]
    assert len(projection['records']) == 1
    assert [field['name'] for field in projection['records'][0]['fields']] == [
        'ip.ttl', 'ip.src',
    ]
    assert evidence.verify(projection).ok

    with pytest.raises(evidence.EvidenceError):
        evidence.project(_FIXTURE, fields='ip.payload')
    with pytest.raises(evidence.EvidenceError):
        evidence.project(_FIXTURE, records=[99])


def test_projection_is_read_only():
    with open(_FIXTURE, 'rb') as stream:
        before = hashlib.sha256(stream.read()).hexdigest()
    projection = _projection()
    assert evidence.verify(projection, source=_FIXTURE).ok
    with open(_FIXTURE, 'rb') as stream:
        after = hashlib.sha256(stream.read()).hexdigest()
    assert before == after


def test_verification_result_json_round_trip():
    projection = json.loads(evidence.dumps_projection(_projection()))
    result = evidence.verify(projection)
    assert result.ok
    assert json.loads(evidence.dumps_projection(result))['ok'] is True

    projection['records'][0]['fields'][0]['representation']['value'] = 'changed'
    failed = evidence.verify(projection)
    encoded = json.loads(evidence.dumps_projection(failed))
    assert encoded['ok'] is False
    assert encoded['errors']
