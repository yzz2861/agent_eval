"""Tests for the read-only evidence binding inspection.

The fixtures build tiny in-repo bundles from the existing registry samples,
so the tests need no network access and never mutate the source hives.
"""

import hashlib
import io
import json
import os
import shutil

import pytest

from Registry import Registry, RegistryParse

from evidence_binding.excerpts import load_excerpt
from evidence_binding.inspector import inspect_bundle
from evidence_binding.models import ArtifactKind, ProvenanceGrade, Reachability
from evidence_binding.reporting import write_binding_output

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLES = os.path.join(REPO_ROOT, 'tests', 'reg_samples')


def _value_fingerprint(value):
    digest = hashlib.sha256()
    digest.update(b'vk' + chr(10).encode())
    digest.update(value.name().encode('utf-16le', errors='replace'))
    digest.update(chr(10).encode())
    digest.update(str(value.value_type()).encode('ascii'))
    digest.update(chr(10).encode())
    digest.update(value.raw_data())
    return digest.hexdigest()


def _excerpt_record(hive_path):
    with open(hive_path, 'rb') as handle:
        raw = handle.read()
    registry = Registry.Registry(io.BytesIO(raw))
    key = registry.open('ASCII_KEY_NAME0')
    value = key.value('ASCII_VALUE_NAME0')
    regf = RegistryParse.REGFBlock(raw, 0, False)
    record = {
        'record_kind': 'value',
        'registry_path': key.path(),
        'value_name': value.name(),
        'value_type': value.value_type_str(),
        'timestamp': str(key.timestamp()),
        'content_fingerprint': _value_fingerprint(value),
        'data_hex': value.raw_data().hex(),
        'provenance': {
            'source_sha256': hashlib.sha256(raw).hexdigest(),
            'source_sequence1': regf.hive_sequence1(),
            'source_sequence2': regf.hive_sequence2(),
            'record_absolute_offset_hex': '0x%x' % value._vkrecord.offset(),
            'record_relative_offset_hex': '0x%x' % (value._vkrecord.offset() - 0x1000),
            'record_kind': 'value',
        },
    }
    return record


@pytest.fixture
def bundle(tmp_path):
    live = tmp_path / 'live'
    live.mkdir()
    unicode_src = os.path.join(SAMPLES, 'UNICODE_TESTS')
    reorg_src = os.path.join(SAMPLES, 'REORGANIZED_VALUES_TESTS')
    shutil.copy(unicode_src, live / 'UNICODE_TESTS')
    shutil.copy(reorg_src, live / 'REORGANIZED_VALUES_TESTS')

    excerpts = tmp_path / 'excerpts'
    excerpts.mkdir()
    record = _excerpt_record(unicode_src)
    full = {'manifest_type': 'registry-excerpt/v1', 'records': [record]}
    (excerpts / 'full.json').write_text(json.dumps(full), encoding='utf-8')

    content_only = dict(record)
    content_only['provenance'] = {}
    (excerpts / 'only_a.json').write_text(
        json.dumps({'manifest_type': 'registry-excerpt/v1', 'records': [dict(content_only)]}),
        encoding='utf-8',
    )
    (excerpts / 'only_b.json').write_text(
        json.dumps({'manifest_type': 'registry-excerpt/v1', 'records': [dict(content_only)]}),
        encoding='utf-8',
    )
    return tmp_path


def _excerpt_exhibits(result):
    return [
        exhibit
        for exhibit in result['exhibits']
        if any(o.artifact_kind == ArtifactKind.EXCERPT for o in exhibit.occurrences)
    ]


def test_full_provenance_binds_to_source_cell(bundle):
    result = inspect_bundle(str(bundle))
    bound = [
        exhibit for exhibit in _excerpt_exhibits(result)
        if exhibit.decision.bound
    ]
    assert len(bound) == 1
    kinds = {o.artifact_kind for o in bound[0].occurrences}
    assert kinds == {ArtifactKind.PRIMARY, ArtifactKind.EXCERPT}
    excerpt = next(o for o in bound[0].occurrences if o.artifact_kind == ArtifactKind.EXCERPT)
    assert excerpt.provenance_grade == ProvenanceGrade.FULL


def test_content_only_excerpts_remain_separate(bundle):
    result = inspect_bundle(str(bundle))
    standalone = [
        exhibit for exhibit in _excerpt_exhibits(result)
        if not exhibit.decision.bound
    ]
    assert len(standalone) == 2
    fingerprints = {
        exhibit.occurrences[0].content_fingerprint for exhibit in standalone
    }
    assert len(fingerprints) == 1
    for exhibit in standalone:
        assert exhibit.occurrences[0].reachability == Reachability.EXCERPT_ONLY


def test_equal_content_in_distinct_hives_stays_unbound(bundle):
    result = inspect_bundle(str(bundle))
    primary = [
        o for o in result['occurrences']
        if o.artifact_kind == ArtifactKind.PRIMARY and o.value_name == 'ASCII_VALUE_NAME0'
    ]
    assert len(primary) == 2
    assert len({o.artifact_sha256 for o in primary}) == 2
    assert len({o.content_fingerprint for o in primary}) == 1
    exhibit_ids = {
        next(
            exhibit.exhibit_id
            for exhibit in result['exhibits']
            if o in exhibit.occurrences
        )
        for o in primary
    }
    assert len(exhibit_ids) == 2


def test_primary_occurrences_carry_layered_citations(bundle):
    result = inspect_bundle(str(bundle))
    primary = next(
        o for o in result['occurrences']
        if o.artifact_kind == ArtifactKind.PRIMARY and o.record_kind == 'value'
    )
    layers = [citation.layer for citation in primary.citations]
    assert layers[:3] == ['REGF header', 'HBIN block', 'HBIN cell']
    assert 'VK record' in layers


def test_reporting_writes_two_level_tree(bundle, tmp_path):
    result = inspect_bundle(str(bundle))
    output = tmp_path / 'binding'
    write_binding_output(result, str(output))
    assert (output / 'index.json').is_file()
    assert (output / 'index.txt').is_file()
    exhibit_dirs = list((output / 'exhibits').iterdir())
    assert exhibit_dirs
    for directory in exhibit_dirs:
        assert (directory / 'locations.json').is_file()
        assert (directory / 'locations.txt').is_file()


def test_source_files_are_not_modified(bundle):
    before = {
        entry: (entry.stat().st_mtime_ns, hashlib.sha256(entry.read_bytes()).hexdigest())
        for entry in bundle.rglob('*')
        if entry.is_file()
    }
    inspect_bundle(str(bundle))
    after = {
        entry: (entry.stat().st_mtime_ns, hashlib.sha256(entry.read_bytes()).hexdigest())
        for entry in bundle.rglob('*')
        if entry.is_file()
    }
    assert before == after


def test_excerpt_with_unknown_source_is_standalone(bundle):
    record = _excerpt_record(os.path.join(SAMPLES, 'UNICODE_TESTS'))
    record['provenance']['source_sha256'] = 'f' * 64
    manifest = bundle / 'excerpts' / 'unknown_source.json'
    manifest.write_text(
        json.dumps({'manifest_type': 'registry-excerpt/v1', 'records': [record]}),
        encoding='utf-8',
    )
    result = inspect_bundle(str(bundle))
    target = next(
        exhibit for exhibit in result['exhibits']
        if any('unknown_source' in o.artifact_path for o in exhibit.occurrences)
    )
    assert target.decision.bound is False
    assert target.occurrences[0].binding_blockers


def test_transaction_logs_recover_in_memory_only():
    from evidence_binding.hives import recover_with_logs

    sample_dir = os.path.join(
        REPO_ROOT, 'testing', 'reg_samples', 'new_log_1'
    )
    primary_path = os.path.join(sample_dir, 'SYSTEM')
    with open(primary_path, 'rb') as handle:
        primary_bytes = handle.read()
    before = hashlib.sha256(primary_bytes).hexdigest()

    recovered, reports = recover_with_logs(
        primary_bytes,
        [
            os.path.join(sample_dir, 'SYSTEM.LOG1'),
            os.path.join(sample_dir, 'SYSTEM.LOG2'),
        ],
    )

    assert hashlib.sha256(primary_bytes).hexdigest() == before
    assert recovered != primary_bytes
    applied = [report for report in reports if report.get('applied')]
    assert len(applied) == 2
    assert [report['applied_sequence'] for report in applied] == [185, 216]
    for report in reports:
        assert report['eligible'] is True
        assert report['entries']
        assert report['entries'][0]['dirty_pages']
