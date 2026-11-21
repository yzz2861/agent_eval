import json
import os
from pathlib import Path

import pytest

from detect_secrets.__version__ import VERSION
from detect_secrets.audit import vendor
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.main import main


MANIFEST = 'test_data/vendor_audit/vendors.json'
ALPHA = 'test_data/vendor_audit/shared/alpha/alpha_service.py'
BETA = 'test_data/vendor_audit/shared/beta/beta_service.py'
JOINT = 'test_data/vendor_audit/shared/joint/shared_module.py'
ORPHAN = 'test_data/vendor_audit/unassigned/orphan.py'

ALPHA_VALUE = 'fixture-alpha-value'
BETA_VALUE = 'fixture-beta-value'
JOINT_VALUE = 'fixture-joint-value'
ORPHAN_VALUE = 'fixture-orphan-value'


def _secret(filename, value, is_secret=None, line_number=2):
    return PotentialSecret(
        type='Basic Auth',
        filename=filename,
        secret=value,
        line_number=line_number,
        is_secret=is_secret,
    )


@pytest.fixture
def baseline_file(tmp_path):
    path = tmp_path / 'baseline.json'
    data = {
        'version': VERSION,
        'plugins_used': [{'name': 'BasicAuthDetector'}],
        'filters_used': [],
        'results': {},
    }
    secrets = [
        _secret(ALPHA, ALPHA_VALUE, is_secret=True),
        _secret(BETA, BETA_VALUE),
        _secret(JOINT, JOINT_VALUE),
        _secret(ORPHAN, ORPHAN_VALUE),
    ]
    for secret in secrets:
        data['results'].setdefault(secret.filename, []).append(secret.json())
    path.write_text(json.dumps(data))
    return str(path)


def _export(baseline_file, tmp_path):
    output = tmp_path / 'exports'
    summary = vendor.export_vendor_packages(
        baseline_file=baseline_file,
        manifest_file=MANIFEST,
        output_dir=str(output),
        exported_at='2026-11-21T00:00:00Z',
    )
    return output, summary


def _load(path):
    return json.loads(Path(path).read_text())


def _write(path, data):
    Path(path).write_text(json.dumps(data))


def _response(path, statuses, signed_off, revision=None):
    data = _load(path)
    if revision is not None:
        data['revision'] = revision
    for finding in data['findings']:
        if finding['path'] in statuses:
            finding['status'] = statuses[finding['path']]
            finding['signed_off'] = signed_off
    _write(path, data)
    return data


def _finding(response, path):
    return [item for item in response['findings'] if item['path'] == path][0]


def _finding_in_state(state, path):
    return [item for item in state['findings'].values() if item['path'] == path][0]


def test_export_scopes_paths_and_redacts_secrets(baseline_file, tmp_path):
    output, summary = _export(baseline_file, tmp_path)
    package_a = _load(output / 'vendor-a.json')
    package_b = _load(output / 'vendor-b.json')

    assert {item['path'] for item in package_a['findings']} == {ALPHA, JOINT}
    assert {item['path'] for item in package_b['findings']} == {BETA, JOINT}
    assert package_a['summary'] == {
        'total': 2,
        'true_positive': 1,
        'false_positive': 0,
        'unreviewed': 1,
    }
    assert package_b['summary']['total'] == 2

    a_text = json.dumps(package_a)
    b_text = json.dumps(package_b)
    assert BETA not in a_text
    assert ALPHA not in b_text
    assert ORPHAN not in a_text and ORPHAN not in b_text
    assert ALPHA_VALUE not in a_text and BETA_VALUE not in b_text
    assert JOINT_VALUE not in a_text
    assert chr(34) + 'lines' + chr(34) not in a_text
    assert chr(34) + 'secrets' + chr(34) not in a_text
    assert all('beta' not in path for path in package_a['scope']['paths'])

    assert _finding(package_a, JOINT)['finding_id'] == _finding(package_b, JOINT)['finding_id']
    assert summary['vendors']['vendor-a']['findings'] == 2


def test_merge_keeps_opposite_conclusions_and_signed_version(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    state_path = str(output / 'master-state.json')
    a_path = str(output / 'vendor-a.json')
    b_path = str(output / 'vendor-b.json')

    _response(a_path, {JOINT: 'true_positive', ALPHA: 'true_positive'}, True)
    _response(b_path, {JOINT: 'false_positive', BETA: 'false_positive'}, True)

    result = vendor.merge_vendor_responses(
        state_file=state_path,
        response_files=[a_path, b_path],
        baseline_file=baseline_file,
        merged_at='2026-11-21T01:00:00Z',
    )

    assert len(result['conflicts']) == 1
    conflict = result['conflicts'][0]
    assert conflict['path'] == JOINT
    assert conflict['statuses'] == {
        'vendor-a': 'true_positive',
        'vendor-b': 'false_positive',
    }
    assert conflict['accepted']['status'] == 'true_positive'
    assert conflict['accepted']['source'] == 'vendor-a'
    assert conflict['accepted']['signed_off'] is True

    state = _load(state_path)
    joint = _finding_in_state(state, JOINT)
    assert joint['accepted']['status'] == 'true_positive'
    assert joint['accepted']['signed_off'] is True
    assert joint['conflict']['statuses']['vendor-b'] == 'false_positive'

    report = vendor.report_conflicts(state_path)
    text = vendor.format_conflict_report(report)
    assert JOINT in text
    assert 'vendor-a: true_positive' in text
    assert 'vendor-b: false_positive' in text

    _response(a_path, {JOINT: 'false_positive'}, False)
    late = vendor.merge_vendor_responses(
        state_file=state_path,
        response_files=[a_path],
        merged_at='2026-11-21T02:00:00Z',
    )
    state = _load(state_path)
    joint = _finding_in_state(state, JOINT)
    assert joint['accepted']['status'] == 'true_positive'
    assert joint['accepted']['signed_off'] is True
    assert joint['reviews']['vendor-a']['status'] == 'true_positive'
    assert joint['late_feedback'][-1]['vendor'] == 'vendor-a'
    assert late['merged'][0]['ignored_as_stale'] == 2
    late_text = vendor.format_conflict_report(vendor.report_conflicts(state_path))
    assert 'late feedback' in late_text


def test_merge_rejects_findings_outside_vendor_scope(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    state_path = str(output / 'master-state.json')
    a_path = str(output / 'vendor-a.json')
    b_path = str(output / 'vendor-b.json')

    package_a = _load(a_path)
    package_b = _load(b_path)
    beta_id = _finding(package_b, BETA)['finding_id']
    package_a['findings'].append({'finding_id': beta_id, 'status': 'true_positive'})
    _write(a_path, package_a)

    before = Path(state_path).read_bytes()
    with pytest.raises(vendor.VendorDistributionError):
        vendor.merge_vendor_responses(state_path, [a_path])
    assert Path(state_path).read_bytes() == before


def test_export_again_preserves_state_and_increments_revision(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    state_path = str(output / 'master-state.json')
    a_path = str(output / 'vendor-a.json')
    _response(a_path, {JOINT: 'false_positive'}, True)
    vendor.merge_vendor_responses(state_path, [a_path])

    _, summary = _export(baseline_file, tmp_path)
    assert summary['vendors']['vendor-a']['revision'] == 2
    package_a = _load(output / 'vendor-a.json')
    assert _finding(package_a, JOINT)['status'] == 'false_positive'
    assert _finding(package_a, JOINT)['review_state'] == 'signed_off'


def test_conflict_cli_and_sign_off(baseline_file, tmp_path, printer):
    output, _ = _export(baseline_file, tmp_path)
    state_path = str(output / 'master-state.json')
    main(['audit', '--report-conflicts', '--vendor-state', state_path])
    assert 'No vendor review conflicts.' in printer.message

    result = vendor.sign_off_accepted(state_path, signed_at='2026-11-21T03:00:00Z')
    assert result['signed_off'] == 1
    assert result['skipped_unreviewed'] == 3


def test_cli_export_writes_only_scoped_packages(baseline_file, tmp_path, printer):
    output = tmp_path / 'cli-exports'
    result = main([
        'audit',
        baseline_file,
        '--vendor-manifest',
        MANIFEST,
        '--export-vendors',
        str(output),
    ])

    assert result == 0
    summary = json.loads(printer.message)
    assert set(summary['vendors']) == {'vendor-a', 'vendor-b'}
    assert (output / 'master-state.json').exists()
    package_b = _load(output / 'vendor-b.json')
    assert {item['path'] for item in package_b['findings']} == {BETA, JOINT}


@pytest.mark.parametrize(
    'data, expected',
    [
        ({'vendors': {'a': ['src/a/']}}, {'a': ['src/a']}),
        ({'suppliers': [{'id': 'b', 'paths': ['src/b/']}]}, {'b': ['src/b']}),
        ({'groups': {'c': {'paths': ['src/c']}}}, {'c': ['src/c']}),
        ({'d': 'src/d'}, {'d': ['src/d']}),
    ],
)
def test_manifest_shapes(data, expected):
    assert vendor.normalize_vendor_manifest(data) == expected


@pytest.mark.parametrize(
    'data',
    [
        [],
        {},
        {'vendors': 3},
        {'vendors': [1]},
        {'vendors': [{}]},
        {'vendors': [{'id': 'a', 'paths': []}]},
        {'vendors': [{'id': 'a', 'paths': [1]}]},
        {'vendors': [{'id': 'a', 'paths': ['x']}, {'id': 'a', 'paths': ['y']}]},
        {'vendors': {'a/b': ['x']}},
    ],
)
def test_manifest_errors(data):
    with pytest.raises(vendor.VendorDistributionError):
        vendor.normalize_vendor_manifest(data)


def test_manifest_file_error(tmp_path):
    bad = tmp_path / 'bad.json'
    bad.write_text('{')
    with pytest.raises(vendor.VendorDistributionError):
        vendor.load_vendor_manifest(str(bad))


def test_path_matching_and_status_aliases():
    assert vendor.path_is_owned('src/a/x.py', ['src/a'])
    assert not vendor.path_is_owned('src/ab/x.py', ['src/a'])
    assert vendor.path_is_owned('src/a/x.py', ['.'])
    assert vendor.path_is_owned('src/a/x.py', ['src/**/x.py'])
    absolute = os.path.abspath('src/a/x.py').replace(chr(92), '/')
    assert vendor.path_is_owned(absolute, [absolute])

    false_secret = _secret(BETA, BETA_VALUE, is_secret=False)
    assert vendor.status_from_secret(false_secret) == 'false_positive'
    assert vendor.normalize_status(True) == 'true_positive'
    assert vendor.normalize_status('NO') == 'false_positive'
    assert vendor.normalize_status('pending') == 'unreviewed'
    assert vendor.normalize_status('true-positive') == 'true_positive'
    with pytest.raises(vendor.VendorDistributionError):
        vendor.normalize_status('maybe')


def test_state_loading_errors(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    state_path = output / 'master-state.json'
    a_path = output / 'vendor-a.json'

    with pytest.raises(vendor.VendorDistributionError):
        vendor.load_state(str(a_path))

    bad = tmp_path / 'state.json'
    bad.write_text('{}')
    with pytest.raises(vendor.VendorDistributionError):
        vendor.load_state(str(bad))

    state = _load(state_path)
    state['format_version'] = 99
    _write(bad, state)
    with pytest.raises(vendor.VendorDistributionError):
        vendor.load_state(str(bad))

    state = _load(state_path)
    del state['findings']
    _write(bad, state)
    with pytest.raises(vendor.VendorDistributionError):
        vendor.load_state(str(bad))


def test_response_errors_do_not_change_state(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    state_path = str(output / 'master-state.json')
    a_path = str(output / 'vendor-a.json')
    original = _load(a_path)
    before = Path(state_path).read_bytes()

    with pytest.raises(vendor.VendorDistributionError):
        vendor.merge_vendor_responses(state_path, [])

    Path(a_path).write_text('{')
    with pytest.raises(vendor.VendorDistributionError):
        vendor.merge_vendor_responses(state_path, [a_path])

    mutations = [
        lambda item: item.update(format='wrong'),
        lambda item: item.update(format_version=99),
        lambda item: item.pop('vendor'),
        lambda item: item.pop('findings'),
        lambda item: item.update(vendor='ghost'),
        lambda item: item.update(baseline_fingerprint='wrong'),
        lambda item: item.update(revision='bad'),
        lambda item: item.update(findings=[1]),
        lambda item: item.update(findings=[{'status': 'true_positive'}]),
        lambda item: item['findings'][0].update(status='maybe'),
    ]
    for mutate in mutations:
        response = json.loads(json.dumps(original))
        mutate(response)
        _write(a_path, response)
        with pytest.raises(vendor.VendorDistributionError):
            vendor.merge_vendor_responses(state_path, [a_path])
        assert Path(state_path).read_bytes() == before

    _write(a_path, original)
    other = tmp_path / 'other-baseline.json'
    other.write_text('{}')
    with pytest.raises(vendor.VendorDistributionError):
        vendor.merge_vendor_responses(state_path, [a_path], baseline_file=str(other))


def test_merge_accepts_response_directory(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    result = vendor.merge_vendor_responses(
        state_file=str(output / 'master-state.json'),
        response_files=[str(output)],
    )
    assert {item['vendor'] for item in result['merged']} == {'vendor-a', 'vendor-b'}


def test_export_rejects_changed_manifest_or_baseline(baseline_file, tmp_path):
    first = tmp_path / 'first'
    vendor.export_vendor_packages(baseline_file, MANIFEST, str(first))

    manifest = _load(MANIFEST)
    manifest['vendors'][0]['paths'].append('test_data/vendor_audit/unassigned/')
    changed_manifest = tmp_path / 'vendors.json'
    _write(changed_manifest, manifest)
    with pytest.raises(vendor.VendorDistributionError):
        vendor.export_vendor_packages(baseline_file, str(changed_manifest), str(first))

    second = tmp_path / 'second'
    vendor.export_vendor_packages(baseline_file, MANIFEST, str(second))
    original = Path(baseline_file).read_text()
    Path(baseline_file).write_text(original + chr(10))
    try:
        with pytest.raises(vendor.VendorDistributionError):
            vendor.export_vendor_packages(baseline_file, MANIFEST, str(second))
    finally:
        Path(baseline_file).write_text(original)


def test_vendor_filename_is_safe(baseline_file, tmp_path):
    manifest = tmp_path / 'vendors.json'
    _write(
        manifest,
        {
            'vendors': [
                {
                    'id': 'vendor a',
                    'paths': ['test_data/vendor_audit/shared/alpha/'],
                },
            ],
        },
    )
    output = tmp_path / 'safe'
    summary = vendor.export_vendor_packages(baseline_file, str(manifest), str(output))
    package_path = Path(summary['vendors']['vendor a']['file'])
    assert package_path.name.startswith('vendor_a-')
    assert package_path.exists()


def test_new_revision_cannot_replace_signed_acceptance(baseline_file, tmp_path):
    output, _ = _export(baseline_file, tmp_path)
    state_path = str(output / 'master-state.json')
    a_path = str(output / 'vendor-a.json')
    b_path = str(output / 'vendor-b.json')

    _response(a_path, {JOINT: 'true_positive', ALPHA: 'true_positive'}, True)
    _response(b_path, {JOINT: 'false_positive', BETA: 'false_positive'}, True)
    vendor.merge_vendor_responses(state_path, [a_path, b_path])

    _export(baseline_file, tmp_path)
    _response(a_path, {JOINT: 'false_positive', ALPHA: 'false_positive'}, True)
    result = vendor.merge_vendor_responses(state_path, [a_path])

    joint = _finding_in_state(_load(state_path), JOINT)
    assert joint['accepted']['status'] == 'true_positive'
    assert joint['accepted']['signed_off'] is True
    assert joint['reviews']['vendor-a']['revision'] == 2
    assert result['conflicts'][0]['reason'] == 'signed_version_challenged'
