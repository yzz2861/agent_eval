import json

from detect_secrets.provenance import build_feedback
from detect_secrets.provenance import GenerationDeclaration
from detect_secrets.provenance import resolve_provenance


def make_hit(filename, line_number=1, secret_hash='same-hash'):
    return {
        'filename': filename,
        'line_number': line_number,
        'hashed_secret': secret_hash,
        'type': 'TestingSecret',
    }


def make_manifest(*edges, config_version='config-v1'):
    return {
        'config_version': config_version,
        'edges': [
            {'generated': generated, 'source': source}
            for generated, source in edges
        ],
    }


def test_generated_hits_collapse_to_one_upstream_remediation():
    hits = [
        make_hit('generated/output_%s.py' % index, line_number=2)
        for index in range(40)
    ]
    manifest = make_manifest(*[
        ('generated/output_%s.py' % index, 'templates/release.j2')
        for index in range(40)
    ])

    feedback = build_feedback(hits, manifest, config_version='config-v1')

    assert len(feedback['upstream_remediation']) == 1
    remediation = feedback['upstream_remediation'][0]
    assert remediation['source'] == 'templates/release.j2'
    assert remediation['hit_count'] == 40
    assert {
        (location['filename'], location['line_number'])
        for location in remediation['locations']
    } == {
        ('generated/output_%s.py' % index, 2)
        for index in range(40)
    }
    assert feedback['pending_verification'] == []
    assert feedback['rescan'] == []


def test_handwritten_hit_with_same_digest_is_not_absorbed():
    hits = [
        make_hit('generated/output.py'),
        make_hit('src/handwritten.py', line_number=9),
    ]
    manifest = make_manifest(('generated/output.py', 'templates/source.j2'))

    feedback = build_feedback(hits, manifest, config_version='config-v1')

    assert len(feedback['upstream_remediation']) == 1
    assert feedback['upstream_remediation'][0]['hit_count'] == 1
    assert [
        (item['filename'], item['line_number'])
        for item in feedback['manual']
    ] == [('src/handwritten.py', 9)]


def test_one_to_many_sources_are_pending_and_need_rescan():
    hit = make_hit('generated/output.py')
    manifest = make_manifest(
        ('generated/output.py', 'templates/a.j2'),
        ('generated/output.py', 'templates/b.j2'),
    )

    feedback = build_feedback([hit], manifest, config_version='config-v1')

    assert feedback['upstream_remediation'] == []
    assert feedback['pending_verification'][0]['reason'] == 'one_to_many_sources'
    assert feedback['rescan'][0]['filename'] == 'generated/output.py'
    assert feedback['rescan'][0]['reason'] == 'one_to_many_sources'
    assert feedback['rescan'][0]['sources'] == ['templates/a.j2', 'templates/b.j2']
    assert feedback['rescan'][0]['locations'][0]['line_number'] == 1


def test_config_version_mismatch_requires_rescan():
    hit = make_hit('generated/output.py')
    manifest = make_manifest(
        ('generated/output.py', 'templates/source.j2'),
        config_version='old-config',
    )

    feedback = build_feedback([hit], manifest, config_version='new-config')

    assert feedback['pending_verification'][0]['reason'] == 'config_version_mismatch'
    assert feedback['rescan'][0]['reason'] == 'config_version_mismatch'


def test_removed_source_edge_surfaces_newly_pending_hit():
    hits = [
        make_hit('generated/keep.py'),
        make_hit('generated/removed.py'),
    ]
    before = make_manifest(
        ('generated/keep.py', 'templates/keep.j2'),
        ('generated/removed.py', 'templates/removed.j2'),
    )
    previous = build_feedback(hits, before, config_version='config-v1')

    after = make_manifest(('generated/keep.py', 'templates/keep.j2'))
    feedback = build_feedback(
        hits,
        after,
        config_version='config-v1',
        previous_feedback=previous,
    )

    assert len(feedback['upstream_remediation']) == 1
    assert [
        (item['filename'], item['reason'])
        for item in feedback['newly_pending']
    ] == [('generated/removed.py', 'generation_rule_removed')]
    assert feedback['rescan'][0]['filename'] == 'generated/removed.py'
    assert feedback['rescan'][0]['locations'][0]['line_number'] == 1


def test_mapping_and_edge_declaration_formats_are_supported():
    hit = make_hit('generated/output.py')

    mapping_feedback = build_feedback(
        [hit],
        {'generated/output.py': ['templates/source.j2']},
        config_version='config-v1',
    )
    edge_feedback = build_feedback(
        [hit],
        [{'from': 'generated/output.py', 'to': 'templates/source.j2'}],
        config_version='config-v1',
    )

    assert mapping_feedback['upstream_remediation'][0]['source'] == 'templates/source.j2'
    assert edge_feedback['upstream_remediation'][0]['source'] == 'templates/source.j2'


def test_resolve_provenance_exposes_source_and_original_location():
    hit = make_hit('generated/output.py', line_number=12)
    manifest = make_manifest(('generated/output.py', 'templates/source.j2'))

    attribution = resolve_provenance(hit, manifest, config_version='config-v1')

    assert attribution['source'] == 'templates/source.j2'
    assert attribution['status'] == 'verified'
    assert attribution['filename'] == 'generated/output.py'
    assert attribution['line_number'] == 12


def test_declaration_can_be_loaded_from_json_file(tmp_path):
    manifest = make_manifest(('generated/output.py', 'templates/source.j2'))
    path = tmp_path / 'sources.json'
    path.write_text(json.dumps(manifest))

    declaration = GenerationDeclaration.from_value(str(path))

    assert declaration.config_version == 'config-v1'
    assert declaration.sources_for('generated/output.py') == ['templates/source.j2']
