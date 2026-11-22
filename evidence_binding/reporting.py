"""Write the two-generation binding directory and its manifests.

The output tree is deliberately limited to two levels:

    <output_root>/
        index.json
        index.txt
        exhibits/
            EXH-001/
                locations.json
                locations.txt
            EXH-002/
                ...

The first generation is the output root with its global index; the second
generation is one directory per bound exhibit, each spelling out the exact
bundle locations and byte offsets that make up the evidence.
"""

import json
import os

NL = chr(10)


def write_binding_output(result, output_root):
    """Materialise the binding result into the two-level directory tree."""
    exhibits_dir = os.path.join(output_root, 'exhibits')
    os.makedirs(exhibits_dir, exist_ok=True)

    index_payload = {
        'bundle_root': result['bundle_root'],
        'artifact_count': len(result['artifacts']),
        'occurrence_count': len(result['occurrences']),
        'exhibit_count': len(result['exhibits']),
        'warnings': result['warnings'],
        'artifacts': [artifact.as_dict() for artifact in result['artifacts']],
        'exhibits': [
            {
                'exhibit_id': exhibit.exhibit_id,
                'title': exhibit.title,
                'directory': 'exhibits/%s' % exhibit.exhibit_id,
                'occurrence_count': len(exhibit.occurrences),
                'bound': exhibit.decision.bound if exhibit.decision else False,
            }
            for exhibit in result['exhibits']
        ],
    }

    with open(os.path.join(output_root, 'index.json'), 'w', encoding='utf-8') as handle:
        json.dump(index_payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write(NL)

    with open(os.path.join(output_root, 'index.txt'), 'w', encoding='utf-8') as handle:
        handle.write(_render_index_text(index_payload))

    for exhibit in result['exhibits']:
        exhibit_dir = os.path.join(exhibits_dir, exhibit.exhibit_id)
        os.makedirs(exhibit_dir, exist_ok=True)
        with open(os.path.join(exhibit_dir, 'locations.json'), 'w', encoding='utf-8') as handle:
            json.dump(
                exhibit.as_dict(),
                handle,
                indent=2,
                ensure_ascii=False,
                sort_keys=True,
            )
            handle.write(NL)
        with open(os.path.join(exhibit_dir, 'locations.txt'), 'w', encoding='utf-8') as handle:
            handle.write(_render_locations_text(exhibit))

    return output_root


def _render_index_text(payload):
    lines = [
        'Read-only registry evidence binding index',
        'Bundle root: %s' % payload['bundle_root'],
        'Artifacts: %d  Occurrences: %d  Exhibits: %d' % (
            payload['artifact_count'],
            payload['occurrence_count'],
            payload['exhibit_count'],
        ),
        '',
    ]
    for artifact in payload['artifacts']:
        lines.append('[%s] %s  sha256=%s' % (
            artifact['kind'],
            artifact['relative_path'],
            artifact['sha256'],
        ))
    lines.append('')
    for exhibit in payload['exhibits']:
        lines.append('%s  %s  occurrences=%d  bound=%s  -> %s/' % (
            exhibit['exhibit_id'],
            exhibit['title'],
            exhibit['occurrence_count'],
            exhibit['bound'],
            exhibit['directory'],
        ))
    if payload['warnings']:
        lines.append('')
        lines.append('Warnings:')
        lines.extend('  - %s' % warning for warning in payload['warnings'])
    lines.append('')
    return NL.join(lines)


def _render_locations_text(exhibit):
    lines = [
        '%s  %s' % (exhibit.exhibit_id, exhibit.title),
        'Binding decision: %s' % (
            exhibit.decision.reason if exhibit.decision else 'no decision recorded'
        ),
        '',
    ]
    for index, occurrence in enumerate(exhibit.occurrences, start=1):
        lines.append('Occurrence %d:' % index)
        lines.append('  record: %s %s' % (
            occurrence.record_kind,
            occurrence.registry_path,
        ))
        if occurrence.value_name is not None:
            lines.append('  value: %s (%s)' % (
                occurrence.value_name or '(default)',
                occurrence.value_type,
            ))
        lines.append('  location: %s' % occurrence.artifact_path)
        lines.append('  artifact kind: %s' % occurrence.artifact_kind.value)
        lines.append(
            '  absolute offset: %s  (hive-relative %s)' % (
                _offset_text(occurrence.absolute_offset),
                _offset_text(occurrence.hive_relative_offset),
            )
        )
        lines.append('  reachability: %s' % occurrence.reachability.value)
        lines.append('  provenance grade: %s' % occurrence.provenance_grade.value)
        lines.append('  content fingerprint: %s' % occurrence.content_fingerprint)
        lines.append('  source chain:')
        for citation in occurrence.citations:
            lines.append('    - %s: %s%s' % (
                citation.layer,
                citation.detail,
                _citation_offset(citation),
            ))
        if occurrence.binding_blockers:
            lines.append('  binding blockers:')
            lines.extend('    ! %s' % blocker for blocker in occurrence.binding_blockers)
        lines.append('')
    return NL.join(lines)


def _offset_text(value):
    if value is None or value < 0:
        return 'n/a'
    return '0x%x' % value

def _citation_offset(citation):
    if citation.offset is None:
        return ''
    return ' @ 0x%x' % citation.offset
