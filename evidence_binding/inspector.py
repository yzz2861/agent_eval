"""End-to-end, read-only evidence binding inspection.

The inspector walks a case bundle once, classifies every delivered file,
parses primary hives and their in-memory recovered views, ingests excerpt
manifests, and then delegates the source-chain binding decisions to the
binding module.  Nothing in the bundle is ever modified.
"""

import os

from . import binding as binding_module
from . import excerpts, hashing, hives
from .models import (
    Artifact,
    ArtifactKind,
    Citation,
    ProvenanceGrade,
    RecordOccurrence,
    Reachability,
)


def _iter_files(bundle_root):
    for current_root, _dirs, files in os.walk(bundle_root):
        for name in sorted(files):
            yield os.path.join(current_root, name)


def _parse_hex(value):
    if value in (None, ''):
        return -1
    return int(str(value), 16)


def _build_occurrence(raw, artifact, kind):
    citations = raw.pop('citations')
    grade = (
        ProvenanceGrade.NONE
        if kind != ArtifactKind.EXCERPT
        else raw.get('provenance_grade', ProvenanceGrade.CONTENT_ONLY)
    )
    reachability = raw.get('reachability', Reachability.REACHABLE)
    return RecordOccurrence(
        record_id='%s@0x%x' % (raw['record_kind'], raw['absolute_offset']),
        record_kind=raw['record_kind'],
        registry_path=raw['registry_path'],
        value_name=raw.get('value_name'),
        value_type=raw.get('value_type'),
        content_fingerprint=raw['content_fingerprint'],
        timestamp=raw.get('timestamp'),
        artifact_path=artifact.relative_path,
        artifact_sha256=artifact.sha256,
        artifact_kind=kind,
        hive_relative_offset=raw['relative_offset'],
        absolute_offset=raw['absolute_offset'],
        reachability=reachability,
        provenance_grade=grade,
        citations=citations,
        source_claim=raw.get('provenance', {}),
        binding_blockers=raw.get('binding_blockers', []),
    )


def _excerpt_citations(artifact, record):
    citations = [
        Citation(
            layer='excerpt manifest',
            detail='standalone JSON manifest, record index %d' % record['manifest_index'],
        )
    ]
    provenance = record.get('provenance') or {}
    if provenance:
        citations.append(
            Citation(
                layer='claimed source file',
                detail='source_sha256=%s' % provenance.get('source_sha256', ''),
            )
        )
        offset = _parse_hex(provenance.get('record_absolute_offset_hex'))
        citations.append(
            Citation(
                layer='claimed record offset',
                detail='offset claim carried by the excerpt',
                offset=offset if offset >= 0 else None,
            )
        )
    return citations


def inspect_bundle(bundle_root):
    """Inspect a case bundle and return artifacts, occurrences and exhibits."""
    artifacts = []
    occurrences = []
    warnings = []

    primaries = {}
    logs_by_primary = {}
    excerpt_paths = []

    for absolute_path in _iter_files(bundle_root):
        relative_path = hives.relpath(absolute_path, bundle_root)
        buffer_bytes = hives.read_file(absolute_path)
        digest = hashing.sha256_bytes(buffer_bytes)

        if excerpts.is_excerpt_manifest(relative_path, buffer_bytes):
            artifact = Artifact(
                relative_path=relative_path,
                kind=ArtifactKind.EXCERPT,
                size=len(buffer_bytes),
                sha256=digest,
            )
            artifacts.append(artifact)
            excerpt_paths.append((absolute_path, artifact, buffer_bytes))
            continue

        detected = hives.detect_kind(relative_path, buffer_bytes)
        if detected is None:
            continue
        if detected == 'primary':
            artifact = Artifact(
                relative_path=relative_path,
                kind=ArtifactKind.PRIMARY,
                size=len(buffer_bytes),
                sha256=digest,
            )
            try:
                header, _ = hives.parse_primary(buffer_bytes)
                artifact.hive_name = header['hive_name']
                artifact.hive_sequence1 = header['hive_sequence1']
                artifact.hive_sequence2 = header['hive_sequence2']
                artifact.checksum_valid = header['checksum_valid']
                artifact.recover_header = header['recovery_required']['recover_header']
                artifact.recover_data = header['recovery_required']['recover_data']
                artifact.extra['hbins_size'] = header['hbins_size']
                primaries[relative_path] = (artifact, buffer_bytes)
            except Exception as exc:
                artifact.parse_error = '%s: %s' % (type(exc).__name__, exc)
                warnings.append(artifact.parse_error)
            artifacts.append(artifact)
        elif detected == 'transaction_log':
            artifact = Artifact(
                relative_path=relative_path,
                kind=ArtifactKind.TRANSACTION_LOG,
                size=len(buffer_bytes),
                sha256=digest,
            )
            artifacts.append(artifact)
            primary_dir = os.path.dirname(relative_path)
            logs_by_primary.setdefault(primary_dir, []).append((artifact, absolute_path))
        else:
            artifact = Artifact(
                relative_path=relative_path,
                kind=ArtifactKind.UNKNOWN,
                size=len(buffer_bytes),
                sha256=digest,
                parse_error='unsupported registry file type: %s' % detected,
            )
            artifacts.append(artifact)
            warnings.append(artifact.parse_error)

    for relative_path, (artifact, primary_bytes) in sorted(primaries.items()):
        _header, primary_occurrences = hives.parse_primary(primary_bytes)
        for raw in primary_occurrences:
            occurrences.append(_build_occurrence(dict(raw), artifact, ArtifactKind.PRIMARY))

        primary_dir = os.path.dirname(relative_path)
        log_entries = logs_by_primary.get(primary_dir, [])
        if log_entries:
            log_paths = [absolute for _art, absolute in log_entries]
            try:
                recovered_bytes, log_reports = hives.recover_with_logs(
                    primary_bytes, log_paths
                )
            except Exception as exc:
                warnings.append('log recovery failed for %s: %s' % (relative_path, exc))
                recovered_bytes = primary_bytes
                log_reports = []

            for log_artifact, log_absolute in log_entries:
                for report in log_reports:
                    if report['relative_path'] == log_absolute:
                        log_artifact.extra.update(
                            {
                                'eligible': report['eligible'],
                                'first_log_sequence': report['first_log_sequence'],
                                'applied': report.get('applied', False),
                                'applied_sequence': report.get('applied_sequence'),
                                'log_entries': report['entries'],
                            }
                        )

            if recovered_bytes != primary_bytes:
                recovered_artifact = Artifact(
                    relative_path=relative_path + ' [in-memory recovered view]',
                    kind=ArtifactKind.PRIMARY,
                    size=len(recovered_bytes),
                    sha256=hashing.sha256_bytes(recovered_bytes),
                    hive_name=_header['hive_name'],
                    extra={
                        'derived_from': relative_path,
                        'not_written_to_disk': True,
                    },
                )
                artifacts.append(recovered_artifact)
                _rh, recovered_occurrences = hives.parse_primary(recovered_bytes)
                for raw in recovered_occurrences:
                    raw['provenance'] = {'derived_from': relative_path}
                    occurrences.append(
                        _build_occurrence(dict(raw), recovered_artifact, ArtifactKind.PRIMARY)
                    )

    for absolute_path, artifact, buffer_bytes in excerpt_paths:
        records, errors = excerpts.load_excerpt(absolute_path, buffer_bytes)
        warnings.extend(errors)
        for record in records:
            provenance = record.get('provenance') or {}
            raw = {
                'record_kind': record['record_kind'],
                'registry_path': record['registry_path'],
                'value_name': record['value_name'],
                'value_type': record['value_type'],
                'timestamp': record['timestamp'],
                'relative_offset': _parse_hex(
                    provenance.get('record_relative_offset_hex')
                ),
                'absolute_offset': _parse_hex(
                    provenance.get('record_absolute_offset_hex')
                ),
                'content_fingerprint': record['content_fingerprint'],
                'reachability': Reachability.EXCERPT_ONLY,
                'citations': _excerpt_citations(artifact, record),
                'provenance_grade': record['provenance_grade'],
                'provenance': provenance,
                'binding_blockers': record['binding_blockers'],
            }
            occurrences.append(_build_occurrence(raw, artifact, ArtifactKind.EXCERPT))

    exhibits = binding_module.bind_occurrences(occurrences)
    return {
        'bundle_root': os.path.abspath(bundle_root),
        'artifacts': artifacts,
        'occurrences': occurrences,
        'exhibits': exhibits,
        'warnings': warnings,
    }
