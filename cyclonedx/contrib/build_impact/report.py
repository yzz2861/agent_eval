# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Render deterministic JSON, Markdown, and CSV audit sheets."""

from csv import writer as csv_writer
from datetime import datetime
from io import StringIO
from json import dumps as json_dumps
from typing import Any, Dict, List, Optional, Tuple

from .assess import (
    ImpactFinding,
    ImpactReport,
    OccurrenceFact,
    SameDigestCohort,
    SbomTool,
    ToolObservation,
    ToolSource,
)

REPORT_VERSION = 1


def report_to_dict(report: ImpactReport) -> Dict[str, Any]:
    """Convert a report to a stable, JSON-ready mapping."""
    advisory = report.advisory
    return {
        'report_version': REPORT_VERSION,
        'archive': {
            'id': report.archive_id,
            'frozen': True,
            'frozen_at': _format_datetime(report.archive_frozen_at),
        },
        'advisory': {
            'id': advisory.advisory_id,
            'tool': advisory.tool_name,
            'tool_repository': advisory.tool_repository,
            'affected_versions': sorted(advisory.affected_versions),
            'affected_version_ranges': list(advisory.affected_version_ranges),
            'affected_source_commits': sorted(advisory.affected_source_commits),
            'affected_source_sha256': sorted(advisory.affected_source_sha256),
            'distribution_window': {
                'start': _format_datetime(advisory.window_start),
                'end': _format_datetime(advisory.window_end),
            },
            'fixed_versions': sorted(advisory.fixed_versions),
            'published_at': _format_datetime(advisory.published_at),
        },
        'summary': _summary(report),
        'findings': [_finding_to_dict(finding) for finding in report.findings],
        'same_digest_cohorts': [_cohort_to_dict(cohort) for cohort in report.same_digest_cohorts],
        'tool_provenance_unconfirmed': [finding.package_id for finding in report.tool_unconfirmed],
        'requires_tool_provenance_reverification': [
            finding.package_id for finding in report.requires_tool_provenance_reverification
        ],
    }


def render_json(report: ImpactReport) -> str:
    """Render a deterministic JSON audit sheet."""
    return json_dumps(report_to_dict(report), indent=2, ensure_ascii=False) + '\n'


def render_markdown(report: ImpactReport) -> str:
    """Render a human-readable Markdown audit sheet."""
    lines: List[str] = []
    lines.append('# Build Tool Impact Audit Sheet')
    lines.append('')
    lines.append(f'Archive: `{report.archive_id}` (frozen at {_format_datetime(report.archive_frozen_at)})')
    lines.append(f'Advisory: `{report.advisory.advisory_id}` for `{report.advisory.tool_name}`')
    lines.append('')
    lines.extend(_summary_markdown(report))
    lines.extend(_cohort_markdown(report))
    lines.extend(_section_markdown('Confirmed affected', report.affected))
    lines.extend(_section_markdown('Confirmed not affected', report.not_affected))
    lines.extend(_unconfirmed_markdown(report.tool_unconfirmed))
    lines.extend(_answer_markdown(report))
    lines.extend(_policy_markdown())
    return '\n'.join(lines).rstrip() + '\n'


def render_csv(report: ImpactReport) -> str:
    """Render a flat CSV audit sheet, one row per release package."""
    output = StringIO()
    csv = csv_writer(output, lineterminator='\n')
    csv.writerow([
        'package_id', 'component', 'version', 'sha256', 'status',
        'requires_tool_provenance_reverification', 'build_id', 'lineage_kind',
        'source_build_id', 'source_build_status', 'conclusion_basis',
        'tool', 'tool_version', 'source_commit', 'source_sha256', 'fetched_at', 'used_at',
        'reason_code', 'reason_detail',
    ])
    for finding in report.findings:
        csv.writerow(_finding_csv_row(finding))
    return output.getvalue()


def _summary(report: ImpactReport) -> Dict[str, Any]:
    return {
        'packages_total': len(report.findings),
        'affected': len(report.affected),
        'not_affected': len(report.not_affected),
        'tool_unconfirmed': len(report.tool_unconfirmed),
        'requires_tool_provenance_reverification': len(report.requires_tool_provenance_reverification),
        'same_digest_cohorts': len(report.same_digest_cohorts),
    }


def _summary_markdown(report: ImpactReport) -> List[str]:
    summary = _summary(report)
    packages_total = summary['packages_total']
    affected = summary['affected']
    not_affected = summary['not_affected']
    unconfirmed = summary['tool_unconfirmed']
    reverify = summary['requires_tool_provenance_reverification']
    return [
        '## Summary',
        '',
        '| Packages | Affected | Not affected | Tool unconfirmed | Re-verify tool source |',
        '| ---: | ---: | ---: | ---: | ---: |',
        f'| {packages_total} | {affected} | {not_affected} | {unconfirmed} | {reverify} |',
        '',
    ]


def _cohort_markdown(report: ImpactReport) -> List[str]:
    lines = [
        '## Identical-digest cohort',
        '',
        'Identical digests are shared observations, not shared build conclusions. Each row was reconciled '
        'against its own frozen build record.',
        '',
    ]
    findings = {finding.package_id: finding for finding in report.findings}
    for cohort in report.same_digest_cohorts:
        digest = _short_digest(cohort.sha256)
        lines.append(f'Digest `{digest}` is shared by {len(cohort.package_ids)} package(s).')
        lines.append('')
        lines.append('| Release | Build | Provenance | Tool | Tool source | Status | Re-verify tool source? |')
        lines.append('| --- | --- | --- | --- | --- | --- | --- |')
        for package_id in cohort.package_ids:
            finding = findings[package_id]
            build_id = _cell(finding.build_id or 'n/a')
            lineage = _cell(finding.lineage_kind or 'n/a')
            tool = _cell(_tool_summary(finding))
            source = _cell(_source_summary(finding))
            status = _cell(finding.status.value)
            reverify = _yes_no(finding.requires_tool_provenance_reverification)
            lines.append(
                f'| `{package_id}` | {build_id} | {lineage} | {tool} | {source} | {status} | {reverify} |'
            )
        lines.append('')
    return lines


def _section_markdown(title: str, findings: Tuple[ImpactFinding, ...]) -> List[str]:
    lines = [f'## {title}', '']
    if not findings:
        lines.append('None.')
        lines.append('')
        return lines
    lines.append('| Release | Build | Tool | Tool source | Reason |')
    lines.append('| --- | --- | --- | --- | --- |')
    for finding in findings:
        build_id = _cell(finding.build_id or 'n/a')
        tool = _cell(_tool_summary(finding))
        source = _cell(_source_summary(finding))
        reason = _cell(finding.reason_detail)
        lines.append(f'| `{finding.package_id}` | {build_id} | {tool} | {source} | {reason} |')
    lines.append('')
    return lines


def _unconfirmed_markdown(findings: Tuple[ImpactFinding, ...]) -> List[str]:
    lines = [
        '## Tool provenance unconfirmed (separate list)',
        '',
        'These packages are not counted as clean. Their tool origin cannot be confirmed from the frozen '
        'archive, so they require tool-source re-verification.',
        '',
    ]
    if not findings:
        lines.append('None.')
        lines.append('')
        return lines
    lines.append('| Release | Build | Provenance | Source build | Source build status | Reason |')
    lines.append('| --- | --- | --- | --- | --- | --- |')
    for finding in findings:
        build_id = _cell(finding.build_id or 'n/a')
        lineage = _cell(finding.lineage_kind or 'n/a')
        source_build = _cell(finding.source_build_id or 'n/a')
        source_status = finding.source_build_status.value if finding.source_build_status else 'n/a'
        reason = _cell(finding.reason_detail)
        lines.append(
            f'| `{finding.package_id}` | {build_id} | {lineage} | {source_build} | {source_status} | {reason} |'
        )
    lines.append('')
    return lines


def _answer_markdown(report: ImpactReport) -> List[str]:
    required = report.requires_tool_provenance_reverification
    lines = ['## Re-verification answer', '']
    if len(required) == 1:
        finding = required[0]
        lines.append(f'**Only `{finding.package_id}` must re-verify tool provenance.**')
        lines.append('')
        lines.append(f'- Reason: `{finding.reason_code}` - {finding.reason_detail}.')
        if finding.source_build_id:
            source = finding.source_build_status.value if finding.source_build_status else 'unknown'
            lines.append(
                f'- Source build `{finding.source_build_id}` is `{source}`, but a copy does not inherit '
                'that conclusion.'
            )
    elif not required:
        lines.append('No package requires tool-source re-verification.')
    else:
        joined = ', '.join(f'`{finding.package_id}`' for finding in required)
        lines.append(f'The following packages require tool-source re-verification: {joined}.')
    lines.append('')
    return lines


def _policy_markdown() -> List[str]:
    return [
        '## Reconciliation policy',
        '',
        '- The frozen archive is authoritative for actual tool use, fetch time, use time, and source.',
        '- The advisory is authoritative for affected versions, affected source commits/digests, and the '
        'distribution window.',
        '- A source commit or digest match outranks a version label; a recorded non-matching source can clear '
        'an affected version label.',
        '- A copied or mirrored artifact never inherits the source build conclusion. A rebuild is evaluated '
        'only from its own frozen tool invocation.',
        '- A package whose tool origin cannot be confirmed is listed separately and is not counted as clean.',
        '',
    ]


def _finding_to_dict(finding: ImpactFinding) -> Dict[str, Any]:
    return {
        'package_id': finding.package_id,
        'sbom': finding.sbom_path,
        'component': {
            'name': finding.component_name,
            'version': finding.component_version,
            'purl': finding.purl,
        },
        'sha256': finding.sha256,
        'declared_sha256': finding.declared_sha256,
        'evidence_sha256': finding.evidence_sha256,
        'sha256_conflict': finding.sha256_conflict,
        'status': finding.status.value,
        'requires_tool_provenance_reverification': finding.requires_tool_provenance_reverification,
        'reason_code': finding.reason_code,
        'reason': finding.reason_detail,
        'notes': list(finding.notes),
        'build_id': finding.build_id,
        'lineage': {
            'kind': finding.lineage_kind,
            'source_build_id': finding.source_build_id,
            'inherited_conclusion_blocked': finding.inherited_conclusion_blocked,
            'source_build_status': finding.source_build_status.value if finding.source_build_status else None,
        },
        'conclusion_basis': finding.conclusion_basis,
        'tool_observations': [_tool_observation_to_dict(item) for item in finding.tool_observations],
        'sbom_declared_tools': [_sbom_tool_to_dict(tool) for tool in finding.sbom_tools],
        'occurrences': [_occurrence_to_dict(item) for item in finding.occurrences],
    }


def _tool_observation_to_dict(observation: ToolObservation) -> Dict[str, Any]:
    return {
        'tool': observation.tool,
        'version': observation.version,
        'source': _source_to_dict(observation.source),
        'fetched_at': _format_datetime(observation.fetched_at),
        'used_at': _format_datetime(observation.used_at),
        'verdict': observation.verdict.value,
        'reason_code': observation.reason_code,
        'reason': observation.reason_detail,
        'sbom_declared': _sbom_tool_to_dict(observation.sbom_declared),
    }


def _sbom_tool_to_dict(tool: Optional[SbomTool]) -> Optional[Dict[str, Any]]:
    if tool is None:
        return None
    return {
        'name': tool.name,
        'version': tool.version,
        'sha256': tool.sha256,
        'repository': tool.repository,
        'bom_ref': tool.bom_ref,
    }


def _source_to_dict(source: Optional[ToolSource]) -> Optional[Dict[str, Optional[str]]]:
    if source is None:
        return None
    return {
        'repository': source.repository,
        'commit': source.commit,
        'sha256': source.sha256,
    }


def _occurrence_to_dict(occurrence: OccurrenceFact) -> Dict[str, Any]:
    return {
        'location': occurrence.location,
        'line': occurrence.line,
        'symbol': occurrence.symbol,
        'additional_context': occurrence.additional_context,
    }


def _cohort_to_dict(cohort: SameDigestCohort) -> Dict[str, Any]:
    return {
        'sha256': cohort.sha256,
        'package_ids': list(cohort.package_ids),
        'statuses': dict(cohort.statuses),
        'requires_tool_provenance_reverification': list(cohort.requires_tool_provenance_reverification),
        'conclusion_consistent': cohort.conclusion_consistent,
    }


def _finding_csv_row(finding: ImpactFinding) -> List[str]:
    tools = [item.tool for item in finding.tool_observations]
    versions = [item.version or '' for item in finding.tool_observations]
    commits = [
        item.source.commit if item.source and item.source.commit else ''
        for item in finding.tool_observations
    ]
    digests = [
        item.source.sha256 if item.source and item.source.sha256 else ''
        for item in finding.tool_observations
    ]
    fetched = [_format_datetime(item.fetched_at) or '' for item in finding.tool_observations]
    used = [_format_datetime(item.used_at) or '' for item in finding.tool_observations]
    source_status = finding.source_build_status.value if finding.source_build_status else ''
    return [
        finding.package_id,
        finding.component_name,
        finding.component_version or '',
        finding.sha256 or '',
        finding.status.value,
        'yes' if finding.requires_tool_provenance_reverification else 'no',
        finding.build_id or '',
        finding.lineage_kind or '',
        finding.source_build_id or '',
        source_status,
        finding.conclusion_basis,
        ';'.join(tools),
        ';'.join(versions),
        ';'.join(commits),
        ';'.join(digests),
        ';'.join(fetched),
        ';'.join(used),
        finding.reason_code,
        finding.reason_detail,
    ]


def _tool_summary(finding: ImpactFinding) -> str:
    if not finding.tool_observations:
        return 'n/a (no independent tool invocation)'
    parts: List[str] = []
    for item in finding.tool_observations:
        version = item.version or '<unknown>'
        parts.append(f'{item.tool} {version}')
    return '; '.join(parts)


def _source_summary(finding: ImpactFinding) -> str:
    if not finding.tool_observations:
        return 'UNKNOWN' if finding.lineage_kind in ('copied', 'mirrored') else 'n/a'
    parts: List[str] = []
    for item in finding.tool_observations:
        source = item.source
        if source and source.commit:
            suffix = f' / {source.sha256[:12]}' if source.sha256 else ''
            parts.append(source.commit[:12] + suffix)
        elif source and source.sha256:
            parts.append(source.sha256[:12])
        else:
            parts.append('UNKNOWN')
    return '; '.join(parts)


def _format_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat().replace('+00:00', 'Z')


def _short_digest(value: Optional[str]) -> str:
    return f'{value[:16]}...' if value else '<missing>'


def _yes_no(value: bool) -> str:
    return 'YES' if value else 'no'


def _cell(value: str) -> str:
    return value.replace('|', '\\|').replace('\n', ' ')
