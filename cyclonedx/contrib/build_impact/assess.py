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

"""
Offline impact assessment for a compromised build tool.

The assessment deliberately separates three facts that are often conflated:

* what an SBOM says about a component (including its evidence objects),
* what a frozen build-behaviour archive says actually happened, and
* what a tool repository advisory says was distributed and when.

An artifact digest is an observation, not a build conclusion. A copied or
rebuilt artifact therefore never inherits the conclusion of the build record
it was derived from. If the tool source cannot be confirmed, the package is
reported separately and is never counted as clean.
"""

import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from json import load as json_load
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from ...model import ExternalReferenceType, HashAlgorithm
from ...model.bom import Bom
from ...model.component import Component
from ...model.component_evidence import IdentityField
from ...model.tool import Tool


class AssessmentError(ValueError):
    """Raised when an input cannot be used for an offline assessment."""


class ArchiveNotFrozenError(AssessmentError):
    """Raised when the build-behaviour archive is not explicitly frozen."""


class AdvisoryError(AssessmentError):
    """Raised when a tool repository advisory is malformed."""


class ImpactStatus(str, Enum):
    """Final disposition of one release package."""

    AFFECTED = 'affected'
    NOT_AFFECTED = 'not_affected'
    TOOL_UNCONFIRMED = 'tool_unconfirmed'


class ToolVerdict(str, Enum):
    """Disposition of one observed tool invocation."""

    AFFECTED = 'affected'
    NOT_AFFECTED = 'not_affected'
    UNCONFIRMED = 'unconfirmed'


@dataclass(frozen=True)
class ToolSource:
    """Observed provenance of a build-tool binary."""

    repository: Optional[str] = None
    commit: Optional[str] = None
    sha256: Optional[str] = None

    def has_strong_identity(self) -> bool:
        """Whether the source carries a commit or digest that can clear/flag it."""
        return bool(self.sha256 or (self.commit and len(self.commit) >= 7))


@dataclass(frozen=True)
class ToolInvocation:
    """One tool use recorded by the frozen build-behaviour archive."""

    tool: str
    version: Optional[str] = None
    source: Optional[ToolSource] = None
    fetched_at: Optional[datetime] = None
    used_at: Optional[datetime] = None
    phase: Optional[str] = None


@dataclass(frozen=True)
class BuildRecord:
    """One frozen build, rebuild, copy, or mirror record."""

    build_id: str
    artifact_name: str
    artifact_sha256: str
    release_id: Optional[str] = None
    artifact_version: Optional[str] = None
    artifact_channel: Optional[str] = None
    provenance_kind: str = 'built'
    source_build_id: Optional[str] = None
    built_at: Optional[datetime] = None
    outcome: Optional[str] = None
    tool_invocations: Tuple[ToolInvocation, ...] = ()


@dataclass(frozen=True)
class FrozenBuildArchive:
    """An explicitly frozen, immutable build-behaviour archive."""

    archive_id: str
    frozen_at: datetime
    builds: Tuple[BuildRecord, ...]

    @classmethod
    def load(cls, path: str) -> 'FrozenBuildArchive':
        with open(path, encoding='utf-8') as stream:
            return cls.from_dict(_as_mapping(json_load(stream), 'build archive'))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> 'FrozenBuildArchive':
        if raw.get('frozen') is not True:
            raise ArchiveNotFrozenError('build archive must declare "frozen": true')
        archive_id = _required_str(raw, 'archive_id', 'build archive')
        frozen_at = _required_datetime(raw, 'frozen_at', 'build archive')
        raw_builds = raw.get('builds')
        if not isinstance(raw_builds, list) or not raw_builds:
            raise AssessmentError('build archive must contain a non-empty "builds" list')
        builds = tuple(
            _build_record_from_dict(_as_mapping(item, f'builds[{index}]'))
            for index, item in enumerate(raw_builds)
        )
        _validate_archive(builds)
        return cls(archive_id=archive_id, frozen_at=frozen_at, builds=builds)

    def by_build_id(self, build_id: Optional[str]) -> Optional[BuildRecord]:
        if build_id is None:
            return None
        return next((build for build in self.builds if build.build_id == build_id), None)

    def find_build(
        self,
        *,
        release_id: Optional[str],
        sha256: Optional[str],
        name: Optional[str],
        version: Optional[str],
    ) -> Tuple[Optional[BuildRecord], Optional[str]]:
        """
        Find the build record for an observed release package.

        A release identifier is an exact, unambiguous join. Without one, the
        digest plus component name/version is used; if that remains ambiguous,
        the package cannot be tied to one build and must be re-verified.
        """
        if release_id:
            matches = [build for build in self.builds if build.release_id == release_id]
            if len(matches) == 1:
                return matches[0], None
            if len(matches) > 1:
                return None, 'ambiguous_release_id_in_frozen_archive'
            return None, 'no_frozen_build_record_for_release_id'
        if not sha256:
            return None, 'artifact_digest_missing'
        digest = sha256.casefold()
        candidates = [build for build in self.builds if build.artifact_sha256.casefold() == digest]
        if name:
            candidates = [build for build in candidates if build.artifact_name == name]
        if version:
            candidates = [build for build in candidates if build.artifact_version == version]
        if len(candidates) == 1:
            return candidates[0], None
        if len(candidates) > 1:
            return None, 'ambiguous_artifact_digest_in_frozen_archive'
        return None, 'no_matching_frozen_build_record'


@dataclass(frozen=True)
class ToolAdvisory:
    """A tool repository announcement about distributed, affected builds."""

    advisory_id: str
    tool_name: str
    affected_versions: FrozenSet[str]
    affected_version_ranges: Tuple[str, ...]
    affected_source_commits: FrozenSet[str]
    affected_source_sha256: FrozenSet[str]
    fixed_versions: FrozenSet[str]
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    published_at: Optional[datetime] = None
    tool_repository: Optional[str] = None
    summary: Optional[str] = None

    @classmethod
    def load(cls, path: str) -> 'ToolAdvisory':
        with open(path, encoding='utf-8') as stream:
            return cls.from_dict(_as_mapping(json_load(stream), 'tool advisory'))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> 'ToolAdvisory':
        advisory_id = _required_str(raw, 'advisory_id', 'tool advisory')
        raw_tool = raw.get('tool')
        if isinstance(raw_tool, str):
            tool_name = raw_tool
            tool_repository = None
        elif isinstance(raw_tool, Mapping):
            tool_name = _required_str(raw_tool, 'name', 'tool advisory tool')
            tool_repository = _optional_str(raw_tool.get('repository'))
        else:
            raise AdvisoryError('tool advisory must define "tool" as a string or object')
        affected_versions = _str_set(raw.get('affected_versions'))
        affected_ranges = _str_tuple(raw.get('affected_version_range'))
        fixed_versions = _str_set(raw.get('fixed_versions'))
        if not (affected_versions or affected_ranges):
            raise AdvisoryError('tool advisory must define affected versions or a version range')
        window = raw.get('distribution_window')
        window_start = None
        window_end = None
        if isinstance(window, Mapping):
            window_start = _optional_datetime(window.get('start'), 'distribution_window.start')
            window_end = _optional_datetime(window.get('end'), 'distribution_window.end')
        if window_start and window_end and window_start > window_end:
            raise AdvisoryError('distribution_window.start must not be after distribution_window.end')
        raw_hashes = _str_tuple(raw.get('affected_source_sha256'))
        affected_hashes: Set[str] = set()
        for value in raw_hashes:
            normalized = _normalize_sha256(value)
            if normalized is None:
                raise AdvisoryError(f'affected_source_sha256 contains a non-SHA-256 value: {value!r}')
            affected_hashes.add(normalized)
        return cls(
            advisory_id=advisory_id,
            tool_name=tool_name,
            affected_versions=affected_versions,
            affected_version_ranges=affected_ranges,
            affected_source_commits=frozenset(
                value.casefold() for value in _str_tuple(raw.get('affected_source_commits'))
            ),
            affected_source_sha256=frozenset(affected_hashes),
            fixed_versions=fixed_versions,
            window_start=window_start,
            window_end=window_end,
            published_at=_optional_datetime(raw.get('published_at'), 'published_at'),
            tool_repository=tool_repository,
            summary=_optional_str(raw.get('summary')),
        )

    def matches_tool(self, name: Optional[str]) -> bool:
        return bool(name) and name.casefold() == self.tool_name.casefold()

    def version_affected(self, version: Optional[str]) -> bool:
        if not version:
            return False
        if version in self.affected_versions:
            return True
        return any(_version_in_range(version, version_range) for version_range in self.affected_version_ranges)

    def commit_affected(self, commit: Optional[str]) -> bool:
        if not commit:
            return False
        observed = commit.casefold()
        return any(
            _commit_prefix_match(observed, affected)
            for affected in self.affected_source_commits
        )


@dataclass(frozen=True)
class SbomTool:
    """Tool declaration extracted from metadata.tools or component evidence."""

    name: Optional[str]
    version: Optional[str] = None
    sha256: Optional[str] = None
    repository: Optional[str] = None
    bom_ref: Optional[str] = None


@dataclass(frozen=True)
class OccurrenceFact:
    """Relevant fields of a CycloneDX evidence occurrence."""

    location: str
    line: Optional[int] = None
    symbol: Optional[str] = None
    additional_context: Optional[str] = None


@dataclass(frozen=True)
class SbomObservation:
    """What one CycloneDX SBOM declares about a release package."""

    path: str
    release_id: Optional[str]
    component_name: str
    component_version: Optional[str]
    purl: Optional[str]
    declared_sha256: Optional[str]
    evidence_sha256: Optional[str]
    sha256: Optional[str]
    sha256_conflict: bool
    sbom_tools: Tuple[SbomTool, ...]
    occurrences: Tuple[OccurrenceFact, ...]
    timestamp: Optional[datetime]

    @classmethod
    def load(cls, path: str) -> 'SbomObservation':
        with open(path, encoding='utf-8') as stream:
            return cls.from_dict(_as_mapping(json_load(stream), f'SBOM {path}'), path=path)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any], *, path: str = '<memory>') -> 'SbomObservation':
        bom = Bom.from_json(dict(raw))
        component = bom.metadata.component or _first_component(bom)
        if component is None:
            raise AssessmentError(f'SBOM {path} has no component to assess')
        declared_hashes = _component_sha256_values(component)
        evidence_hashes = _evidence_sha256_values(component)
        declared_sha256 = _single_or_none(declared_hashes)
        evidence_sha256 = _single_or_none(evidence_hashes)
        sha256_conflict = (
            len(declared_hashes) > 1
            or len(evidence_hashes) > 1
            or bool(declared_sha256 and evidence_sha256 and declared_sha256 != evidence_sha256)
        )
        sha256 = declared_sha256 or evidence_sha256
        if sha256_conflict:
            sha256 = None
        occurrences = _component_occurrences(component)
        release_id = (
            _release_id_from_properties(component)
            or _release_id_from_purl(component)
            or _release_id_from_occurrences(occurrences)
        )
        return cls(
            path=path,
            release_id=release_id,
            component_name=component.name,
            component_version=component.version,
            purl=str(component.purl) if component.purl else None,
            declared_sha256=declared_sha256,
            evidence_sha256=evidence_sha256,
            sha256=sha256,
            sha256_conflict=sha256_conflict,
            sbom_tools=_sbom_tools(bom, component),
            occurrences=occurrences,
            timestamp=bom.metadata.timestamp,
        )


@dataclass(frozen=True)
class ToolObservation:
    """Result of one archive tool invocation."""

    tool: str
    version: Optional[str]
    source: Optional[ToolSource]
    fetched_at: Optional[datetime]
    used_at: Optional[datetime]
    verdict: ToolVerdict
    reason_code: str
    reason_detail: str
    sbom_declared: Optional[SbomTool] = None


@dataclass(frozen=True)
class ImpactFinding:
    """Final disposition of one release package."""

    package_id: str
    sbom_path: str
    component_name: str
    component_version: Optional[str]
    purl: Optional[str]
    sha256: Optional[str]
    declared_sha256: Optional[str]
    evidence_sha256: Optional[str]
    sha256_conflict: bool
    status: ImpactStatus
    requires_tool_provenance_reverification: bool
    reason_code: str
    reason_detail: str
    notes: Tuple[str, ...]
    build_id: Optional[str]
    lineage_kind: Optional[str]
    source_build_id: Optional[str]
    inherited_conclusion_blocked: bool
    source_build_status: Optional[ImpactStatus]
    conclusion_basis: str
    tool_observations: Tuple[ToolObservation, ...]
    sbom_tools: Tuple[SbomTool, ...]
    occurrences: Tuple[OccurrenceFact, ...]


@dataclass(frozen=True)
class SameDigestCohort:
    """Packages that share one artifact digest but may not share a conclusion."""

    sha256: Optional[str]
    package_ids: Tuple[str, ...]
    statuses: Tuple[Tuple[str, str], ...]
    requires_tool_provenance_reverification: Tuple[str, ...]
    conclusion_consistent: bool


@dataclass(frozen=True)
class ImpactReport:
    """Deterministic result of one offline impact assessment."""

    archive_id: str
    archive_frozen_at: datetime
    advisory: ToolAdvisory
    findings: Tuple[ImpactFinding, ...]
    same_digest_cohorts: Tuple[SameDigestCohort, ...]

    @property
    def affected(self) -> Tuple[ImpactFinding, ...]:
        return tuple(finding for finding in self.findings if finding.status is ImpactStatus.AFFECTED)

    @property
    def not_affected(self) -> Tuple[ImpactFinding, ...]:
        return tuple(finding for finding in self.findings if finding.status is ImpactStatus.NOT_AFFECTED)

    @property
    def tool_unconfirmed(self) -> Tuple[ImpactFinding, ...]:
        return tuple(finding for finding in self.findings if finding.status is ImpactStatus.TOOL_UNCONFIRMED)

    @property
    def requires_tool_provenance_reverification(self) -> Tuple[ImpactFinding, ...]:
        return tuple(
            finding for finding in self.findings
            if finding.requires_tool_provenance_reverification
        )


def load_observations(paths: Iterable[str]) -> Tuple[SbomObservation, ...]:
    """Load SBOM observations in sorted path order."""
    return tuple(SbomObservation.load(path) for path in sorted(paths))


def assess(
    archive: FrozenBuildArchive,
    advisory: ToolAdvisory,
    observations: Iterable[SbomObservation],
) -> ImpactReport:
    """Assess release packages against one frozen archive and one advisory."""
    ordered = sorted(observations, key=lambda item: (item.release_id or '', item.path))
    seen_release_ids: Set[str] = set()
    for observation in ordered:
        if observation.release_id:
            if observation.release_id in seen_release_ids:
                raise AssessmentError(f'duplicate release_id in SBOM input: {observation.release_id!r}')
            seen_release_ids.add(observation.release_id)
    findings = tuple(
        _assess_one(archive, advisory, observation)
        for observation in ordered
    )
    return ImpactReport(
        archive_id=archive.archive_id,
        archive_frozen_at=archive.frozen_at,
        advisory=advisory,
        findings=findings,
        same_digest_cohorts=_same_digest_cohorts(findings),
    )


def evaluate_tool_invocation(
    advisory: ToolAdvisory,
    invocation: ToolInvocation,
) -> Tuple[ToolVerdict, str]:
    """
    Evaluate one recorded tool invocation.

    Source provenance outranks a version label. If the archive records the
    affected commit or digest, the build is affected even when the version
    string says otherwise. Conversely, a recorded non-matching source clears
    an affected version label for this advisory.
    """
    if not advisory.matches_tool(invocation.tool):
        return ToolVerdict.NOT_AFFECTED, 'tool_not_named_in_advisory'
    source = invocation.source
    if source and source.sha256 and source.sha256.casefold() in advisory.affected_source_sha256:
        return ToolVerdict.AFFECTED, 'tool_source_digest_matches_advisory'
    if source and advisory.commit_affected(source.commit):
        return ToolVerdict.AFFECTED, 'tool_source_commit_matches_advisory'
    if source and source.has_strong_identity():
        return ToolVerdict.NOT_AFFECTED, 'tool_source_does_not_match_advisory'
    if invocation.version is None:
        return ToolVerdict.UNCONFIRMED, 'tool_version_missing'
    if not advisory.version_affected(invocation.version):
        return ToolVerdict.NOT_AFFECTED, 'tool_version_not_affected'
    observed_at = invocation.fetched_at or invocation.used_at
    if observed_at is None:
        return ToolVerdict.UNCONFIRMED, 'tool_usage_time_missing'
    if advisory.window_start and observed_at < advisory.window_start:
        return ToolVerdict.NOT_AFFECTED, 'tool_observed_before_affected_distribution'
    return ToolVerdict.UNCONFIRMED, 'affected_version_without_confirmable_source'


def _assess_one(
    archive: FrozenBuildArchive,
    advisory: ToolAdvisory,
    observation: SbomObservation,
) -> ImpactFinding:
    finding = _finding_from_observation(observation)
    if observation.sha256_conflict:
        return _unconfirmed(
            finding,
            'artifact_digest_conflict',
            'component.hashes and component.evidence.identity disagree or contain multiple SHA-256 values',
        )
    if not observation.sha256:
        return _unconfirmed(
            finding,
            'artifact_digest_missing',
            'the SBOM does not provide a usable SHA-256 artifact digest',
        )
    record, match_code = archive.find_build(
        release_id=observation.release_id,
        sha256=observation.sha256,
        name=observation.component_name,
        version=observation.component_version,
    )
    if record is None:
        return _unconfirmed(
            finding,
            match_code or 'no_matching_frozen_build_record',
            'the release package cannot be tied to exactly one frozen build record',
        )
    if record.artifact_sha256.casefold() != observation.sha256.casefold():
        return _unconfirmed(
            replace(finding, build_id=record.build_id),
            'artifact_digest_differs_from_build_record',
            'the SBOM digest does not match the frozen build record selected by release identifier',
        )
    finding = replace(
        finding,
        build_id=record.build_id,
        lineage_kind=record.provenance_kind,
        source_build_id=record.source_build_id,
    )
    if record.provenance_kind in ('copied', 'mirrored'):
        return _copied_or_mirrored(archive, advisory, finding, record)
    if record.provenance_kind not in ('built', 'rebuilt'):
        return _unconfirmed(
            finding,
            'unknown_build_provenance_kind',
            f'frozen record {record.build_id} has unsupported provenance kind {record.provenance_kind!r}',
        )
    if record.provenance_kind == 'rebuilt' and record.source_build_id:
        source_record = archive.by_build_id(record.source_build_id)
        source_status = _record_status(advisory, source_record) if source_record else None
        finding = replace(finding, source_build_status=source_status)
    return _evaluate_build_record(advisory, observation, finding, record)


def _copied_or_mirrored(
    archive: FrozenBuildArchive,
    advisory: ToolAdvisory,
    finding: ImpactFinding,
    record: BuildRecord,
) -> ImpactFinding:
    source_record = archive.by_build_id(record.source_build_id)
    source_status = _record_status(advisory, source_record) if source_record else None
    notes = list(finding.notes)
    notes.append(
        'a copied or mirrored artifact has no independent tool invocation and must not inherit '
        f"the conclusion of source build {record.source_build_id or '<unknown>'}"
    )
    if source_status is ImpactStatus.AFFECTED:
        notes.append('the source build is affected; treat the copy as potentially affected until re-verified')
    return _unconfirmed(
        finding,
        'copied_artifact_does_not_inherit_build_conclusion',
        'the copy/mirror record contains no independent tool provenance, so the original build conclusion '
        'cannot be reused',
        inherited_conclusion_blocked=True,
        source_build_status=source_status,
        notes=tuple(notes),
    )


def _evaluate_build_record(
    advisory: ToolAdvisory,
    observation: SbomObservation,
    finding: ImpactFinding,
    record: BuildRecord,
) -> ImpactFinding:
    if not record.tool_invocations:
        code = (
            'rebuilt_artifact_has_no_independent_build_record'
            if record.provenance_kind == 'rebuilt'
            else 'frozen_build_record_has_no_tool_invocation'
        )
        return _unconfirmed(finding, code, f'frozen record {record.build_id} contains no tool invocation')
    declared_by_name: Dict[str, SbomTool] = {
        tool.name.casefold(): tool
        for tool in observation.sbom_tools
        if tool.name
    }
    missing = [
        invocation.tool
        for invocation in record.tool_invocations
        if invocation.tool.casefold() not in declared_by_name
    ]
    if missing:
        return _unconfirmed(
            finding,
            'frozen_build_tool_not_declared_in_sbom',
            'the frozen build used a tool that the SBOM does not declare: ' + ', '.join(sorted(set(missing))),
        )
    tool_observations = tuple(
        _tool_observation(advisory, invocation, declared_by_name.get(invocation.tool.casefold()))
        for invocation in record.tool_invocations
    )
    affected = [item for item in tool_observations if item.verdict is ToolVerdict.AFFECTED]
    unconfirmed = [item for item in tool_observations if item.verdict is ToolVerdict.UNCONFIRMED]
    notes = tuple(
        f'{item.tool} {item.version or '<no version>'}: {item.reason_detail}'
        for item in tool_observations
        if item.verdict is not ToolVerdict.NOT_AFFECTED
    )
    conclusion_basis = 'independent_rebuild' if record.provenance_kind == 'rebuilt' else 'frozen_build_record'
    inheritance_blocked = record.provenance_kind == 'rebuilt'
    if affected:
        return replace(
            finding,
            status=ImpactStatus.AFFECTED,
            requires_tool_provenance_reverification=False,
            reason_code=affected[0].reason_code,
            reason_detail=affected[0].reason_detail,
            notes=notes,
            conclusion_basis=conclusion_basis,
            inherited_conclusion_blocked=inheritance_blocked,
            tool_observations=tool_observations,
        )
    if unconfirmed:
        return replace(
            finding,
            status=ImpactStatus.TOOL_UNCONFIRMED,
            requires_tool_provenance_reverification=True,
            reason_code=unconfirmed[0].reason_code,
            reason_detail=unconfirmed[0].reason_detail,
            notes=notes,
            conclusion_basis=conclusion_basis,
            inherited_conclusion_blocked=inheritance_blocked,
            tool_observations=tool_observations,
        )
    clean_details: List[str] = []
    for item in tool_observations:
        version = item.version or '<no version>'
        clean_details.append(f'{item.tool} {version}: {item.reason_detail}')
    return replace(
        finding,
        status=ImpactStatus.NOT_AFFECTED,
        requires_tool_provenance_reverification=False,
        reason_code='all_tool_invocations_are_not_affected',
        reason_detail='; '.join(clean_details),
        notes=notes,
        conclusion_basis=conclusion_basis,
        inherited_conclusion_blocked=inheritance_blocked,
        tool_observations=tool_observations,
    )


def _tool_observation(
    advisory: ToolAdvisory,
    invocation: ToolInvocation,
    declared: Optional[SbomTool],
) -> ToolObservation:
    verdict, reason_code = evaluate_tool_invocation(advisory, invocation)
    conflict = _declaration_conflict(invocation, declared)
    if conflict:
        verdict = ToolVerdict.UNCONFIRMED
        reason_code = conflict
    return ToolObservation(
        tool=invocation.tool,
        version=invocation.version,
        source=invocation.source,
        fetched_at=invocation.fetched_at,
        used_at=invocation.used_at,
        verdict=verdict,
        reason_code=reason_code,
        reason_detail=_tool_reason_detail(reason_code),
        sbom_declared=declared,
    )


def _declaration_conflict(
    invocation: ToolInvocation,
    declared: Optional[SbomTool],
) -> Optional[str]:
    if declared is None:
        return 'frozen_build_tool_not_declared_in_sbom'
    if declared.version and invocation.version and declared.version != invocation.version:
        return 'sbom_tool_version_conflicts_with_frozen_build'
    if declared.version and not invocation.version:
        return 'frozen_build_tool_version_missing'
    if declared.sha256 and invocation.source and invocation.source.sha256 \
            and declared.sha256.casefold() != invocation.source.sha256.casefold():
        return 'sbom_tool_digest_conflicts_with_frozen_build'
    if declared.sha256 and (invocation.source is None or not invocation.source.sha256):
        return 'sbom_tool_digest_not_confirmed_by_frozen_build'
    return None


def _record_status(advisory: ToolAdvisory, record: BuildRecord) -> Optional[ImpactStatus]:
    if record.provenance_kind in ('copied', 'mirrored') or not record.tool_invocations:
        return ImpactStatus.TOOL_UNCONFIRMED
    verdicts = [
        evaluate_tool_invocation(advisory, invocation)[0]
        for invocation in record.tool_invocations
    ]
    if ToolVerdict.AFFECTED in verdicts:
        return ImpactStatus.AFFECTED
    if ToolVerdict.UNCONFIRMED in verdicts:
        return ImpactStatus.TOOL_UNCONFIRMED
    return ImpactStatus.NOT_AFFECTED


def _finding_from_observation(observation: SbomObservation) -> ImpactFinding:
    return ImpactFinding(
        package_id=observation.release_id or Path(observation.path).stem,
        sbom_path=observation.path,
        component_name=observation.component_name,
        component_version=observation.component_version,
        purl=observation.purl,
        sha256=observation.sha256,
        declared_sha256=observation.declared_sha256,
        evidence_sha256=observation.evidence_sha256,
        sha256_conflict=observation.sha256_conflict,
        status=ImpactStatus.TOOL_UNCONFIRMED,
        requires_tool_provenance_reverification=True,
        reason_code='not_assessed',
        reason_detail='the package has not been assessed',
        notes=(),
        build_id=None,
        lineage_kind=None,
        source_build_id=None,
        inherited_conclusion_blocked=False,
        source_build_status=None,
        conclusion_basis='none',
        tool_observations=(),
        sbom_tools=observation.sbom_tools,
        occurrences=observation.occurrences,
    )


def _unconfirmed(finding: ImpactFinding, code: str, detail: str, **overrides: Any) -> ImpactFinding:
    return replace(
        finding,
        status=ImpactStatus.TOOL_UNCONFIRMED,
        requires_tool_provenance_reverification=True,
        reason_code=code,
        reason_detail=detail,
        **overrides,
    )


def _same_digest_cohorts(findings: Tuple[ImpactFinding, ...]) -> Tuple[SameDigestCohort, ...]:
    grouped: Dict[str, List[ImpactFinding]] = {}
    for finding in findings:
        if not finding.sha256:
            continue
        key = finding.sha256.casefold()
        grouped.setdefault(key, []).append(finding)
    cohorts: List[SameDigestCohort] = []
    for digest, items in sorted(grouped.items()):
        if len(items) < 2:
            continue
        statuses = tuple((item.package_id, item.status.value) for item in items)
        cohort = SameDigestCohort(
            sha256=digest,
            package_ids=tuple(item.package_id for item in items),
            statuses=statuses,
            requires_tool_provenance_reverification=tuple(
                item.package_id for item in items if item.requires_tool_provenance_reverification
            ),
            conclusion_consistent=len({item.status for item in items}) == 1,
        )
        cohorts.append(cohort)
    return tuple(cohorts)


def _build_record_from_dict(raw: Mapping[str, Any]) -> BuildRecord:
    artifact = _as_mapping(raw.get('artifact'), 'build.artifact')
    raw_invocations = raw.get('tool_invocations') or []
    if not isinstance(raw_invocations, list):
        raise AssessmentError('build.tool_invocations must be a list')
    return BuildRecord(
        build_id=_required_str(raw, 'build_id', 'build'),
        release_id=_optional_str(raw.get('release_id')),
        artifact_name=_required_str(artifact, 'name', 'build.artifact'),
        artifact_version=_optional_str(artifact.get('version')),
        artifact_sha256=_required_sha256(artifact, 'sha256', 'build.artifact'),
        artifact_channel=_optional_str(artifact.get('channel')),
        provenance_kind=_optional_str(raw.get('provenance_kind')) or 'built',
        source_build_id=_optional_str(raw.get('source_build_id')),
        built_at=_optional_datetime(raw.get('built_at'), 'build.built_at'),
        outcome=_optional_str(raw.get('outcome')),
        tool_invocations=tuple(
            _tool_invocation_from_dict(_as_mapping(item, 'build.tool_invocations[]'))
            for item in raw_invocations
        ),
    )


def _tool_invocation_from_dict(raw: Mapping[str, Any]) -> ToolInvocation:
    raw_source = raw.get('source')
    source = (
        _tool_source_from_dict(_as_mapping(raw_source, 'tool_invocation.source'))
        if isinstance(raw_source, Mapping)
        else None
    )
    return ToolInvocation(
        tool=_required_str(raw, 'tool', 'tool invocations'),
        version=_optional_str(raw.get('version')),
        source=source,
        fetched_at=_optional_datetime(raw.get('fetched_at'), 'tool_invocation.fetched_at'),
        used_at=_optional_datetime(raw.get('used_at'), 'tool_invocation.used_at'),
        phase=_optional_str(raw.get('phase')),
    )


def _tool_source_from_dict(raw: Mapping[str, Any]) -> ToolSource:
    sha256 = _optional_str(raw.get('sha256'))
    normalized_sha256 = None
    if sha256 is not None:
        normalized_sha256 = _normalize_sha256(sha256)
        if normalized_sha256 is None:
            raise AssessmentError(f'tool_invocation.source.sha256 is not a SHA-256 value: {sha256!r}')
    return ToolSource(
        repository=_optional_str(raw.get('repository')),
        commit=_optional_str(raw.get('commit')),
        sha256=normalized_sha256,
    )


def _validate_archive(builds: Tuple[BuildRecord, ...]) -> None:
    build_ids = [build.build_id for build in builds]
    if len(build_ids) != len(set(build_ids)):
        raise AssessmentError('build archive contains duplicate build_id values')
    release_ids = [build.release_id for build in builds if build.release_id]
    if len(release_ids) != len(set(release_ids)):
        raise AssessmentError('build archive contains duplicate release_id values')
    known = set(build_ids)
    for build in builds:
        if build.source_build_id and build.source_build_id not in known:
            raise AssessmentError(
                f'build {build.build_id} references unknown source_build_id {build.source_build_id}'
            )


def _component_sha256_values(component: Component) -> FrozenSet[str]:
    return frozenset(
        value
        for item in component.hashes
        if item.alg is HashAlgorithm.SHA_256
        for value in (_normalize_sha256(item.content),)
        if value
    )


def _evidence_sha256_values(component: Component) -> FrozenSet[str]:
    values: Set[str] = set()
    evidence = component.evidence
    if not evidence:
        return frozenset()
    for identity in evidence.identity:
        is_hash_identity = identity.field is IdentityField.HASH or str(identity.field) == IdentityField.HASH.value
        if is_hash_identity:
            value = _normalize_sha256(identity.concluded_value)
            if value:
                values.add(value)
            for method in identity.methods:
                value = _normalize_sha256(method.value)
                if value:
                    values.add(value)
    return frozenset(values)


def _component_occurrences(component: Component) -> Tuple[OccurrenceFact, ...]:
    evidence = component.evidence
    if not evidence:
        return ()
    return tuple(
        OccurrenceFact(
            location=occurrence.location,
            line=occurrence.line,
            symbol=occurrence.symbol,
            additional_context=occurrence.additional_context,
        )
        for occurrence in evidence.occurrences
    )


def _sbom_tools(bom: Bom, root: Component) -> Tuple[SbomTool, ...]:
    tools: List[SbomTool] = []
    known_components = list(bom.metadata.tools.components)
    known_components.extend(bom.components)
    components_by_ref = {
        component.bom_ref.value: component
        for component in known_components
        if component.bom_ref.value
    }
    for component in bom.metadata.tools.components:
        tools.append(_sbom_tool_from_component(component))
    for tool in bom.metadata.tools.tools:
        tools.append(_sbom_tool_from_tool(tool))
    for service in bom.metadata.tools.services:
        tools.append(SbomTool(name=service.name, version=service.version))
    if root.evidence:
        for identity in root.evidence.identity:
            for ref in identity.tools:
                if ref.value:
                    referenced = components_by_ref.get(ref.value)
                    tools.append(
                        _sbom_tool_from_component(referenced)
                        if referenced
                        else SbomTool(name=ref.value, bom_ref=ref.value)
                    )
    return tuple(_deduplicate_tools(tools))


def _sbom_tool_from_component(component: Component) -> SbomTool:
    sha256 = next(
        (
            value
            for item in component.hashes
            if item.alg is HashAlgorithm.SHA_256
            for value in (_normalize_sha256(item.content),)
            if value
        ),
        None,
    )
    repository = next(
        (
            str(reference.url)
            for reference in component.external_references
            if reference.type in (
                ExternalReferenceType.VCS,
                ExternalReferenceType.DISTRIBUTION,
                ExternalReferenceType.SOURCE_DISTRIBUTION,
            )
        ),
        None,
    )
    return SbomTool(
        name=component.name,
        version=component.version,
        sha256=sha256,
        repository=repository,
        bom_ref=component.bom_ref.value,
    )


def _sbom_tool_from_tool(tool: Tool) -> SbomTool:
    sha256 = next(
        (
            value
            for item in tool.hashes
            if item.alg is HashAlgorithm.SHA_256
            for value in (_normalize_sha256(item.content),)
            if value
        ),
        None,
    )
    repository = next(
        (
            str(reference.url)
            for reference in tool.external_references
            if reference.type in (
                ExternalReferenceType.VCS,
                ExternalReferenceType.DISTRIBUTION,
                ExternalReferenceType.SOURCE_DISTRIBUTION,
            )
        ),
        None,
    )
    return SbomTool(name=tool.name, version=tool.version, sha256=sha256, repository=repository)


def _deduplicate_tools(tools: Iterable[SbomTool]) -> List[SbomTool]:
    seen: Set[Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]] = set()
    result: List[SbomTool] = []
    for tool in tools:
        key = (tool.name, tool.version, tool.sha256, tool.repository, tool.bom_ref)
        if key in seen:
            continue
        seen.add(key)
        result.append(tool)
    return result


def _first_component(bom: Bom) -> Optional[Component]:
    return next(iter(bom.components), None)


def _release_id_from_properties(component: Component) -> Optional[str]:
    for prop in component.properties:
        name = prop.name.casefold()
        if name == 'acme:release_id' or name.endswith('release_id') or name.endswith('release-id'):
            if prop.value:
                return prop.value
    return None


def _release_id_from_purl(component: Component) -> Optional[str]:
    if not component.purl:
        return None
    for key, value in (component.purl.qualifiers or {}).items():
        if key.casefold() in ('release_id', 'release-id'):
            return value
    return None


def _release_id_from_occurrences(occurrences: Iterable[OccurrenceFact]) -> Optional[str]:
    pattern = re.compile(r'release[_-]?id\s*[=:]\s*([A-Za-z0-9._-]+)', re.IGNORECASE)
    for occurrence in occurrences:
        if occurrence.additional_context:
            match = pattern.search(occurrence.additional_context)
            if match:
                return match.group(1)
    return None


def _single_or_none(values: FrozenSet[str]) -> Optional[str]:
    return next(iter(values)) if len(values) == 1 else None


def _tool_reason_detail(code: str) -> str:
    return _TOOL_REASON_DETAILS.get(code, code.replace('_', ' '))


_TOOL_REASON_DETAILS: Dict[str, str] = {
    'tool_not_named_in_advisory': 'the tool is not named in the advisory',
    'tool_source_digest_matches_advisory': 'the observed tool source digest matches the advisory',
    'tool_source_commit_matches_advisory': 'the observed tool source commit matches the advisory',
    'tool_source_does_not_match_advisory': 'the observed tool source does not match the advisory',
    'tool_version_missing': 'the frozen build does not record the tool version',
    'tool_version_not_affected': 'the tool version is not in the affected set',
    'tool_usage_time_missing': 'the affected version has no recorded fetch or use time',
    'tool_observed_before_affected_distribution':
        'the affected version was observed before the advisory distribution window',
    'affected_version_without_confirmable_source':
        'an affected version was observed around the distribution window but its source is not confirmable',
    'sbom_tool_version_conflicts_with_frozen_build':
        'the SBOM tool version conflicts with the frozen build record',
    'sbom_tool_digest_conflicts_with_frozen_build':
        'the SBOM tool digest conflicts with the frozen build record',
    'sbom_tool_digest_not_confirmed_by_frozen_build':
        'the SBOM declares a tool digest that the frozen build cannot confirm',
}


def _commit_prefix_match(observed: str, affected: str) -> bool:
    if observed == affected:
        return True
    shortest = min(len(observed), len(affected))
    if shortest < 7:
        return False
    return observed.startswith(affected) or affected.startswith(observed)


def _version_in_range(version: str, version_range: str) -> bool:
    clauses = [clause.strip() for clause in version_range.split(',') if clause.strip()]
    if not clauses:
        return False
    return all(_version_clause_matches(version, clause) for clause in clauses)


def _version_clause_matches(version: str, clause: str) -> bool:
    for operator in ('>=', '<=', '==', '>', '<'):
        if clause.startswith(operator):
            target = _version_key(clause[len(operator):].strip())
            current = _version_key(version)
            if operator == '>=':
                return current >= target
            if operator == '<=':
                return current <= target
            if operator == '==':
                return current == target
            if operator == '>':
                return current > target
            return current < target
    return _version_key(version) == _version_key(clause)


def _version_key(version: str) -> Tuple[Tuple[int, Any], ...]:
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.casefold())
        for part in re.split(r'[._+-]', version)
    )


def _normalize_sha256(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    match = re.search(r'(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])', value)
    return match.group(1).casefold() if match else None


def _as_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AssessmentError(f'{context} must be a JSON object')
    return value


def _required_str(raw: Mapping[str, Any], key: str, context: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise AssessmentError(f'{context} requires a non-empty string "{key}"')
    return value


def _optional_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _required_sha256(raw: Mapping[str, Any], key: str, context: str) -> str:
    value = _normalize_sha256(_optional_str(raw.get(key)))
    if not value:
        raise AssessmentError(f'{context} requires a 64-hex "{key}"')
    return value


def _str_set(value: Any) -> FrozenSet[str]:
    return frozenset(item for item in _str_tuple(value) if item)


def _str_tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _required_datetime(raw: Mapping[str, Any], key: str, context: str) -> datetime:
    value = _optional_datetime(raw.get(key), f'{context}.{key}')
    if value is None:
        raise AssessmentError(f'{context} requires an ISO-8601 "{key}"')
    return value


def _optional_datetime(value: Any, context: str) -> Optional[datetime]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AssessmentError(f'{context} must be an ISO-8601 string')
    normalized = value[:-1] + '+00:00' if value.endswith('Z') else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise AssessmentError(f'{context} is not a valid ISO-8601 timestamp: {value!r}') from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
