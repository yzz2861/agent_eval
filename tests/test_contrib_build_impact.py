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

from datetime import datetime, timezone
from glob import glob
from json import loads as json_loads
from os.path import join
from unittest import TestCase

from cyclonedx.contrib.build_impact import (
    ArchiveNotFrozenError,
    FrozenBuildArchive,
    ImpactStatus,
    ToolAdvisory,
    ToolInvocation,
    ToolSource,
    ToolVerdict,
    assess,
    evaluate_tool_invocation,
    load_observations,
    render_csv,
    render_json,
    render_markdown,
)
from tests import PROJECT_ROOT_DIRECTORY

DATA_DIRECTORY = join(PROJECT_ROOT_DIRECTORY, 'examples', 'build_tool_impact', 'data')
ARCHIVE_PATH = join(DATA_DIRECTORY, 'frozen-build-archive.json')
ADVISORY_PATH = join(DATA_DIRECTORY, 'tool-advisory.json')
SBOM_GLOB = join(DATA_DIRECTORY, 'sbom', '*.json')


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


class TestBuildImpactAssessment(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.archive = FrozenBuildArchive.load(ARCHIVE_PATH)
        cls.advisory = ToolAdvisory.load(ADVISORY_PATH)
        cls.observations = load_observations(glob(SBOM_GLOB))
        cls.report = assess(cls.archive, cls.advisory, cls.observations)
        cls.by_id = {finding.package_id: finding for finding in cls.report.findings}

    def test_archive_is_frozen_and_has_six_builds(self) -> None:
        self.assertEqual('ACME-BBA-2026-05-31', self.archive.archive_id)
        self.assertEqual(6, len(self.archive.builds))
        self.assertEqual(datetime(2026, 5, 31, 12, 0, tzinfo=timezone.utc), self.archive.frozen_at)

    def test_non_frozen_archive_is_rejected(self) -> None:
        with self.assertRaises(ArchiveNotFrozenError):
            FrozenBuildArchive.from_dict({
                'archive_id': 'NOT-FROZEN',
                'frozen': False,
                'frozen_at': '2026-05-31T12:00:00Z',
                'builds': [],
            })

    def test_component_and_evidence_objects_are_used(self) -> None:
        observation = next(item for item in self.observations if item.release_id == 'REL-EU-BAD')
        self.assertEqual(self.report.findings[0].sha256, observation.sha256)
        self.assertEqual(observation.declared_sha256, observation.evidence_sha256)
        self.assertFalse(observation.sha256_conflict)
        self.assertEqual(1, len(observation.occurrences))
        self.assertIn('release_id=REL-EU-BAD', observation.occurrences[0].additional_context or '')
        self.assertEqual(['forgepack'], [tool.name for tool in observation.sbom_tools])
        self.assertIsNone(observation.sbom_tools[0].sha256)
        self.assertEqual('tool:forgepack', observation.sbom_tools[0].bom_ref)

    def test_summary_counts(self) -> None:
        self.assertEqual(6, len(self.report.findings))
        self.assertEqual(1, len(self.report.affected))
        self.assertEqual(4, len(self.report.not_affected))
        self.assertEqual(1, len(self.report.tool_unconfirmed))
        self.assertEqual(1, len(self.report.requires_tool_provenance_reverification))

    def test_identical_digest_does_not_imply_identical_conclusion(self) -> None:
        self.assertEqual(1, len(self.report.same_digest_cohorts))
        cohort = self.report.same_digest_cohorts[0]
        self.assertEqual(6, len(cohort.package_ids))
        self.assertEqual({cohort.sha256}, {finding.sha256 for finding in self.report.findings})
        self.assertFalse(cohort.conclusion_consistent)
        self.assertEqual(('REL-LATAM-COPY',), cohort.requires_tool_provenance_reverification)

    def test_release_identifier_does_not_fall_back_to_a_matching_digest(self) -> None:
        digest = '84ff0b62b508841b3010e8707eb0b0c9463bb8a052580903b08f93c30829cda0'
        record, code = self.archive.find_build(
            release_id='REL-UNKNOWN', sha256=digest, name='orders-api', version='4.2.0',
        )
        self.assertIsNone(record)
        self.assertEqual('no_frozen_build_record_for_release_id', code)

    def test_digest_only_match_is_ambiguous_for_this_cohort(self) -> None:
        digest = '84ff0b62b508841b3010e8707eb0b0c9463bb8a052580903b08f93c30829cda0'
        record, code = self.archive.find_build(
            release_id=None, sha256=digest, name='orders-api', version='4.2.0',
        )
        self.assertIsNone(record)
        self.assertEqual('ambiguous_artifact_digest_in_frozen_archive', code)

    def test_affected_package_is_matched_by_observed_tool_source(self) -> None:
        finding = self.by_id['REL-EU-BAD']
        self.assertIs(ImpactStatus.AFFECTED, finding.status)
        self.assertEqual('tool_source_digest_matches_advisory', finding.reason_code)
        self.assertEqual('B-4102', finding.build_id)
        self.assertFalse(finding.requires_tool_provenance_reverification)
        self.assertEqual('2.4.1', finding.tool_observations[0].version)
        self.assertEqual(
            '9f2c7d1e4b6a8c0d2e4f60718293a4b5c6d7e8f9',
            finding.tool_observations[0].source.commit if finding.tool_observations[0].source else None,
        )

    def test_affected_version_with_pinned_clean_source_is_cleared(self) -> None:
        finding = self.by_id['REL-CN-PINNED']
        self.assertIs(ImpactStatus.NOT_AFFECTED, finding.status)
        self.assertEqual('2.4.1', finding.tool_observations[0].version)
        self.assertEqual('tool_source_does_not_match_advisory', finding.tool_observations[0].reason_code)

    def test_rebuild_is_evaluated_from_its_own_build_record(self) -> None:
        finding = self.by_id['REL-APAC-REBUILD']
        self.assertIs(ImpactStatus.NOT_AFFECTED, finding.status)
        self.assertEqual('independent_rebuild', finding.conclusion_basis)
        self.assertTrue(finding.inherited_conclusion_blocked)
        self.assertEqual('B-4103', finding.build_id)
        self.assertEqual('B-4101', finding.source_build_id)
        self.assertIs(ImpactStatus.NOT_AFFECTED, finding.source_build_status)

    def test_copy_cannot_inherit_source_build_conclusion(self) -> None:
        finding = self.by_id['REL-LATAM-COPY']
        self.assertIs(ImpactStatus.TOOL_UNCONFIRMED, finding.status)
        self.assertEqual('copied_artifact_does_not_inherit_build_conclusion', finding.reason_code)
        self.assertTrue(finding.requires_tool_provenance_reverification)
        self.assertTrue(finding.inherited_conclusion_blocked)
        self.assertEqual('B-4105', finding.build_id)
        self.assertEqual('B-4101', finding.source_build_id)
        self.assertIs(ImpactStatus.NOT_AFFECTED, finding.source_build_status)
        self.assertEqual((), finding.tool_observations)

    def test_only_one_package_requires_tool_source_reverification(self) -> None:
        required = [finding.package_id for finding in self.report.requires_tool_provenance_reverification]
        self.assertEqual(['REL-LATAM-COPY'], required)

    def test_unconfirmed_items_are_not_counted_as_clean(self) -> None:
        unconfirmed_ids = {finding.package_id for finding in self.report.tool_unconfirmed}
        clean_ids = {finding.package_id for finding in self.report.not_affected}
        self.assertFalse(unconfirmed_ids & clean_ids)
        self.assertEqual({'REL-LATAM-COPY'}, unconfirmed_ids)

    def test_markdown_answer_names_the_single_reverification_candidate(self) -> None:
        markdown = render_markdown(self.report)
        self.assertIn('Only `REL-LATAM-COPY` must re-verify tool provenance.', markdown)
        self.assertIn('does not inherit', markdown)
        self.assertIn('Tool provenance unconfirmed (separate list)', markdown)

    def test_json_report_is_deterministic_and_contains_required_sections(self) -> None:
        first = render_json(self.report)
        second = render_json(self.report)
        self.assertEqual(first, second)
        parsed = json_loads(first)
        self.assertEqual(1, parsed['summary']['requires_tool_provenance_reverification'])
        self.assertEqual(['REL-LATAM-COPY'], parsed['requires_tool_provenance_reverification'])
        self.assertEqual(['REL-LATAM-COPY'], parsed['tool_provenance_unconfirmed'])
        self.assertFalse(parsed['same_digest_cohorts'][0]['conclusion_consistent'])

    def test_csv_audit_sheet_has_one_row_per_package(self) -> None:
        lines = render_csv(self.report).strip().splitlines()
        self.assertEqual(7, len(lines))
        self.assertTrue(any('REL-LATAM-COPY' in line and ',yes,' in line for line in lines[1:]))

    def test_source_match_outranks_version_label(self) -> None:
        invocation = ToolInvocation(
            tool='forgepack',
            version='2.4.4',
            source=ToolSource(
                repository='https://github.com/acme/forgepack',
                commit='9f2c7d1e4b6a8c0d2e4f60718293a4b5c6d7e8f9',
                sha256='3eb43e330685dc080bcc76520721f6ae390a1a452886d122bc653d48007dd978',
            ),
            fetched_at=_dt('2026-04-10T00:00:00Z'),
            used_at=_dt('2026-04-10T01:00:00Z'),
        )
        verdict, reason = evaluate_tool_invocation(self.advisory, invocation)
        self.assertIs(ToolVerdict.AFFECTED, verdict)
        self.assertEqual('tool_source_digest_matches_advisory', reason)

    def test_affected_version_without_source_is_unconfirmed_after_window_start(self) -> None:
        invocation = ToolInvocation(
            tool='forgepack',
            version='2.4.1',
            source=None,
            fetched_at=_dt('2026-03-10T00:00:00Z'),
            used_at=_dt('2026-03-11T00:00:00Z'),
        )
        verdict, reason = evaluate_tool_invocation(self.advisory, invocation)
        self.assertIs(ToolVerdict.UNCONFIRMED, verdict)
        self.assertEqual('affected_version_without_confirmable_source', reason)

    def test_affected_version_before_distribution_window_is_clear(self) -> None:
        invocation = ToolInvocation(
            tool='forgepack',
            version='2.4.1',
            source=None,
            fetched_at=_dt('2026-02-01T00:00:00Z'),
            used_at=_dt('2026-02-02T00:00:00Z'),
        )
        verdict, reason = evaluate_tool_invocation(self.advisory, invocation)
        self.assertIs(ToolVerdict.NOT_AFFECTED, verdict)
        self.assertEqual('tool_observed_before_affected_distribution', reason)

    def test_advisory_version_range_is_supported(self) -> None:
        advisory = ToolAdvisory.from_dict({
            'advisory_id': 'TEST-1',
            'tool': 'forgepack',
            'affected_version_range': '>=2.4.0,<2.4.3',
        })
        self.assertTrue(advisory.version_affected('2.4.0'))
        self.assertTrue(advisory.version_affected('2.4.2'))
        self.assertFalse(advisory.version_affected('2.4.3'))
        self.assertFalse(advisory.version_affected('2.3.9'))
