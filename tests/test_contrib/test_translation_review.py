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

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from cyclonedx.contrib.vulnerability.translation_review import (
    AnalysisClaim,
    LanguageFallbackPolicy,
    TranslationManifest,
    TranslationRecord,
    check_release,
)
from cyclonedx.model.impact_analysis import ImpactAnalysisJustification, ImpactAnalysisState
from cyclonedx.model.vulnerability import BomTarget, Vulnerability, VulnerabilityAnalysis


class TranslationReviewTest(TestCase):

    def _vulnerability(self, vulnerability_id: str, ref: str, action: str) -> Vulnerability:
        return Vulnerability(
            id=vulnerability_id,
            analysis=VulnerabilityAnalysis(
                state=ImpactAnalysisState.RESOLVED,
                justification=ImpactAnalysisJustification.CODE_NOT_PRESENT,
                detail=action,
            ),
            affects=[BomTarget(ref=ref)],
        )

    def test_changed_action_only_invalidates_matching_vulnerability_translations(self) -> None:
        current_action = 'Upgrade component to 2.0'
        claim = AnalysisClaim(
            state=ImpactAnalysisState.RESOLVED.value,
            justification=ImpactAnalysisJustification.CODE_NOT_PRESENT.value,
            action_statement=current_action,
        )
        manifest = TranslationManifest([
            TranslationRecord('CVE-1', 'component@1', 'ja-JP').sign(claim, by='ja-reviewer'),
            TranslationRecord('CVE-1', 'component@1', 'en-US').sign(claim, by='en-reviewer'),
            TranslationRecord('CVE-2', 'other@1', 'ja-JP').sign(claim, by='other-reviewer'),
            TranslationRecord('CVE-2', 'other@1', 'en-US').sign(claim, by='other-en-reviewer'),
        ])
        vulnerabilities = [
            self._vulnerability('CVE-1', 'component@1', current_action),
            self._vulnerability('CVE-2', 'other@1', current_action),
        ]

        before = check_release(vulnerabilities, manifest, languages=['ja-JP', 'en-US'])
        self.assertTrue(before.can_release)
        self.assertEqual(4, len(before.approved))

        vulnerabilities[0].analysis.detail = 'Upgrade component to 2.0.1'
        after = check_release(vulnerabilities, manifest, languages=['ja-JP', 'en-US'])

        stale = after.stale
        self.assertEqual(2, len(stale))
        self.assertEqual({'CVE-1'}, {item.vulnerability_id for item in stale})
        self.assertEqual({'action_statement'}, set(stale[0].changed_fields))
        self.assertFalse(after.can_release)

        other_report = after.for_vulnerability('CVE-2')
        self.assertTrue(other_report.can_release)
        self.assertTrue(other_report.get('CVE-2', 'other@1', 'ja-JP').approved)
        self.assertTrue(other_report.get('CVE-2', 'other@1', 'en-US').approved)

    def test_stale_locale_is_not_authorized_by_approved_fallback_locale(self) -> None:
        old_japanese_claim = AnalysisClaim('in_triage', None, 'Waiting for investigation')
        current_english_claim = AnalysisClaim('resolved', 'code_not_present', 'Upgrade to 2.0')
        manifest = TranslationManifest([
            TranslationRecord('CVE-1', 'component@1', 'ja').sign(old_japanese_claim, by='ja'),
            TranslationRecord('CVE-1', 'component@1', 'en').sign(current_english_claim, by='en'),
        ])
        vulnerability = self._vulnerability('CVE-1', 'component@1', 'Upgrade to 2.0')
        vulnerability.analysis.state = ImpactAnalysisState.RESOLVED
        vulnerability.analysis.justification = ImpactAnalysisJustification.CODE_NOT_PRESENT

        report = check_release(
            [vulnerability], manifest, languages=['ja'], fallback_languages={'ja': 'en'}
        )

        japanese = report.get('CVE-1', 'component@1', 'ja')
        self.assertTrue(japanese.needs_review)
        self.assertEqual('needs_review', japanese.status)
        self.assertEqual('stale', japanese.status)
        self.assertEqual('en', japanese.fallback_language)
        self.assertEqual('en', japanese.fallback_record.language)
        self.assertFalse(japanese.fallback_used)
        self.assertFalse(report.can_release)

    def test_fallback_record_keeps_its_own_audience_scope(self) -> None:
        claim = AnalysisClaim('resolved', 'code_not_present', 'Upgrade to 2.0')
        manifest = TranslationManifest([
            TranslationRecord('CVE-1', 'component@1', 'en').sign(claim, by='en'),
        ])
        vulnerability = self._vulnerability('CVE-1', 'component@1', 'Upgrade to 2.0')

        unresolved = check_release(
            [vulnerability], manifest, languages=['ja'], fallback_languages={'ja': 'en'}
        )
        result = unresolved.get('CVE-1', 'component@1', 'ja')
        self.assertEqual('fallback_unauthorized', result.status)
        self.assertEqual('en', result.fallback_language)
        self.assertFalse(result.approved)
        self.assertFalse(result.has_release_basis)

        authorized = check_release(
            [vulnerability],
            manifest,
            languages=['ja'],
            fallback_languages={'ja': 'en'},
            authorize_fallback=True,
        )
        fallback_result = authorized.get('CVE-1', 'component@1', 'ja')
        self.assertEqual('approved_via_fallback', fallback_result.status)
        self.assertFalse(fallback_result.approved)
        self.assertTrue(fallback_result.has_release_basis)
        self.assertEqual('release_fallback_policy', fallback_result.authorization_source)
        self.assertEqual('en', fallback_result.record.language)

    def test_manifest_is_local_json_checklist_keyed_by_vulnerability_and_target(self) -> None:
        raw_manifest = {
            'records': [
                {
                    'vulnerability_id': 'CVE-9',
                    'affected_ref': 'pkg:example/lib@1.0',
                    'locale': 'de-DE',
                    'state': 'resolved',
                    'justification': 'code_not_reachable',
                    'action_statement': 'Apply vendor patch',
                    'approved': True,
                    'approved_by': 'reviewer',
                }
            ]
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'translations.json'
            path.write_text(__import__('json').dumps(raw_manifest), encoding='utf-8')
            manifest = TranslationManifest.load(path)

        vulnerability = Vulnerability(
            id='CVE-9',
            analysis=VulnerabilityAnalysis(
                state=ImpactAnalysisState.RESOLVED,
                justification=ImpactAnalysisJustification.CODE_NOT_REACHABLE,
                detail='Apply vendor patch',
            ),
            affects=[BomTarget(ref='pkg:example/lib@1.0')],
        )
        report = check_release(vulnerability, manifest, locales=['de-DE'])
        result = report.get('CVE-9', 'pkg:example/lib@1.0', 'de-DE')
        self.assertTrue(result.approved)
        self.assertTrue(report.can_release)

    def test_policy_accepts_explicit_audience_scope_on_record(self) -> None:
        claim = AnalysisClaim('resolved', None, 'Patch now')
        record = TranslationRecord(
            vulnerability_id='CVE-1',
            affected_ref='lib',
            language='en',
            audiences=['ja'],
        ).sign(claim)
        policy = LanguageFallbackPolicy({'ja': 'en'})

        authorized, source = policy.is_authorized('ja', 'en', record)

        self.assertTrue(authorized)
        self.assertEqual('record_audience_scope', source)
