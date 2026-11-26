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

import json
from typing import Any
from unittest import TestCase
from uuid import UUID

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType, Swid
from cyclonedx.model.contact import OrganizationalContact
from cyclonedx.model.impact_analysis import ImpactAnalysisState
from cyclonedx.model.vulnerability import (
    BomTarget,
    Vulnerability,
    VulnerabilityAnalysis,
    VulnerabilityReference,
    VulnerabilitySource,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.view import (
    ANONYMOUS_VULNERABILITY_ID,
    DISCLOSURE_AUTHORIZATION_SOURCE_PROPERTY,
    DISCLOSURE_STATE_PROPERTY,
    DisclosurePolicy,
    DisclosureState,
    DisclosureView,
    FieldDecisionAction,
    project_bom,
)


class ViewProjectionTest(TestCase):

    def test_withdrawn_vulnerability_keeps_anonymous_placeholder_and_closed_refs(self) -> None:
        bom = _make_bom()

        projection = project_bom(bom, DisclosurePolicy(view=DisclosureView.PROCUREMENT_COMMITTEE))

        vulnerability = next(iter(projection.bom.vulnerabilities))
        self.assertEqual(ANONYMOUS_VULNERABILITY_ID, vulnerability.id)
        self.assertEqual('vulnerability-1', vulnerability.bom_ref.value)
        self.assertEqual('component-1', next(iter(vulnerability.affects)).ref)
        self.assertEqual('component-1', next(iter(projection.bom.components)).bom_ref.value)
        self.assertEqual(0, len(vulnerability.references))
        self.assertEqual(ImpactAnalysisState.FALSE_POSITIVE, vulnerability.analysis.state)

    def test_technical_withdrawal_only_withdraws_authorized_fields(self) -> None:
        bom = _make_bom()

        before = _json_document(bom)
        outputter = make_outputter(
            bom, OutputFormat.JSON, SchemaVersion.V1_6,
            view_policy=DisclosurePolicy(view=DisclosureView.TECHNICAL),
        )
        after = json.loads(outputter.output_as_string())

        changed_paths = _changed_paths(before, after)
        self.assertEqual(
            {
                'vulnerabilities[0].id',
                'vulnerabilities[0].description',
                'vulnerabilities[0].references',
                'vulnerabilities[0].source',
            },
            changed_paths,
        )
        self.assertEqual(
            ANONYMOUS_VULNERABILITY_ID,
            after['vulnerabilities'][0]['id'],
        )
        withdrawn = {
            decision.path: decision
            for decision in outputter.view_audit.decisions
            if decision.action is FieldDecisionAction.WITHDRAW
        }
        self.assertEqual(
            {
                'vulnerabilities[0].advisories',
                'vulnerabilities[0].created',
                'vulnerabilities[0].credits',
                'vulnerabilities[0].cwes',
                'vulnerabilities[0].description',
                'vulnerabilities[0].detail',
                'vulnerabilities[0].id',
                'vulnerabilities[0].published',
                'vulnerabilities[0].ratings',
                'vulnerabilities[0].recommendation',
                'vulnerabilities[0].references',
                'vulnerabilities[0].references[0].id',
                'vulnerabilities[0].references[0].source',
                'vulnerabilities[0].source',
                'vulnerabilities[0].tools',
                'vulnerabilities[0].updated',
                'vulnerabilities[0].workaround',
            },
            set(withdrawn),
        )
        self.assertTrue(all(
            decision.authorization_source == 'review-team'
            for decision in outputter.view_audit.decisions
            if decision.path.startswith('vulnerabilities[0]')
        ))

    def test_procurement_policy_applies_identically_to_json_and_xml(self) -> None:
        bom = _make_bom()
        policy = DisclosurePolicy(view=DisclosureView.PROCUREMENT_COMMITTEE)
        for schema_version in (
            SchemaVersion.V1_4,
            SchemaVersion.V1_5,
            SchemaVersion.V1_6,
            SchemaVersion.V1_7,
        ):
            with self.subTest(schema_version=schema_version):
                json_outputter = make_outputter(bom, OutputFormat.JSON, schema_version, view_policy=policy)
                xml_outputter = make_outputter(bom, OutputFormat.XML, schema_version, view_policy=policy)
                json_document = json.loads(json_outputter.output_as_string())
                xml_document = xml_outputter.output_as_string()

                self.assertEqual(
                    ['component-1'],
                    [component['bom-ref'] for component in json_document['components']],
                )
                self.assertEqual(
                    ['vulnerability-1'],
                    [vulnerability['bom-ref'] for vulnerability in json_document['vulnerabilities']],
                )
                self.assertEqual(
                    'component-1',
                    json_document['vulnerabilities'][0]['affects'][0]['ref'],
                )
                self.assertIn('bom-ref="vulnerability-1"', xml_document)
                self.assertIn('<ref>component-1</ref>', xml_document)
                self.assertIn(f'<id>{ANONYMOUS_VULNERABILITY_ID}</id>', xml_document)
                self.assertNotIn('secret description', xml_document)
                self.assertEqual(json_outputter.view_audit, xml_outputter.view_audit)

    def test_legacy_mapping_and_nested_identity_are_adjudicated(self) -> None:
        nested = Component(
            name='nested', bom_ref='nested-1', description='nested secret', cpe='cpe:nested',
        )
        component = Component(
            name='component', bom_ref='component-1', description='secret', cpe='cpe:component',
            authors=[OrganizationalContact(name='legacy author')],
            swid=Swid(tag_id='legacy-tag', name='legacy-swid'), components=[nested],
        )
        bom = Bom(components=[component])

        projection = project_bom(bom, DisclosurePolicy(view=DisclosureView.PROCUREMENT_COMMITTEE))

        projected = next(iter(projection.bom.components))
        projected_nested = next(iter(projected.components))
        self.assertIsNone(projected.cpe)
        self.assertEqual(0, len(projected.authors))
        self.assertIsNone(projected_nested.cpe)
        self.assertEqual('nested-1', projected_nested.bom_ref.value)
        decision_paths = {decision.path for decision in projection.audit.decisions}
        self.assertIn('components[0].cpe', decision_paths)
        self.assertIn('components[0].authors', decision_paths)
        self.assertIn('components[0].authors[0].bom_ref', decision_paths)
        self.assertIn('components[0].authors[0].name', decision_paths)
        self.assertIn('components[0].swid.tag_id', decision_paths)
        self.assertIn('components[0].components[0].bom_ref', decision_paths)
        self.assertIn('components[0].components[0].cpe', decision_paths)

    def test_policy_state_overrides_properties_and_preserves_source_bom(self) -> None:
        bom = _make_bom()

        projection = project_bom(
            bom,
            DisclosurePolicy(
                view=DisclosureView.TECHNICAL,
                vulnerability_states={'vulnerability-1': DisclosureState.PUBLIC},
            ),
        )

        vulnerability = next(iter(projection.bom.vulnerabilities))
        self.assertEqual('CVE-2026-0001', vulnerability.id)
        self.assertEqual('secret description', vulnerability.description)
        self.assertEqual('CVE-2026-0001', next(iter(bom.vulnerabilities)).id)
        self.assertEqual('secret', next(iter(bom.components)).description)

    def test_field_authorization_source_can_be_configured(self) -> None:
        bom = _make_bom()

        projection = project_bom(
            bom,
            DisclosurePolicy(
                view=DisclosureView.TECHNICAL,
                authorization_sources={
                    'vulnerabilities[0].description': 'manual-review',
                },
            ),
        )

        decision = next(
            decision for decision in projection.audit.decisions
            if decision.path == 'vulnerabilities[0].description'
        )
        self.assertEqual('manual-review', decision.authorization_source)


def _make_bom() -> Bom:
    component = Component(
        type=ComponentType.LIBRARY,
        name='example-library',
        version='1.2.3',
        bom_ref='component-1',
        description='secret',
        cpe='cpe:2.3:a:example:library:1.2.3:*:*:*:*:*:*:*',
    )
    vulnerability = Vulnerability(
        bom_ref='vulnerability-1',
        id='CVE-2026-0001',
        source=VulnerabilitySource(name='NVD'),
        references=[VulnerabilityReference(
            id='CVE-2026-0001',
            source=VulnerabilitySource(name='NVD'),
        )],
        description='secret description',
        analysis=VulnerabilityAnalysis(state=ImpactAnalysisState.FALSE_POSITIVE),
        affects=[BomTarget(ref='component-1')],
        properties=[
            Property(name=DISCLOSURE_STATE_PROPERTY, value=DisclosureState.WITHDRAWN.value),
            Property(name=DISCLOSURE_AUTHORIZATION_SOURCE_PROPERTY, value='review-team'),
        ],
    )
    return Bom(
        serial_number=UUID('11111111-1111-1111-1111-111111111111'),
        components=[component],
        vulnerabilities=[vulnerability],
    )


def _json_document(bom: Bom) -> dict[str, Any]:
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return json.loads(outputter.output_as_string())


def _changed_paths(left: Any, right: Any, path: str = '') -> set[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        paths: set[str] = set()
        for key in sorted(set(left) | set(right)):
            child_path = f'{path}.{key}' if path else str(key)
            if key not in left or key not in right:
                paths.add(_missing_path(child_path))
            else:
                paths.update(_changed_paths(left[key], right[key], child_path))
        return paths
    if isinstance(left, list) and isinstance(right, list):
        if not left and not right:
            return set()
        if len(left) != len(right):
            if not left or not right:
                return {path}
            changed: set[str] = set()
            for index in range(min(len(left), len(right))):
                changed.update(_changed_paths(left[index], right[index], f'{path}[{index}]'))
            return changed
        paths: set[str] = set()
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            child_path = f'{path}[{index}]'
            paths.update(_changed_paths(left_item, right_item, child_path))
        return paths
    if _is_empty(left) and _is_empty(right):
        return set()
    if type(left) is not type(right):
        return {path}
    return set() if left == right else {path}


def _is_empty(value: Any) -> bool:
    return value is None or value == '' or value == [] or value == {}


def _missing_path(path: str) -> str:
    return path.rsplit('[', 1)[0] if '[' in path and path.endswith(']') else path
