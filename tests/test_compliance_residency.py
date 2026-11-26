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

from typing import Optional
from unittest import TestCase

from cyclonedx.compliance import ViolationCode, check_residency
from cyclonedx.model import DataClassification, DataFlow, Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service


def _service(ref: str, country: str, proof: Optional[str] = None, category: str = 'PII') -> dict:
    properties = [{'name': 'residency:proof', 'value': proof}] if proof else []
    return {
        'bom-ref': ref,
        'name': ref,
        'provider': {'address': {'country': country}},
        'data': [{'classification': category, 'flow': 'bi-directional'}],
        'properties': properties,
    }


class TestResidencyCompliance(TestCase):

    def test_failover_and_primary_share_two_intermediate_services(self) -> None:
        services = [
            _service('entry', 'DE', 'proof:entry'),
            _service('primary-1', 'DE', 'proof:p1'),
            _service('primary-2', 'DE', 'proof:p2'),
            _service('primary-3', 'DE', 'proof:p3'),
            _service('backup-1', 'US', 'proof:b1'),
            _service('backup-2', 'DE', 'proof:b2'),
            _service('shared-1', 'DE', 'proof:s1'),
            _service('shared-2', 'DE', 'proof:s2'),
            _service('end-eu', 'DE', 'proof:e1'),
            _service('end-us', 'US', 'proof:e2'),
            _service('end-noproof', 'DE'),
            _service('end-failover-only', 'US', 'proof:b3'),
            _service('end-unreachable', 'US'),
        ]
        dependencies = [
            {'ref': 'entry', 'dependsOn': ['primary-1', 'backup-1']},
            {'ref': 'primary-1', 'dependsOn': ['primary-2']},
            {'ref': 'primary-2', 'dependsOn': ['primary-3']},
            {'ref': 'primary-3', 'dependsOn': ['shared-1']},
            {'ref': 'backup-1', 'dependsOn': ['backup-2']},
            {'ref': 'backup-2', 'dependsOn': ['shared-1', 'end-failover-only']},
            {'ref': 'shared-1', 'dependsOn': ['shared-2']},
            {'ref': 'shared-2', 'dependsOn': ['end-eu', 'end-us', 'end-noproof']},
        ]
        manifest = {
            'services': services,
            'dependencies': dependencies,
            'x-residency': {
                'entrypoints': ['entry'],
                'edges': [{'from': 'entry', 'to': 'backup-1', 'condition': 'failover'}],
            },
        }
        report = check_residency(manifest, {'PII': ['EU']})
        self.assertEqual(
            {'end-eu', 'end-us', 'end-noproof', 'end-failover-only'},
            {finding.endpoint for finding in report.non_compliant_endpoints},
        )
        self.assertEqual(
            ('end-eu', 'end-failover-only', 'end-noproof', 'end-us'),
            report.reachable_endpoints,
        )
        self.assertNotIn('end-unreachable', report.reachable_endpoints)
        eu = next(finding for finding in report.non_compliant_endpoints if finding.endpoint == 'end-eu')
        self.assertTrue(eu.has_compliant_path)
        self.assertEqual(
            ('entry', 'backup-1', 'backup-2', 'shared-1', 'shared-2', 'end-eu'),
            eu.path.refs,
        )
        self.assertIn('shared-1', eu.path.refs)
        self.assertIn('shared-2', eu.path.refs)
        no_proof = next(finding for finding in report.non_compliant_endpoints
                        if finding.endpoint == 'end-noproof')
        self.assertTrue(any(violation.code is ViolationCode.PROOF_MISSING for violation in no_proof.violations))
        self.assertIn(no_proof, report.unverified_endpoints)
        self.assertTrue(any(step.proofs for step in no_proof.path.steps))
        self.assertTrue(any(not step.proofs for step in no_proof.path.steps))

    def test_disabled_condition_is_reported_separately(self) -> None:
        services = [
            _service('entry', 'DE', 'proof:entry'),
            _service('primary', 'DE', 'proof:primary'),
            _service('backup', 'US', 'proof:backup'),
            _service('primary-end', 'DE', 'proof:primary-end'),
            _service('backup-end', 'US', 'proof:backup-end'),
        ]
        manifest = {
            'services': services,
            'dependencies': [
                {'ref': 'entry', 'dependsOn': ['primary', 'backup']},
                {'ref': 'primary', 'dependsOn': ['primary-end']},
                {'ref': 'backup', 'dependsOn': ['backup-end']},
            ],
            'x-residency': {
                'entrypoints': ['entry'],
                'edges': [{'from': 'entry', 'to': 'backup', 'condition': 'failover'}],
            },
        }
        report = check_residency(manifest, {'PII': ['EU']}, enabled_conditions=[])
        self.assertEqual(('primary-end',), report.reachable_endpoints)
        self.assertEqual((), report.non_compliant_endpoints)
        self.assertEqual(1, len(report.conditions_disabled))
        self.assertEqual('condition_not_enabled', report.conditions_disabled[0].reason)
        self.assertNotIn('backup-end', report.reachable_endpoints)

    def test_circular_dependency_terminates_and_is_reported(self) -> None:
        services = [
            _service('a', 'DE', 'proof:a'),
            _service('b', 'DE', 'proof:b'),
            _service('c', 'DE', 'proof:c'),
            _service('end', 'DE', 'proof:end'),
        ]
        report = check_residency({
            'services': services,
            'dependencies': [
                {'ref': 'a', 'dependsOn': ['b']},
                {'ref': 'b', 'dependsOn': ['c']},
                {'ref': 'c', 'dependsOn': ['a', 'end']},
            ],
            'x-residency': {'entrypoints': ['a']},
        }, {'PII': ['EU']})
        self.assertEqual(('end',), report.reachable_endpoints)
        self.assertEqual(1, len(report.cycles))
        self.assertEqual(('a', 'b', 'c', 'a'), report.cycles[0].refs)

    def test_region_declaration_without_proof_is_not_silently_compliant(self) -> None:
        manifest = {
            'services': [_service('end', 'DE')],
            'x-residency': {'entrypoints': ['end'], 'endpoints': ['end']},
        }
        report = check_residency(manifest, {'PII': ['EU']})
        self.assertEqual(('end',), report.reachable_endpoints)
        self.assertEqual(1, len(report.non_compliant_endpoints))
        self.assertTrue(any(
            violation.code is ViolationCode.PROOF_MISSING
            for violation in report.non_compliant_endpoints[0].violations
        ))
        declaration_only = check_residency(manifest, {'PII': ['EU']}, require_proof=False)
        self.assertTrue(declaration_only.is_compliant)

    def test_bom_model_input(self) -> None:
        services = [
            Service(
                name='gateway', bom_ref='gateway',
                data=[DataClassification(flow=DataFlow.INBOUND, classification='PII')],
                properties=[
                    Property(name='residency:region', value='DE'),
                    Property(name='residency:proof', value='proof:gateway'),
                ],
            ),
            Service(
                name='store', bom_ref='store',
                data=[DataClassification(flow=DataFlow.BI_DIRECTIONAL, classification='PII')],
                properties=[
                    Property(name='residency:region', value='US'),
                    Property(name='residency:proof', value='proof:store'),
                ],
            ),
        ]
        bom = Bom(
            services=services,
            dependencies=[Dependency(ref=services[0].bom_ref, dependencies=[
                Dependency(ref=services[1].bom_ref),
            ])],
        )
        report = check_residency(bom, {'PII': ['EU']})
        self.assertEqual(('store',), report.reachable_endpoints)
        self.assertEqual(('store',), tuple(item.endpoint for item in report.non_compliant_endpoints))
