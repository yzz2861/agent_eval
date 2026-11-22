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

from decimal import Decimal
from unittest import TestCase

from cyclonedx.contrib.batch import BatchList, CoverageStatus, PhysicalWitness, ReviewScope, verify_batches
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.component_evidence import ComponentEvidence, Identity, IdentityField, Occurrence


class TestBatchNumberVerifier(TestCase):

    def test_assigns_only_confirmed_and_witnessed_subpackages(self) -> None:
        report = verify_batches(
            [
                {'delivery_batch': 'D1', 'subpackage': 'P1', 'lot': 'L1', 'quantity': 4},
                {'delivery_batch': 'D1', 'subpackage': 'P0', 'lot': 'L1', 'quantity': 2},
                {'delivery_batch': 'D2', 'subpackage': 'P2', 'lot': 'L2', 'quantity': 3},
            ],
            [
                {'evidence_ref': 'CERT-1', 'packages': ['P1']},
                {'evidence_ref': 'CERT-1', 'packages': ['P2']},
            ],
            [
                {'subpackage': 'P1', 'location': 'dock-a'},
                {'subpackage': 'P2', 'location': 'dock-b'},
            ],
        )

        self.assertEqual(Decimal('9'), report.declared_quantity)
        self.assertEqual(Decimal('7'), report.covered_quantity)
        self.assertEqual(Decimal('4'), report.delivery_batches['D1'].covered_quantity)
        self.assertEqual(Decimal('3'), report.delivery_batches['D2'].covered_quantity)
        statuses = {item.subpackage: item.status for item in report.subpackages}
        self.assertIs(CoverageStatus.UNSCOPED, statuses['P0'])
        self.assertIn('reused-evidence', {issue.code for issue in report.issues})

    def test_overlapping_registration_is_counted_once(self) -> None:
        report = verify_batches(
            [
                {'delivery_batch': 'D1', 'subpackage': 'P1', 'quantity': 5},
                {'delivery_batch': 'D1', 'subpackage': 'P1', 'quantity': 3},
            ],
            [{'evidence_ref': 'CERT-1', 'package': 'P1'}],
            [{'package': 'P1'}],
        )

        self.assertEqual(Decimal('5'), report.declared_quantity)
        self.assertEqual(Decimal('5'), report.covered_quantity)
        codes = {issue.code for issue in report.issues}
        self.assertIn('overlapping-registration', codes)
        self.assertIn('quantity-conflict', codes)

    def test_reused_evidence_quantity_is_shared(self) -> None:
        report = verify_batches(
            [
                {'delivery_batch': 'D1', 'subpackage': 'P1', 'quantity': 4},
                {'delivery_batch': 'D2', 'subpackage': 'P2', 'quantity': 4},
            ],
            [
                {'evidence_ref': 'CERT-1', 'packages': ['P1', 'P2'], 'quantity': 6},
                {'evidence_ref': 'CERT-1', 'packages': ['P1', 'P2'], 'quantity': 6},
            ],
            [{'subpackage': 'P1'}, {'subpackage': 'P2'}],
        )

        self.assertEqual(Decimal('6'), report.covered_quantity)
        self.assertEqual(Decimal('6'), report.evidence_allocations['CERT-1'])
        statuses = {item.subpackage: item.status for item in report.subpackages}
        self.assertIs(CoverageStatus.VERIFIED, statuses['P1'])
        self.assertIs(CoverageStatus.PARTIAL, statuses['P2'])

    def test_consolidated_lot_declaration_is_not_apportioned(self) -> None:
        report = verify_batches(
            [
                {'delivery_batch': 'D1', 'subpackage': 'P1', 'lot': 'L1', 'quantity': 4},
                {'delivery_batch': 'D2', 'subpackage': 'P2', 'lot': 'L1', 'quantity': 5},
            ],
            [{'evidence_ref': 'CERT-1', 'lot': 'L1', 'quantity': 9, 'consolidated': True}],
            [{'subpackage': 'P1'}, {'subpackage': 'P2'}],
        )

        self.assertEqual(Decimal('0'), report.covered_quantity)
        self.assertEqual(Decimal('9'), report.unconfirmed_quantity)
        self.assertTrue(all(item.status is CoverageStatus.CONSOLIDATED_UNCONFIRMED for item in report.subpackages))

    def test_scope_without_physical_witness_is_not_covered(self) -> None:
        report = verify_batches(
            [{'delivery_batch': 'D1', 'subpackage': 'P1', 'quantity': 4}],
            [{'evidence_ref': 'CERT-1', 'package': 'P1'}],
            [],
        )

        self.assertEqual(Decimal('0'), report.covered_quantity)
        self.assertIs(CoverageStatus.UNWITNESSED, report.subpackages[0].status)

    def test_dropping_middle_review_scope_reduces_both_delivery_batches(self) -> None:
        batch_list = [
            {'delivery_batch': 'DELIVERY-A', 'subpackage': 'SUB-A', 'quantity': 4},
            {'delivery_batch': 'DELIVERY-B', 'subpackage': 'SUB-B', 'quantity': 3},
        ]
        review_scope = [
            {'evidence_ref': 'CERT-7', 'package': 'SUB-A'},
            {'evidence_ref': 'CERT-7', 'package': 'SUB-B'},
        ]
        physical_witness = [{'package': 'SUB-A'}, {'package': 'SUB-B'}]

        before = verify_batches(batch_list, review_scope, physical_witness)
        after = verify_batches(batch_list, [], physical_witness)
        delta = after.compare(before)

        self.assertEqual(('DELIVERY-A', 'DELIVERY-B'), delta.decreased)
        self.assertIn('DELIVERY-A', delta.describe())
        self.assertIn('DELIVERY-B', delta.describe())

    def test_component_and_evidence_adapters(self) -> None:
        components = [
            Component(
                name='P1',
                bom_ref='P1',
                properties=[
                    Property(name='cdx:batch:delivery', value='D1'),
                    Property(name='cdx:batch:quantity', value='4'),
                ],
            ),
            Component(
                name='P2',
                bom_ref='P2',
                properties=[
                    Property(name='cdx:batch:delivery', value='D2'),
                    Property(name='cdx:batch:quantity', value='3'),
                ],
            ),
        ]
        witness = ComponentEvidence(occurrences=[
            Occurrence(bom_ref='P1', location='dock-a'),
            Occurrence(bom_ref='P2', location='dock-b'),
        ])

        report = verify_batches(
            components,
            [
                {'evidence_ref': 'CERT-1', 'package': 'P1'},
                {'evidence_ref': 'CERT-1', 'package': 'P2'},
            ],
            witness,
        )

        self.assertEqual(Decimal('7'), report.covered_quantity)
        self.assertEqual(Decimal('4'), report.delivery_batches['D1'].covered_quantity)
        self.assertEqual(Decimal('3'), report.delivery_batches['D2'].covered_quantity)

    def test_grouped_delivery_batches(self) -> None:
        report = verify_batches(
            {
                'delivery_batches': [
                    {'batch': 'D1', 'packages': [{'package': 'P1', 'quantity': 2}]},
                    {'batch': 'D2', 'packages': {'P2': 3}},
                ],
            },
            [
                {'evidence_ref': 'CERT-1', 'package': 'P1'},
                {'evidence_ref': 'CERT-1', 'package': 'P2'},
            ],
            [{'package': 'P1'}, {'package': 'P2'}],
        )

        self.assertEqual(Decimal('5'), report.covered_quantity)

    def test_bom_adapters(self) -> None:
        component = Component(
            name='P1',
            bom_ref='P1',
            properties=[
                Property(name='cdx:batch:delivery', value='D1'),
                Property(name='cdx:batch:quantity', value='4'),
            ],
            evidence=ComponentEvidence(
                identity=[
                    Identity(field=IdentityField.NAME, concluded_value='CERT-1'),
                    Identity(field=IdentityField.NAME, concluded_value='P1'),
                ],
                occurrences=[Occurrence(bom_ref='P1', location='dock-a')],
            ),
        )
        bom = Bom(components=[component])

        report = verify_batches(
            BatchList.from_bom(bom),
            ReviewScope.from_bom(bom),
            PhysicalWitness.from_bom(bom),
        )

        self.assertEqual(Decimal('4'), report.covered_quantity)
        self.assertEqual(Decimal('4'), report.delivery_batches['D1'].covered_quantity)

    def test_grouped_scope_and_witness(self) -> None:
        report = verify_batches(
            [
                {'delivery_batch': 'D1', 'package': 'P1', 'quantity': 4},
                {'delivery_batch': 'D2', 'package': 'P2', 'quantity': 3},
            ],
            {'CERT-1': [{'package': 'P1'}, {'package': 'P2'}]},
            {'P1': {'location': 'dock-a'}, 'P2': {'location': 'dock-b'}},
        )

        self.assertEqual(Decimal('7'), report.covered_quantity)
