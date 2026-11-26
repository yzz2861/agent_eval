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

from typing import Tuple
from unittest import TestCase

from cyclonedx.contrib.coverage import CoverageValidator, DeliveryScope
from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency

MOD_CORE = 'pkg:mod/core@1.0'
MOD_UTIL = 'pkg:mod/util@1.0'
SYS_IFACE = 'pkg:sys/iface-a@2.0'
SYS_APP = 'pkg:sys/app@2.0'


def merged_bom(*dependencies: Dependency) -> Bom:
    return Bom(
        components=[
            Component(name='core', bom_ref=BomRef(MOD_CORE)),
            Component(name='util', bom_ref=BomRef(MOD_UTIL)),
            Component(name='iface-a', bom_ref=BomRef(SYS_IFACE)),
            Component(name='app', bom_ref=BomRef(SYS_APP)),
        ],
        dependencies=dependencies,
    )


def delivery_scopes() -> Tuple[DeliveryScope, ...]:
    # the module vendor guarantees its component count is complete
    # and attests all dependency relations of its own components;
    # the integrator only acknowledges the dependencies of its key interface.
    return (
        DeliveryScope(
            'module-vendor',
            component_refs=(MOD_CORE, MOD_UTIL),
            attests_components=True,
            attests_dependencies=True,
        ),
        DeliveryScope(
            'integrator',
            component_refs=(SYS_IFACE, SYS_APP),
            dependency_refs=(SYS_IFACE,),
        ),
    )


class TestDeliveryScope(TestCase):

    def test_attests_dependency_for(self) -> None:
        scope = DeliveryScope('integrator', dependency_refs=('a',))
        self.assertTrue(scope.attests_dependency_for('a'))
        self.assertFalse(scope.attests_dependency_for('b'))
        full = DeliveryScope('module-vendor', attests_dependencies=True)
        self.assertTrue(full.attests_dependency_for('anything'))


class TestCoverageValidatorMergedBom(TestCase):

    def test_baseline_merged_bom_is_fully_covered(self) -> None:
        bom = merged_bom(
            Dependency(ref=BomRef(SYS_IFACE), dependencies=[Dependency(ref=BomRef(MOD_CORE))]),
            Dependency(ref=BomRef(MOD_CORE), dependencies=[Dependency(ref=BomRef(MOD_UTIL))]),
        )
        report = CoverageValidator().validate(bom, delivery_scopes())
        self.assertTrue(report.components.holds)
        self.assertTrue(report.dependencies.closed)
        self.assertTrue(report.ok)
        # the cross-delivery relation is attributed to both sources
        self.assertEqual(1, len(report.dependencies.cross_delivery))
        relation = report.dependencies.cross_delivery[0]
        self.assertEqual(SYS_IFACE, relation.source_ref)
        self.assertEqual(MOD_CORE, relation.target_ref)
        self.assertEqual(('integrator',), relation.source_sources)
        self.assertEqual(('module-vendor',), relation.target_sources)

    def test_changed_cross_supplier_dependency_keeps_inventory_but_names_missing_signatory(self) -> None:
        # acceptance: change one cross-supplier dependency in the small BOM;
        # the component inventory still holds, while the relation report
        # points out whose sign-off is missing.
        bom = merged_bom(
            Dependency(ref=BomRef(SYS_APP), dependencies=[Dependency(ref=BomRef(MOD_CORE))]),
            Dependency(ref=BomRef(MOD_CORE), dependencies=[Dependency(ref=BomRef(MOD_UTIL))]),
        )
        report = CoverageValidator().validate(bom, delivery_scopes())
        self.assertTrue(report.components.holds, 'component inventory must be unaffected')
        self.assertFalse(report.dependencies.closed)
        self.assertFalse(report.ok)
        self.assertEqual(1, len(report.dependencies.missing_attestations))
        missing = report.dependencies.missing_attestations[0]
        self.assertEqual(SYS_APP, missing.source_ref)
        self.assertEqual(MOD_CORE, missing.target_ref)
        self.assertEqual(('integrator',), missing.expected_signatories)
        relation = report.dependencies.cross_delivery[0]
        self.assertEqual(('integrator',), relation.source_sources)
        self.assertEqual(('module-vendor',), relation.target_sources)


class TestComponentInventoryReport(TestCase):

    def test_missing_component_breaks_only_attesting_scope(self) -> None:
        bom = merged_bom()
        scopes = delivery_scopes()
        report = CoverageValidator().validate(bom, (
            DeliveryScope('module-vendor',
                          component_refs=(MOD_CORE, 'pkg:mod/gone@1.0'),
                          attests_components=True),
            scopes[1],
        ))
        by_source = {s.source: s for s in report.components.scopes}
        self.assertFalse(by_source['module-vendor'].holds)
        self.assertEqual(('pkg:mod/gone@1.0',), by_source['module-vendor'].missing_refs)
        # the integrator never attested its inventory, so it is vacuously fine
        self.assertTrue(by_source['integrator'].holds)
        self.assertFalse(report.components.holds)

    def test_unclaimed_component_breaks_inventory(self) -> None:
        bom = merged_bom()
        bom.components.add(Component(name='stray', bom_ref=BomRef('pkg:stray@0')))
        report = CoverageValidator().validate(bom, delivery_scopes())
        self.assertEqual(('pkg:stray@0',), report.components.unclaimed_refs)
        self.assertFalse(report.components.holds)

    def test_empty_scope_requires_explicit_empty_signoff(self) -> None:
        unsigned = CoverageValidator().validate(Bom(), (
            DeliveryScope('empty-vendor', attests_components=True),
        ))
        self.assertFalse(unsigned.components.holds)
        signed = CoverageValidator().validate(Bom(), (
            DeliveryScope('empty-vendor', attests_components=True, attests_empty=True),
        ))
        self.assertTrue(signed.components.holds)

    def test_duplicate_names_are_attributed_to_their_sources(self) -> None:
        bom = merged_bom()
        bom.components.add(Component(name='core', bom_ref=BomRef('pkg:sys/core@2.0')))
        scopes = delivery_scopes() + (
            DeliveryScope('integrator-2', component_refs=('pkg:sys/core@2.0',)),
        )
        report = CoverageValidator().validate(bom, scopes)
        self.assertEqual(1, len(report.components.duplicate_names))
        duplicate = report.components.duplicate_names[0]
        self.assertEqual('core', duplicate.name)
        attribution = {h.bom_ref: h.sources for h in duplicate.holders}
        self.assertEqual(('module-vendor',), attribution[MOD_CORE])
        self.assertEqual(('integrator-2',), attribution['pkg:sys/core@2.0'])

    def test_shared_object_external_references_are_attributed_to_all_sources(self) -> None:
        shared = Component(
            name='shared', bom_ref=BomRef('pkg:shared@1'),
            external_references=[ExternalReference(
                type=ExternalReferenceType.WEBSITE,
                url=XsUri('https://example.com/shared'),
            )],
        )
        bom = merged_bom()
        bom.components.add(shared)
        scopes = delivery_scopes() + (
            DeliveryScope('module-vendor', component_refs=('pkg:shared@1',)),
            DeliveryScope('integrator', component_refs=('pkg:shared@1',)),
        )
        report = CoverageValidator().validate(bom, scopes)
        self.assertEqual(1, len(report.components.external_references))
        attribution = report.components.external_references[0]
        self.assertEqual('pkg:shared@1', attribution.bom_ref)
        self.assertEqual(('module-vendor', 'integrator'), attribution.sources)
        self.assertTrue(attribution.shared)
        self.assertEqual(('https://example.com/shared',), attribution.urls)


class TestDependencyClosureReport(TestCase):

    def test_unresolved_target_breaks_closure(self) -> None:
        bom = merged_bom(
            Dependency(ref=BomRef(MOD_CORE),
                       dependencies=[Dependency(ref=BomRef('pkg:mod/ghost@9'))]),
        )
        report = CoverageValidator().validate(bom, delivery_scopes())
        self.assertFalse(report.dependencies.closed)
        self.assertEqual(1, len(report.dependencies.unresolved_targets))
        unresolved = report.dependencies.unresolved_targets[0]
        self.assertEqual('pkg:mod/ghost@9', unresolved.ref)
        self.assertEqual(MOD_CORE, unresolved.referenced_by)
        self.assertEqual(('module-vendor',), unresolved.expected_signatories)

    def test_unclaimed_edge_source_breaks_closure(self) -> None:
        bom = merged_bom(
            Dependency(ref=BomRef('pkg:stray@0'),
                       dependencies=[Dependency(ref=BomRef(MOD_CORE))]),
        )
        report = CoverageValidator().validate(bom, delivery_scopes())
        self.assertFalse(report.dependencies.closed)
        self.assertEqual(('pkg:stray@0',), report.dependencies.unclaimed_edge_sources)
        missing = report.dependencies.missing_attestations[0]
        self.assertEqual((), missing.expected_signatories)

    def test_internal_relation_is_not_cross_delivery(self) -> None:
        bom = merged_bom(
            Dependency(ref=BomRef(MOD_CORE), dependencies=[Dependency(ref=BomRef(MOD_UTIL))]),
        )
        report = CoverageValidator().validate(bom, delivery_scopes())
        self.assertEqual((), report.dependencies.cross_delivery)
        self.assertTrue(report.dependencies.closed)
