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

from packageurl import PackageURL

from cyclonedx.contrib.bom.utils import (
    BomMerger,
    EvidenceClaim,
    TrustSource,
    UnattributedReason,
    merge_boms,
)
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.component_evidence import (
    ComponentEvidence,
    Identity,
    IdentityField,
)
from cyclonedx.model.contact import OrganizationalEntity


def _component(
    name: str,
    version: str,
    bom_ref: str,
    supplier: OrganizationalEntity,
    *,
    purl: str,
    digest: str,
    identity_value: str,
) -> Component:
    return Component(
        name=name,
        version=version,
        bom_ref=bom_ref,
        supplier=supplier,
        purl=PackageURL.from_string(purl),
        hashes=[HashType(alg=HashAlgorithm.SHA_256, content=digest)],
        evidence=ComponentEvidence(identity=[
            Identity(
                field=IdentityField.NAME,
                confidence=Decimal('1'),
                concluded_value=identity_value,
            ),
        ]),
    )


class TestBomMerge(TestCase):

    def test_similar_coordinates_are_not_merged(self) -> None:
        foundry = OrganizationalEntity(name='Foundry')
        inhouse = OrganizationalEntity(name='In-house')
        foundry_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'shared-ref', foundry,
                purl='pkg:generic/libcrypto@3.0?source=foundry',
                digest='a' * 64,
                identity_value='foundry-libcrypto',
            ),
        ])
        inhouse_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'shared-ref', inhouse,
                purl='pkg:generic/libcrypto@3.0?source=inhouse',
                digest='b' * 64,
                identity_value='inhouse-libcrypto',
            ),
        ])

        merged = merge_boms(foundry_bom, inhouse_bom)

        self.assertEqual(2, len(merged.components))
        self.assertEqual(2, len({component.bom_ref.value for component in merged.components}))
        evidence_values = {
            identity.concluded_value
            for component in merged.components
            for identity in (component.evidence.identity if component.evidence else ())
        }
        self.assertSetEqual({'foundry-libcrypto', 'inhouse-libcrypto'}, evidence_values)

    def test_strong_identity_merges_component_without_moving_claims(self) -> None:
        foundry = OrganizationalEntity(name='Foundry')
        inhouse = OrganizationalEntity(name='In-house')
        foundry_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'libcrypto', foundry,
                purl='pkg:generic/libcrypto@3.0',
                digest='c' * 64,
                identity_value='libcrypto',
            ),
        ])
        inhouse_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'libcrypto-renamed', inhouse,
                purl='pkg:generic/libcrypto@3.0',
                digest='c' * 64,
                identity_value='libcrypto',
            ),
        ])

        merged = merge_boms(foundry_bom, inhouse_bom)

        self.assertEqual(1, len(merged.components))
        component = merged.components[0]
        self.assertIsNotNone(component.evidence)
        self.assertEqual(1, len(component.evidence.identity))
        self.assertEqual('libcrypto', component.evidence.identity[0].concluded_value)
        self.assertEqual(2, len(merged.trust_sources))

    def test_conflicting_evidence_is_kept_in_sidecar(self) -> None:
        foundry = OrganizationalEntity(name='Foundry')
        inhouse = OrganizationalEntity(name='In-house')
        foundry_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'libcrypto', foundry,
                purl='pkg:generic/libcrypto@3.0',
                digest='d' * 64,
                identity_value='foundry-name',
            ),
        ])
        inhouse_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'libcrypto', inhouse,
                purl='pkg:generic/libcrypto@3.0',
                digest='d' * 64,
                identity_value='inhouse-name',
            ),
        ])

        merged = merge_boms(foundry_bom, inhouse_bom)

        self.assertEqual(1, len(merged.components))
        component = merged.components[0]
        self.assertIsNone(component.evidence)
        self.assertEqual(2, len(merged.unattributed))
        self.assertSetEqual(
            {UnattributedReason.CONTRADICTORY},
            {claim.reason for claim in merged.unattributed},
        )

    def test_supplier_cannot_claim_scan_pass_for_another_component(self) -> None:
        foundry = OrganizationalEntity(name='Foundry')
        other = OrganizationalEntity(name='Other')
        source_component = _component(
            'libfoo', '3.0', 'libfoo', foundry,
            purl='pkg:generic/libfoo@3.0',
            digest='e' * 64,
            identity_value='libfoo',
        )
        target = _component(
            'libssl', '3.0', 'libssl', other,
            purl='pkg:generic/libssl@3.0',
            digest='e' * 64,
            identity_value='libssl',
        )
        foundry_bom = Bom(components=[source_component])
        target_bom = Bom(components=[target])
        scan_claim = EvidenceClaim(
            target=target,
            predicate='scan:passed',
            value=True,
            source=foundry,
            kind='scan',
        )
        digest_claim = EvidenceClaim(
            target=target,
            predicate='hash:sha256',
            value='e' * 64,
            source=foundry,
            kind='digest',
            stance='endorse',
        )

        result = merge_boms(foundry_bom, target_bom, claims=[scan_claim, digest_claim])

        self.assertEqual(1, len(result.unattributed))
        self.assertEqual(UnattributedReason.UNAUTHORIZED_SOURCE, result.unattributed[0].reason)
        self.assertEqual('scan:passed', result.unattributed[0].predicate)
        self.assertTrue(any(
            claim.predicate == 'hash:sha256' for claim in result.claims
        ))

    def test_swapping_inputs_is_stable(self) -> None:
        foundry = OrganizationalEntity(name='Foundry')
        inhouse = OrganizationalEntity(name='In-house')
        foundry_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'libcrypto', foundry,
                purl='pkg:generic/libcrypto@3.0',
                digest='f' * 64,
                identity_value='foundry-name',
            ),
            _component(
                'libssl', '3.0', 'libssl', foundry,
                purl='pkg:generic/libssl@3.0',
                digest='1' * 64,
                identity_value='libssl',
            ),
        ])
        inhouse_bom = Bom(components=[
            _component(
                'libcrypto', '3.0', 'libcrypto', inhouse,
                purl='pkg:generic/libcrypto@3.0',
                digest='f' * 64,
                identity_value='inhouse-name',
            ),
        ])

        first = BomMerger().merge(foundry_bom, inhouse_bom)
        second = BomMerger().merge(inhouse_bom, foundry_bom)

        self.assertEqual(
            [(c.bom_ref.value, c.name) for c in first.components],
            [(c.bom_ref.value, c.name) for c in second.components],
        )
        self.assertEqual(
            [claim.claim.canonical_key for claim in first.unattributed],
            [claim.claim.canonical_key for claim in second.unattributed],
        )
        self.assertEqual(
            [claim.canonical_key for claim in first.claims],
            [claim.canonical_key for claim in second.claims],
        )

    def test_trust_sources_merge_independently(self) -> None:
        source_a = TrustSource(name='Foundry', authorized_targets=['pkg:a'])
        source_b = TrustSource(name='Foundry', authorized_targets=['pkg:b'])

        merged = BomMerger().merge_trust_sources(source_a, source_b)

        self.assertEqual(1, len(merged))
        self.assertSetEqual({'pkg:a', 'pkg:b'}, merged[0].authorized_targets)
