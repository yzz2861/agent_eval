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

"""Independent coverage validation for BOMs merged from multiple deliveries."""

__all__ = [
    'CoverageValidator',
]

from collections.abc import Iterable
from typing import TYPE_CHECKING, Dict, List, Set, Tuple

from ...model.component import Component
from .report import (
    ComponentInventoryReport,
    CoverageReport,
    CrossDeliveryRelation,
    DependencyClosureReport,
    DuplicateNameAttribution,
    ExternalReferenceAttribution,
    MissingAttestation,
    NamedRefAttribution,
    ScopeInventoryResult,
    UnresolvedReference,
)
from .scopes import DeliveryScope

if TYPE_CHECKING:  # pragma: no cover
    from ...model.bom import Bom


class CoverageValidator:
    """
    Validates a merged BOM against the attestation scopes of its deliveries.

    Produces a coverage report with two independent verdicts:

    - the scoped component inventory,
    - the dependency closure.

    Shared objects' external references, duplicate names and cross-delivery
    relations are attributed to their respective sources, so a merged BOM is
    never read as "everything guaranteed" when each delivering party only
    signed off a part of it.

    Components without a bom-ref value cannot be attributed to any delivery
    and are ignored by this validator.
    """

    def validate(self, bom: 'Bom', scopes: Iterable[DeliveryScope]) -> CoverageReport:
        scopes_ = tuple(scopes)
        components = tuple(
            component for component in bom.components
            if component.bom_ref.value is not None
        )
        bom_refs = {str(component.bom_ref.value) for component in components}
        owners = self._owners(scopes_)
        return CoverageReport(
            components=self._inventory(components, bom_refs, scopes_, owners),
            dependencies=self._closure(bom, bom_refs, scopes_, owners),
        )

    @staticmethod
    def _owners(scopes: Tuple[DeliveryScope, ...]) -> Dict[str, Tuple[str, ...]]:
        owners: Dict[str, List[str]] = {}
        for scope in scopes:
            for ref in scope.component_refs:
                owners.setdefault(ref, []).append(scope.source)
        return {ref: tuple(sources) for ref, sources in owners.items()}

    def _inventory(
        self,
        components: Tuple[Component, ...],
        bom_refs: Set[str],
        scopes: Tuple[DeliveryScope, ...],
        owners: Dict[str, Tuple[str, ...]],
    ) -> ComponentInventoryReport:
        scope_results: List[ScopeInventoryResult] = []
        for scope in scopes:
            expected = scope.component_refs
            scope_results.append(ScopeInventoryResult(
                source=scope.source,
                expected_refs=tuple(sorted(expected)),
                found_refs=tuple(sorted(expected & bom_refs)),
                missing_refs=tuple(sorted(expected - bom_refs)),
                attests_components=scope.attests_components,
                attests_empty=scope.attests_empty,
            ))
        unclaimed = tuple(sorted(bom_refs - set(owners)))
        return ComponentInventoryReport(
            scopes=tuple(scope_results),
            unclaimed_refs=unclaimed,
            duplicate_names=self._duplicate_names(components, owners),
            external_references=self._external_references(components, owners),
        )

    @staticmethod
    def _duplicate_names(
        components: Tuple[Component, ...],
        owners: Dict[str, Tuple[str, ...]],
    ) -> Tuple[DuplicateNameAttribution, ...]:
        by_name: Dict[str, List[NamedRefAttribution]] = {}
        for component in components:
            ref = str(component.bom_ref.value)
            by_name.setdefault(component.name, []).append(
                NamedRefAttribution(bom_ref=ref, sources=owners.get(ref, ())))
        return tuple(
            DuplicateNameAttribution(name=name, holders=tuple(holders))
            for name, holders in sorted(by_name.items())
            if len(holders) > 1
        )

    @staticmethod
    def _external_references(
        components: Tuple[Component, ...],
        owners: Dict[str, Tuple[str, ...]],
    ) -> Tuple[ExternalReferenceAttribution, ...]:
        attributions: List[ExternalReferenceAttribution] = []
        for component in components:
            if not component.external_references:
                continue
            ref = str(component.bom_ref.value)
            sources = owners.get(ref, ())
            attributions.append(ExternalReferenceAttribution(
                bom_ref=ref,
                sources=sources,
                urls=tuple(sorted(str(er.url) for er in component.external_references)),
                shared=len(sources) > 1,
            ))
        return tuple(sorted(attributions, key=lambda a: a.bom_ref))

    def _closure(
        self,
        bom: 'Bom',
        bom_refs: Set[str],
        scopes: Tuple[DeliveryScope, ...],
        owners: Dict[str, Tuple[str, ...]],
    ) -> DependencyClosureReport:
        cross_delivery: List[CrossDeliveryRelation] = []
        missing_attestations: List[MissingAttestation] = []
        unclaimed_edge_sources: Set[str] = set()
        unresolved_targets: List[UnresolvedReference] = []
        for dependency in bom.dependencies:
            src = dependency.ref.value
            if src is None:
                continue
            src_sources = owners.get(src, ())
            if not src_sources:
                unclaimed_edge_sources.add(src)
            attested = any(
                src in scope.component_refs and scope.attests_dependency_for(src)
                for scope in scopes
            )
            for target in dependency.dependencies_as_bom_refs():
                tgt = target.value
                if tgt is None:
                    continue
                tgt_sources = owners.get(tgt, ())
                if not attested:
                    missing_attestations.append(MissingAttestation(
                        source_ref=src,
                        target_ref=tgt,
                        expected_signatories=src_sources,
                    ))
                if tgt not in bom_refs:
                    unresolved_targets.append(UnresolvedReference(
                        ref=tgt,
                        referenced_by=src,
                        expected_signatories=src_sources,
                    ))
                elif set(src_sources) != set(tgt_sources):
                    cross_delivery.append(CrossDeliveryRelation(
                        source_ref=src,
                        target_ref=tgt,
                        source_sources=src_sources,
                        target_sources=tgt_sources,
                    ))
        return DependencyClosureReport(
            cross_delivery=tuple(cross_delivery),
            missing_attestations=tuple(missing_attestations),
            unclaimed_edge_sources=tuple(sorted(unclaimed_edge_sources)),
            unresolved_targets=tuple(unresolved_targets),
        )
