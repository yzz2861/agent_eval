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

"""Report types for delivery coverage validation of merged BOMs."""

__all__ = [
    'NamedRefAttribution',
    'DuplicateNameAttribution',
    'ExternalReferenceAttribution',
    'ScopeInventoryResult',
    'ComponentInventoryReport',
    'CrossDeliveryRelation',
    'MissingAttestation',
    'UnresolvedReference',
    'DependencyClosureReport',
    'CoverageReport',
]

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class NamedRefAttribution:
    """A single bom-ref and the sources (delivering parties) claiming it."""

    bom_ref: str
    sources: Tuple[str, ...]  # empty means: not claimed by any scope


@dataclass(frozen=True)
class DuplicateNameAttribution:
    """Components that share the same name, attributed to their sources."""

    name: str
    holders: Tuple[NamedRefAttribution, ...]


@dataclass(frozen=True)
class ExternalReferenceAttribution:
    """External references of a component, attributed to the sources of that component."""

    bom_ref: str
    sources: Tuple[str, ...]  # empty means: not claimed by any scope
    urls: Tuple[str, ...]
    shared: bool  # whether the component is claimed by more than one scope


@dataclass(frozen=True)
class ScopeInventoryResult:
    """Component inventory verdict for a single delivery scope."""

    source: str
    expected_refs: Tuple[str, ...]
    found_refs: Tuple[str, ...]
    missing_refs: Tuple[str, ...]
    attests_components: bool
    attests_empty: bool

    @property
    def holds(self) -> bool:
        """
        Whether this scope's component inventory attestation holds.

        A scope that does not attest its component inventory makes no
        guarantee here, so the verdict is vacuously true.
        An empty delivery only counts as proof when the scope explicitly
        signed off its emptiness (:attr:`attests_empty`).
        """
        if not self.attests_components:
            return True
        if self.missing_refs:
            return False
        if not self.found_refs and not self.attests_empty:
            return False
        return True


@dataclass(frozen=True)
class ComponentInventoryReport:
    """
    Scoped component inventory of a merged BOM.

    Independent of any dependency considerations.
    """

    scopes: Tuple[ScopeInventoryResult, ...]
    unclaimed_refs: Tuple[str, ...]  # components in the BOM that no scope claims
    duplicate_names: Tuple[DuplicateNameAttribution, ...]
    external_references: Tuple[ExternalReferenceAttribution, ...]

    @property
    def holds(self) -> bool:
        return not self.unclaimed_refs and all(scope.holds for scope in self.scopes)


@dataclass(frozen=True)
class CrossDeliveryRelation:
    """A dependency edge that crosses a delivery boundary, attributed to both ends."""

    source_ref: str
    target_ref: str
    source_sources: Tuple[str, ...]  # sources delivering source_ref
    target_sources: Tuple[str, ...]  # sources delivering target_ref


@dataclass(frozen=True)
class MissingAttestation:
    """A dependency edge that no delivering party signed off."""

    source_ref: str
    target_ref: str
    expected_signatories: Tuple[str, ...]  # whose sign-off is missing


@dataclass(frozen=True)
class UnresolvedReference:
    """A dependency target that does not resolve to any component in the BOM."""

    ref: str
    referenced_by: str
    expected_signatories: Tuple[str, ...]  # sources of the referencing component


@dataclass(frozen=True)
class DependencyClosureReport:
    """
    Dependency closure of a merged BOM.

    Independent of any component inventory considerations.
    """

    cross_delivery: Tuple[CrossDeliveryRelation, ...]
    missing_attestations: Tuple[MissingAttestation, ...]
    unclaimed_edge_sources: Tuple[str, ...]  # edge sources no scope claims
    unresolved_targets: Tuple[UnresolvedReference, ...]

    @property
    def closed(self) -> bool:
        return not (
            self.missing_attestations
            or self.unclaimed_edge_sources
            or self.unresolved_targets
        )


@dataclass(frozen=True)
class CoverageReport:
    """
    Independent coverage verdicts for a merged BOM.

    `components` and `dependencies` are evaluated separately, so a merged
    BOM is never read as "fully guaranteed" when only one of them holds.
    """

    components: ComponentInventoryReport = field(
        default_factory=lambda: ComponentInventoryReport((), (), (), ()))
    dependencies: DependencyClosureReport = field(
        default_factory=lambda: DependencyClosureReport((), (), (), ()))

    @property
    def ok(self) -> bool:
        return self.components.holds and self.dependencies.closed
