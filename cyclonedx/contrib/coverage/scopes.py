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

"""Attestation scopes of a single delivery/source within a merged BOM."""

__all__ = [
    'DeliveryScope',
]

from collections.abc import Iterable
from typing import FrozenSet


class DeliveryScope:
    """
    Describes what a single delivering party (source) attests to inside a merged BOM.

    A merged BOM may combine deliveries from multiple parties that guarantee
    different things — e.g. a module vendor may guarantee the completeness of
    its component inventory, while an integrator may only acknowledge the
    dependency relations of a few key interfaces. A :class:`DeliveryScope`
    captures exactly one such set of guarantees, so that coverage validation
    can report per guarantee instead of blurring them into a single
    "complete" claim.
    """

    def __init__(
        self,
        source: str,
        *,
        component_refs: Iterable[str] = (),
        attests_components: bool = False,
        attests_dependencies: bool = False,
        dependency_refs: Iterable[str] = (),
        attests_empty: bool = False,
    ) -> None:
        """
        :param source: identifier of the delivering party (e.g. `'module-vendor'`).
        :param component_refs: bom-ref values of the components this party delivered.
        :param attests_components: whether the party guarantees its component
            inventory (`component_refs`) is complete.
        :param attests_dependencies: whether the party attests dependency closure
            for all of its `component_refs`.
        :param dependency_refs: bom-ref values whose outgoing dependencies the party
            attests — for parties that only acknowledge a few key interfaces.
            Ignored when `attests_dependencies` is `True`.
        :param attests_empty: explicit sign-off that this scope is intentionally
            empty. An empty delivery only counts as proof when this is set.
        """
        self._source = source
        self._component_refs = frozenset(component_refs)
        self._attests_components = attests_components
        self._attests_dependencies = attests_dependencies
        self._dependency_refs = frozenset(dependency_refs)
        self._attests_empty = attests_empty

    @property
    def source(self) -> str:
        return self._source

    @property
    def component_refs(self) -> FrozenSet[str]:
        return self._component_refs

    @property
    def attests_components(self) -> bool:
        return self._attests_components

    @property
    def attests_dependencies(self) -> bool:
        return self._attests_dependencies

    @property
    def dependency_refs(self) -> FrozenSet[str]:
        return self._dependency_refs

    @property
    def attests_empty(self) -> bool:
        return self._attests_empty

    def attests_dependency_for(self, ref: str) -> bool:
        """
        Whether this party attests the outgoing dependencies of `ref`.
        """
        return self._attests_dependencies or ref in self._dependency_refs

    def __repr__(self) -> str:
        return f'<DeliveryScope source={self._source!r}, components={len(self._component_refs)}>'
