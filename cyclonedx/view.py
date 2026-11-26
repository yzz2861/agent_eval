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

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

from .model.bom_ref import BomRef
from .model.component import Component
from .model.service import Service
from .model.vulnerability import (
    BomTarget,
    Vulnerability,
    VulnerabilityAnalysis,
    VulnerabilityReference,
)

if TYPE_CHECKING:  # pragma: no cover
    from .model.bom import Bom


class DisclosureView(str, Enum):
    PROCUREMENT_COMMITTEE = 'procurement-committee'
    TECHNICAL = 'technical'


class DisclosureState(str, Enum):
    PUBLIC = 'public'
    WITHDRAWN = 'withdrawn'


class FieldDecisionAction(str, Enum):
    RETAIN = 'retain'
    WITHDRAW = 'withdraw'


ANONYMOUS_VULNERABILITY_ID = 'ANONYMOUS-VULNERABILITY'
DISCLOSURE_STATE_PROPERTY = 'disclosure:state'
DISCLOSURE_AUTHORIZATION_SOURCE_PROPERTY = 'disclosure:authorization-source'
DEFAULT_AUTHORIZATION_SOURCE = 'disclosure-policy'
_PROCUREMENT_VULNERABILITY_FIELDS = frozenset(('bom_ref', 'analysis', 'affects'))
_PROCUREMENT_ANALYSIS_FIELDS = frozenset(('state',))
_WITHDRAWN_VULNERABILITY_FIELDS = frozenset((
    'bom_ref', 'analysis', 'affects', 'properties',
))
_COMPONENT_IDENTITY_FIELDS = frozenset((
    'bom_ref', 'type', 'group', 'name', 'version', 'components',
))
_SERVICE_IDENTITY_FIELDS = frozenset((
    'bom_ref', 'group', 'name', 'version', 'services',
))
_NESTED_IDENTITY_FIELDS = frozenset((
    'author', 'authors', 'cpe', 'omnibor_ids', 'publisher', 'supplier', 'swid', 'swhids',
))


@dataclass(frozen=True)
class FieldDecision:
    path: str
    action: FieldDecisionAction
    view: DisclosureView
    state: DisclosureState
    authorization_source: str


@dataclass(frozen=True)
class ViewAudit:
    view: DisclosureView
    decisions: tuple[FieldDecision, ...]
    authorization_sources: frozenset[str]

    def decisions_for(self, path_prefix: str) -> tuple[FieldDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.path.startswith(path_prefix))


@dataclass(frozen=True)
class ViewProjection:
    bom: Bom
    audit: ViewAudit


@dataclass(frozen=True)
class DisclosurePolicy:
    view: DisclosureView
    vulnerability_states: dict[str, DisclosureState] = field(default_factory=dict)
    authorization_sources: dict[str, str] = field(default_factory=dict)
    default_authorization_source: str = DEFAULT_AUTHORIZATION_SOURCE

    def state_for(self, vulnerability: Vulnerability) -> DisclosureState:
        ref = _vulnerability_key(vulnerability)
        return self.vulnerability_states.get(ref, _state_from_properties(vulnerability))

    def source_for(self, path: str) -> str:
        ordered_sources = sorted(
            self.authorization_sources.items(), key=lambda item: len(item[0]), reverse=True,
        )
        for field_path, source in ordered_sources:
            if path == field_path or path.startswith(f'{field_path}.'):
                return source
        return self.default_authorization_source

    def source_for_vulnerability(self, path: str, vulnerability: Vulnerability) -> str:
        configured_source = self.source_for(path)
        if configured_source != self.default_authorization_source:
            return configured_source
        for prop in vulnerability.properties:
            if prop.name == DISCLOSURE_AUTHORIZATION_SOURCE_PROPERTY and prop.value:
                return prop.value
        return configured_source


def project_bom(bom: Bom, policy: DisclosurePolicy) -> ViewProjection:
    projected_bom = deepcopy(bom)
    decisions: list[FieldDecision] = []

    _project_metadata(projected_bom, policy, decisions)
    for index, component in enumerate(projected_bom.components):
        _project_component(component, f'components[{index}]', policy, decisions)
    for index, service in enumerate(projected_bom.services):
        _project_service(service, f'services[{index}]', policy, decisions)
    for index, vulnerability in enumerate(projected_bom.vulnerabilities):
        _project_vulnerability(vulnerability, index, policy, decisions)

    audit = ViewAudit(
        view=policy.view,
        decisions=tuple(decisions),
        authorization_sources=frozenset(decision.authorization_source for decision in decisions),
    )
    return ViewProjection(bom=projected_bom, audit=audit)


def _project_metadata(bom: Bom, policy: DisclosurePolicy, decisions: list[FieldDecision]) -> None:
    _decide_field(bom, 'serial_number', True, 'metadata', policy, decisions)
    _decide_field(bom, 'version', True, 'metadata', policy, decisions)
    _decide_field(bom, 'dependencies', True, 'metadata', policy, decisions)
    if policy.view is DisclosureView.PROCUREMENT_COMMITTEE:
        bom.external_references = []
        bom.properties = []
    _decide_field(bom, 'external_references', policy.view is DisclosureView.TECHNICAL, 'metadata', policy, decisions)
    _decide_field(bom, 'properties', policy.view is DisclosureView.TECHNICAL, 'metadata', policy, decisions)
    _decide_field(bom, 'definitions', policy.view is DisclosureView.TECHNICAL, 'metadata', policy, decisions)
    _decide_field(bom.metadata, 'timestamp', True, 'metadata', policy, decisions)
    if bom.metadata.component is not None:
        _project_component(bom.metadata.component, 'metadata.component', policy, decisions)


def _project_component(
    component: Component, path: str, policy: DisclosurePolicy, decisions: list[FieldDecision]
) -> None:
    for field_name in _COMPONENT_IDENTITY_FIELDS:
        _decide_field(component, field_name, True, path, policy, decisions)
    for field_name in _COMPONENT_FIELDS.difference(_COMPONENT_IDENTITY_FIELDS):
        allowed = policy.view is DisclosureView.TECHNICAL
        if not allowed:
            _adjudicate_nested_identity_fields(component, field_name, path, policy, decisions)
        _decide_field(component, field_name, allowed, path, policy, decisions)
    for nested_index, nested in enumerate(component.components):
        _project_component(nested, f'{path}.components[{nested_index}]', policy, decisions)


def _project_service(
    service: Service, path: str, policy: DisclosurePolicy, decisions: list[FieldDecision]
) -> None:
    for field_name in _SERVICE_IDENTITY_FIELDS:
        _decide_field(service, field_name, True, path, policy, decisions)
    for field_name in _SERVICE_FIELDS.difference(_SERVICE_IDENTITY_FIELDS):
        allowed = policy.view is DisclosureView.TECHNICAL
        _decide_field(service, field_name, allowed, path, policy, decisions)
    for nested_index, nested in enumerate(service.services):
        _project_service(nested, f'{path}.services[{nested_index}]', policy, decisions)


def _project_vulnerability(
    vulnerability: Vulnerability, index: int, policy: DisclosurePolicy,
    decisions: list[FieldDecision],
) -> None:
    state = policy.state_for(vulnerability)
    path = f'vulnerabilities[{index}]'
    if state is DisclosureState.WITHDRAWN:
        vulnerability.id = ANONYMOUS_VULNERABILITY_ID
    if vulnerability.analysis is not None:
        _project_analysis(
            vulnerability.analysis, f'{path}.analysis', policy, decisions, state, vulnerability,
        )
    for reference_index, reference in enumerate(vulnerability.references):
        _project_reference(
            reference, f'{path}.references[{reference_index}]', policy, decisions, state, vulnerability,
        )
    for field_name in _VULNERABILITY_FIELDS:
        allowed = _vulnerability_field_allowed(policy.view, state, field_name)
        field_source = policy.source_for_vulnerability(f'{path}.{field_name}', vulnerability)
        _decide_vulnerability_field(
            vulnerability, field_name, allowed, path, policy, decisions, state, field_source,
        )
    for target_index, target in enumerate(vulnerability.affects):
        _project_target(
            target, f'{path}.affects[{target_index}]', policy, decisions, state, vulnerability,
        )


def _project_analysis(
    analysis: VulnerabilityAnalysis, path: str, policy: DisclosurePolicy,
    decisions: list[FieldDecision], state: DisclosureState, vulnerability: Vulnerability,
) -> None:
    for field_name in _ANALYSIS_FIELDS:
        allowed = policy.view is DisclosureView.TECHNICAL or field_name in _PROCUREMENT_ANALYSIS_FIELDS
        field_source = policy.source_for_vulnerability(f'{path}.{field_name}', vulnerability)
        _decide_vulnerability_field(
            analysis, field_name, allowed, path, policy, decisions, state, field_source,
        )


def _project_reference(
    reference: VulnerabilityReference, path: str, policy: DisclosurePolicy,
    decisions: list[FieldDecision], state: DisclosureState, vulnerability: Vulnerability,
) -> None:
    for field_name in ('id', 'source'):
        allowed = _vulnerability_field_allowed(policy.view, state, 'references')
        field_source = policy.source_for_vulnerability(f'{path}.{field_name}', vulnerability)
        _decide_vulnerability_field(
            reference, field_name, allowed, path, policy, decisions, state, field_source,
        )


def _project_target(
    target: BomTarget, path: str, policy: DisclosurePolicy,
    decisions: list[FieldDecision], state: DisclosureState, vulnerability: Vulnerability,
) -> None:
    field_source = policy.source_for_vulnerability(f'{path}.ref', vulnerability)
    _decide_vulnerability_field(target, 'ref', True, path, policy, decisions, state, field_source)
    for version_index, version in enumerate(target.versions):
        version_path = f'{path}.versions[{version_index}]'
        for field_name in ('version', 'range', 'status'):
            field_source = policy.source_for_vulnerability(f'{version_path}.{field_name}', vulnerability)
            _decide_vulnerability_field(
                version, field_name, True, version_path, policy, decisions, state, field_source,
            )


def _vulnerability_field_allowed(
    view: DisclosureView, state: DisclosureState, field_name: str,
) -> bool:
    if view is DisclosureView.PROCUREMENT_COMMITTEE:
        return field_name in _PROCUREMENT_VULNERABILITY_FIELDS
    if state is DisclosureState.WITHDRAWN:
        return field_name in _WITHDRAWN_VULNERABILITY_FIELDS
    return True


def _adjudicate_nested_identity_fields(
    component: Component, field_name: str, path: str, policy: DisclosurePolicy,
    decisions: list[FieldDecision],
) -> None:
    value = getattr(component, field_name)
    if field_name in ('authors', 'supplier') and value is not None:
        items = value if field_name == 'authors' else [value]
        for index, item in enumerate(items):
            for nested_field_name in ('bom_ref', 'name'):
                _record_decision(
                    nested_field_name,
                    f'{path}.{field_name}[{index}]', policy, decisions,
                )
    elif field_name == 'swid' and value is not None:
        _record_decision('tag_id', f'{path}.{field_name}', policy, decisions)
    elif field_name in ('omnibor_ids', 'swhids'):
        for index, item in enumerate(value):
            _record_decision('id', f'{path}.{field_name}[{index}]', policy, decisions)


def _decide_field(
    instance: Any, field_name: str, allowed: bool, path: str,
    policy: DisclosurePolicy, decisions: list[FieldDecision],
    state: Optional[DisclosureState] = None,
) -> None:
    field_path = f'{path}.{field_name}'
    decision = FieldDecision(
        path=field_path,
        action=FieldDecisionAction.RETAIN if allowed else FieldDecisionAction.WITHDRAW,
        view=policy.view,
        state=state or DisclosureState.PUBLIC,
        authorization_source=policy.source_for(field_path),
    )
    if not allowed:
        _clear_field(instance, field_name)
    decisions.append(decision)


def _record_decision(
    field_name: str, path: str,
    policy: DisclosurePolicy, decisions: list[FieldDecision],
) -> None:
    field_path = f'{path}.{field_name}'
    decisions.append(FieldDecision(
        path=field_path,
        action=FieldDecisionAction.WITHDRAW,
        view=policy.view,
        state=DisclosureState.PUBLIC,
        authorization_source=policy.source_for(field_path),
    ))

def _decide_vulnerability_field(
    instance: Any, field_name: str, allowed: bool, path: str,
    policy: DisclosurePolicy, decisions: list[FieldDecision],
    state: DisclosureState, authorization_source: str,
) -> None:
    field_path = f'{path}.{field_name}'
    decision = FieldDecision(
        path=field_path,
        action=FieldDecisionAction.RETAIN if allowed else FieldDecisionAction.WITHDRAW,
        view=policy.view,
        state=state,
        authorization_source=authorization_source,
    )
    if not allowed:
        _clear_field(instance, field_name)
        if field_name == 'id' and state is DisclosureState.WITHDRAWN:
            setattr(instance, field_name, ANONYMOUS_VULNERABILITY_ID)
    decisions.append(decision)


def _clear_field(instance: Any, field_name: str) -> None:
    value = getattr(instance, field_name)
    if field_name == 'definitions' and value is None:
        return
    if isinstance(value, str):
        replacement: Any = None
    elif isinstance(value, BomRef):
        replacement = BomRef()
    elif isinstance(value, frozenset):
        replacement = frozenset()
    elif isinstance(value, set):
        replacement = set()
    elif isinstance(value, list):
        replacement = []
    elif hasattr(value, 'clear'):
        value.clear()
        return
    else:
        replacement = None
    setattr(instance, field_name, replacement)


def _vulnerability_key(vulnerability: Vulnerability) -> str:
    if vulnerability.bom_ref.value is not None:
        return vulnerability.bom_ref.value
    if vulnerability.id is not None:
        return vulnerability.id
    return str(id(vulnerability))


def _state_from_properties(vulnerability: Vulnerability) -> DisclosureState:
    for prop in vulnerability.properties:
        if prop.name == DISCLOSURE_STATE_PROPERTY:
            try:
                return DisclosureState(prop.value)
            except ValueError:
                break
    return DisclosureState.PUBLIC


_COMPONENT_FIELDS = frozenset((
    'type', 'mime_type', 'bom_ref', 'supplier', 'manufacturer', 'authors', 'publisher',
    'group', 'name',
    'description', 'scope', 'is_external', 'hashes', 'licenses', 'copyright', 'purl', 'external_references',
    'properties', 'release_notes', 'cpe', 'swid', 'pedigree', 'components', 'evidence', 'modified', 'author',
    'version', 'omnibor_ids', 'swhids', 'crypto_properties', 'tags',
))
_SERVICE_FIELDS = frozenset((
    'bom_ref', 'provider', 'group', 'name', 'version', 'description', 'endpoints', 'authenticated',
    'x_trust_boundary', 'data', 'licenses', 'external_references', 'properties', 'services', 'release_notes',
))
_VULNERABILITY_FIELDS = frozenset((
    'bom_ref', 'id', 'source', 'references', 'ratings', 'cwes', 'description', 'detail', 'recommendation',
    'workaround', 'advisories', 'created', 'published', 'updated', 'credits', 'tools', 'analysis', 'affects',
    'properties',
))
_ANALYSIS_FIELDS = frozenset((
    'state', 'justification', 'responses', 'detail', 'first_issued', 'last_updated',
))
