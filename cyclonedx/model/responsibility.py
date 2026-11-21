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

"""
Freezable responsibility assignment planning on top of a CycloneDX BOM.

This module deliberately does not add non-standard fields to the BOM. Instead,
it derives an auditable assignment plan from the BOM's components, component
evidence, and dependency edges, combined with capabilities and time-bounded
authorization grants.

The central guarantees are:

* assignments are deterministic at an evaluation time;
* a frozen snapshot is immutable;
* revoking a grant changes future eligibility, but never removes a completed
  sign-off.
"""

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from json import dumps as json_dumps
from types import MappingProxyType
from typing import Any, Optional, Union
from uuid import uuid4

from .._internal.time import get_now_utc as _get_now_utc
from ..exception.model import (
    AssignmentStepAlreadySignedOffException,
    InvalidAuthorizationWindowException,
    InvalidValueException,
    ResponsibilityPlanException,
    ResponsibilityTeamNotAssignedException,
    UnassignedAssignmentStepException,
    UnknownAssignmentStepException,
    UnknownAuthorizationGrantException,
    UnknownResponsibilityTeamException,
)
from .bom import Bom
from .bom_ref import BomRef
from .component import Component


class AssignmentStatus(str, Enum):
    """The current handling state of a responsibility step."""

    ASSIGNED = 'assigned'
    UNASSIGNED = 'unassigned'
    SIGNED_OFF = 'signed-off'
    SIGNEDOFF = 'signed-off'


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _ref(value: Union[str, BomRef]) -> str:
    ref = str(value)
    if not ref:
        raise InvalidValueException('component references must not be empty')
    return ref


def _first(value: Optional[str], *alternatives: Optional[str]) -> Optional[str]:
    for candidate in (value, *alternatives):
        if candidate is not None and str(candidate).strip():
            return str(candidate)
    return None


def _normalize_evidence_kind(value: str) -> str:
    kind = value.strip().lower()
    return {
        'identities': 'identity',
        'occurrences': 'occurrence',
        'licenses': 'license',
        'copyrights': 'copyright',
        'callstacks': 'callstack',
    }.get(kind, kind)


def _evidence_kinds(value: Union[None, str, Iterable[str]]) -> frozenset[str]:
    if value is None:
        return frozenset()
    values = (value,) if isinstance(value, str) else value
    return frozenset(
        _normalize_evidence_kind(kind)
        for kind in values
        if kind and str(kind).strip()
    )


def _capabilities(value: Union[None, str, Iterable[str]]) -> frozenset[str]:
    if value is None:
        return frozenset()
    values = (value,) if isinstance(value, str) else value
    return frozenset(
        capability.strip()
        for capability in values
        if capability and capability.strip()
    )


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


@dataclass(frozen=True)
class AuthorizationWindow:
    """A half-open authorization interval: ``[valid_from, valid_until)``."""

    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None

    def __post_init__(self) -> None:
        start = _utc(self.valid_from) if self.valid_from is not None else None
        end = _utc(self.valid_until) if self.valid_until is not None else None
        if start is not None and end is not None and end <= start:
            raise InvalidAuthorizationWindowException(
                'authorization window must have a positive duration')
        object.__setattr__(self, 'valid_from', start)
        object.__setattr__(self, 'valid_until', end)

    @property
    def start(self) -> Optional[datetime]:
        return self.valid_from

    @property
    def end(self) -> Optional[datetime]:
        return self.valid_until

    def contains(self, at: datetime) -> bool:
        moment = _utc(at)
        if self.valid_from is not None and moment < self.valid_from:
            return False
        return self.valid_until is None or moment < self.valid_until

    def as_dict(self) -> dict[str, Optional[str]]:
        return {
            'validFrom': _iso(self.valid_from),
            'validUntil': _iso(self.valid_until),
        }


@dataclass(frozen=True)
class EvidenceSummary:
    """Small, serializable view of the evidence attached to one component."""

    identities: tuple[str, ...] = ()
    occurrences: tuple[str, ...] = ()
    licenses: tuple[str, ...] = ()
    copyrights: tuple[str, ...] = ()
    has_callstack: bool = False

    @property
    def kinds(self) -> tuple[str, ...]:
        kinds = []
        if self.identities:
            kinds.append('identity')
        if self.occurrences:
            kinds.append('occurrence')
        if self.has_callstack:
            kinds.append('callstack')
        if self.licenses:
            kinds.append('license')
        if self.copyrights:
            kinds.append('copyright')
        return tuple(kinds)

    @property
    def evidence_kinds(self) -> tuple[str, ...]:
        return self.kinds

    @property
    def present(self) -> bool:
        return bool(self.kinds)

    def satisfies(self, required: Iterable[str]) -> bool:
        return set(required).issubset(self.kinds)

    def as_dict(self) -> dict[str, Any]:
        return {
            'kinds': list(self.kinds),
            'identities': list(self.identities),
            'occurrences': list(self.occurrences),
            'licenses': list(self.licenses),
            'copyrights': list(self.copyrights),
            'hasCallstack': self.has_callstack,
        }

    @classmethod
    def from_component(cls, component: Optional[Component]) -> 'EvidenceSummary':
        if component is None or component.evidence is None:
            return cls()
        evidence = component.evidence
        identities = tuple(sorted(
            f'{identity.field.value}:{identity.concluded_value or ""}'
            for identity in evidence.identity
        ))
        occurrences = tuple(sorted(occurrence.location for occurrence in evidence.occurrences))
        licenses = tuple(sorted(str(license_) for license_ in evidence.licenses))
        copyrights = tuple(sorted(copyright_.text for copyright_ in evidence.copyright))
        return cls(
            identities=identities,
            occurrences=occurrences,
            licenses=licenses,
            copyrights=copyrights,
            has_callstack=evidence.callstack is not None,
        )


@dataclass(frozen=True, init=False)
class ResponsibilityTeam:
    """A team and the handling capabilities it claims."""

    id: str
    capabilities: frozenset[str]
    name: Optional[str]

    def __init__(
        self,
        id: Optional[str] = None,
        capabilities: Union[None, str, Iterable[str]] = None,
        name: Optional[str] = None,
        *,
        team_id: Optional[str] = None,
        capability: Optional[str] = None,
        roles: Union[None, str, Iterable[str]] = None,
        display_name: Optional[str] = None,
    ) -> None:
        resolved_id = _first(id, team_id)
        if resolved_id is None:
            raise InvalidValueException('team id must not be empty')
        declared = capabilities if capabilities is not None else roles
        if capability is not None:
            declared = set(_capabilities(declared)) | {capability.strip()}
        object.__setattr__(self, 'id', resolved_id)
        object.__setattr__(self, 'capabilities', _capabilities(declared))
        object.__setattr__(self, 'name', name if name is not None else display_name)

    @property
    def team_id(self) -> str:
        return self.id

    def can(self, capability: str) -> bool:
        return '*' in self.capabilities or capability in self.capabilities

    def supports(self, capability: str) -> bool:
        return self.can(capability)

    def as_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'teamId': self.id,
            'name': self.name,
            'capabilities': sorted(self.capabilities),
        }


@dataclass(frozen=True, init=False)
class AssignmentStep:
    """One handling step for one component position."""

    id: str
    capability: str
    component_ref: str
    required_evidence: frozenset[str]
    description: Optional[str]
    depends_on: tuple[str, ...]
    additional_component_refs: tuple[str, ...]

    def __init__(
        self,
        id: Optional[str] = None,
        capability: Optional[str] = None,
        component_ref: Optional[Union[str, BomRef]] = None,
        required_evidence: Union[None, str, Iterable[str]] = None,
        description: Optional[str] = None,
        *,
        step_id: Optional[str] = None,
        action: Optional[str] = None,
        role: Optional[str] = None,
        component: Optional[Union[str, BomRef]] = None,
        component_id: Optional[Union[str, BomRef]] = None,
        target_component: Optional[Union[str, BomRef]] = None,
        components: Optional[Iterable[Union[str, BomRef]]] = None,
        evidence_required: Union[None, str, Iterable[str]] = None,
        depends_on: Union[None, str, Iterable[str]] = None,
    ) -> None:
        resolved_id = _first(id, step_id)
        resolved_capability = _first(capability, action, role)
        if resolved_id is None or resolved_capability is None:
            raise InvalidValueException('step id and capability must not be empty')
        refs = tuple(str(value) for value in components) if components is not None else ()
        resolved_ref = _first(
            str(component_ref) if component_ref is not None else None,
            str(component) if component is not None else None,
            str(component_id) if component_id is not None else None,
            str(target_component) if target_component is not None else None,
            refs[0] if refs else None,
        )
        if resolved_ref is None:
            raise InvalidValueException('step component reference must not be empty')
        required = evidence_required if evidence_required is not None else required_evidence
        dependencies = (depends_on,) if isinstance(depends_on, str) else (depends_on or ())
        object.__setattr__(self, 'id', resolved_id)
        object.__setattr__(self, 'capability', resolved_capability)
        object.__setattr__(self, 'component_ref', _ref(resolved_ref))
        object.__setattr__(self, 'required_evidence', _evidence_kinds(required))
        object.__setattr__(self, 'description', description)
        object.__setattr__(self, 'depends_on', tuple(str(value) for value in dependencies))
        object.__setattr__(
            self,
            'additional_component_refs',
            tuple(_ref(value) for value in refs[1:]),
        )

    @property
    def action(self) -> str:
        return self.capability

    @property
    def component(self) -> str:
        return self.component_ref

    @property
    def components(self) -> tuple[str, ...]:
        return (self.component_ref, *self.additional_component_refs)

    @property
    def evidence_required(self) -> frozenset[str]:
        return self.required_evidence

    def as_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'stepId': self.id,
            'capability': self.capability,
            'componentRef': self.component_ref,
            'componentRefs': list(self.components),
            'requiredEvidence': sorted(self.required_evidence),
            'dependsOn': list(self.depends_on),
            'description': self.description,
        }


@dataclass(frozen=True, init=False)
class AuthorizationGrant:
    """A time-bounded authorization for a team to act on a component scope."""

    team_id: str
    capability: str
    component_ref: str
    valid_from: Optional[datetime]
    valid_until: Optional[datetime]
    id: str
    revoked_at: Optional[datetime]
    capabilities: frozenset[str]
    required_evidence: frozenset[str]
    evidence_ref: Optional[str]

    def __init__(
        self,
        team_id: Optional[str] = None,
        capability: Optional[Union[str, Iterable[str]]] = None,
        component_ref: Optional[Union[str, BomRef]] = None,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        id: Optional[str] = None,
        revoked_at: Optional[datetime] = None,
        *,
        grant_id: Optional[str] = None,
        team: Optional[str] = None,
        role: Optional[str] = None,
        capabilities: Optional[Iterable[str]] = None,
        component: Optional[Union[str, BomRef]] = None,
        scope: Optional[Union[str, BomRef]] = None,
        from_: Optional[datetime] = None,
        start: Optional[datetime] = None,
        until: Optional[datetime] = None,
        end: Optional[datetime] = None,
        expires: Optional[datetime] = None,
        window: Optional[AuthorizationWindow] = None,
        required_evidence: Union[None, str, Iterable[str]] = None,
        evidence_ref: Optional[str] = None,
    ) -> None:
        resolved_id = _first(id, grant_id) or uuid4().hex
        resolved_team = _first(team_id, team)
        if resolved_team is None:
            raise InvalidValueException('grant team id must not be empty')
        declared_capabilities = capabilities if capabilities is not None else capability
        if role is not None:
            declared_capabilities = set(_capabilities(declared_capabilities)) | {role.strip()}
        declared = _capabilities(declared_capabilities)
        if not declared:
            raise InvalidValueException('grant capability must not be empty')
        resolved_scope = _first(
            str(component_ref) if component_ref is not None else None,
            str(component) if component is not None else None,
            str(scope) if scope is not None else None,
        ) or '*'
        resolved_start = _first_time(valid_from, from_, start)
        resolved_until = _first_time(valid_until, until, end, expires)
        if window is not None:
            resolved_start = window.valid_from if resolved_start is None else resolved_start
            resolved_until = window.valid_until if resolved_until is None else resolved_until
        start_at = _utc(resolved_start) if resolved_start is not None else None
        end_at = _utc(resolved_until) if resolved_until is not None else None
        if start_at is not None and end_at is not None and end_at <= start_at:
            raise InvalidAuthorizationWindowException(
                f'grant {resolved_id!r} has a non-positive authorization window')
        object.__setattr__(self, 'id', resolved_id)
        object.__setattr__(self, 'team_id', resolved_team)
        object.__setattr__(self, 'capabilities', declared)
        object.__setattr__(
            self,
            'capability',
            next(iter(declared)) if len(declared) == 1 else '*',
        )
        object.__setattr__(self, 'component_ref', _ref(resolved_scope))
        object.__setattr__(self, 'valid_from', start_at)
        object.__setattr__(self, 'valid_until', end_at)
        object.__setattr__(self, 'revoked_at', _utc(revoked_at) if revoked_at is not None else None)
        object.__setattr__(self, 'required_evidence', _evidence_kinds(required_evidence))
        object.__setattr__(self, 'evidence_ref', evidence_ref)

    @property
    def grant_id(self) -> str:
        return self.id

    @property
    def from_(self) -> Optional[datetime]:
        return self.valid_from

    @property
    def until(self) -> Optional[datetime]:
        return self.valid_until

    @property
    def window(self) -> AuthorizationWindow:
        return AuthorizationWindow(valid_from=self.valid_from, valid_until=self.valid_until)

    def supports_capability(self, capability: str) -> bool:
        return '*' in self.capabilities or capability in self.capabilities

    def supports(self, capability: str) -> bool:
        return self.supports_capability(capability)

    def is_active(self, at: datetime) -> bool:
        return self.active_failure(at) is None

    def active_failure(self, at: datetime) -> Optional[str]:
        moment = _utc(at)
        if self.revoked_at is not None and moment >= self.revoked_at:
            return f'grant {self.id} was revoked at {_iso(self.revoked_at)}'
        if self.valid_from is not None and moment < self.valid_from:
            return f'grant {self.id} starts at {_iso(self.valid_from)}'
        if self.valid_until is not None and moment >= self.valid_until:
            return f'grant {self.id} ended at {_iso(self.valid_until)}'
        return None

    def revoke(self, at: Optional[datetime] = None) -> 'AuthorizationGrant':
        return replace(self, revoked_at=_utc(at) if at is not None else _get_now_utc())

    def as_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'grantId': self.id,
            'teamId': self.team_id,
            'capability': self.capability,
            'capabilities': sorted(self.capabilities),
            'componentRef': self.component_ref,
            'validFrom': _iso(self.valid_from),
            'validUntil': _iso(self.valid_until),
            'revokedAt': _iso(self.revoked_at),
            'requiredEvidence': sorted(self.required_evidence),
            'evidenceRef': self.evidence_ref,
        }


@dataclass(frozen=True)
class AssignmentCandidate:
    """One team that is eligible for a step, plus the authorization basis."""

    team_id: str
    grant_id: str
    dependency_path: tuple[str, ...]

    @property
    def direct(self) -> bool:
        return len(self.dependency_path) <= 1

    @property
    def inherited(self) -> bool:
        return not self.direct

    def as_dict(self) -> dict[str, Any]:
        return {
            'teamId': self.team_id,
            'grantId': self.grant_id,
            'dependencyPath': list(self.dependency_path),
            'basis': 'direct' if self.direct else 'dependency',
        }


@dataclass(frozen=True)
class SignOff:
    """An immutable record of completed handling acceptance."""

    step_id: str
    team_id: str
    completed_at: datetime
    grant_id: Optional[str] = None
    dependency_path: tuple[str, ...] = ()
    note: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, 'completed_at', _utc(self.completed_at))
        object.__setattr__(self, 'dependency_path', tuple(self.dependency_path))

    @property
    def signed_at(self) -> datetime:
        return self.completed_at

    @property
    def signer_team_id(self) -> str:
        return self.team_id

    def as_dict(self) -> dict[str, Any]:
        return {
            'stepId': self.step_id,
            'teamId': self.team_id,
            'completedAt': _iso(self.completed_at),
            'signedAt': _iso(self.completed_at),
            'grantId': self.grant_id,
            'dependencyPath': list(self.dependency_path),
            'note': self.note,
        }


@dataclass(frozen=True)
class StepResult:
    """The readable handling result for one step/component position."""

    step_id: str
    capability: str
    component_ref: str
    status: AssignmentStatus
    team_id: Optional[str]
    grant_id: Optional[str]
    dependency_path: tuple[str, ...]
    evidence: EvidenceSummary
    required_evidence: tuple[str, ...]
    candidates: tuple[AssignmentCandidate, ...]
    sign_off: Optional[SignOff]
    reason: str
    evaluated_at: datetime

    @property
    def assignee(self) -> Optional[str]:
        return self.team_id

    @property
    def team(self) -> Optional[str]:
        return self.team_id

    @property
    def assigned(self) -> bool:
        return self.team_id is not None

    @property
    def unassigned(self) -> bool:
        return self.status is AssignmentStatus.UNASSIGNED

    @property
    def signed_off(self) -> bool:
        return self.sign_off is not None

    @property
    def eligible_teams(self) -> tuple[str, ...]:
        return tuple(candidate.team_id for candidate in self.candidates)

    @property
    def candidate_teams(self) -> tuple[str, ...]:
        return self.eligible_teams

    @property
    def explanation(self) -> str:
        return self.reason

    @property
    def basis(self) -> str:
        return self.reason

    @property
    def outcome(self) -> str:
        return self.status.value

    @property
    def disposition(self) -> str:
        return self.status.value

    def as_dict(self) -> dict[str, Any]:
        return {
            'stepId': self.step_id,
            'step_id': self.step_id,
            'capability': self.capability,
            'componentRef': self.component_ref,
            'component_ref': self.component_ref,
            'status': self.status.value,
            'teamId': self.team_id,
            'team_id': self.team_id,
            'grantId': self.grant_id,
            'grant_id': self.grant_id,
            'dependencyPath': list(self.dependency_path),
            'evidence': self.evidence.as_dict(),
            'requiredEvidence': list(self.required_evidence),
            'candidates': [candidate.as_dict() for candidate in self.candidates],
            'eligibleTeams': list(self.eligible_teams),
            'signOff': self.sign_off.as_dict() if self.sign_off is not None else None,
            'reason': self.reason,
            'evaluatedAt': _iso(self.evaluated_at),
        }

    def as_row(self) -> dict[str, Any]:
        """Flat representation intended for logs, tables, or direct assertions."""
        return {
            'stepId': self.step_id,
            'step_id': self.step_id,
            'componentRef': self.component_ref,
            'component_ref': self.component_ref,
            'capability': self.capability,
            'status': self.status.value,
            'teamId': self.team_id,
            'team_id': self.team_id,
            'grantId': self.grant_id,
            'dependencyPath': list(self.dependency_path),
            'evidenceKinds': list(self.evidence.kinds),
            'eligibleTeams': list(self.eligible_teams),
            'signedOff': self.signed_off,
            'signed_off': self.signed_off,
            'reason': self.reason,
        }

    to_dict = as_dict
    to_row = as_row


def _first_time(*values: Optional[datetime]) -> Optional[datetime]:
    for value in values:
        if value is not None:
            return value
    return None


@dataclass(frozen=True)
class FrozenResponsibilityPlan:
    """An immutable, deterministic snapshot of all step results."""

    frozen_at: datetime
    results: tuple[StepResult, ...]
    sign_offs: tuple[SignOff, ...]
    grants: tuple[AuthorizationGrant, ...]
    teams: tuple[ResponsibilityTeam, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, 'frozen_at', _utc(self.frozen_at))
        object.__setattr__(self, 'results', tuple(self.results))
        object.__setattr__(self, 'sign_offs', tuple(self.sign_offs))
        object.__setattr__(self, 'grants', tuple(self.grants))
        object.__setattr__(self, 'teams', tuple(self.teams))

    @property
    def created_at(self) -> datetime:
        return self.frozen_at

    @property
    def positions(self) -> tuple[StepResult, ...]:
        return self.results

    @property
    def outcomes(self) -> tuple[StepResult, ...]:
        return self.results

    @property
    def results_by_step(self) -> Mapping[str, StepResult]:
        return MappingProxyType({result.step_id: result for result in self.results})

    @property
    def by_step(self) -> Mapping[str, StepResult]:
        return self.results_by_step

    @property
    def assignments(self) -> Mapping[str, Optional[str]]:
        return MappingProxyType({result.step_id: result.team_id for result in self.results})

    @property
    def unassigned(self) -> tuple[StepResult, ...]:
        return tuple(result for result in self.results if result.unassigned)

    @property
    def unassigned_steps(self) -> tuple[StepResult, ...]:
        return self.unassigned

    @property
    def signed_off(self) -> tuple[StepResult, ...]:
        return tuple(result for result in self.results if result.signed_off)

    def result_for(self, step_id: str) -> StepResult:
        try:
            return self.results_by_step[step_id]
        except KeyError as err:
            raise UnknownAssignmentStepException(f'unknown assignment step: {step_id!r}') from err

    def get_result(self, step_id: str) -> Optional[StepResult]:
        return self.results_by_step.get(step_id)

    def resolve(self, step_id: str) -> StepResult:
        return self.result_for(step_id)

    def __getitem__(self, step_id: str) -> StepResult:
        return self.result_for(step_id)

    def __iter__(self) -> Iterable[StepResult]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __contains__(self, step_id: object) -> bool:
        return step_id in self.results_by_step

    def as_rows(self) -> list[dict[str, Any]]:
        return [result.as_row() for result in self.results]

    def _content(self) -> dict[str, Any]:
        return {
            'frozenAt': _iso(self.frozen_at),
            'results': [result.as_dict() for result in self.results],
            'signOffs': [sign_off.as_dict() for sign_off in self.sign_offs],
            'grants': [grant.as_dict() for grant in self.grants],
            'teams': [team.as_dict() for team in self.teams],
        }

    @property
    def digest(self) -> str:
        encoded = json_dumps(self._content(), sort_keys=True, separators=(',', ':')).encode('utf-8')
        return sha256(encoded).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        content = self._content()
        content['digest'] = self.digest
        return content

    def as_json(self, *, indent: Optional[int] = None) -> str:
        return json_dumps(self.as_dict(), sort_keys=True, indent=indent)

    to_dict = as_dict


class ResponsibilityPlan:
    """
    Build and evaluate a responsibility assignment plan for one BOM.

    Teams need both a declared capability and a matching authorization grant
    that is active at evaluation time. A grant covers its own component and
    components reachable through outgoing BOM dependency edges. Component
    evidence can be required per step and is always included in the result.
    """

    def __init__(
        self,
        bom: Optional[Bom] = None,
        *,
        components: Optional[Iterable[Component]] = None,
        dependencies: Optional[Iterable[Any]] = None,
    ) -> None:
        self._bom = bom if bom is not None else Bom(
            components=components or [],
            dependencies=dependencies or [],
        )
        self._teams: dict[str, ResponsibilityTeam] = {}
        self._steps: dict[str, AssignmentStep] = {}
        self._grants: dict[str, AuthorizationGrant] = {}
        self._sign_offs: dict[str, SignOff] = {}

    @classmethod
    def from_bom(cls, bom: Bom) -> 'ResponsibilityPlan':
        return cls(bom)

    @classmethod
    def for_bom(cls, bom: Bom) -> 'ResponsibilityPlan':
        return cls(bom)

    @property
    def bom(self) -> Bom:
        return self._bom

    @property
    def teams(self) -> tuple[ResponsibilityTeam, ...]:
        return tuple(self._teams[team_id] for team_id in sorted(self._teams))

    @property
    def steps(self) -> tuple[AssignmentStep, ...]:
        return tuple(self._steps.values())

    @property
    def grants(self) -> tuple[AuthorizationGrant, ...]:
        return tuple(self._grants[grant_id] for grant_id in sorted(self._grants))

    @property
    def sign_offs(self) -> tuple[SignOff, ...]:
        return tuple(self._sign_offs.values())

    @property
    def results(self) -> tuple[StepResult, ...]:
        return self.freeze().results

    @property
    def positions(self) -> tuple[StepResult, ...]:
        return self.results

    @property
    def outcomes(self) -> tuple[StepResult, ...]:
        return self.results

    @property
    def unassigned(self) -> tuple[StepResult, ...]:
        return self.freeze().unassigned

    def add_team(self, team: ResponsibilityTeam) -> ResponsibilityTeam:
        if team.id in self._teams:
            raise ResponsibilityPlanException(f'duplicate team id: {team.id!r}')
        self._teams[team.id] = team
        return team

    def register_team(self, team: ResponsibilityTeam) -> ResponsibilityTeam:
        return self.add_team(team)

    def add_step(self, step: AssignmentStep) -> AssignmentStep:
        if step.id in self._steps:
            raise ResponsibilityPlanException(f'duplicate step id: {step.id!r}')
        self._steps[step.id] = step
        return step

    def register_step(self, step: AssignmentStep) -> AssignmentStep:
        return self.add_step(step)

    def add_grant(self, grant: AuthorizationGrant) -> AuthorizationGrant:
        if grant.id in self._grants:
            raise ResponsibilityPlanException(f'duplicate grant id: {grant.id!r}')
        if grant.team_id not in self._teams:
            raise UnknownResponsibilityTeamException(f'unknown responsibility team: {grant.team_id!r}')
        self._grants[grant.id] = grant
        return grant

    def authorize(self, grant: AuthorizationGrant) -> AuthorizationGrant:
        return self.add_grant(grant)

    def revoke_grant(
        self,
        grant_id: str,
        at: Optional[datetime] = None,
        *,
        revoked_at: Optional[datetime] = None,
    ) -> AuthorizationGrant:
        try:
            grant = self._grants[grant_id]
        except KeyError as err:
            raise UnknownAuthorizationGrantException(f'unknown authorization grant: {grant_id!r}') from err
        moment = _utc(revoked_at or at) if (revoked_at is not None or at is not None) else _get_now_utc()
        if grant.revoked_at is not None and grant.revoked_at <= moment:
            return grant
        revoked = grant.revoke(moment)
        self._grants[grant_id] = revoked
        return revoked

    def revoke_authorization(
        self,
        grant_id: str,
        at: Optional[datetime] = None,
        *,
        revoked_at: Optional[datetime] = None,
    ) -> AuthorizationGrant:
        return self.revoke_grant(grant_id, at, revoked_at=revoked_at)

    def revoke(
        self,
        grant_id: str,
        at: Optional[datetime] = None,
        *,
        revoked_at: Optional[datetime] = None,
    ) -> AuthorizationGrant:
        return self.revoke_grant(grant_id, at, revoked_at=revoked_at)

    def sign_off(
        self,
        step_id: str,
        team_id: Optional[str] = None,
        *,
        completed_at: Optional[datetime] = None,
        at: Optional[datetime] = None,
        note: Optional[str] = None,
    ) -> SignOff:
        if step_id in self._sign_offs:
            raise AssignmentStepAlreadySignedOffException(
                f'assignment step {step_id!r} already has a completed sign-off')
        moment = _utc(completed_at or at) if (completed_at is not None or at is not None) else _get_now_utc()
        result = self._evaluate_step(self._step(step_id), moment, *self._bom_indexes())
        if not result.assigned:
            raise UnassignedAssignmentStepException(
                f'assignment step {step_id!r} is unassigned at {_iso(moment)}: {result.reason}')
        signer = team_id or result.team_id
        if signer != result.team_id:
            raise ResponsibilityTeamNotAssignedException(
                f'assignment step {step_id!r} is assigned to {result.team_id!r}, not {signer!r}')
        assert signer is not None
        sign_off = SignOff(
            step_id=step_id,
            team_id=signer,
            completed_at=moment,
            grant_id=result.grant_id,
            dependency_path=result.dependency_path,
            note=note,
        )
        self._sign_offs[step_id] = sign_off
        return sign_off

    def accept(
        self,
        step_id: str,
        team_id: Optional[str] = None,
        *,
        completed_at: Optional[datetime] = None,
        at: Optional[datetime] = None,
        note: Optional[str] = None,
    ) -> SignOff:
        return self.sign_off(step_id, team_id, completed_at=completed_at, at=at, note=note)

    signoff = sign_off

    def evaluate(self, at: Optional[datetime] = None) -> FrozenResponsibilityPlan:
        return self.freeze(at=at)

    def freeze(self, at: Optional[datetime] = None) -> FrozenResponsibilityPlan:
        evaluated_at = _utc(at) if at is not None else _get_now_utc()
        components, graph = self._bom_indexes()
        results = tuple(
            self._evaluate_step(step, evaluated_at, components, graph)
            for step in self._steps.values()
        )
        return FrozenResponsibilityPlan(
            frozen_at=evaluated_at,
            results=results,
            sign_offs=self.sign_offs,
            grants=self.grants,
            teams=self.teams,
        )

    snapshot = freeze

    def result_for(self, step_id: str, at: Optional[datetime] = None) -> StepResult:
        evaluated_at = _utc(at) if at is not None else _get_now_utc()
        return self._evaluate_step(self._step(step_id), evaluated_at, *self._bom_indexes())

    resolve = result_for

    def who_can(self, step_id: str, at: Optional[datetime] = None) -> tuple[str, ...]:
        return self.result_for(step_id, at).eligible_teams

    def available_teams(self, step_id: str, at: Optional[datetime] = None) -> tuple[str, ...]:
        return self.who_can(step_id, at)

    def _step(self, step_id: str) -> AssignmentStep:
        try:
            return self._steps[step_id]
        except KeyError as err:
            raise UnknownAssignmentStepException(f'unknown assignment step: {step_id!r}') from err

    def _bom_indexes(self) -> tuple[dict[str, Component], dict[str, tuple[str, ...]]]:
        components: dict[str, Component] = {}
        graph: dict[str, set[str]] = {}
        for component in self._all_components():
            ref = str(component.bom_ref)
            if ref:
                components.setdefault(ref, component)
        for dependency in self._bom.dependencies:
            targets = graph.setdefault(str(dependency.ref), set())
            targets.update(str(target.ref) for target in dependency.dependencies)
        return components, {ref: tuple(sorted(targets)) for ref, targets in graph.items()}

    def _all_components(self) -> Iterable[Component]:
        if self._bom.metadata.component is not None:
            yield from self._bom.metadata.component.iter_all_nested_components(include_self=True)
        for component in self._bom.components:
            yield from component.iter_all_nested_components(include_self=True)

    def _evaluate_step(
        self,
        step: AssignmentStep,
        at: datetime,
        components: dict[str, Component],
        graph: dict[str, tuple[str, ...]],
    ) -> StepResult:
        component = components.get(step.component_ref)
        evidence = EvidenceSummary.from_component(component)
        candidates, diagnostics = self._candidates(step, at, components, graph)
        sign_off = self._sign_offs.get(step.id)
        if sign_off is not None:
            suffix = 'no active authorization remains' if not candidates else 'authorization remains available'
            reason = (
                f'Signed off by {sign_off.team_id} at {_iso(sign_off.completed_at)}; '
                f'completed sign-off retained ({suffix}).'
            )
            return StepResult(
                step_id=step.id,
                capability=step.capability,
                component_ref=step.component_ref,
                status=AssignmentStatus.SIGNED_OFF,
                team_id=sign_off.team_id,
                grant_id=sign_off.grant_id,
                dependency_path=sign_off.dependency_path,
                evidence=evidence,
                required_evidence=tuple(sorted(step.required_evidence)),
                candidates=candidates,
                sign_off=sign_off,
                reason=reason,
                evaluated_at=at,
            )
        if candidates:
            selected = candidates[0]
            return StepResult(
                step_id=step.id,
                capability=step.capability,
                component_ref=step.component_ref,
                status=AssignmentStatus.ASSIGNED,
                team_id=selected.team_id,
                grant_id=selected.grant_id,
                dependency_path=selected.dependency_path,
                evidence=evidence,
                required_evidence=tuple(sorted(step.required_evidence)),
                candidates=candidates,
                sign_off=None,
                reason=self._assignment_reason(step, selected, evidence),
                evaluated_at=at,
            )
        reason = (
            f'No team can take {step.capability!r} for {step.component_ref!r} at {_iso(at)}: '
            + '; '.join(diagnostics)
        )
        return StepResult(
            step_id=step.id,
            capability=step.capability,
            component_ref=step.component_ref,
            status=AssignmentStatus.UNASSIGNED,
            team_id=None,
            grant_id=None,
            dependency_path=(),
            evidence=evidence,
            required_evidence=tuple(sorted(step.required_evidence)),
            candidates=(),
            sign_off=None,
            reason=reason,
            evaluated_at=at,
        )

    def _candidates(
        self,
        step: AssignmentStep,
        at: datetime,
        components: dict[str, Component],
        graph: dict[str, tuple[str, ...]],
    ) -> tuple[tuple[AssignmentCandidate, ...], list[str]]:
        diagnostics: list[str] = []
        component = components.get(step.component_ref)
        if component is None:
            diagnostics.append(f'component {step.component_ref!r} is not present in the BOM')
        evidence = EvidenceSummary.from_component(component)
        if not evidence.satisfies(step.required_evidence):
            missing = sorted(step.required_evidence.difference(evidence.kinds))
            diagnostics.append(f'component evidence is missing {", ".join(missing)}')
        if not any(team.can(step.capability) for team in self._teams.values()):
            diagnostics.append(f'no registered team has capability {step.capability!r}')
        if not any(grant.supports_capability(step.capability) for grant in self._grants.values()):
            diagnostics.append(f'no authorization grant names capability {step.capability!r}')
        if diagnostics:
            return (), diagnostics

        candidates = []
        for grant in self.grants:
            if not grant.supports_capability(step.capability):
                continue
            team = self._teams[grant.team_id]
            if not team.can(step.capability):
                diagnostics.append(f'team {team.id!r} does not claim capability {step.capability!r}')
                continue
            if not evidence.satisfies(grant.required_evidence):
                missing = sorted(grant.required_evidence.difference(evidence.kinds))
                diagnostics.append(f'grant {grant.id} requires missing evidence {", ".join(missing)}')
                continue
            inactive = grant.active_failure(at)
            if inactive is not None:
                diagnostics.append(inactive)
                continue
            path = self._dependency_path(grant.component_ref, step.component_ref, graph)
            if path is None:
                diagnostics.append(
                    f'grant {grant.id} on {grant.component_ref!r} does not cover {step.component_ref!r}')
                continue
            candidates.append(AssignmentCandidate(team.id, grant.id, path))
        candidates.sort(key=lambda candidate: (
            len(candidate.dependency_path),
            candidate.team_id,
            candidate.grant_id,
        ))
        return tuple(candidates), list(dict.fromkeys(diagnostics))

    @staticmethod
    def _dependency_path(
        start: str,
        target: str,
        graph: dict[str, tuple[str, ...]],
    ) -> Optional[tuple[str, ...]]:
        if start in ('*', target):
            return (target,)
        queue = deque([(start, (start,))])
        visited = {start}
        while queue:
            current, path = queue.popleft()
            for dependency in graph.get(current, ()):
                if dependency in visited:
                    continue
                next_path = (*path, dependency)
                if dependency == target:
                    return next_path
                visited.add(dependency)
                queue.append((dependency, next_path))
        return None

    @staticmethod
    def _assignment_reason(
        step: AssignmentStep,
        candidate: AssignmentCandidate,
        evidence: EvidenceSummary,
    ) -> str:
        if candidate.direct:
            basis = f'direct grant {candidate.grant_id}'
        else:
            basis = (
                f'grant {candidate.grant_id} inherited via '
                + ' -> '.join(candidate.dependency_path)
            )
        evidence_text = ', '.join(evidence.kinds) if evidence.kinds else 'none'
        return (
            f'Assigned {candidate.team_id} for {step.capability!r}: {basis}; '
            f'component evidence: {evidence_text}.'
        )


AssignmentPlan = ResponsibilityPlan
ResponsibilityAssignmentPlan = ResponsibilityPlan
RemediationPlan = ResponsibilityPlan
Plan = ResponsibilityPlan
Team = ResponsibilityTeam
Step = AssignmentStep
Grant = AuthorizationGrant
Signoff = SignOff
PlanSnapshot = FrozenResponsibilityPlan
TimeWindow = AuthorizationWindow
AuthorizationPeriod = AuthorizationWindow
Position = StepResult


__all__ = [
    'AssignmentPlan',
    'AssignmentCandidate',
    'AssignmentStatus',
    'AssignmentStep',
    'AuthorizationGrant',
    'AuthorizationPeriod',
    'AuthorizationWindow',
    'EvidenceSummary',
    'FrozenResponsibilityPlan',
    'Grant',
    'Plan',
    'PlanSnapshot',
    'Position',
    'RemediationPlan',
    'ResponsibilityAssignmentPlan',
    'ResponsibilityPlan',
    'ResponsibilityTeam',
    'SignOff',
    'Signoff',
    'Step',
    'StepResult',
    'Team',
    'TimeWindow',
]
