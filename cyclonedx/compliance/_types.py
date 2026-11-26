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

"""Public result and policy types for offline service-residency checks."""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ViolationCode(str, Enum):
    """Machine-readable reasons a processing node failed the residency check."""

    REGION_MISSING = 'region_missing'
    REGION_NOT_ALLOWED = 'region_not_allowed'
    PROOF_MISSING = 'proof_missing'
    PROOF_REGION_MISMATCH = 'proof_region_mismatch'


@dataclass(frozen=True)
class ProofReference:
    """A traceable, offline region-proof reference from the manifest."""

    reference: str
    region: Optional[str] = None
    source: str = 'property'

    def to_dict(self) -> dict[str, Any]:
        return {
            'reference': self.reference,
            'region': self.region,
            'source': self.source,
        }


@dataclass(frozen=True)
class Violation:
    """A residency violation attached to one node and the data carried through it."""

    code: ViolationCode
    ref: str
    message: str
    categories: tuple[str, ...] = ()
    regions: tuple[str, ...] = ()
    proofs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            'code': self.code.value,
            'ref': self.ref,
            'message': self.message,
            'categories': list(self.categories),
            'regions': list(self.regions),
            'proofs': list(self.proofs),
        }


@dataclass(frozen=True)
class PathStep:
    """An auditable hop in a processing path."""

    ref: str
    name: str
    categories: tuple[str, ...]
    regions: tuple[str, ...]
    proofs: tuple[str, ...]
    violations: tuple[Violation, ...] = ()
    condition: Optional[str] = None

    @property
    def compliant(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            'ref': self.ref,
            'name': self.name,
            'categories': list(self.categories),
            'regions': list(self.regions),
            'proofs': list(self.proofs),
            'compliant': self.compliant,
            'violations': [v.to_dict() for v in self.violations],
            'condition': self.condition,
        }


@dataclass(frozen=True)
class PathTrace:
    """A complete path from an entry point to an endpoint."""

    steps: tuple[PathStep, ...]

    @property
    def refs(self) -> tuple[str, ...]:
        return tuple(step.ref for step in self.steps)

    @property
    def nodes(self) -> tuple[str, ...]:
        return self.refs

    @property
    def length(self) -> int:
        return len(self.steps) - 1

    @property
    def compliant(self) -> bool:
        return all(step.compliant for step in self.steps)

    @property
    def violations(self) -> tuple[Violation, ...]:
        return tuple(
            violation
            for step in self.steps
            for violation in step.violations
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            'refs': list(self.refs),
            'length': self.length,
            'compliant': self.compliant,
            'steps': [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True)
class EndpointFinding:
    """A reachable endpoint and the shortest failing path(s) to it."""

    endpoint: str
    name: str
    path: PathTrace
    shortest_paths: tuple[PathTrace, ...]
    violations: tuple[Violation, ...]
    has_compliant_path: bool = False

    @property
    def path_refs(self) -> tuple[str, ...]:
        return self.path.refs

    def to_dict(self) -> dict[str, Any]:
        return {
            'endpoint': self.endpoint,
            'name': self.name,
            'path': self.path.to_dict(),
            'shortest_paths': [path.to_dict() for path in self.shortest_paths],
            'violations': [violation.to_dict() for violation in self.violations],
            'has_compliant_path': self.has_compliant_path,
        }


@dataclass(frozen=True)
class ConditionSkip:
    """A branch that was intentionally not followed because its condition is inactive."""

    from_ref: Optional[str]
    to_ref: str
    condition: Optional[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'from': self.from_ref,
            'to': self.to_ref,
            'condition': self.condition,
            'reason': self.reason,
        }


@dataclass(frozen=True)
class Cycle:
    """A structural service-reference cycle."""

    refs: tuple[str, ...]

    @property
    def nodes(self) -> tuple[str, ...]:
        return self.refs

    def to_dict(self) -> dict[str, Any]:
        return {'refs': list(self.refs)}


@dataclass(frozen=True)
class BrokenReference:
    """A service reference that cannot be resolved within the manifest."""

    source: Optional[str]
    target: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'source': self.source,
            'target': self.target,
            'reason': self.reason,
        }


@dataclass(frozen=True)
class ComplianceReport:
    """Deterministic, serializable result of an offline residency check."""

    entrypoints: tuple[str, ...]
    reachable_endpoints: tuple[str, ...]
    compliant_endpoints: tuple[EndpointFinding, ...]
    non_compliant_endpoints: tuple[EndpointFinding, ...]
    conditions_disabled: tuple[ConditionSkip, ...]
    cycles: tuple[Cycle, ...]
    broken_references: tuple[BrokenReference, ...]

    @property
    def condition_skipped(self) -> tuple[ConditionSkip, ...]:
        return self.conditions_disabled

    @property
    def skipped_conditions(self) -> tuple[ConditionSkip, ...]:
        return self.conditions_disabled

    @property
    def unverified_endpoints(self) -> tuple[EndpointFinding, ...]:
        return tuple(
            endpoint
            for endpoint in self.non_compliant_endpoints
            if any(v.code in {
                ViolationCode.PROOF_MISSING,
                ViolationCode.PROOF_REGION_MISMATCH,
            } for v in endpoint.violations)
        )

    @property
    def non_compliant_endpoint_refs(self) -> tuple[str, ...]:
        return tuple(endpoint.endpoint for endpoint in self.non_compliant_endpoints)

    @property
    def failed_endpoints(self) -> tuple[EndpointFinding, ...]:
        return self.non_compliant_endpoints

    @property
    def status(self) -> str:
        if self.non_compliant_endpoints:
            return 'non_compliant'
        if self.broken_references or self.cycles:
            return 'invalid'
        if not self.reachable_endpoints:
            return 'no_reachable_endpoints'
        return 'compliant'

    @property
    def is_compliant(self) -> bool:
        return self.status == 'compliant'

    @property
    def compliant(self) -> bool:
        return self.is_compliant

    def to_dict(self) -> dict[str, Any]:
        return {
            'status': self.status,
            'compliant': self.is_compliant,
            'entrypoints': list(self.entrypoints),
            'reachable_endpoints': list(self.reachable_endpoints),
            'compliant_endpoints': [endpoint.to_dict() for endpoint in self.compliant_endpoints],
            'non_compliant_endpoints': [endpoint.to_dict() for endpoint in self.non_compliant_endpoints],
            'unverified_endpoints': [endpoint.to_dict() for endpoint in self.unverified_endpoints],
            'conditions_disabled': [condition.to_dict() for condition in self.conditions_disabled],
            'cycles': [cycle.to_dict() for cycle in self.cycles],
            'broken_references': [reference.to_dict() for reference in self.broken_references],
        }

    def as_dict(self) -> dict[str, Any]:
        return self.to_dict()

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


@dataclass(frozen=True)
class ResidencyPolicy:
    """Policy used by the offline checker.

    ``enabled_conditions`` uses three-state semantics:

    * ``None`` means conditional branches are active unless a ``conditions`` map
      explicitly marks one inactive;
    * a set means only those conditions are active and takes precedence over the
      ``conditions`` map;
    * ``disabled_conditions`` always takes precedence.
    """

    allowed_regions: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    require_proof: bool = True
    default_regions: Optional[tuple[str, ...]] = None
    enabled_conditions: Optional[frozenset[str]] = None
    disabled_conditions: frozenset[str] = frozenset()
    conditions: Mapping[str, bool] = field(default_factory=dict)
    entrypoints: Optional[tuple[str, ...]] = None
    endpoints: Optional[tuple[str, ...]] = None

    def allowed_for(self, category: str) -> Optional[tuple[str, ...]]:
        key = category.casefold()
        for configured, regions in self.allowed_regions.items():
            if configured.casefold() == key:
                return regions
        for configured, regions in self.allowed_regions.items():
            if configured == '*':
                return regions
        return self.default_regions

    def condition_enabled(self, condition: Optional[str]) -> bool:
        if not condition:
            return True
        key = condition.casefold()
        if key in (self.disabled_conditions or frozenset()):
            return False
        if self.enabled_conditions is not None:
            return key in self.enabled_conditions
        for configured, enabled in self.conditions.items():
            if configured.casefold() == key:
                return enabled
        return True

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> 'ResidencyPolicy':
        raw = _casefold_mapping(value)
        allowed = _policy_allowed_regions(raw, value)
        default = _regions_value(_first(raw, 'default_regions', 'defaultregions'))
        global_regions = _regions_value(_first(raw, 'allowed_regions', 'allowedregions'))
        if global_regions is not None and not isinstance(
            _first(raw, 'data_categories', 'datacategories', 'data_classes', 'dataclasses'), Mapping
        ):
            default = default or global_regions
        proof = _as_bool(raw.get('require_proof', raw.get('requireproof', True)))
        enabled = _condition_set(_first(raw, 'enabled_conditions', 'enabledconditions'))
        disabled = _condition_set(_first(raw, 'disabled_conditions', 'disabledconditions')) or frozenset()
        conditions = _condition_map(raw.get('conditions'))
        entrypoints = _string_tuple(_first(raw, 'entrypoints', 'entry_points'))
        endpoints = _string_tuple(raw.get('endpoints'))
        return cls(
            allowed_regions=allowed,
            require_proof=bool(proof),
            default_regions=default,
            enabled_conditions=enabled,
            disabled_conditions=disabled,
            conditions=conditions,
            entrypoints=entrypoints,
            endpoints=endpoints,
        )


def _casefold_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key).casefold(): item for key, item in value.items()}


def _first(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _regions_value(value: Any) -> Optional[tuple[str, ...]]:
    if value is None:
        return None
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(',') if part.strip())
    if isinstance(value, Mapping):
        normalized = _casefold_mapping(value)
        value = _first(normalized, 'allowed_regions', 'allowedregions', 'regions', 'allowed')
        return _regions_value(value)
    if isinstance(value, Iterable):
        return tuple(str(part).strip() for part in value if str(part).strip())
    return (str(value),)


def _policy_allowed_regions(raw: Mapping[str, Any], original: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    categories = _first(
        raw, 'data_categories', 'datacategories', 'data_classes', 'dataclasses',
        'allowed_regions', 'allowedregions',
    )
    if categories is None:
        reserved = {
            'data_classes', 'dataclasses', 'default_regions', 'defaultregions', 'require_proof', 'requireproof',
            'enabled_conditions', 'enabledconditions', 'disabled_conditions', 'disabledconditions',
            'conditions', 'entrypoints', 'entry_points', 'endpoints',
        }
        categories = {
            key: value for key, value in original.items()
            if str(key).casefold() not in reserved
        }
    if not isinstance(categories, Mapping):
        return {}
    result: dict[str, tuple[str, ...]] = {}
    for category, rules in categories.items():
        result[str(category)] = _regions_value(rules) or ()
    return result


def _condition_set(value: Any) -> Optional[frozenset[str]]:
    if value is None:
        return None
    if isinstance(value, str):
        return frozenset((value.casefold(),))
    if isinstance(value, Iterable):
        return frozenset(str(item).casefold() for item in value)
    return frozenset((str(value).casefold(),))


def _condition_map(value: Any) -> dict[str, bool]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _as_bool(enabled) for key, enabled in value.items()}


def _string_tuple(value: Any) -> Optional[tuple[str, ...]]:
    if value is None:
        return None
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(',') if part.strip())
    return tuple(str(item) for item in value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {'1', 'true', 'yes', 'on', 'enabled', 'active'}
