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

"""Offline CycloneDX service-residency and failover-path compliance checks.

The checker evaluates every condition-enabled route through the service-reference
graph, not just the shortest route. A node is compliant only when its declared
region is allowed for all data categories carried into that node and a traceable
region proof is present. Endpoint findings always retain the shortest failing
paths and their proof references for audit.
"""

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Any, Optional, Union

from ._manifest import ManifestGraph, ManifestInput, build_manifest_graph
from ._types import (
    BrokenReference,
    ComplianceReport,
    ConditionSkip,
    Cycle,
    EndpointFinding,
    PathStep,
    PathTrace,
    ResidencyPolicy,
    Violation,
    ViolationCode,
)

_EU_COUNTRIES = frozenset({
    'at', 'be', 'bg', 'cy', 'cz', 'de', 'dk', 'ee', 'es', 'fi', 'fr', 'gr', 'hr',
    'hu', 'ie', 'it', 'lt', 'lu', 'lv', 'mt', 'nl', 'pl', 'pt', 'ro', 'se', 'si', 'sk',
})
_COUNTRY_ALIASES = {
    'germany': 'de',
    'deutschland': 'de',
    'france': 'fr',
    'unitedstates': 'us',
    'unitedstatesofamerica': 'us',
    'usa': 'us',
    'unitedkingdom': 'gb',
    'uk': 'gb',
    'greatbritain': 'gb',
    'china': 'cn',
    'singapore': 'sg',
    'japan': 'jp',
    'canada': 'ca',
    'australia': 'au',
}
_EU_NAMES = {'eu', 'europe', 'europeanunion'}


def check_residency(
    manifest: ManifestInput,
    policy: Optional[Union[ResidencyPolicy, Mapping[str, Any]]] = None,
    *,
    allowed_regions: Optional[Mapping[str, Iterable[str]]] = None,
    enabled_conditions: Optional[Iterable[str]] = None,
    disabled_conditions: Optional[Iterable[str]] = None,
    require_proof: Optional[bool] = None,
    entrypoints: Optional[Iterable[str]] = None,
    endpoints: Optional[Iterable[str]] = None,
) -> ComplianceReport:
    """Check all condition-enabled processing paths in a CycloneDX service manifest.

    Args:
        manifest: A :class:`Bom`, service model/iterable, JSON/XML text, path, or mapping.
        policy: A :class:`ResidencyPolicy` or a flexible policy mapping.
        allowed_regions: Per-data-category allowed regions, overriding policy values.
        enabled_conditions: Conditions that are active; an empty iterable disables all.
        disabled_conditions: Conditions that are inactive, overriding enabled ones.
        require_proof: Require a traceable proof reference for every region claim.
        entrypoints: Optional service refs/names to use as traversal roots.
        endpoints: Optional service refs/names to report as terminal processing nodes.

    Returns:
        A deterministic :class:`ComplianceReport`. Missing service references and
        cycles are reported separately and never cause unbounded traversal.
    """
    graph = build_manifest_graph(manifest)
    effective_policy = _effective_policy(
        policy,
        allowed_regions=allowed_regions,
        enabled_conditions=enabled_conditions,
        disabled_conditions=disabled_conditions,
        require_proof=require_proof,
        entrypoints=entrypoints,
        endpoints=endpoints,
        manifest_conditions=graph.conditions,
    )
    broken = list(graph.broken_references)
    roots = _selected_refs(effective_policy.entrypoints, graph, broken, 'entry point') \
        if effective_policy.entrypoints is not None else list(graph.entrypoints)
    terminals = _selected_refs(effective_policy.endpoints, graph, broken, 'endpoint') \
        if effective_policy.endpoints is not None else list(graph.endpoints)
    trace = _Traversal(graph=graph, policy=effective_policy, terminals=frozenset(terminals))
    for root in roots:
        trace.walk(root)
    return _build_report(roots, terminals, trace, _find_cycles(graph, roots), broken)


def _effective_policy(
    policy: Optional[Union[ResidencyPolicy, Mapping[str, Any]]],
    *,
    allowed_regions: Optional[Mapping[str, Iterable[str]]],
    enabled_conditions: Optional[Iterable[str]],
    disabled_conditions: Optional[Iterable[str]],
    require_proof: Optional[bool],
    entrypoints: Optional[Iterable[str]],
    endpoints: Optional[Iterable[str]],
    manifest_conditions: Mapping[str, bool],
) -> ResidencyPolicy:
    if isinstance(policy, Mapping):
        policy = ResidencyPolicy.from_mapping(policy)
    elif policy is None:
        policy = ResidencyPolicy()
    if not policy.conditions and manifest_conditions:
        policy = replace(policy, conditions=dict(manifest_conditions))
    if allowed_regions is not None:
        categories = {
            str(category): tuple(str(region) for region in regions)
            for category, regions in allowed_regions.items()
        }
        policy = replace(policy, allowed_regions=categories)
    if enabled_conditions is not None:
        policy = replace(policy, enabled_conditions=frozenset(str(item).casefold() for item in enabled_conditions))
    if disabled_conditions is not None:
        disabled = frozenset(str(item).casefold() for item in disabled_conditions)
        policy = replace(policy, disabled_conditions=(policy.disabled_conditions or frozenset()) | disabled)
    if require_proof is not None:
        policy = replace(policy, require_proof=require_proof)
    if entrypoints is not None:
        policy = replace(policy, entrypoints=tuple(str(item) for item in entrypoints))
    if endpoints is not None:
        policy = replace(policy, endpoints=tuple(str(item) for item in endpoints))
    return policy


def _selected_refs(
    values: Optional[Iterable[str]], graph: ManifestGraph, broken: list[BrokenReference], label: str,
) -> list[str]:
    if values is None:
        return []
    result: list[str] = []
    for value in values:
        resolved = graph.aliases.get(str(value), graph.aliases.get(str(value).casefold()))
        if resolved is None:
            broken.append(BrokenReference(None, str(value), f'unknown {label}'))
        elif resolved not in result:
            result.append(resolved)
    return result


class _Traversal:
    """Breadth-first traversal over (service, carried categories) states."""

    def __init__(self, graph: ManifestGraph, policy: ResidencyPolicy, terminals: frozenset[str]) -> None:
        self._graph = graph
        self._policy = policy
        self._terminals = terminals
        self._outgoing = _outgoing_edges(graph)
        self._best_distance: dict[tuple[str, frozenset[str], bool], int] = {}
        self._failed: dict[str, list[PathTrace]] = {}
        self._passed: dict[str, list[PathTrace]] = {}
        self._conditions_disabled: dict[tuple[Optional[str], str, Optional[str], str], ConditionSkip] = {}

    @property
    def failed(self) -> Mapping[str, list[PathTrace]]:
        return self._failed

    @property
    def passed(self) -> Mapping[str, list[PathTrace]]:
        return self._passed

    @property
    def conditions_disabled(self) -> tuple[ConditionSkip, ...]:
        return tuple(sorted(
            self._conditions_disabled.values(),
            key=lambda item: (item.from_ref or '', item.to_ref, item.condition or '', item.reason),
        ))

    def walk(self, root: str) -> None:
        record = self._graph.records.get(root)
        if record is None:
            return
        if not self._node_enabled(record, None):
            return
        categories = frozenset(record.categories)
        step = self._step(record, categories)
        path = (step,)
        failed = bool(step.violations)
        self._remember_terminal(record.ref, path)
        self._best_distance[(root, categories, failed)] = 0
        queue: deque[tuple[PathStep, frozenset[str], tuple[PathStep, ...], bool]] = deque(
            ((step, categories, path, failed),)
        )
        while queue:
            step, categories, path, failed = queue.popleft()
            if step.ref in self._terminals:
                continue
            for edge in self._outgoing.get(step.ref, ()):
                target = self._graph.records.get(edge.target)
                if target is None:
                    continue
                if not self._edge_enabled(edge, step.ref):
                    continue
                if not self._node_enabled(target, step.ref):
                    continue
                next_categories = categories | frozenset(target.categories)
                next_step = self._step(target, next_categories, edge.condition)
                next_failed = failed or bool(next_step.violations)
                next_path = path + (next_step,)
                key = (target.ref, next_categories, next_failed)
                distance = len(next_path) - 1
                if key in self._best_distance and self._best_distance[key] < distance:
                    continue
                self._best_distance[key] = min(distance, self._best_distance.get(key, distance))
                queue.append((next_step, next_categories, next_path, next_failed))
                self._remember_terminal(target.ref, next_path)

    def _remember_terminal(self, endpoint: str, path: tuple[PathStep, ...]) -> None:
        if endpoint not in self._terminals:
            return
        trace = PathTrace(path)
        bundle = self._failed if self._path_failed(path) else self._passed
        paths = bundle.setdefault(endpoint, [])
        if not paths or trace.length < paths[0].length:
            bundle[endpoint] = [trace]
        elif trace.length == paths[0].length and path not in {item.steps for item in paths}:
            paths.append(trace)

    def _step(
        self, record: Any, categories: frozenset[str], condition: Optional[str] = None,
    ) -> PathStep:
        violations = _violations(record, categories, self._policy)
        return PathStep(
            ref=record.ref,
            name=record.name,
            categories=tuple(sorted(categories, key=str.casefold)),
            regions=record.claims,
            proofs=tuple(proof.reference for proof in record.proofs),
            violations=tuple(violations),
            condition=condition,
        )

    def _edge_enabled(self, edge: Any, source: str) -> bool:
        reason = _condition_reason(edge.condition, edge.enabled, self._policy)
        if reason is None:
            return True
        key = (source, edge.target, edge.condition, reason)
        self._conditions_disabled.setdefault(key, ConditionSkip(source, edge.target, edge.condition, reason))
        return False

    def _node_enabled(self, record: Any, source: Optional[str]) -> bool:
        if record.enabled is False:
            skip = ConditionSkip(source, record.ref, record.condition, 'node_disabled')
            self._conditions_disabled.setdefault((source, record.ref, record.condition, 'node_disabled'), skip)
            return False
        reason = _condition_reason(record.condition, None, self._policy)
        if reason is None:
            return True
        skip = ConditionSkip(source, record.ref, record.condition, reason)
        self._conditions_disabled.setdefault((source, record.ref, record.condition, reason), skip)
        return False

    @staticmethod
    def _path_failed(path: tuple[PathStep, ...]) -> bool:
        return any(step.violations for step in path)


def _outgoing_edges(graph: ManifestGraph) -> dict[str, tuple[Any, ...]]:
    outgoing: dict[str, list[Any]] = {}
    for edge in graph.edges:
        outgoing.setdefault(edge.source, []).append(edge)
    return {source: tuple(sorted(items, key=lambda edge: edge.target)) for source, items in outgoing.items()}


def _condition_reason(condition: Optional[str], enabled: Optional[bool], policy: ResidencyPolicy) -> Optional[str]:
    if enabled is False:
        return 'edge_disabled'
    if condition and not policy.condition_enabled(condition):
        return 'condition_not_enabled'
    return None


def _violations(record: Any, categories: frozenset[str], policy: ResidencyPolicy) -> list[Violation]:
    violations: list[Violation] = []
    claims = record.claims
    proofs = record.proofs
    regions = tuple(claims)
    proof_refs = tuple(proof.reference for proof in proofs)
    if not claims:
        violations.append(Violation(
            ViolationCode.REGION_MISSING, record.ref,
            'No processing-region claim was found', tuple(sorted(categories)), regions, proof_refs,
        ))
    else:
        for category in sorted(categories, key=str.casefold):
            allowed = policy.allowed_for(category)
            if allowed is None:
                continue
            for claim in claims:
                if not any(_region_matches(claim, permitted) for permitted in allowed):
                    violations.append(Violation(
                        ViolationCode.REGION_NOT_ALLOWED, record.ref,
                        f'Region {claim!r} is not allowed for data category {category!r}',
                        tuple(sorted(categories)), regions, proof_refs,
                    ))
    if policy.require_proof and not proofs:
        violations.append(Violation(
            ViolationCode.PROOF_MISSING, record.ref,
            'No traceable region proof was supplied for this processing node',
            tuple(sorted(categories)), regions, proof_refs,
        ))
    for proof in proofs:
        if proof.region and claims and not any(
            _regions_overlap(claim, proof.region) for claim in claims
        ):
            violations.append(Violation(
                ViolationCode.PROOF_REGION_MISMATCH, record.ref,
                f'Proof region {proof.region!r} does not match declared regions {claims!r}',
                tuple(sorted(categories)), regions, proof_refs,
            ))
            break
    return violations


def _normalize_region(value: str) -> str:
    return ''.join(character for character in value.casefold() if character.isalnum())


def _country_of(value: str) -> str:
    compact = _normalize_region(value)
    alias = _COUNTRY_ALIASES.get(compact)
    if alias:
        return alias
    for separator in ('-', '_', '/', ':', ' '):
        if separator in value.casefold():
            part = value.casefold().split(separator, 1)[0]
            token = _normalize_region(part)
            if len(token) == 2:
                return token
    return compact if len(compact) == 2 else ''


def _region_matches(claim: str, allowed: str) -> bool:
    if allowed.strip() == '*':
        return True
    claim_normalized = _normalize_region(claim)
    allowed_normalized = _normalize_region(allowed)
    if not allowed_normalized:
        return False
    if claim_normalized == allowed_normalized:
        return True
    if claim_normalized.startswith(allowed_normalized) and len(claim_normalized) > len(allowed_normalized):
        return True
    claim_parts = {
        _normalize_region(part)
        for part in claim.replace('_', '-').replace('/', '-').replace(':', '-').replace(' ', '-').split('-')
    }
    if allowed_normalized in claim_parts:
        return True
    claim_country = _country_of(claim)
    allowed_country = _country_of(allowed)
    if claim_country and allowed_country and claim_country == allowed_country:
        return True
    if allowed_normalized in _EU_NAMES:
        return claim_country in _EU_COUNTRIES or claim_normalized.startswith('eu')
    return False


def _regions_overlap(first: str, second: str) -> bool:
    return _region_matches(first, second) or _region_matches(second, first)


def _find_cycles(graph: ManifestGraph, roots: Iterable[str]) -> tuple[Cycle, ...]:
    outgoing = _outgoing_edges(graph)
    color: dict[str, int] = {}
    stack: list[str] = []
    cycles: set[tuple[str, ...]] = set()

    def visit(ref: str) -> None:
        color[ref] = 1
        stack.append(ref)
        for edge in outgoing.get(ref, ()):
            if edge.target not in color:
                visit(edge.target)
            elif color[edge.target] == 1:
                cycle = tuple(stack[stack.index(edge.target):]) + (edge.target,)
                cycles.add(_canonical_cycle(cycle))
        stack.pop()
        color[ref] = 2

    for root in sorted(set(roots) | set(graph.records)):
        if root in graph.records and root not in color:
            visit(root)
    return tuple(Cycle(cycle) for cycle in sorted(cycles))


def _canonical_cycle(cycle: tuple[str, ...]) -> tuple[str, ...]:
    body = cycle[:-1]
    if not body:
        return cycle
    rotations = [body[index:] + body[:index] for index in range(len(body))]
    start = min(rotations)
    return start + (start[0],)


def _build_report(
    roots: Iterable[str], terminals: Iterable[str], traversal: _Traversal,
    cycles: Iterable[Cycle], broken: Iterable[BrokenReference],
) -> ComplianceReport:
    reachable = sorted(set(traversal.failed) | set(traversal.passed))
    compliant: list[EndpointFinding] = []
    non_compliant: list[EndpointFinding] = []
    for endpoint in reachable:
        failed = traversal.failed.get(endpoint, [])
        passed = traversal.passed.get(endpoint, [])
        if failed:
            shortest = tuple(sorted(failed, key=lambda path: (path.length, path.refs)))
            non_compliant.append(EndpointFinding(
                endpoint=endpoint,
                name=shortest[0].steps[-1].name,
                path=shortest[0],
                shortest_paths=shortest,
                violations=_merge_violations(shortest),
                has_compliant_path=bool(passed),
            ))
        elif passed:
            shortest = tuple(sorted(passed, key=lambda path: (path.length, path.refs)))
            compliant.append(EndpointFinding(
                endpoint=endpoint,
                name=shortest[0].steps[-1].name,
                path=shortest[0],
                shortest_paths=shortest,
                violations=(),
                has_compliant_path=True,
            ))
    references = tuple(sorted(
        set(broken),
        key=lambda item: (item.source or '', item.target, item.reason),
    ))
    return ComplianceReport(
        entrypoints=tuple(roots),
        reachable_endpoints=tuple(reachable),
        compliant_endpoints=tuple(compliant),
        non_compliant_endpoints=tuple(non_compliant),
        conditions_disabled=traversal.conditions_disabled,
        cycles=tuple(cycles),
        broken_references=references,
    )


def _merge_violations(paths: Iterable[PathTrace]) -> tuple[Violation, ...]:
    merged: list[Violation] = []
    for path in paths:
        for violation in path.violations:
            if violation not in merged:
                merged.append(violation)
    return tuple(merged)


class ResidencyChecker:
    """Small convenience wrapper around :func:`check_residency`."""

    def __init__(self, manifest: Optional[ManifestInput] = None,
                 policy: Optional[Union[ResidencyPolicy, Mapping[str, Any]]] = None) -> None:
        self._manifest = manifest
        self._policy = policy

    def check(self, manifest: Optional[ManifestInput] = None) -> ComplianceReport:
        selected = manifest if manifest is not None else self._manifest
        if selected is None:
            raise ValueError('No CycloneDX manifest supplied')
        return check_residency(selected, self._policy)


check_service_residency = check_residency
check_residency_compliance = check_residency
audit_residency = check_residency
