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

"""Manifest normalization and service-reference graph extraction."""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from os import PathLike, path
from typing import Any, Optional, Union
from xml.etree.ElementTree import Element  # nosec B405
from xml.etree.ElementTree import fromstring as xml_fromstring  # nosec B405

from ..model import DataClassification, ExternalReference, Property
from ..model.bom import Bom
from ..model.service import Service
from ._types import BrokenReference, ProofReference

ManifestInput = Union[str, PathLike[str], Mapping[str, Any], Bom, Service, Iterable[Service]]


@dataclass(frozen=True)
class ServiceRecord:
    ref: str
    name: str
    categories: tuple[str, ...]
    claims: tuple[str, ...]
    proofs: tuple[ProofReference, ...]
    condition: Optional[str] = None
    enabled: Optional[bool] = None
    endpoint: bool = False


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    condition: Optional[str] = None
    enabled: Optional[bool] = None
    origin: str = 'dependency'


@dataclass(frozen=True)
class ManifestGraph:
    records: Mapping[str, ServiceRecord]
    aliases: Mapping[str, str]
    edges: tuple[Edge, ...]
    entrypoints: tuple[str, ...]
    endpoints: tuple[str, ...]
    conditions: Mapping[str, bool]
    broken_references: tuple[BrokenReference, ...]


_PROOF_REFERENCE_KEYS = (
    'reference', 'uri', 'url', 'id', 'digest', 'hash', 'sha256', 'location', 'evidence',
)
_PROOF_EXTERNAL_TYPES = {'evidence', 'attestation', 'certification-report'}
def build_manifest_graph(manifest: ManifestInput) -> ManifestGraph:
    raw, top = _coerce_manifest(manifest)
    raw = _apply_top_metadata(raw, top)
    records, aliases, broken = _collect_records(raw)
    edges, external_roots = _collect_edges(raw, top, aliases, broken)
    entrypoints = sorted(set(_resolve_entrypoints(raw, top, records, edges, aliases, broken)) | external_roots)
    endpoints = _resolve_endpoints(raw, top, records, edges, aliases, broken)
    conditions = _collect_condition_state(raw, top, edges)
    return ManifestGraph(
        records=records,
        aliases=aliases,
        edges=tuple(edges),
        entrypoints=tuple(entrypoints),
        endpoints=tuple(endpoints),
        conditions=conditions,
        broken_references=tuple(broken),
    )


def _coerce_manifest(manifest: ManifestInput) -> tuple[dict[str, Any], dict[str, Any]]:
    if isinstance(manifest, Bom):
        return _from_bom(manifest)
    if isinstance(manifest, Service):
        return _from_bom(Bom(services=[manifest]))
    if isinstance(manifest, (str, PathLike)):
        return _from_text(str(manifest))
    if isinstance(manifest, Mapping):
        raw = dict(manifest)
    elif isinstance(manifest, Iterable):
        raw = {'services': [_service_to_mapping(service) for service in manifest]}
    else:
        raise TypeError(f'Unsupported CycloneDX manifest input: {type(manifest)!r}')
    return raw, _top_extension(raw)


def _from_text(value: str) -> tuple[dict[str, Any], dict[str, Any]]:
    stripped = value.lstrip()
    if stripped.startswith(('{', '[')):
        raw = json.loads(value)
    elif stripped.startswith('<'):
        raw = _xml_to_mapping(stripped)
    elif path.exists(value):
        with open(value, encoding='utf-8') as source:
            return _from_text(source.read())
    else:
        raise FileNotFoundError(value)
    if not isinstance(raw, dict):
        raise ValueError('CycloneDX service manifest must be an object')
    return raw, _top_extension(raw)


def _from_bom(bom: Bom) -> tuple[dict[str, Any], dict[str, Any]]:
    raw: dict[str, Any] = {
        'services': [_service_to_mapping(service) for service in bom.services],
        'dependencies': [
            {
                'ref': str(dependency.ref),
                'dependsOn': [str(item.ref) for item in dependency.dependencies],
            }
            for dependency in bom.dependencies
        ],
        'properties': [{'name': item.name, 'value': item.value} for item in bom.properties],
    }
    return raw, _top_extension(raw)


def _service_to_mapping(service: Service) -> dict[str, Any]:
    provider = service.provider
    address = provider.address if provider else None
    return {
        'bom-ref': str(service.bom_ref) if service.bom_ref.value else None,
        'name': service.name,
        'group': service.group,
        'version': service.version,
        'provider': {
            'name': provider.name if provider else None,
            'address': {
                'country': address.country if address else None,
                'region': address.region if address else None,
                'locality': address.locality if address else None,
            } if address else None,
        } if provider else None,
        'data': [
            {'classification': item.classification, 'flow': item.flow.value}
            for item in service.data
        ],
        'properties': [{'name': item.name, 'value': item.value} for item in service.properties],
        'externalReferences': [
            _external_reference_to_mapping(item) for item in service.external_references
        ],
        'services': [_service_to_mapping(item) for item in service.services],
    }


def _external_reference_to_mapping(reference: ExternalReference) -> dict[str, Any]:
    return {
        'type': reference.type.value,
        'url': str(reference.url),
        'comment': reference.comment,
        'properties': [{'name': item.name, 'value': item.value} for item in reference.properties],
    }


def _top_extension(raw: Mapping[str, Any]) -> dict[str, Any]:
    top = raw.get('x-residency') or raw.get('x_residency') or raw.get('residency')
    extension = dict(top) if isinstance(top, Mapping) else {}
    extension.update(_extension_from_properties(raw.get('properties', ())).get('residency', {}))
    return extension


def _extension_from_properties(values: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes, Mapping)):
        return result
    for item in values:
        name = item.name if isinstance(item, Property) else (
            item.get('name') if isinstance(item, Mapping) else None
        )
        value = item.value if isinstance(item, Property) else (
            item.get('value') if isinstance(item, Mapping) else None
        )
        if name is None or value is None:
            continue
        key = _normalized_key(str(name))
        if key in {'residencyedges', 'residencynodes', 'residencyconditions'}:
            try:
                parsed = json.loads(str(value))
            except ValueError:
                continue
            if isinstance(parsed, Mapping):
                result.setdefault('residency', {})[key.replace('residency', '', 1)] = parsed
        elif key in {'residencyentrypoints', 'residencyendpoints'}:
            result.setdefault('residency', {})[key.replace('residency', '', 1)] = _split_references(value)
    return result


def _raw_services(raw: Mapping[str, Any]) -> list[Any]:
    services = raw.get('services', ())
    if isinstance(services, Mapping):
        return [dict(value, **{'bom-ref': key}) for key, value in services.items()]
    return list(services) if isinstance(services, Iterable) and not isinstance(services, str) else []


def _apply_top_metadata(raw: dict[str, Any], top: Mapping[str, Any]) -> dict[str, Any]:
    nodes = top.get('nodes')
    if isinstance(nodes, Mapping):
        _inject_node_metadata(raw, nodes)
    reserved = {
        'nodes', 'edges', 'entrypoints', 'entry_points', 'endpoints', 'conditions',
        'conditionsState', 'conditions_state', 'enabledConditions', 'enabled_conditions',
        'disabledConditions', 'disabled_conditions', 'regions', 'proofs', 'regionProofs',
        'region_proofs', 'proof', 'region', 'country', 'location',
    }
    direct_nodes = {
        ref: metadata for ref, metadata in top.items()
        if ref not in reserved and isinstance(metadata, (Mapping, str, list, tuple))
    }
    if direct_nodes:
        _inject_node_metadata(raw, direct_nodes)
    for key in ('regions', 'proofs', 'regionProofs', 'region_proofs'):
        values = top.get(key)
        if isinstance(values, Mapping):
            _inject_node_metadata(raw, {ref: {_metadata_key(key): value} for ref, value in values.items()})
    return raw


def _metadata_key(key: str) -> str:
    return 'proof' if key in {'proofs', 'regionProofs', 'region_proofs'} else key


def _inject_node_metadata(raw: dict[str, Any], nodes: Mapping[str, Any]) -> None:
    services = raw.setdefault('services', [])
    for ref, metadata in nodes.items():
        if not isinstance(metadata, Mapping):
            metadata = {'region': metadata}
        service = next((item for item in services
                        if _raw_ref(item) == str(ref) or _raw_name(item) == str(ref)), None)
        if service is None:
            service = {'bom-ref': str(ref), 'name': str(ref)}
            services.append(service)
        extension = service.setdefault('x-residency', {})
        extension.update(metadata)


def _collect_records(
    raw: Mapping[str, Any],
) -> tuple[dict[str, ServiceRecord], dict[str, str], list[BrokenReference]]:
    records: dict[str, ServiceRecord] = {}
    aliases: dict[str, str] = {}
    broken: list[BrokenReference] = []
    for service in _raw_services(raw):
        _collect_service(service, records, aliases, broken)
    return records, aliases, broken


def _collect_service(
    service: Any, records: dict[str, ServiceRecord], aliases: dict[str, str], broken: list[BrokenReference],
) -> None:
    if not isinstance(service, Mapping):
        return
    ref = _raw_ref(service) or _raw_name(service)
    if not ref:
        broken.append(BrokenReference(None, '<unnamed-service>', 'service has neither bom-ref nor name'))
        return
    record = _record_from_mapping(service, ref)
    if ref in records and records[ref] != record:
        raise ValueError(f'Duplicate or conflicting service bom-ref: {ref!r}')
    records[ref] = record
    aliases.setdefault(ref, ref)
    aliases.setdefault(ref.casefold(), ref)
    aliases.setdefault(record.name.casefold(), ref)
    for child in _nested_services(service):
        _collect_service(child, records, aliases, broken)


def _record_from_mapping(service: Mapping[str, Any], ref: str) -> ServiceRecord:
    extension = service.get('x-residency') if isinstance(service.get('x-residency'), Mapping) else {}
    claims = _region_claims(service, extension)
    proofs = _proofs(service, extension)
    if not claims:
        claims = tuple(sorted(
            {proof.region for proof in proofs if proof.region},
            key=str.casefold,
        ))
    return ServiceRecord(
        ref=ref,
        name=str(_raw_name(service) or ref),
        categories=_data_categories(service),
        claims=claims,
        proofs=proofs,
        condition=_condition(service, extension),
        enabled=_enabled(service, extension),
        endpoint=_endpoint_flag(service, extension),
    )


def _nested_services(service: Mapping[str, Any]) -> list[Any]:
    nested = service.get('services', ())
    if isinstance(nested, Mapping):
        return [dict(value, **{'bom-ref': key}) for key, value in nested.items()]
    return list(nested) if isinstance(nested, Iterable) and not isinstance(nested, str) else []


def _raw_ref(service: Mapping[str, Any]) -> Optional[str]:
    for key in ('bom-ref', 'bomRef', 'ref', 'id'):
        value = service.get(key)
        if value not in (None, ''):
            return str(value)
    return None


def _raw_name(service: Mapping[str, Any]) -> Optional[str]:
    value = service.get('name')
    return str(value) if value not in (None, '') else None


def _data_categories(service: Mapping[str, Any]) -> tuple[str, ...]:
    categories: list[str] = []
    values = service.get('data', ())
    if service.get('dataCategories') is not None:
        values = service.get('dataCategories')
    if service.get('data_categories') is not None:
        values = service.get('data_categories')
    if isinstance(values, Mapping):
        values = [values]
    for item in values if isinstance(values, Iterable) and not isinstance(values, str) else ():
        if isinstance(item, str):
            category = item
        elif isinstance(item, Mapping):
            category = item.get('classification')
            if category in (None, ''):
                _append_classifications(categories, item)
                continue
        elif isinstance(item, DataClassification):
            category = item.classification
        else:
            category = None
        if category not in (None, '') and str(category).casefold() not in {v.casefold() for v in categories}:
            categories.append(str(category))
    return tuple(sorted(categories, key=str.casefold))


def _append_classifications(categories: list[str], value: Any) -> None:
    if isinstance(value, Mapping):
        classification = value.get('classification')
        if classification not in (None, '') and str(classification).casefold() not in {
            item.casefold() for item in categories
        }:
            categories.append(str(classification))
        for nested in value.values():
            _append_classifications(categories, nested)
    elif isinstance(value, Iterable) and not isinstance(value, str):
        for nested in value:
            _append_classifications(categories, nested)


def _region_claims(service: Mapping[str, Any], extension: Mapping[str, Any]) -> tuple[str, ...]:
    claims: list[str] = []
    for value in _direct_region_values(service):
        _append_unique(claims, value)
    provider = service.get('provider')
    if isinstance(provider, Mapping):
        _append_region_claim(claims, provider)
        _append_region_claim(claims, provider.get('address'))
    _append_region_claim(claims, extension)
    for name, value in _properties(service):
        normalized = _normalized_key(name)
        if _is_region_property(normalized):
            _append_unique(claims, value)
    return tuple(sorted(claims, key=str.casefold))


def _direct_region_values(service: Mapping[str, Any]) -> list[Any]:
    values: list[Any] = []
    for key in (
        'region', 'regions', 'country', 'countries', 'jurisdiction', 'processing-region',
        'processingRegion', 'processing-location', 'processingLocation', 'dataResidency',
        'data-residency',
    ):
        value = service.get(key)
        if value is not None and not isinstance(value, Mapping):
            values.append(value)
    residency = service.get('dataResidency', service.get('data-residency'))
    if isinstance(residency, Mapping):
        values.extend(residency.get(key) for key in ('region', 'regions', 'country', 'jurisdiction')
                      if residency.get(key))
    nested = service.get('residency')
    if isinstance(nested, Mapping):
        values.extend(nested.get(key) for key in ('region', 'regions', 'country', 'jurisdiction')
                      if nested.get(key))
    return values


def _append_region_claim(claims: list[str], value: Any) -> None:
    if not isinstance(value, Mapping):
        return
    country = next((value[key] for key in ('country', 'countries') if value.get(key) not in (None, '')), None)
    region = next((value[key] for key in ('region', 'regions', 'jurisdiction') if value.get(key) not in (None, '')), None)
    if country is not None and region is not None and not isinstance(region, (list, tuple, set)):
        _append_unique(claims, country)
        _append_unique(claims, f'{country}-{region}')
        return
    for key in ('region', 'regions', 'country', 'countries', 'location', 'jurisdiction'):
        if value.get(key) not in (None, ''):
            _append_unique(claims, value[key])


def _append_unique(values: list[str], value: Any) -> None:
    if isinstance(value, Mapping):
        for item in value.values():
            _append_unique(values, item)
        return
    if isinstance(value, Iterable) and not isinstance(value, str):
        for item in value:
            _append_unique(values, item)
        return
    text = str(value).strip()
    if text and text.casefold() not in {item.casefold() for item in values}:
        values.append(text)


def _proofs(service: Mapping[str, Any], extension: Mapping[str, Any]) -> tuple[ProofReference, ...]:
    proofs: list[ProofReference] = []
    _proofs_from_properties(proofs, service)
    _proofs_from_external_references(proofs, service)
    _proofs_from_keys(proofs, service, 'service')
    _proofs_from_keys(proofs, extension, 'x-residency')
    provider = service.get('provider')
    if isinstance(provider, Mapping):
        _proofs_from_keys(proofs, provider, 'provider')
        _proofs_from_keys(proofs, provider.get('address'), 'provider')
    return tuple(sorted(proofs, key=lambda item: item.reference.casefold()))


def _proofs_from_properties(proofs: list[ProofReference], service: Mapping[str, Any]) -> None:
    for name, value in _properties(service):
        if _is_proof_property(_normalized_key(name)):
            _append_proofs(proofs, value, 'property')


def _proofs_from_external_references(proofs: list[ProofReference], service: Mapping[str, Any]) -> None:
    for reference in _external_references(service):
        if _is_region_proof_reference(reference):
            _append_proofs(proofs, reference, 'external-reference')


def _proofs_from_keys(proofs: list[ProofReference], source: Any, label: str) -> None:
    if not isinstance(source, Mapping):
        return
    for key in ('proof', 'proofs', 'regionProof', 'region_proof', 'regionProofs', 'evidence', 'attestation'):
        if source.get(key) is not None:
            _append_proofs(proofs, source[key], label)


def _append_proofs(proofs: list[ProofReference], value: Any, source: str) -> None:
    if value in (None, '', False, True):
        return
    if isinstance(value, Mapping):
        _append_proof_mapping(proofs, value, source)
        return
    if isinstance(value, Iterable) and not isinstance(value, str):
        for item in value:
            _append_proofs(proofs, item, source)
        return
    if isinstance(value, str) and value.lstrip().startswith('{'):
        if _append_proof_json(proofs, value, source):
            return
    proof = ProofReference(str(value).strip(), None, source)
    if proof.reference and proof not in proofs:
        proofs.append(proof)


def _append_proof_mapping(proofs: list[ProofReference], value: Mapping[str, Any], source: str) -> None:
    reference = next((value[key] for key in _PROOF_REFERENCE_KEYS if value.get(key) not in (None, '')), None)
    region = value.get('region') or value.get('jurisdiction')
    if reference is not None:
        proof = ProofReference(str(reference), str(region) if region else None, source)
        if proof not in proofs:
            proofs.append(proof)
        return
    for item in value.values():
        _append_proofs(proofs, item, source)


def _append_proof_json(proofs: list[ProofReference], value: str, source: str) -> bool:
    try:
        parsed = json.loads(value)
    except ValueError:
        return False
    if not isinstance(parsed, Mapping):
        return False
    _append_proofs(proofs, parsed, source)
    return True


def _external_references(service: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values = service.get('externalReferences', service.get('external_references', ()))
    if isinstance(values, Mapping):
        values = [values]
    return [item for item in values if isinstance(item, Mapping)] if isinstance(values, Iterable) else []


def _condition(service: Mapping[str, Any], extension: Mapping[str, Any]) -> Optional[str]:
    value = extension.get('condition', extension.get('when', service.get('condition', service.get('when'))))
    for name, item in _properties(service):
        if _normalized_key(name) in {'residencycondition', 'condition', 'condition_id', 'conditionid'}:
            value = item
    return str(value) if value not in (None, '') else None


def _enabled(service: Mapping[str, Any], extension: Mapping[str, Any]) -> Optional[bool]:
    value = extension.get('enabled', service.get('enabled'))
    for name, item in _properties(service):
        if _normalized_key(name) in {'residencyenabled', 'conditionenabled', 'active'}:
            value = item
    return _as_bool(value)


def _endpoint_flag(service: Mapping[str, Any], extension: Mapping[str, Any]) -> bool:
    value = extension.get('endpoint', service.get('endpoint'))
    for name, item in _properties(service):
        if _normalized_key(name) in {'residencyendpoint', 'endpoint'}:
            value = item
    return bool(_as_bool(value))


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {'1', 'true', 'yes', 'on', 'enabled', 'active'}


def _properties(service: Mapping[str, Any]) -> list[tuple[str, Any]]:
    values = service.get('properties', ())
    if isinstance(values, Mapping):
        return [(str(name), value) for name, value in values.items()]
    result: list[tuple[str, Any]] = []
    for item in values if isinstance(values, Iterable) and not isinstance(values, str) else ():
        if isinstance(item, Property):
            result.append((item.name, item.value))
        elif isinstance(item, Mapping):
            result.append((str(item.get('name', '')), item.get('value')))
    return result


def _normalized_key(value: str) -> str:
    return ''.join(character for character in str(value).casefold() if character.isalnum())


def _is_region_property(key: str) -> bool:
    if 'proof' in key or 'evidence' in key or 'attestation' in key:
        return False
    return key in {'region', 'country', 'location'} or any(
        token in key for token in (
            'residencyregion', 'processingregion', 'dataregion', 'regionclaim',
            'regiondeclaration', 'jurisdiction', 'processinglocation',
        )
    )


def _is_proof_property(key: str) -> bool:
    return (
        'proof' in key or 'evidence' in key or 'attestation' in key
    ) and not any(token in key for token in ('proofregion', 'proofcountry', 'proofjurisdiction'))


def _is_region_proof_reference(reference: Mapping[str, Any]) -> bool:
    reference_type = str(reference.get('type', '')).casefold()
    if reference_type in _PROOF_EXTERNAL_TYPES:
        return True
    text = ' '.join(str(reference.get(key, '')) for key in ('url', 'comment')).casefold()
    return 'region' in text and any(token in text for token in ('proof', 'attest', 'evidence'))


def _collect_edges(
    raw: Mapping[str, Any], top: Mapping[str, Any], aliases: Mapping[str, str], broken: list[BrokenReference],
) -> tuple[list[Edge], set[str]]:
    edges: list[Edge] = []
    external_roots = _dependency_edges(raw, aliases, broken, edges)
    _nested_edges(raw, aliases, edges)
    _property_edges(raw, aliases, edges)
    _extension_edges(top, aliases, broken, edges)
    return _merge_edges(edges), external_roots


def _dependency_edges(
    raw: Mapping[str, Any], aliases: Mapping[str, str], broken: list[BrokenReference], edges: list[Edge],
) -> set[str]:
    external_roots: set[str] = set()
    for dependency in raw.get('dependencies', ()):
        if not isinstance(dependency, Mapping):
            continue
        source = _resolve_ref(dependency.get('ref'), aliases)
        targets = dependency.get('dependsOn', dependency.get('depends_on', dependency.get('dependencies', ())))
        condition = dependency.get('condition') or dependency.get('when')
        enabled = _as_bool(dependency.get('enabled'))
        for target in targets if isinstance(targets, Iterable) and not isinstance(targets, str) else ():
            resolved = _resolve_ref(target, aliases)
            if resolved is None:
                broken.append(BrokenReference(source, str(target), 'unknown service dependency'))
            elif source is not None:
                edges.append(Edge(source, resolved, str(condition) if condition else None, enabled))
            elif source is None:
                external_roots.add(resolved)
    return external_roots


def _nested_edges(raw: Mapping[str, Any], aliases: Mapping[str, str], edges: list[Edge]) -> None:
    for service in _all_services(raw):
        if not isinstance(service, Mapping):
            continue
        source = _resolve_ref(_raw_ref(service) or _raw_name(service), aliases)
        if source is None:
            continue
        for child in _nested_services(service):
            target = _resolve_ref(_raw_ref(child) or _raw_name(child), aliases)
            if target is not None:
                edges.append(Edge(source, target, origin='nested'))


def _property_edges(raw: Mapping[str, Any], aliases: Mapping[str, str], edges: list[Edge]) -> None:
    for service in _all_services(raw):
        if not isinstance(service, Mapping):
            continue
        source = _resolve_ref(_raw_ref(service) or _raw_name(service), aliases)
        if source is None:
            continue
        for name, value in _properties(service):
            key = _normalized_key(name)
            if key in {'residencynext', 'next', 'residencydependson', 'residencyfailover'}:
                condition = 'failover' if 'failover' in key else None
                for target in _split_references(value):
                    resolved = _resolve_ref(target, aliases)
                    if resolved is not None:
                        edges.append(Edge(source, resolved, condition, origin='property'))


def _extension_edges(
    top: Mapping[str, Any], aliases: Mapping[str, str], broken: list[BrokenReference], edges: list[Edge],
) -> None:
    values = top.get('edges', ())
    if isinstance(values, Mapping):
        values = [
            {'from': source, 'to': target}
            for source, targets in values.items()
            for target in _split_references(targets)
        ]
    for item in values if isinstance(values, Iterable) and not isinstance(values, str) else ():
        if not isinstance(item, Mapping):
            continue
        source = _resolve_ref(item.get('from', item.get('source')), aliases)
        target = _resolve_ref(item.get('to', item.get('target')), aliases)
        if source is None or target is None:
            broken.append(BrokenReference(source, str(item.get('to', item.get('target'))), 'invalid conditional edge'))
            continue
        condition = item.get('condition') or item.get('when')
        edges.append(Edge(
            source, target,
            str(condition) if condition else None,
            _as_bool(item.get('enabled')),
            'x-residency',
        ))


def _split_references(value: Any) -> list[str]:
    if isinstance(value, Iterable) and not isinstance(value, str):
        return [str(item) for item in value]
    return [part.strip() for part in str(value).replace(';', ',').split(',') if part.strip()]


def _merge_edges(edges: Iterable[Edge]) -> list[Edge]:
    merged: dict[tuple[str, str], Edge] = {}
    for edge in edges:
        key = (edge.source, edge.target)
        previous = merged.get(key)
        if previous is None or (previous.condition is None and edge.condition is not None):
            merged[key] = edge
    return sorted(merged.values(), key=lambda edge: (edge.source, edge.target, edge.condition or ''))


def _all_services(raw: Mapping[str, Any]) -> list[Any]:
    result: list[Any] = []
    for service in _raw_services(raw):
        result.append(service)
        if isinstance(service, Mapping):
            result.extend(_all_nested_services(service))
    return result


def _all_nested_services(service: Mapping[str, Any]) -> list[Any]:
    result: list[Any] = []
    for child in _nested_services(service):
        result.append(child)
        if isinstance(child, Mapping):
            result.extend(_all_nested_services(child))
    return result


def _resolve_ref(value: Any, aliases: Mapping[str, str]) -> Optional[str]:
    if value in (None, ''):
        return None
    key = str(value)
    return aliases.get(key, aliases.get(key.casefold()))


def _resolve_entrypoints(
    raw: Mapping[str, Any], top: Mapping[str, Any], records: Mapping[str, ServiceRecord],
    edges: Iterable[Edge], aliases: Mapping[str, str], broken: list[BrokenReference],
) -> list[str]:
    configured = top.get('entrypoints', top.get('entry_points'))
    if configured is None:
        for name, value in _properties(raw):
            if _normalized_key(name) in {'residencyentrypoints', 'entrypoints'}:
                configured = value
    if configured is not None:
        return _resolve_configured(configured, aliases, broken, 'entry point')
    incoming = {edge.target for edge in edges}
    outgoing = {edge.source for edge in edges}
    roots = [
        ref for ref in records
        if ref not in incoming and (ref in outgoing or not (incoming or outgoing))
    ]
    return sorted(roots)


def _resolve_endpoints(
    raw: Mapping[str, Any], top: Mapping[str, Any], records: Mapping[str, ServiceRecord],
    edges: Iterable[Edge], aliases: Mapping[str, str], broken: list[BrokenReference],
) -> list[str]:
    configured = top.get('endpoints')
    if configured is None:
        for name, value in _properties(raw):
            if _normalized_key(name) in {'residencyendpoints', 'endpoints'}:
                configured = value
    if configured is not None:
        return _resolve_configured(configured, aliases, broken, 'endpoint')
    outgoing = {edge.source for edge in edges}
    flagged = [record.ref for record in records.values() if record.endpoint]
    sinks = [ref for ref in records if ref not in outgoing and not flagged]
    return sorted(set(flagged) | set(sinks))


def _resolve_configured(
    value: Any, aliases: Mapping[str, str], broken: list[BrokenReference], label: str,
) -> list[str]:
    result: list[str] = []
    for item in _split_references(value):
        resolved = _resolve_ref(item, aliases)
        if resolved is None:
            broken.append(BrokenReference(None, item, f'unknown {label}'))
        elif resolved not in result:
            result.append(resolved)
    return result


def _collect_condition_state(
    raw: Mapping[str, Any], top: Mapping[str, Any], edges: Iterable[Edge],
) -> dict[str, bool]:
    state: dict[str, bool] = {}
    condition_names = {str(edge.condition) for edge in edges if edge.condition}
    disabled_value = top.get('disabledConditions', top.get('disabled_conditions', ()))
    disabled = _split_references(disabled_value)
    enabled = top.get('enabledConditions', top.get('enabled_conditions'))
    if enabled is not None:
        enabled_names = set(_split_references(enabled))
        state.update({name: name in enabled_names for name in condition_names})
    for name in disabled:
        state[name] = False
    for key in ('conditions', 'conditionsState', 'conditions_state'):
        value = top.get(key)
        if isinstance(value, Mapping):
            state.update({str(name): _as_bool(active) for name, active in value.items()})
    for name, value in _properties(raw):
        if _normalized_key(name) in {'residencyconditions', 'conditions'}:
            parsed = _json_mapping(value)
            state.update(parsed)
    return state


def _json_mapping(value: Any) -> dict[str, bool]:
    if isinstance(value, Mapping):
        return {str(name): _as_bool(enabled) for name, enabled in value.items()}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError):
        return {}
    return {str(name): _as_bool(enabled) for name, enabled in parsed.items()} if isinstance(parsed, Mapping) else {}


def _xml_to_mapping(text: str) -> dict[str, Any]:
    root = xml_fromstring(text)
    services = [_xml_service(item) for item in root.findall('./{*}services/{*}service')]
    dependencies = [_xml_dependency(item) for item in root.findall('./{*}dependencies/{*}dependency')]
    return {'services': services, 'dependencies': dependencies}


def _xml_service(element: Element) -> dict[str, Any]:
    provider = element.find('./{*}provider')
    address = provider.find('./{*}address') if provider is not None else None
    return {
        'bom-ref': element.get('bom-ref'),
        'name': _xml_text(element.find('./{*}name')),
        'provider': {
            'name': _xml_text(provider.find('./{*}name')) if provider is not None else None,
            'address': {
                'country': _xml_text(address.find('./{*}country')) if address is not None else None,
                'region': _xml_text(address.find('./{*}region')) if address is not None else None,
                'locality': _xml_text(address.find('./{*}locality')) if address is not None else None,
            } if address is not None else None,
        } if provider is not None else None,
        'data': [
            {'classification': item.text, 'flow': item.get('flow')}
            for item in element.findall('./{*}data//{*}classification')
        ],
        'properties': [
            {'name': item.get('name'), 'value': item.text}
            for item in element.findall('./{*}properties/{*}property')
        ],
        'externalReferences': [
            {'type': item.get('type'), 'url': _xml_text(item.find('./{*}url'))}
            for item in element.findall('./{*}externalReferences/{*}reference')
        ],
        'services': [_xml_service(item) for item in element.findall('./{*}services/{*}service')],
    }


def _xml_dependency(element: Element) -> dict[str, Any]:
    return {
        'ref': element.get('ref'),
        'dependsOn': [item.get('ref') for item in element.findall('./{*}dependency')],
    }


def _xml_text(element: Optional[Element]) -> Optional[str]:
    return element.text if element is not None else None
