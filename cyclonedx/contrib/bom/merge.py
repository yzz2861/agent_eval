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
Order-independent merging of component evidence.

The merger deliberately keeps three things apart:

* components are matched by strong identities (PURL, CPE, SWID, OmniBOR,
  SWHID, or hashes) - never by ``bom-ref`` alone and never by a merely
  similar name/version coordinate;
* evidence claims are keyed by their target identity and predicate;
* trust sources are keyed independently from the components carrying them.

Claims that cannot be attributed unambiguously (dangling targets, conflicting
endorsements, or a supplier speaking outside its scope) are returned in the
result's ``unattributed`` side channel.  They do not prevent the remaining,
verifiable part of the BOM from being produced.
"""

__all__ = [
    'BomEvidenceMerger',
    'BomMergeResult',
    'BomMerger',
    'Claim',
    'ComponentEvidenceMerger',
    'ComponentIdentity',
    'EvidenceClaim',
    'EvidenceClaimMergeResult',
    'EvidenceClaimMerger',
    'EvidenceMerger',
    'MergeResult',
    'Source',
    'TrustSource',
    'Unattributed',
    'UnattributedClaim',
    'UnattributedReason',
    'merge',
    'merge_boms',
    'merge_components',
    'merge_evidence_claims',
    'merge_trust_sources',
]

import copy
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, Union
from uuid import NAMESPACE_URL, uuid5

from ...model import Copyright, Property
from ...model.bom import Bom, BomMetaData
from ...model.bom_ref import BomRef
from ...model.component import Component
from ...model.component_evidence import (
    AnalysisTechnique,
    CallStack,
    ComponentEvidence,
    Identity,
    IdentityField,
    Method,
    Occurrence,
)
from ...model.contact import OrganizationalEntity
from ...model.dependency import Dependency
from ...model.license import License
from ...schema.schema import SchemaVersion1Dot7


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, Bom, Component, BomRef, EvidenceClaim,
                          TrustSource, OrganizationalEntity)):
        return [value]
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _flatten(values: Iterable[Any]) -> List[Any]:
    result: List[Any] = []
    for value in values:
        result.extend(_as_list(value))
    return result


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _strip_bom_refs(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_bom_refs(item)
            for key, item in value.items()
            if key != 'bom-ref'
        }
    if isinstance(value, list):
        return [_strip_bom_refs(item) for item in value]
    return value


def _model_json(value: Any) -> Optional[Any]:
    try:
        return json.loads(value.as_json(view_=SchemaVersion1Dot7))
    except (AttributeError, AssertionError, TypeError, ValueError):
        return None


def _stable_key(value: Any) -> str:
    if value is None:
        return 'null'
    if isinstance(value, Enum):
        return f'{type(value).__name__}:{value.value}'
    if isinstance(value, BomRef):
        return f'bom-ref:{value.value}'
    if isinstance(value, Component):
        return f'component:{ComponentIdentity.from_component(value).key}'
    if isinstance(value, ComponentIdentity):
        return f'identity:{value.key}'
    if isinstance(value, TrustSource):
        return f'source:{value.key}'
    if isinstance(value, (str, int, float, bool)):
        return f'{type(value).__name__}:{value}'
    if isinstance(value, Decimal):
        return f'decimal:{value}'
    if isinstance(value, Mapping):
        items = sorted((str(key), _stable_key(item)) for key, item in value.items())
        return f'map:{json.dumps(items, separators=(",", ":"))}'
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(_stable_key(item) for item in value)
        return f'seq:{json.dumps(items, separators=(",", ":"))}'

    model_json = _model_json(value)
    if model_json is not None:
        return f'model:{json.dumps(_strip_bom_refs(model_json), sort_keys=True, separators=(",", ":"), default=str)}'
    return f'{type(value).__module__}.{type(value).__qualname__}:{value!r}'


def _component_json(component: Component, *, strip_refs: bool = True) -> Any:
    data = _model_json(component)
    if data is None:
        data = {
            'type': _stable_key(component.type),
            'group': component.group,
            'name': component.name,
            'version': component.version,
            'purl': None if component.purl is None else component.purl.to_string(),
            'cpe': component.cpe,
            'hashes': sorted((h.alg.value, h.content) for h in component.hashes),
        }
    return _strip_bom_refs(data) if strip_refs else data


def _component_fingerprint(component: Component) -> str:
    return json.dumps(_component_json(component), sort_keys=True, separators=(',', ':'), default=str)


def _bom_json(bom: Bom) -> Dict[str, Any]:
    data = _model_json(bom)
    if data is None:
        return {
            'components': [_component_json(component) for component in bom.components],
            'version': bom.version,
        }
    data.pop('serialNumber', None)
    metadata = data.get('metadata')
    if isinstance(metadata, dict):
        metadata.pop('timestamp', None)
    return data


def _bom_fingerprint(bom: Bom) -> str:
    return json.dumps(_bom_json(bom), sort_keys=True, separators=(',', ':'), default=str)


def _bom_origin(bom: Bom) -> str:
    return _hash_text(_bom_fingerprint(bom))[:16]


def _entity_details(entity: OrganizationalEntity) -> Dict[str, Any]:
    address = _model_json(entity.address)
    return {
        'name': entity.name,
        'urls': sorted(str(url) for url in entity.urls),
        'contacts': sorted(_stable_key(contact) for contact in entity.contacts),
        'address': None if address is None else json.dumps(address, sort_keys=True, default=str),
    }


def _entity_key(entity: Optional[OrganizationalEntity]) -> str:
    if entity is None:
        return 'anonymous'
    details = _entity_details(entity)
    has_details = any(details[key] for key in ('urls', 'contacts', 'address'))
    base = entity.name or 'anonymous'
    if not has_details:
        return base
    return f'{base}#{_hash_text(json.dumps(details, sort_keys=True, default=str))[:12]}'


@dataclass(frozen=True)
class ComponentIdentity:
    """Stable, non-``bom-ref`` identity of a component."""

    key: str
    purl: Optional[str] = None
    cpe: Optional[str] = None
    swid: Optional[str] = None
    omnibor_ids: Tuple[str, ...] = ()
    swhids: Tuple[str, ...] = ()
    hashes: Tuple[Tuple[str, str], ...] = ()
    version: Optional[str] = None
    coordinate: Optional[str] = None

    @classmethod
    def from_component(cls, component: Component) -> 'ComponentIdentity':
        purl = None if component.purl is None else component.purl.to_string()
        cpe = component.cpe
        swid = None if component.swid is None else component.swid.tag_id
        omnibor_ids = tuple(sorted(item.id for item in component.omnibor_ids))
        swhids = tuple(sorted(item.id for item in component.swhids))
        hashes = tuple(sorted((item.alg.value, item.content) for item in component.hashes))
        coordinate = json.dumps(
            [component.type.value, component.group, component.name, component.version],
            separators=(',', ':'),
            default=str,
        )

        identity_key: Optional[str] = None
        if purl:
            identity_key = f'purl:{purl}'
        elif cpe:
            identity_key = f'cpe:{cpe}'
        elif swid:
            identity_key = f'swid:{swid}'
        elif omnibor_ids:
            identity_key = f'omnibor:{omnibor_ids[0]}'
        elif swhids:
            identity_key = f'swhid:{swhids[0]}'
        elif hashes:
            identity_key = f'hash:{hashes[0][0]}:{hashes[0][1]}'
        else:
            identity_key = f'weak:{_component_fingerprint(component)}'

        return cls(
            key=identity_key,
            purl=purl,
            cpe=cpe,
            swid=swid,
            omnibor_ids=omnibor_ids,
            swhids=swhids,
            hashes=hashes,
            version=component.version,
            coordinate=coordinate,
        )

    def domains(self) -> Dict[str, FrozenSet[str]]:
        domains: Dict[str, Set[str]] = {}
        if self.purl:
            domains['purl'] = {self.purl}
        if self.cpe:
            domains['cpe'] = {self.cpe}
        if self.swid:
            domains['swid'] = {self.swid}
        if self.omnibor_ids:
            domains['omnibor'] = set(self.omnibor_ids)
        if self.swhids:
            domains['swhid'] = set(self.swhids)
        if self.version is not None:
            domains['version'] = {self.version}
        for alg, content in self.hashes:
            domains.setdefault(f'hash:{alg}', set()).add(content)
        return {name: frozenset(values) for name, values in domains.items()}

    def compatible_with(self, other: 'ComponentIdentity') -> bool:
        domains = self.domains()
        other_domains = other.domains()
        shared_domain = False
        for name, values in domains.items():
            if name not in other_domains:
                continue
            if not values.intersection(other_domains[name]):
                return False
            shared_domain = True
        return shared_domain

    def lookup_keys(self) -> Set[str]:
        keys = {self.key}
        for name, values in self.domains().items():
            for value in values:
                keys.add(value)
                keys.add(f'{name}:{value}')
        return keys

    def __lt__(self, other: object) -> bool:
        if isinstance(other, ComponentIdentity):
            return self.key < other.key
        return NotImplemented


class TrustSource:
    """A supplier/manufacturer/assessor that can endorse claims."""

    def __init__(
        self, key: Optional[str] = None, *,
        entity: Optional[OrganizationalEntity] = None,
        name: Optional[str] = None,
        urls: Optional[Iterable[str]] = None,
        kind: str = 'supplier',
        authorized_targets: Optional[Iterable[str]] = None,
        endorsed_digests: Optional[Iterable[str]] = None,
    ) -> None:
        if entity is None and (name is not None or urls is not None):
            entity = OrganizationalEntity(name=name, urls=urls or ())
        self._entity = entity
        self._kind = kind
        self._key = key or _entity_key(entity)
        self._authorized_targets = frozenset(authorized_targets or ())
        self._endorsed_digests = frozenset(endorsed_digests or ())

    @classmethod
    def from_entity(
        cls, entity: Optional[OrganizationalEntity], *,
        kind: str = 'supplier',
    ) -> 'TrustSource':
        return cls(entity=entity, kind=kind)

    @property
    def key(self) -> str:
        return self._key

    @property
    def identifier(self) -> str:
        return self.name or self._key

    @property
    def name(self) -> Optional[str]:
        return None if self._entity is None else self._entity.name

    @property
    def entity(self) -> Optional[OrganizationalEntity]:
        return self._entity

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def bom_ref(self) -> Optional[str]:
        if self._entity is None:
            return None
        return self._entity.bom_ref.value

    @property
    def authorized_targets(self) -> FrozenSet[str]:
        return self._authorized_targets

    @property
    def endorsed_digests(self) -> FrozenSet[str]:
        return self._endorsed_digests

    def with_scope(
        self, *,
        authorized_targets: Optional[Iterable[str]] = None,
        endorsed_digests: Optional[Iterable[str]] = None,
    ) -> 'TrustSource':
        return TrustSource(
            self._key,
            entity=self._entity,
            kind=self._kind,
            authorized_targets=self._authorized_targets.union(authorized_targets or ()),
            endorsed_digests=self._endorsed_digests.union(endorsed_digests or ()),
        )

    def aliases(self) -> Set[str]:
        aliases = {self._key}
        if self.name:
            aliases.add(self.name)
            aliases.add(f'named:{self.name}')
        if self.bom_ref:
            aliases.add(self.bom_ref)
            aliases.add(f'ref:{self.bom_ref}')
        return aliases

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TrustSource):
            return (
                self._key == other._key
                and _entity_key(self._entity) == _entity_key(other._entity)
                and self._kind == other._kind
            )
        return False

    def __hash__(self) -> int:
        return hash((self._key, _entity_key(self._entity), self._kind))

    def __lt__(self, other: object) -> bool:
        if isinstance(other, TrustSource):
            return (self._key, _entity_key(self._entity), self._kind) < (
                other._key, _entity_key(other._entity), other._kind)
        return NotImplemented

    def __repr__(self) -> str:
        return f'<TrustSource key={self._key!r}, name={self.name!r}>'

    def as_dict(self) -> Dict[str, Any]:
        return {
            'key': self._key,
            'name': self.name,
            'kind': self._kind,
            'bom_ref': self.bom_ref,
            'authorized_targets': sorted(self._authorized_targets),
            'endorsed_digests': sorted(self._endorsed_digests),
        }


def _normalize_source(source: Any) -> Optional[TrustSource]:
    if source is None:
        return None
    if isinstance(source, TrustSource):
        return source
    if isinstance(source, OrganizationalEntity):
        return TrustSource.from_entity(source)
    if isinstance(source, BomRef):
        key = source.value or 'anonymous'
        return TrustSource(name=key)
    if isinstance(source, str):
        return TrustSource(name=source)
    if isinstance(source, Mapping):
        return TrustSource(
            source.get('key'),
            name=source.get('name'),
            urls=source.get('urls'),
            kind=source.get('kind', 'supplier'),
            authorized_targets=source.get('authorized_targets'),
            endorsed_digests=source.get('endorsed_digests'),
        )
    raise TypeError(f'Unsupported trust source: {source!r}')


class EvidenceClaim:
    """A single assertion about a component, optionally endorsed by a source."""

    def __init__(
        self, *,
        target: Any,
        predicate: str,
        value: Any = None,
        source: Any = None,
        kind: str = 'claim',
        stance: str = 'assert',
        confidence: Optional[Decimal] = None,
        methods: Optional[Iterable[Method]] = None,
        tools: Optional[Iterable[BomRef]] = None,
        origin: Optional[str] = None,
        component_ref: Optional[str] = None,
        payload: Any = None,
        implicit_source: bool = False,
    ) -> None:
        self._target = target
        self._predicate = str(predicate)
        self._value = value
        self._source = _normalize_source(source)
        self._kind = kind
        self._stance = stance
        self._confidence = confidence
        self._methods = tuple(methods or ())
        self._tools = tuple(tools or ())
        self._origin = origin
        self._component_ref = component_ref
        self._payload = payload
        self._implicit_source = implicit_source

    @classmethod
    def from_identity(
        cls, identity: Identity, *,
        target: Any,
        source: Any = None,
        origin: Optional[str] = None,
        component_ref: Optional[str] = None,
        value: Any = None,
        implicit_source: bool = False,
    ) -> 'EvidenceClaim':
        digest = identity.field is IdentityField.HASH
        return cls(
            target=target,
            predicate=f'identity:{identity.field.value}',
            value=identity.concluded_value if value is None else value,
            source=source,
            kind='digest' if digest else 'identity',
            stance='endorse' if digest else 'assert',
            confidence=identity.confidence,
            methods=identity.methods,
            tools=identity.tools,
            origin=origin,
            component_ref=component_ref,
            payload=identity,
            implicit_source=implicit_source,
        )

    @property
    def target(self) -> Any:
        return self._target

    @property
    def predicate(self) -> str:
        return self._predicate

    @property
    def value(self) -> Any:
        return self._value

    @property
    def source(self) -> Optional[TrustSource]:
        return self._source

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def stance(self) -> str:
        return self._stance

    @property
    def confidence(self) -> Optional[Decimal]:
        return self._confidence

    @property
    def methods(self) -> Tuple[Method, ...]:
        return self._methods

    @property
    def tools(self) -> Tuple[BomRef, ...]:
        return self._tools

    @property
    def origin(self) -> Optional[str]:
        return self._origin

    @property
    def component_ref(self) -> Optional[str]:
        return self._component_ref

    @property
    def payload(self) -> Any:
        return self._payload

    @property
    def implicit_source(self) -> bool:
        return self._implicit_source

    @property
    def value_key(self) -> str:
        return _stable_key(self._value)

    @property
    def semantic_predicate(self) -> str:
        predicate = self._predicate.lower()
        for prefix in ('hash:', 'digest:'):
            if predicate.startswith(prefix):
                alg = predicate[len(prefix):].replace('-', '').replace('_', '')
                return prefix + alg
        return predicate

    @property
    def semantic_key(self) -> Tuple[str, str]:
        return _claim_target_label(self._target), self._predicate

    @property
    def canonical_key(self) -> Tuple[str, ...]:
        return (
            self.semantic_key[0],
            self._predicate,
            self._kind,
            self._stance,
            self.value_key,
            '' if self._source is None else self._source.key,
            self._origin or '',
            self._component_ref or '',
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EvidenceClaim):
            return self.canonical_key == other.canonical_key
        return False

    def __hash__(self) -> int:
        return hash(self.canonical_key)

    def __lt__(self, other: object) -> bool:
        if isinstance(other, EvidenceClaim):
            return self.canonical_key < other.canonical_key
        return NotImplemented

    def __repr__(self) -> str:
        return (
            f'<EvidenceClaim target={_claim_target_label(self._target)!r}, '
            f'predicate={self._predicate!r}, value={self._value!r}>'
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            'target': _claim_target_label(self._target),
            'predicate': self._predicate,
            'value': self._value if isinstance(self._value, (str, int, float, bool, type(None))) else self.value_key,
            'kind': self._kind,
            'stance': self._stance,
            'source': None if self._source is None else self._source.as_dict(),
            'origin': self._origin,
            'component_ref': self._component_ref,
        }


class UnattributedReason(str, Enum):
    CONTRADICTORY = 'contradictory'
    UNAUTHORIZED_SOURCE = 'unauthorized-source'
    UNKNOWN_SOURCE = 'unknown-source'
    AMBIGUOUS_TARGET = 'ambiguous-target'
    UNRESOLVED_TARGET = 'unresolved-target'
    MISSING_SOURCE = 'missing-source'


class UnattributedClaim:
    """A claim that was intentionally parked outside the trusted BOM."""

    def __init__(
        self, claim: EvidenceClaim, reason: Union[UnattributedReason, str], *,
        detail: Optional[str] = None,
        candidates: Optional[Iterable[str]] = None,
    ) -> None:
        self._claim = claim
        self._reason = UnattributedReason(reason)
        self._detail = detail
        self._candidates = tuple(sorted(candidates or ()))

    @property
    def claim(self) -> EvidenceClaim:
        return self._claim

    @property
    def reason(self) -> UnattributedReason:
        return self._reason

    @property
    def detail(self) -> Optional[str]:
        return self._detail

    @property
    def candidates(self) -> Tuple[str, ...]:
        return self._candidates

    @property
    def target(self) -> Any:
        return self._claim.target

    @property
    def predicate(self) -> str:
        return self._claim.predicate

    @property
    def value(self) -> Any:
        return self._claim.value

    @property
    def source(self) -> Optional[TrustSource]:
        return self._claim.source

    @property
    def kind(self) -> str:
        return self._claim.kind

    @property
    def stance(self) -> str:
        return self._claim.stance

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UnattributedClaim):
            return (
                self._claim == other._claim
                and self._reason == other._reason
                and self._detail == other._detail
                and self._candidates == other._candidates
            )
        return False

    def __hash__(self) -> int:
        return hash((self._claim, self._reason, self._detail, self._candidates))

    def __lt__(self, other: object) -> bool:
        if isinstance(other, UnattributedClaim):
            return (
                self._claim.canonical_key,
                self._reason.value,
                self._detail or '',
                self._candidates,
            ) < (
                other._claim.canonical_key,
                other._reason.value,
                other._detail or '',
                other._candidates,
            )
        return NotImplemented

    def __repr__(self) -> str:
        return f'<UnattributedClaim reason={self._reason.value!r}, claim={self._claim!r}>'

    def as_dict(self) -> Dict[str, Any]:
        return {
            'claim': self._claim.as_dict(),
            'reason': self._reason.value,
            'detail': self._detail,
            'candidates': list(self._candidates),
        }


class EvidenceClaimMergeResult:
    """Result of merging claims without constructing a BOM."""

    def __init__(
        self, *,
        trusted: Iterable[EvidenceClaim],
        unattributed: Iterable[UnattributedClaim],
        trust_sources: Iterable[TrustSource] = (),
    ) -> None:
        self._trusted = tuple(sorted(set(trusted)))
        self._unattributed = tuple(sorted(set(unattributed)))
        self._trust_sources = tuple(sorted(set(trust_sources)))

    @property
    def trusted(self) -> Tuple[EvidenceClaim, ...]:
        return self._trusted

    @property
    def attributed(self) -> Tuple[EvidenceClaim, ...]:
        return self._trusted

    @property
    def trusted_claims(self) -> Tuple[EvidenceClaim, ...]:
        return self._trusted

    @property
    def unattributed(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def unattributed_claims(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def sidecar(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def quarantine(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def trust_sources(self) -> Tuple[TrustSource, ...]:
        return self._trust_sources

    @property
    def sources(self) -> Tuple[TrustSource, ...]:
        return self._trust_sources

    def __iter__(self) -> Iterator[Any]:
        yield self._trusted
        yield self._unattributed

    def as_tuple(self) -> Tuple[Tuple[EvidenceClaim, ...], Tuple[UnattributedClaim, ...]]:
        return self._trusted, self._unattributed


class BomMergeResult(Bom):
    """
    The trusted, merged BOM plus the unattributed-claim side channel.

    This is a real :class:`cyclonedx.model.bom.Bom`, so callers that only need
    the trusted part can use it directly.  The side channel is available as
    ``unattributed`` (aliases: ``unattributed_claims``, ``sidecar``,
    ``quarantine``).
    """

    def __init__(
        self, *,
        components: Optional[Iterable[Component]] = None,
        services: Optional[Iterable[Any]] = None,
        external_references: Optional[Iterable[Any]] = None,
        serial_number: Any = None,
        version: int = 1,
        metadata: Optional[BomMetaData] = None,
        dependencies: Optional[Iterable[Dependency]] = None,
        vulnerabilities: Optional[Iterable[Any]] = None,
        properties: Optional[Iterable[Property]] = None,
        definitions: Any = None,
        trust_sources: Iterable[TrustSource] = (),
        claims: Iterable[EvidenceClaim] = (),
        unattributed_claims: Iterable[UnattributedClaim] = (),
    ) -> None:
        super().__init__(
            components=components,
            services=services,
            external_references=external_references,
            serial_number=serial_number,
            version=version,
            metadata=metadata,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            properties=properties,
            definitions=definitions,
        )
        self._trust_sources = tuple(sorted(set(trust_sources)))
        self._claims = tuple(sorted(set(claims)))
        self._unattributed = tuple(sorted(set(unattributed_claims)))

    def _as_plain_bom(self) -> Bom:
        # ``py-serializable`` dispatches on the exact class name.  Build a
        # plain Bom for output so the trusted part remains serializable
        # without depending on this contrib wrapper being registered there.
        return Bom(
            components=self.components,
            services=self.services,
            external_references=self.external_references,
            serial_number=self.serial_number,
            version=self.version,
            metadata=self.metadata,
            dependencies=self.dependencies,
            vulnerabilities=self.vulnerabilities,
            properties=self.properties,
            definitions=self.definitions,
        )

    def as_json(self, view_: Any = None) -> str:
        return self._as_plain_bom().as_json(view_=view_)  # type:ignore[attr-defined]

    def as_xml(
        self, view_: Any = None, as_string: bool = True,
        element_name: Optional[str] = None, xmlns: Optional[str] = None,
    ) -> Any:
        return self._as_plain_bom().as_xml(  # type:ignore[attr-defined]
            view_, as_string=as_string, element_name=element_name, xmlns=xmlns,
        )

    @property
    def bom(self) -> 'BomMergeResult':
        return self

    @property
    def merged_bom(self) -> 'BomMergeResult':
        return self

    @property
    def trusted(self) -> 'BomMergeResult':
        return self

    @property
    def trusted_bom(self) -> 'BomMergeResult':
        return self

    @property
    def trusted_part(self) -> 'BomMergeResult':
        return self

    @property
    def trust_sources(self) -> Tuple[TrustSource, ...]:
        return self._trust_sources

    @property
    def sources(self) -> Tuple[TrustSource, ...]:
        return self._trust_sources

    @property
    def trust_sources_by_key(self) -> Dict[str, TrustSource]:
        return {source.key: source for source in self._trust_sources}

    @property
    def claims(self) -> Tuple[EvidenceClaim, ...]:
        return self._claims

    @property
    def evidence_claims(self) -> Tuple[EvidenceClaim, ...]:
        return self._claims

    @property
    def attributed_claims(self) -> Tuple[EvidenceClaim, ...]:
        return self._claims

    @property
    def unattributed(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def unattributed_claims(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def sidecar(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def quarantine(self) -> Tuple[UnattributedClaim, ...]:
        return self._unattributed

    @property
    def conflicts(self) -> Tuple[UnattributedClaim, ...]:
        return tuple(
            claim for claim in self._unattributed
            if claim.reason is UnattributedReason.CONTRADICTORY
        )

    def __iter__(self) -> Iterator[Any]:
        yield self
        yield self._unattributed

    def as_tuple(self) -> Tuple['BomMergeResult', Tuple[UnattributedClaim, ...]]:
        return self, self._unattributed


@dataclass
class _ComponentRecord:
    component: Component
    bom: Optional[Bom]
    origin: str
    is_metadata: bool = False


@dataclass
class _Cluster:
    key: str
    records: List[_ComponentRecord]
    identity: ComponentIdentity
    ref: Optional[str] = None


@dataclass
class _SourceState:
    entity: Optional[OrganizationalEntity]
    kind: str
    targets: Set[str]
    digests: Set[str]


def _retarget_claim(claim: EvidenceClaim, refs: Mapping[str, str]) -> EvidenceClaim:
    target = refs.get(claim.semantic_key[0], claim.target)
    return EvidenceClaim(
        target=target,
        predicate=claim.predicate,
        value=claim.value,
        source=claim.source,
        kind=claim.kind,
        stance=claim.stance,
        confidence=claim.confidence,
        methods=claim.methods,
        tools=claim.tools,
        origin=claim.origin,
        component_ref=claim.component_ref,
        payload=claim.payload,
        implicit_source=claim.implicit_source,
    )


def _retarget_unattributed(claim: UnattributedClaim, refs: Mapping[str, str]) -> UnattributedClaim:
    return UnattributedClaim(
        _retarget_claim(claim.claim, refs), claim.reason,
        detail=claim.detail, candidates=claim.candidates,
    )


def _claim_target_label(target: Any) -> str:
    if isinstance(target, Component):
        return ComponentIdentity.from_component(target).key
    if isinstance(target, ComponentIdentity):
        return target.key
    if isinstance(target, BomRef):
        return target.value or ''
    return str(target)


def _identity_value(identity: Identity, component: Component) -> Any:
    if identity.concluded_value is not None:
        return identity.concluded_value
    field = identity.field
    if field is IdentityField.NAME:
        return component.name
    if field is IdentityField.GROUP:
        return component.group
    if field is IdentityField.VERSION:
        return component.version
    if field is IdentityField.PURL:
        return None if component.purl is None else component.purl.to_string()
    if field is IdentityField.CPE:
        return component.cpe
    if field is IdentityField.SWID:
        return None if component.swid is None else component.swid.tag_id
    if field is IdentityField.OMNIBOR_ID:
        return tuple(sorted(item.id for item in component.omnibor_ids))
    if field is IdentityField.SWHID:
        return tuple(sorted(item.id for item in component.swhids))
    if field is IdentityField.HASH:
        return tuple(sorted((item.alg.value, item.content) for item in component.hashes))
    return None


def _is_endorsement(claim: EvidenceClaim) -> bool:
    predicate = claim.predicate.lower()
    return (
        claim.kind in {'digest', 'endorsement', 'source', 'provenance'}
        or predicate.startswith(('hash:', 'digest:', 'source:', 'provenance:'))
    )


def _identity_claims(
    identities: Iterable[Identity], *, component: Component, target: str,
    source: Optional[OrganizationalEntity], origin: str, component_ref: Optional[str],
) -> List[EvidenceClaim]:
    claims = []
    for identity in identities:
        digest_attestation = (
            identity.field is IdentityField.HASH
            and any(method.technique is AnalysisTechnique.ATTESTATION for method in identity.methods)
        )
        claim = EvidenceClaim.from_identity(
            identity,
            target=target,
            source=source,
            origin=origin,
            component_ref=component_ref,
            value=_identity_value(identity, component),
            implicit_source=True,
        )
        if digest_attestation:
            claim = EvidenceClaim(
                target=target,
                predicate=claim.predicate,
                value=claim.value,
                source=source,
                kind='digest-endorsement',
                stance='endorse',
                confidence=identity.confidence,
                methods=identity.methods,
                tools=identity.tools,
                origin=origin,
                component_ref=component_ref,
                payload=identity,
                implicit_source=True,
            )
        claims.append(claim)
    return claims


def _misc_evidence_claims(
    evidence: ComponentEvidence, *, target: str, source: Optional[OrganizationalEntity],
    origin: str, component_ref: Optional[str],
) -> List[EvidenceClaim]:
    claims = []
    for occurrence in evidence.occurrences:
        key = _hash_text(_stable_key(occurrence))[:16]
        claims.append(EvidenceClaim(
            target=target, predicate=f'occurrence:{key}', value=occurrence.location,
            source=source, kind='occurrence', origin=origin, component_ref=component_ref,
            payload=occurrence, implicit_source=True,
        ))
    if evidence.callstack is not None:
        claims.append(EvidenceClaim(
            target=target, predicate='callstack', value=evidence.callstack,
            source=source, kind='callstack', origin=origin, component_ref=component_ref,
            payload=evidence.callstack, implicit_source=True,
        ))
    for license_item in evidence.licenses:
        key = _hash_text(_stable_key(license_item))[:16]
        claims.append(EvidenceClaim(
            target=target, predicate=f'license:{key}', value=license_item,
            source=source, kind='license', origin=origin, component_ref=component_ref,
            payload=license_item, implicit_source=True,
        ))
    for copyright_item in evidence.copyright:
        key = _hash_text(copyright_item.text)[:16]
        claims.append(EvidenceClaim(
            target=target, predicate=f'copyright:{key}', value=copyright_item.text,
            source=source, kind='copyright', origin=origin, component_ref=component_ref,
            payload=copyright_item, implicit_source=True,
        ))
    return claims


def _component_claims(
    component: Component, *, target: str, origin: str,
) -> Tuple[List[EvidenceClaim], Optional[OrganizationalEntity]]:
    source = component.supplier or component.manufacturer
    component_ref = component.bom_ref.value
    claims: List[EvidenceClaim] = []
    for hash_item in component.hashes:
        claims.append(EvidenceClaim(
            target=target,
            predicate=f'hash:{hash_item.alg.value}',
            value=hash_item.content,
            source=source,
            kind='digest',
            stance='endorse',
            origin=origin,
            component_ref=component_ref,
            payload=hash_item,
            implicit_source=True,
        ))
    evidence = component.evidence
    if evidence is not None:
        claims.extend(_identity_claims(
            evidence.identity, component=component, target=target,
            source=source, origin=origin, component_ref=component_ref,
        ))
        claims.extend(_misc_evidence_claims(
            evidence, target=target, source=source, origin=origin, component_ref=component_ref,
        ))
    return claims, source


def _cluster_identity(records: Sequence[_ComponentRecord]) -> ComponentIdentity:
    return min((ComponentIdentity.from_component(record.component) for record in records), key=lambda i: i.key)


def _cluster_key(records: Sequence[_ComponentRecord], identity: ComponentIdentity) -> str:
    fingerprint = _hash_text('\n'.join(sorted(_component_fingerprint(record.component) for record in records)))[:12]
    return f'{identity.key}#{fingerprint}'


def _build_clusters(records: Sequence[_ComponentRecord]) -> List[_Cluster]:
    identities = [ComponentIdentity.from_component(record.component) for record in records]
    parents = list(range(len(records)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    for left, left_identity in enumerate(identities):
        for right in range(left + 1, len(identities)):
            if left_identity.compatible_with(identities[right]):
                union(left, right)

    grouped: Dict[int, List[_ComponentRecord]] = defaultdict(list)
    for index, record in enumerate(records):
        grouped[find(index)].append(record)

    clusters = []
    for cluster_records in grouped.values():
        identity = _cluster_identity(cluster_records)
        clusters.append(_Cluster(_cluster_key(cluster_records, identity), cluster_records, identity))
    clusters.sort(key=lambda cluster: cluster.key)
    return clusters


def _target_lookup(
    records: Sequence[_ComponentRecord], clusters: Sequence[_Cluster],
) -> Dict[str, Set[str]]:
    lookup: Dict[str, Set[str]] = defaultdict(set)
    for cluster in clusters:
        lookup[cluster.key].add(cluster.key)
        for key in cluster.identity.lookup_keys():
            lookup[key].add(cluster.key)
    for record, cluster in zip(records, _cluster_for_records(records, clusters)):
        if record.bom is not None and record.component.bom_ref.value:
            lookup[record.component.bom_ref.value].add(cluster.key)
    return lookup


def _cluster_for_records(
    records: Sequence[_ComponentRecord], clusters: Sequence[_Cluster],
) -> List[_Cluster]:
    by_id = {id(record): cluster for cluster in clusters for record in cluster.records}
    return [by_id[id(record)] for record in records]


def _resolve_target(
    target: Any, *, lookup: Mapping[str, Set[str]], strict: bool,
) -> Tuple[Optional[str], Tuple[str, ...]]:
    if isinstance(target, Component):
        label = ComponentIdentity.from_component(target).key
        candidates = tuple(sorted(lookup.get(label, ())))
    elif isinstance(target, ComponentIdentity):
        candidates = tuple(sorted(lookup.get(target.key, ())))
    elif isinstance(target, BomRef):
        candidates = tuple(sorted(lookup.get(target.value or '', ())))
    else:
        label = str(target)
        candidates = tuple(sorted(lookup.get(label, ())))
        if not candidates and label in lookup:
            candidates = tuple(sorted(lookup[label]))
    if len(candidates) == 1:
        return candidates[0], candidates
    if len(candidates) > 1:
        return None, candidates
    return (None if strict else _claim_target_label(target)), ()


def _source_alias_map(sources: Sequence[TrustSource]) -> Dict[str, str]:
    aliases: Dict[str, Set[str]] = defaultdict(set)
    for source in sources:
        for alias in source.aliases():
            aliases[alias].add(source.key)
    return {
        alias: next(iter(keys))
        for alias, keys in aliases.items()
        if len(keys) == 1
    }


def _resolve_source_key(
    source: Optional[TrustSource], aliases: Mapping[str, str],
) -> Optional[str]:
    if source is None:
        return None
    for alias in source.aliases():
        if alias in aliases:
            return aliases[alias]
    return None


def _authorize(
    claim: EvidenceClaim, *, target: str,
    scopes: Mapping[str, Set[str]], digests: Mapping[str, Set[str]],
    aliases: Mapping[str, str], strict_source: bool,
) -> Optional[UnattributedReason]:
    if claim.source is None:
        return None if claim.implicit_source else UnattributedReason.MISSING_SOURCE
    source_key = _resolve_source_key(claim.source, aliases)
    if source_key is None:
        return UnattributedReason.UNKNOWN_SOURCE if strict_source else None
    if target in scopes.get(source_key, ()):
        return None
    if _is_endorsement(claim):
        source_digests = digests.get(source_key, ())
        if claim.value in source_digests or claim.value_key in {
            _stable_key(digest) for digest in source_digests
        }:
            return None
    return UnattributedReason.UNAUTHORIZED_SOURCE


def _contradiction_reason(claims: Sequence[EvidenceClaim]) -> Optional[str]:
    values = {claim.value_key for claim in claims}
    stances = {claim.stance for claim in claims}
    if len(values) <= 1 and not ('assert' in stances and 'deny' in stances):
        return None
    return 'conflicting values: ' + ', '.join(sorted(values))


def _split_attributed(
    claims: Sequence[EvidenceClaim], *,
    scopes: Mapping[str, Set[str]], digests: Mapping[str, Set[str]],
    aliases: Mapping[str, str], strict_source: bool,
) -> Tuple[List[Tuple[str, EvidenceClaim]], List[UnattributedClaim]]:
    attributed: List[Tuple[str, EvidenceClaim]] = []
    unattributed: List[UnattributedClaim] = []
    groups: Dict[Tuple[str, str], List[EvidenceClaim]] = defaultdict(list)

    for claim in claims:
        target, candidates = claim.semantic_key[0], ()
        if not target:
            unattributed.append(UnattributedClaim(
                claim, UnattributedReason.UNRESOLVED_TARGET, candidates=candidates,
            ))
            continue
        reason = _authorize(
            claim, target=target, scopes=scopes, digests=digests,
            aliases=aliases, strict_source=strict_source,
        )
        if reason is not None:
            unattributed.append(UnattributedClaim(claim, reason))
        else:
            groups[(target, claim.semantic_predicate)].append(claim)

    for (_, predicate), group in groups.items():
        reason = _contradiction_reason(group)
        if reason is None:
            attributed.extend((claim.semantic_key[0], claim) for claim in group)
        else:
            unattributed.extend(
                UnattributedClaim(claim, UnattributedReason.CONTRADICTORY, detail=reason)
                for claim in group
            )
    return attributed, unattributed


def _ref_map_by_origin(clusters: Sequence[_Cluster]) -> Dict[Tuple[str, str], Optional[str]]:
    grouped: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for cluster in clusters:
        for record in cluster.records:
            ref = record.component.bom_ref.value
            if ref and cluster.ref:
                grouped[(record.origin, ref)].add(cluster.ref)
    return {
        key: next(iter(values)) if len(values) == 1 else None
        for key, values in grouped.items()
    }


def _remap_evidence_ref(
    ref: BomRef, *, origin: Optional[str],
    ref_map: Mapping[Tuple[str, str], Optional[str]], new_refs: Set[str],
) -> Optional[BomRef]:
    old = ref.value
    if not old:
        return ref
    mapping_key = (origin or '', old)
    if mapping_key in ref_map:
        mapped = ref_map[mapping_key]
        return BomRef(mapped) if mapped else None
    if old in new_refs:
        return None
    return ref


def _remap_evidence_payload(
    payload: Any, *, origin: Optional[str],
    ref_map: Mapping[Tuple[str, str], Optional[str]], new_refs: Set[str],
) -> Any:
    if isinstance(payload, Identity):
        remapped_tools = []
        for tool in payload.tools:
            remapped = _remap_evidence_ref(tool, origin=origin, ref_map=ref_map, new_refs=new_refs)
            if remapped is not None:
                remapped_tools.append(remapped)
        payload.tools = remapped_tools
    elif isinstance(payload, Occurrence) and payload.bom_ref.value:
        remapped = _remap_evidence_ref(
            payload.bom_ref, origin=origin, ref_map=ref_map, new_refs=new_refs)
        payload._bom_ref = remapped or BomRef()
    return payload


def _evidence_from_claims(
    claims: Iterable[EvidenceClaim], *,
    ref_map: Optional[Mapping[Tuple[str, str], Optional[str]]] = None,
    new_refs: Optional[Set[str]] = None,
) -> Optional[ComponentEvidence]:
    identities: List[Identity] = []
    occurrences: List[Occurrence] = []
    callstacks: List[CallStack] = []
    licenses: List[License] = []
    copyrights: List[Copyright] = []
    ref_map = ref_map or {}
    new_refs = new_refs or set()

    for claim in sorted(claims):
        payload = _remap_evidence_payload(
            copy.deepcopy(claim.payload), origin=claim.origin,
            ref_map=ref_map, new_refs=new_refs,
        )
        if isinstance(payload, Identity):
            identities.append(payload)
        elif isinstance(payload, Occurrence):
            occurrences.append(payload)
        elif isinstance(payload, CallStack):
            callstacks.append(payload)
        elif isinstance(payload, License):
            licenses.append(payload)
        elif isinstance(payload, Copyright):
            copyrights.append(payload)

    if not any((identities, occurrences, callstacks, licenses, copyrights)):
        return None
    return ComponentEvidence(
        identity=identities,
        occurrences=occurrences,
        callstack=min(callstacks, key=_stable_key) if callstacks else None,
        licenses=licenses,
        copyright=copyrights,
    )


def _unique_records(records: Iterable[_ComponentRecord], attr: str) -> List[Any]:
    values: Dict[str, Any] = {}
    for record in sorted(records, key=lambda item: _component_fingerprint(item.component)):
        for value in getattr(record.component, attr):
            values.setdefault(_stable_key(value), value)
    return [copy.deepcopy(values[key]) for key in sorted(values)]


def _first_value(records: Sequence[_ComponentRecord], attr: str, key: Any) -> Any:
    for record in sorted(records, key=lambda item: _component_fingerprint(item.component)):
        value = getattr(record.component, attr)
        if value is not None:
            key(value)
            return copy.deepcopy(value)
    return None


def _merge_component_fields(
    base: Component, records: Sequence[_ComponentRecord],
    evidence: Optional[ComponentEvidence],
) -> Component:
    component = copy.deepcopy(base)
    component.hashes = _unique_records(records, 'hashes')
    component.licenses = _unique_records(records, 'licenses')
    component.external_references = _unique_records(records, 'external_references')
    component.properties = _unique_records(records, 'properties')
    component.authors = _unique_records(records, 'authors')
    component.omnibor_ids = _unique_records(records, 'omnibor_ids')
    component.swhids = _unique_records(records, 'swhids')
    component.tags = _unique_records(records, 'tags')
    component.components = _unique_records(records, 'components')
    component.evidence = evidence
    component.supplier = _first_value(records, 'supplier', _entity_key)
    component.manufacturer = _first_value(records, 'manufacturer', _entity_key)
    component.copyright = _first_value(records, 'copyright', _stable_key)
    component.description = _first_value(records, 'description', _stable_key)
    component.publisher = _first_value(records, 'publisher', _stable_key)
    component.scope = _first_value(records, 'scope', _stable_key)
    component.cpe = _first_value(records, 'cpe', _stable_key)
    component.purl = _first_value(records, 'purl', _stable_key)
    component.swid = _first_value(records, 'swid', _stable_key)
    component.release_notes = _first_value(records, 'release_notes', _stable_key)
    component.crypto_properties = _first_value(records, 'crypto_properties', _stable_key)
    return component


def _assign_refs(clusters: Sequence[_Cluster]) -> Dict[str, str]:
    preferred = [
        sorted({
            record.component.bom_ref.value
            for record in cluster.records
            if record.component.bom_ref.value
        })
        for cluster in clusters
    ]
    counts = Counter(ref for refs in preferred for ref in set(refs))
    used: Set[str] = set()
    refs: Dict[str, str] = {}
    for cluster, cluster_refs in zip(clusters, preferred):
        candidates = [ref for ref in cluster_refs if counts[ref] == 1 and ref not in used]
        if candidates:
            assigned = candidates[0]
        else:
            base = cluster_refs[0] if cluster_refs else 'BomRef'
            assigned = f'{base}--{_hash_text(cluster.key)[:8]}'
            suffix = 2
            while assigned in used:
                assigned = f'{base}--{_hash_text(cluster.key)[:8]}-{suffix}'
                suffix += 1
        used.add(assigned)
        refs[cluster.key] = assigned
        cluster.ref = assigned
    return refs


def _remap_dependencies(
    boms: Sequence[Bom], clusters: Sequence[_Cluster], refs: Mapping[str, str],
) -> List[Dependency]:
    by_bom_ref: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for cluster in clusters:
        for record in cluster.records:
            if record.bom is not None and record.component.bom_ref.value:
                by_bom_ref[(record.origin, record.component.bom_ref.value)].add(cluster.key)

    edges: Dict[str, Set[str]] = defaultdict(set)

    def resolve(origin: str, ref: Optional[str]) -> Optional[str]:
        if not ref:
            return None
        candidates = by_bom_ref.get((origin, ref), set())
        if len(candidates) != 1:
            return None
        cluster_key = next(iter(candidates))
        return refs.get(cluster_key)

    def walk(origin: str, dependency: Dependency) -> None:
        target = resolve(origin, dependency.ref.value)
        if target is None:
            return
        targets = edges[target]
        for child in dependency.dependencies:
            resolved_child = resolve(origin, child.ref.value)
            if resolved_child is not None:
                targets.add(resolved_child)
                walk(origin, child)

    for bom in boms:
        origin = _bom_origin(bom)
        for dependency in bom.dependencies:
            walk(origin, dependency)
    return [
        Dependency(BomRef(target), (Dependency(BomRef(child)) for child in sorted(children)))
        for target, children in sorted(edges.items())
    ]


def _metadata_for(boms: Sequence[Bom]) -> BomMetaData:
    if not boms:
        return BomMetaData()
    base = min(boms, key=lambda bom: (_bom_fingerprint(bom), bom.metadata.timestamp))
    return copy.deepcopy(base.metadata)


def _unique_bom_values(boms: Sequence[Bom], attr: str) -> List[Any]:
    values: Dict[str, Any] = {}
    for bom in sorted(boms, key=_bom_fingerprint):
        for value in getattr(bom, attr):
            values.setdefault(_stable_key(value), value)
    return [copy.deepcopy(values[key]) for key in sorted(values)]


def _register_source(
    states: Dict[str, _SourceState], entity: Optional[OrganizationalEntity], *,
    kind: str, targets: Iterable[str] = (), digests: Iterable[str] = (),
) -> Optional[str]:
    if entity is None:
        return None
    key = _entity_key(entity)
    state = states.get(key)
    if state is None:
        state = states[key] = _SourceState(entity=entity, kind=kind, targets=set(), digests=set())
    state.targets.update(targets)
    state.digests.update(digests)
    return key


def _digest_values(component: Component) -> Set[str]:
    values = {item.content for item in component.hashes}
    evidence = component.evidence
    if evidence is not None:
        for identity in evidence.identity:
            if identity.field is IdentityField.HASH and identity.concluded_value:
                values.add(identity.concluded_value)
    return values


def _collect_sources(
    boms: Sequence[Bom], records: Sequence[_ComponentRecord],
    clusters: Sequence[_Cluster], explicit: Sequence[TrustSource],
) -> Dict[str, _SourceState]:
    states: Dict[str, _SourceState] = {}
    refs_by_record = {
        id(record): cluster.key
        for cluster in clusters for record in cluster.records
    }
    for record in records:
        target = refs_by_record.get(id(record))
        if target is None:
            continue
        component_digests = _digest_values(record.component)
        _register_source(
            states, record.component.supplier, kind='supplier', targets=(target,),
            digests=component_digests,
        )
        _register_source(
            states, record.component.manufacturer, kind='manufacturer', targets=(target,),
            digests=component_digests,
        )
    for bom in boms:
        document_digests = {
            digest
            for record in records
            if record.bom is bom
            for digest in _digest_values(record.component)
        }
        # A document-level supplier is a source for the document's digests,
        # but it is not thereby authorized to assert analysis results for
        # every component in the document.
        _register_source(states, bom.metadata.supplier, kind='supplier', digests=document_digests)
        _register_source(states, bom.metadata.manufacturer, kind='manufacturer', digests=document_digests)
        _register_source(states, bom.metadata.manufacture, kind='manufacturer', digests=document_digests)
    for source in explicit:
        state = states.get(source.key)
        if state is None:
            state = states[source.key] = _SourceState(
                entity=source.entity, kind=source.kind, targets=set(), digests=set())
        state.targets.update(source.authorized_targets)
        state.digests.update(source.endorsed_digests)
    return states


def _final_sources(states: Mapping[str, _SourceState]) -> Tuple[TrustSource, ...]:
    return tuple(sorted((
        TrustSource(
            key,
            entity=state.entity,
            kind=state.kind,
            authorized_targets=state.targets,
            endorsed_digests=state.digests,
        )
        for key, state in states.items()
    )))


def _normalize_claim_inputs(values: Iterable[Any]) -> List[EvidenceClaim]:
    claims: List[EvidenceClaim] = []
    for value in _flatten(values):
        if isinstance(value, EvidenceClaim):
            claims.append(value)
        elif isinstance(value, Mapping):
            claims.append(EvidenceClaim(
                target=value.get('target', value.get('component', value.get('bom_ref'))),
                predicate=str(value.get('predicate', 'claim')),
                value=value.get('value'),
                source=value.get('source', value.get('endorsed_by')),
                kind=str(value.get('kind', 'claim')),
                stance=str(value.get('stance', 'assert')),
                confidence=value.get('confidence'),
                origin=value.get('origin'),
                component_ref=value.get('component_ref'),
            ))
        else:
            raise TypeError(f'Unsupported evidence claim: {value!r}')
    return claims


def _normalize_source_inputs(values: Iterable[Any]) -> List[TrustSource]:
    return [source for source in (_normalize_source(value) for value in _flatten(values)) if source is not None]


def _merge_records(
    boms: Sequence[Bom], explicit_components: Sequence[Component],
    explicit_claims: Sequence[EvidenceClaim], explicit_sources: Sequence[TrustSource],
) -> BomMergeResult:
    records: List[_ComponentRecord] = []
    for bom in boms:
        origin = _bom_origin(bom)
        if bom.metadata.component is not None:
            records.append(_ComponentRecord(bom.metadata.component, bom, origin, True))
        for component in bom.components:
            records.append(_ComponentRecord(component, bom, origin, False))
    records.extend(_ComponentRecord(component, None, 'components') for component in explicit_components)
    clusters = _build_clusters(records)
    lookup = _target_lookup(records, clusters)
    record_cluster = {
        id(record): cluster
        for cluster in clusters for record in cluster.records
    }

    claims: List[EvidenceClaim] = []
    for record in records:
        cluster = record_cluster[id(record)]
        extracted, _ = _component_claims(
            record.component, target=cluster.key, origin=record.origin,
        )
        claims.extend(extracted)

    resolved_explicit: List[EvidenceClaim] = []
    unattributed: List[UnattributedClaim] = []
    for claim in explicit_claims:
        requested = _claim_target_label(claim.target)
        resolved, candidates = _resolve_target(claim.target, lookup=lookup, strict=bool(records))
        if resolved is None:
            reason = (
                UnattributedReason.AMBIGUOUS_TARGET
                if len(candidates) > 1
                else UnattributedReason.UNRESOLVED_TARGET
            )
            unattributed.append(UnattributedClaim(claim, reason, candidates=candidates))
            continue
        resolved_explicit.append(EvidenceClaim(
            target=resolved,
            predicate=claim.predicate,
            value=claim.value,
            source=claim.source,
            kind=claim.kind,
            stance=claim.stance,
            confidence=claim.confidence,
            methods=claim.methods,
            tools=claim.tools,
            origin=claim.origin or requested,
            component_ref=claim.component_ref,
            payload=claim.payload,
            implicit_source=claim.implicit_source,
        ))
    claims.extend(resolved_explicit)

    states = _collect_sources(boms, records, clusters, explicit_sources)
    if not states:
        # With no component-level source information, a claim's declared
        # source can only vouch for that claim's target.  Materialize it as
        # a real trust source so it is not lost from the result.
        for claim in claims:
            if claim.source is None:
                continue
            state = states.setdefault(
                claim.source.key,
                _SourceState(entity=claim.source.entity, kind=claim.source.kind, targets=set(), digests=set()),
            )
            state.targets.add(claim.semantic_key[0])
            if _is_endorsement(claim):
                state.digests.add(str(claim.value))
    strict_source = bool(states)
    aliases = _source_alias_map(_final_sources(states))
    attributed, split_unattributed = _split_attributed(
        claims,
        scopes={key: state.targets for key, state in states.items()},
        digests={key: state.digests for key, state in states.items()},
        aliases=aliases,
        strict_source=strict_source,
    )
    unattributed.extend(split_unattributed)

    trusted_by_cluster: Dict[str, List[EvidenceClaim]] = defaultdict(list)
    for target, claim in attributed:
        trusted_by_cluster[target].append(claim)

    refs = _assign_refs(clusters)
    ref_map = _ref_map_by_origin(clusters)
    new_refs = set(refs.values())
    components: List[Component] = []
    merged_by_cluster: Dict[str, Component] = {}
    metadata_component_keys = {
        cluster.key
        for cluster in clusters
        if any(record.is_metadata for record in cluster.records)
    }
    for cluster in clusters:
        base = min(cluster.records, key=lambda record: _component_fingerprint(record.component)).component
        evidence = _evidence_from_claims(
            trusted_by_cluster.get(cluster.key, ()), ref_map=ref_map, new_refs=new_refs)
        merged = _merge_component_fields(base, cluster.records, evidence)
        merged.bom_ref.value = refs[cluster.key]
        merged_by_cluster[cluster.key] = merged
        if cluster.key not in metadata_component_keys:
            components.append(merged)

    metadata = _metadata_for(boms)
    metadata_cluster = None
    if metadata.component is not None:
        metadata_identity = ComponentIdentity.from_component(metadata.component)
        metadata_cluster = next(
            (cluster for cluster in clusters if cluster.identity.key == metadata_identity.key),
            None,
        )
    if metadata_cluster is None:
        metadata_cluster = next((c for c in clusters if c.key in metadata_component_keys), None)
    if metadata_cluster is not None:
        metadata.component = copy.deepcopy(merged_by_cluster[metadata_cluster.key])

    sorted_trusted = tuple(sorted({
        _retarget_claim(claim, refs) for _, claim in attributed
    }))
    retargeted_unattributed = tuple(
        _retarget_unattributed(claim, refs) for claim in unattributed
    )
    serial_source = '\n'.join(sorted(_bom_fingerprint(bom) for bom in boms))
    if not serial_source:
        serial_source = '\n'.join(sorted(
            [_component_fingerprint(component) for component in explicit_components]
            + [claim.canonical_key[0] + '|' + claim.predicate + '|' + claim.value_key
               for claim in explicit_claims]
            + [source.key for source in explicit_sources]
        ))
    return BomMergeResult(
        components=components,
        services=_unique_bom_values(boms, 'services'),
        external_references=_unique_bom_values(boms, 'external_references'),
        serial_number=uuid5(NAMESPACE_URL, f'cyclonedx-merge:{serial_source}'),
        version=max((bom.version for bom in boms), default=1),
        metadata=metadata,
        dependencies=_remap_dependencies(boms, clusters, refs),
        vulnerabilities=_unique_bom_values(boms, 'vulnerabilities'),
        properties=_unique_bom_values(boms, 'properties'),
        trust_sources=_final_sources(states),
        claims=sorted_trusted,
        unattributed_claims=retargeted_unattributed,
    )


class BomMerger:
    """
    Merge BOMs without mixing up evidence ownership.

    ``merge()`` can be called repeatedly and also accepts explicit components,
    claims, and trust sources when a caller has already separated the three
    concerns.
    """

    def __init__(
        self, *boms: Any, components: Any = None, claims: Any = None,
        trust_sources: Any = None,
    ) -> None:
        self._boms: List[Bom] = []
        self._components: List[Component] = []
        self._claims: List[EvidenceClaim] = []
        self._trust_sources: List[TrustSource] = []
        self._result: Optional[BomMergeResult] = None
        self.add(*boms, components=components, claims=claims, trust_sources=trust_sources)

    def add(
        self, *boms: Any, components: Any = None, claims: Any = None,
        trust_sources: Any = None,
    ) -> 'BomMerger':
        for bom in _flatten(boms):
            if not isinstance(bom, Bom):
                raise TypeError(f'Unsupported BOM input: {bom!r}')
            self._boms.append(bom)
        for component in _flatten((components,)):
            if not isinstance(component, Component):
                raise TypeError(f'Unsupported component input: {component!r}')
            self._components.append(component)
        self._claims.extend(_normalize_claim_inputs((claims,)))
        self._trust_sources.extend(_normalize_source_inputs((trust_sources,)))
        return self

    def merge(
        self, *boms: Any, components: Any = None, claims: Any = None,
        trust_sources: Any = None,
    ) -> BomMergeResult:
        incoming_boms = _flatten(boms)
        for bom in incoming_boms:
            if not isinstance(bom, Bom):
                raise TypeError(f'Unsupported BOM input: {bom!r}')
        incoming_components = _flatten((components,))
        for component in incoming_components:
            if not isinstance(component, Component):
                raise TypeError(f'Unsupported component input: {component!r}')
        self._result = _merge_records(
            [*self._boms, *incoming_boms],
            [*self._components, *incoming_components],
            [*self._claims, *_normalize_claim_inputs((claims,))],
            [*self._trust_sources, *_normalize_source_inputs((trust_sources,))],
        )
        return self._result

    def __call__(self, *boms: Any, **kwargs: Any) -> BomMergeResult:
        return self.merge(*boms, **kwargs)

    @property
    def result(self) -> Optional[BomMergeResult]:
        return self._result

    @property
    def unattributed(self) -> Tuple[UnattributedClaim, ...]:
        return () if self._result is None else self._result.unattributed

    @property
    def claims(self) -> Tuple[EvidenceClaim, ...]:
        return () if self._result is None else self._result.claims

    @staticmethod
    def merge_components(*components: Any, trust_sources: Any = None) -> Tuple[Component, ...]:
        """Merge component collections without constructing a BOM result."""
        return merge_components(*components, trust_sources=trust_sources)

    @staticmethod
    def merge_evidence_claims(
        *claims: Any, trust_sources: Any = None, targets: Any = None,
    ) -> EvidenceClaimMergeResult:
        """Merge evidence claims without constructing a BOM result."""
        return merge_evidence_claims(*claims, trust_sources=trust_sources, targets=targets)

    @staticmethod
    def merge_trust_sources(*sources: Any) -> Tuple[TrustSource, ...]:
        """Merge trust-source declarations without involving components."""
        return merge_trust_sources(*sources)


def merge_boms(
    *boms: Any, components: Any = None, claims: Any = None,
    trust_sources: Any = None,
) -> BomMergeResult:
    """Merge BOMs and return the trusted BOM plus unattributed claims."""
    return BomMerger().merge(
        *boms, components=components, claims=claims, trust_sources=trust_sources,
    )


def merge_components(*components: Any, trust_sources: Any = None) -> Tuple[Component, ...]:
    """Merge component collections independently of a BOM document."""
    result = merge_boms(components=_flatten(components), trust_sources=trust_sources)
    return tuple(result.components)


def merge_trust_sources(*sources: Any) -> Tuple[TrustSource, ...]:
    """Merge trust-source declarations without involving components."""
    states: Dict[str, _SourceState] = {}
    for source in _normalize_source_inputs(sources):
        state = states.get(source.key)
        if state is None:
            state = states[source.key] = _SourceState(
                entity=source.entity, kind=source.kind, targets=set(), digests=set())
        state.targets.update(source.authorized_targets)
        state.digests.update(source.endorsed_digests)
    return _final_sources(states)


def _standalone_claim_merge(
    claims: Sequence[EvidenceClaim], sources: Sequence[TrustSource],
) -> EvidenceClaimMergeResult:
    states: Dict[str, _SourceState] = {
        source.key: _SourceState(
            entity=source.entity, kind=source.kind,
            targets=set(source.authorized_targets), digests=set(source.endorsed_digests),
        )
        for source in sources
    }
    # Without component context, a named source only vouches for the exact
    # targets it explicitly scoped.  If no scopes were supplied at all, the
    # claims are treated as self-attested by their declared source.
    strict_source = any(state.targets or state.digests for state in states.values())
    scopes = {key: state.targets for key, state in states.items()}
    digests = {key: state.digests for key, state in states.items()}
    aliases = _source_alias_map(_final_sources(states))
    attributed, unattributed = _split_attributed(
        claims, scopes=scopes, digests=digests, aliases=aliases, strict_source=strict_source,
    )
    return EvidenceClaimMergeResult(
        trusted=(claim for _, claim in attributed),
        unattributed=unattributed,
        trust_sources=_final_sources(states),
    )


def merge_evidence_claims(
    *claims: Any, trust_sources: Any = None, targets: Any = None,
) -> EvidenceClaimMergeResult:
    """
    Merge evidence claims by target and predicate.

    ``targets`` may be components used to resolve claim targets.  When omitted,
    target strings are treated as already-canonical identity labels.
    """
    claim_list = _normalize_claim_inputs(claims)
    source_list = _normalize_source_inputs((trust_sources,))
    component_list = _flatten((targets,))
    if component_list:
        result = merge_boms(
            components=component_list, claims=claim_list, trust_sources=source_list,
        )
        return EvidenceClaimMergeResult(
            trusted=result.claims, unattributed=result.unattributed,
            trust_sources=result.trust_sources,
        )
    return _standalone_claim_merge(claim_list, source_list)


merge = merge_boms
MergeResult = BomMergeResult
Claim = EvidenceClaim
Source = TrustSource
Unattributed = UnattributedClaim
EvidenceMerger = BomMerger
EvidenceClaimMerger = BomMerger
ComponentEvidenceMerger = BomMerger
BomEvidenceMerger = BomMerger
