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
Reconcile declared sub-package quantities with review evidence and physical witnesses.

The verifier deliberately keeps the three inputs independent:

* :class:`BatchList` is the authoritative list of delivery batches and sub-packages.
* :class:`ReviewScope` describes what a certificate/record claims to cover.
* :class:`PhysicalWitness` describes which concrete sub-packages were actually observed.

Only quantities that satisfy all three inputs are assigned to a sub-package.  A record
identifier shared by multiple downstreams is treated as one reusable proof, not as a
multiplicand for quantity.  Consolidated declarations that cannot be tied to one
concrete sub-package are reported as unconfirmed instead of being apportioned.
"""

__all__ = [
    'BatchChecker',
    'BatchEntry',
    'BatchList',
    'BatchNumberChecker',
    'BatchNumberVerifier',
    'BatchReconciler',
    'BatchVerificationReport',
    'BatchVerifier',
    'CoverageChange',
    'CoverageDelta',
    'CoverageStatus',
    'DeliveryCoverage',
    'IssueSeverity',
    'LotVerifier',
    'PhysicalWitness',
    'PhysicalWitnessEntry',
    'ReviewScope',
    'ReviewScopeEntry',
    'SubpackageCoverage',
    'VerificationIssue',
    'check_batches',
    'reconcile_batches',
    'verify_batches',
]

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Optional

from ...model.component import Component
from ...model.component_evidence import ComponentEvidence, IdentityField, Occurrence


class CoverageStatus(str, Enum):
    """Outcome for one concrete sub-package."""

    VERIFIED = 'verified'
    PARTIAL = 'partial'
    UNSCOPED = 'unscoped'
    UNWITNESSED = 'unwitnessed'
    CONSOLIDATED_UNCONFIRMED = 'consolidated-unconfirmed'
    EVIDENCE_EXHAUSTED = 'evidence-exhausted'
    ZERO_QUANTITY = 'zero-quantity'


class IssueSeverity(str, Enum):
    """Severity of a reconciliation finding."""

    INFO = 'info'
    WARNING = 'warning'


class _Missing:
    pass


_MISSING = _Missing()
_ZERO = Decimal('0')


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _decimal(value: Any, *, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        result = value
    else:
        try:
            result = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as error:
            raise ValueError(f'{field_name} must be a number, got {value!r}') from error
    if not result.is_finite():
        raise ValueError(f'{field_name} must be finite, got {value!r}')
    if result < 0:
        raise ValueError(f'{field_name} must not be negative, got {value!r}')
    return result


def _optional_decimal(value: Any, *, field_name: str) -> Optional[Decimal]:
    return None if value is None else _decimal(value, field_name=field_name)


def _mapping_value(source: Mapping[str, Any], *names: str) -> Any:
    normalized = {
        str(key).lower().replace('-', '_'): value
        for key, value in source.items()
    }
    for name in names:
        key = name.lower().replace('-', '_')
        if key in normalized:
            return normalized[key]
    return _MISSING


def _mapping_flag(source: Mapping[str, Any], *names: str) -> bool:
    value = _mapping_value(source, *names)
    if value is _MISSING:
        return False
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'y'}
    return bool(value)


def _string_set(value: Any) -> frozenset[str]:
    if value is None or value is _MISSING:
        return frozenset()
    if isinstance(value, str):
        return frozenset((item for item in (value.strip(),) if item))
    if isinstance(value, Iterable):
        return frozenset(item for item in (_text(entry) for entry in value) if item)
    text = _text(value)
    return frozenset((text,)) if text else frozenset()


def _first_text(source: Mapping[str, Any], *names: str) -> Optional[str]:
    value = _mapping_value(source, *names)
    return None if value is _MISSING else _text(value)


def _property_values(obj: Any) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for prop in getattr(obj, 'properties', ()) or ():
        name = _text(getattr(prop, 'name', None))
        value = _text(getattr(prop, 'value', None))
        if name and value:
            values.setdefault(name.lower().replace('_', '-'), []).append(value)
    return values


def _property_first(obj: Any, *names: str) -> Optional[str]:
    values = _property_values(obj)
    for name in names:
        candidates = values.get(name.lower().replace('_', '-'))
        if candidates:
            return candidates[0]
    return None


def _component_delivery_batch(component: Component) -> str:
    return (
        _property_first(
            component,
            'cdx:batch:delivery',
            'cdx:batch:delivery-batch',
            'batch:delivery',
            'delivery-batch',
            'delivery_batch',
        )
        or _text(component.group)
        or 'default'
    )


def _component_subpackage(component: Component) -> str:
    return (
        _property_first(
            component,
            'cdx:batch:subpackage',
            'cdx:batch:package',
            'batch:subpackage',
            'subpackage',
            'package-id',
        )
        or _text(component.name)
        or _text(component.bom_ref.value if component.bom_ref else None)
        or 'unnamed'
    )


def _component_lot(component: Component) -> Optional[str]:
    return (
        _property_first(
            component,
            'cdx:batch:lot',
            'cdx:batch:lot-id',
            'batch:lot',
            'lot',
            'lot-id',
        )
        or _text(component.version)
    )


def _component_quantity(component: Component) -> Decimal:
    raw = _property_first(
        component,
        'cdx:batch:quantity',
        'batch:quantity',
        'quantity',
        'qty',
    )
    return Decimal('1') if raw is None else _decimal(raw, field_name='component quantity')


def _component_evidence_refs(component: Component) -> frozenset[str]:
    refs = set()
    for prop in getattr(component, 'properties', ()) or ():
        name = (_text(getattr(prop, 'name', None)) or '').lower().replace('_', '-')
        if name in {
            'cdx:batch:evidence',
            'cdx:batch:certificate',
            'batch:evidence',
            'batch:certificate',
            'certificate',
            'evidence-ref',
        }:
            value = _text(getattr(prop, 'value', None))
            if value:
                refs.add(value)
    evidence = component.evidence
    if evidence is not None:
        for identity in evidence.identity:
            value = _text(identity.concluded_value)
            if value and identity.field != IdentityField.NAME and identity.field != 'name':
                refs.add(value)
    return frozenset(refs)


def _single_evidence_ref(component: Component) -> Optional[str]:
    refs = _component_evidence_refs(component)
    return next(iter(refs)) if len(refs) == 1 else None


def _component_to_batch_entry(component: Component) -> 'BatchEntry':
    lot = _component_lot(component)
    return BatchEntry(
        delivery_batch=_component_delivery_batch(component),
        subpackage=_component_subpackage(component),
        quantity=_component_quantity(component),
        lots=frozenset((lot,)) if lot else frozenset(),
        evidence_refs=_component_evidence_refs(component),
    )


def _coerce_batch_entry(value: Any, *, default_delivery_batch: Optional[str] = None) -> 'BatchEntry':
    if isinstance(value, BatchEntry):
        return value
    if isinstance(value, Component):
        return _component_to_batch_entry(value)
    if not isinstance(value, Mapping):
        raise TypeError(f'unsupported batch entry {value!r}')

    delivery_batch = _first_text(
        value,
        'delivery_batch',
        'deliveryBatch',
        'delivery',
        'order',
        'order_id',
        'shipment',
        'batch',
        'batch_number',
    ) or default_delivery_batch or 'default'
    subpackage = _first_text(
        value,
        'subpackage',
        'subpackage_id',
        'subpackageId',
        'packaging',
        'packaging_id',
        'package',
        'package_id',
        'packageId',
        'serial',
        'serial_number',
        'item',
        'id',
        'name',
    )
    if subpackage is None:
        raise ValueError(f'batch entry has no sub-package identifier: {value!r}')

    raw_quantity = _mapping_value(
        value,
        'quantity',
        'qty',
        'count',
        'amount',
        'declared_quantity',
        'declaredQuantity',
        'units',
    )
    quantity = (
        Decimal('1') if raw_quantity is _MISSING or raw_quantity is None
        else _decimal(raw_quantity, field_name='quantity')
    )
    lots = _string_set(_mapping_value(value, 'lots', 'lot_ids', 'lotIds'))
    if not lots:
        lot = _first_text(value, 'lot', 'lot_id', 'lotId', 'lot_number', 'lotNumber', 'batch_lot')
        lots = frozenset((lot,)) if lot else frozenset()
    evidence_refs = _string_set(_mapping_value(
        value,
        'evidence_refs',
        'evidence',
        'certificates',
        'certificate',
        'record',
        'record_id',
        'proof',
        'refs',
    ))
    return BatchEntry(
        delivery_batch=delivery_batch,
        subpackage=subpackage,
        quantity=quantity,
        lots=lots,
        evidence_refs=evidence_refs,
        source=_first_text(value, 'source', 'document', 'document_id', 'order_id'),
    )


def _looks_like_batch_entry(value: Mapping[str, Any]) -> bool:
    return any(
        _mapping_value(value, name) is not _MISSING
        for name in (
            'subpackage', 'subpackage_id', 'subpackageId',
            'package', 'package_id', 'packageId',
            'packaging', 'packaging_id', 'serial', 'serial_number',
        )
    )


def _iter_grouped_batch_entries(delivery_batch: str, group: Any) -> Iterable['BatchEntry']:
    if isinstance(group, Mapping):
        if _looks_like_batch_entry(group):
            yield _coerce_batch_entry(group, default_delivery_batch=delivery_batch)
            return
        for subpackage, quantity in group.items():
            if isinstance(quantity, Mapping):
                member = dict(quantity)
                member.setdefault('subpackage', subpackage)
            else:
                member = {'subpackage': subpackage, 'quantity': quantity}
            yield _coerce_batch_entry(member, default_delivery_batch=delivery_batch)
        return
    if isinstance(group, Iterable) and not isinstance(group, (str, bytes)):
        for member in group:
            yield _coerce_batch_entry(member, default_delivery_batch=delivery_batch)
        return
    yield _coerce_batch_entry({'subpackage': group}, default_delivery_batch=delivery_batch)


def _iter_batch_entries(source: Any) -> Iterable['BatchEntry']:
    if source is None:
        return
    if isinstance(source, BatchList):
        yield from source.entries
        return
    if isinstance(source, (Component, BatchEntry)):
        yield _coerce_batch_entry(source)
        return
    components = getattr(source, 'components', None)
    if components is not None and not isinstance(source, Mapping):
        yield from _iter_batch_entries(components)
        return
    if isinstance(source, Mapping):
        wrapped = _mapping_value(source, 'entries', 'batch_entries', 'batchEntries', 'items')
        if wrapped is not _MISSING:
            yield from _iter_batch_entries(wrapped)
            return
        batch = _first_text(source, 'delivery_batch', 'deliveryBatch', 'delivery', 'order', 'batch')
        packages = _mapping_value(source, 'packages', 'subpackages', 'members')
        if batch is not None and packages is not _MISSING:
            yield from _iter_grouped_batch_entries(batch, packages)
            return
        batches = _mapping_value(source, 'delivery_batches', 'deliveryBatches', 'batches', 'orders')
        if batches is not _MISSING:
            for batch in batches if isinstance(batches, Iterable) and not isinstance(batches, Mapping) else (batches,):
                yield from _iter_batch_entries(batch)
            return
        if _looks_like_batch_entry(source):
            yield _coerce_batch_entry(source)
            return
        for delivery_batch, group in source.items():
            yield from _iter_grouped_batch_entries(str(delivery_batch), group)
        return
    if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
        for entry in source:
            yield from _iter_batch_entries(entry)
        return
    raise TypeError(f'unsupported batch list source {source!r}')


@dataclass(frozen=True, init=False)
class BatchEntry:
    """One concrete sub-package in the independent batch list."""

    delivery_batch: str
    subpackage: str
    quantity: Decimal = Decimal('1')
    lots: frozenset[str] = field(default_factory=frozenset)
    evidence_refs: frozenset[str] = field(default_factory=frozenset)
    source: Optional[str] = None

    def __init__(
        self,
        *,
        delivery_batch: str,
        subpackage: str,
        quantity: Any = 1,
        lots: Any = None,
        lot: Optional[str] = None,
        evidence_refs: Any = None,
        source: Optional[str] = None,
    ) -> None:
        object.__setattr__(self, 'delivery_batch', delivery_batch)
        object.__setattr__(self, 'subpackage', subpackage)
        object.__setattr__(self, 'quantity', quantity)
        object.__setattr__(self, 'lots', _string_set(lots) | _string_set(lot))
        object.__setattr__(self, 'evidence_refs', evidence_refs)
        object.__setattr__(self, 'source', source)
        self.__post_init__()

    def __post_init__(self) -> None:
        delivery_batch = _text(self.delivery_batch) or 'default'
        subpackage = _text(self.subpackage)
        if subpackage is None:
            raise ValueError('subpackage must not be empty')
        object.__setattr__(self, 'delivery_batch', delivery_batch)
        object.__setattr__(self, 'subpackage', subpackage)
        object.__setattr__(self, 'quantity', _decimal(self.quantity, field_name='quantity'))
        object.__setattr__(self, 'lots', _string_set(self.lots))
        object.__setattr__(self, 'evidence_refs', _string_set(self.evidence_refs))

    @property
    def lot(self) -> Optional[str]:
        """The single lot number, if exactly one was supplied."""
        return next(iter(self.lots)) if len(self.lots) == 1 else None

    @property
    def package(self) -> str:
        return self.subpackage


class BatchList:
    """Independent, authoritative list of delivery batches and sub-packages."""

    def __init__(self, entries: Any = None) -> None:
        self._entries = tuple(_iter_batch_entries(entries))

    @property
    def entries(self) -> tuple[BatchEntry, ...]:
        return self._entries

    @classmethod
    def from_components(cls, components: Iterable[Component]) -> 'BatchList':
        """Build a batch list from CycloneDX components and their ``cdx:batch:*`` properties."""
        return cls(components)

    @classmethod
    def from_bom(cls, bom: Any) -> 'BatchList':
        return cls(bom)

    def __iter__(self) -> Iterable[BatchEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


def _scope_packages(value: Mapping[str, Any]) -> frozenset[str]:
    packages = _string_set(_mapping_value(
        value,
        'packages',
        'subpackages',
        'subpackage_ids',
        'package_ids',
        'packageId',
    ))
    if packages:
        return packages
    package = _first_text(
        value,
        'package',
        'subpackage',
        'package_id',
        'subpackage_id',
        'packaging',
        'packaging_id',
    )
    return frozenset((package,)) if package else frozenset()


def _scope_to_entry(value: Any) -> 'ReviewScopeEntry':
    if isinstance(value, ReviewScopeEntry):
        return value
    if isinstance(value, ComponentEvidence):
        return _scope_from_evidence(value)
    if not isinstance(value, Mapping):
        raise TypeError(f'unsupported review scope entry {value!r}')

    evidence_ref = _first_text(
        value,
        'evidence_ref',
        'evidenceRef',
        'certificate',
        'certificate_ref',
        'record',
        'record_id',
        'proof',
        'ref',
        'id',
    ) or 'UNSPECIFIED'
    lots = _string_set(_mapping_value(value, 'lots', 'lot_ids', 'lotIds'))
    if not lots:
        lot = _first_text(value, 'lot', 'lot_id', 'lotId', 'lot_number', 'batch_lot', 'batch')
        lots = frozenset((lot,)) if lot else frozenset()
    delivery_batches = _string_set(_mapping_value(
        value,
        'delivery_batches',
        'deliveryBatches',
        'orders',
        'order_ids',
    ))
    if not delivery_batches:
        delivery_batch = _first_text(value, 'delivery_batch', 'deliveryBatch', 'delivery', 'shipment')
        delivery_batches = frozenset((delivery_batch,)) if delivery_batch else frozenset()
    raw_quantity = _mapping_value(
        value,
        'quantity',
        'qty',
        'covered_quantity',
        'scope_quantity',
        'eligible_quantity',
        'units',
    )
    return ReviewScopeEntry(
        evidence_ref=evidence_ref,
        packages=_scope_packages(value),
        lots=lots,
        delivery_batches=delivery_batches,
        quantity=(
            None if raw_quantity is _MISSING or raw_quantity is None
            else _decimal(raw_quantity, field_name='scope quantity')
        ),
        consolidated=_mapping_flag(value, 'consolidated', 'merged', 'aggregate', 'declaration'),
        source=_first_text(value, 'source', 'document', 'document_id'),
    )


def _scope_from_evidence(evidence: ComponentEvidence) -> 'ReviewScopeEntry':
    identities = [
        (identity.field, _text(identity.concluded_value))
        for identity in evidence.identity
    ]
    evidence_ref = next(
        (
            text
            for field, text in identities
            if text and field != IdentityField.NAME and field != 'name'
        ),
        next((text for _, text in identities if text), 'UNSPECIFIED'),
    )
    packages = frozenset(
        text
        for field, text in identities
        if text and text != evidence_ref and (field == IdentityField.NAME or field == 'name')
    )
    return ReviewScopeEntry(evidence_ref=evidence_ref, packages=packages)

def _looks_like_scope_entry(value: Mapping[str, Any]) -> bool:
    return any(
        _mapping_value(value, name) is not _MISSING
        for name in (
            'evidence_ref', 'evidenceRef', 'certificate', 'certificate_ref', 'record', 'record_id',
            'proof', 'ref', 'packages', 'package', 'subpackage', 'lot', 'delivery_batch', 'quantity',
        )
    )


def _iter_grouped_scope_entries(evidence_ref: str, group: Any) -> Iterable['ReviewScopeEntry']:
    if isinstance(group, Mapping):
        if _looks_like_scope_entry(group):
            member = dict(group)
            member.setdefault('evidence_ref', evidence_ref)
            yield _scope_to_entry(member)
            return
        for package, value in group.items():
            if isinstance(value, Mapping):
                member = dict(value)
                member.setdefault('package', package)
            else:
                member = {'package': package, 'quantity': value}
            member.setdefault('evidence_ref', evidence_ref)
            yield _scope_to_entry(member)
        return
    if isinstance(group, Iterable) and not isinstance(group, (str, bytes)):
        for member in group:
            if isinstance(member, str):
                yield _scope_to_entry({'evidence_ref': evidence_ref, 'package': member})
            elif isinstance(member, Mapping):
                data = dict(member)
                data.setdefault('evidence_ref', evidence_ref)
                yield _scope_to_entry(data)
            else:
                yield _scope_to_entry({'evidence_ref': evidence_ref, 'package': member})
        return
    yield _scope_to_entry({'evidence_ref': evidence_ref, 'package': group})


def _iter_scope_entries(source: Any) -> Iterable['ReviewScopeEntry']:
    if source is None:
        return
    if isinstance(source, ReviewScope):
        yield from source.entries
        return
    if isinstance(source, (ReviewScopeEntry, ComponentEvidence)):
        yield _scope_to_entry(source)
        return
    components = getattr(source, 'components', None)
    if components is not None and not isinstance(source, Mapping):
        for component in components:
            if getattr(component, 'evidence', None) is not None:
                yield from _iter_scope_entries(component.evidence)
        return
    if isinstance(source, Mapping):
        wrapped = _mapping_value(
            source,
            'entries',
            'scope',
            'review_scope',
            'reviewScope',
            'records',
            'items',
        )
        if wrapped is not _MISSING:
            yield from _iter_scope_entries(wrapped)
            return
        if _looks_like_scope_entry(source):
            yield _scope_to_entry(source)
            return
        for evidence_ref, group in source.items():
            yield from _iter_grouped_scope_entries(str(evidence_ref), group)
        return
    if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
        for entry in source:
            yield from _iter_scope_entries(entry)
        return
    raise TypeError(f'unsupported review scope source {source!r}')


@dataclass(frozen=True, init=False)
class ReviewScopeEntry:
    """A record's claim about which lots, delivery batches, or packages it covers."""

    evidence_ref: str
    packages: frozenset[str] = field(default_factory=frozenset)
    lots: frozenset[str] = field(default_factory=frozenset)
    delivery_batches: frozenset[str] = field(default_factory=frozenset)
    quantity: Optional[Decimal] = None
    consolidated: bool = False
    source: Optional[str] = None

    def __init__(
        self,
        *,
        evidence_ref: str,
        packages: Any = None,
        package: Optional[str] = None,
        lots: Any = None,
        lot: Optional[str] = None,
        delivery_batches: Any = None,
        delivery_batch: Optional[str] = None,
        quantity: Any = None,
        consolidated: bool = False,
        source: Optional[str] = None,
    ) -> None:
        object.__setattr__(self, 'evidence_ref', evidence_ref)
        object.__setattr__(self, 'packages', _string_set(packages) | _string_set(package))
        object.__setattr__(self, 'lots', _string_set(lots) | _string_set(lot))
        object.__setattr__(self, 'delivery_batches', _string_set(delivery_batches) | _string_set(delivery_batch))
        object.__setattr__(self, 'quantity', quantity)
        object.__setattr__(self, 'consolidated', consolidated)
        object.__setattr__(self, 'source', source)
        self.__post_init__()

    def __post_init__(self) -> None:
        evidence_ref = _text(self.evidence_ref)
        if evidence_ref is None:
            raise ValueError('evidence_ref must not be empty')
        object.__setattr__(self, 'evidence_ref', evidence_ref)
        object.__setattr__(self, 'packages', _string_set(self.packages))
        object.__setattr__(self, 'lots', _string_set(self.lots))
        object.__setattr__(self, 'delivery_batches', _string_set(self.delivery_batches))
        object.__setattr__(self, 'quantity', _optional_decimal(self.quantity, field_name='scope quantity'))

    @property
    def lot(self) -> Optional[str]:
        return next(iter(self.lots)) if len(self.lots) == 1 else None

    @property
    def delivery_batch(self) -> Optional[str]:
        return next(iter(self.delivery_batches)) if len(self.delivery_batches) == 1 else None

    @property
    def package(self) -> Optional[str]:
        return next(iter(self.packages)) if len(self.packages) == 1 else None


class ReviewScope:
    """The review scope expressed by one or more quality records."""

    def __init__(self, entries: Any = None) -> None:
        self._entries = tuple(_iter_scope_entries(entries))

    @property
    def entries(self) -> tuple[ReviewScopeEntry, ...]:
        return self._entries

    @classmethod
    def from_evidence(cls, evidence: Any) -> 'ReviewScope':
        """Build a scope from CycloneDX component evidence objects."""
        return cls(evidence)

    @classmethod
    def from_bom(cls, bom: Any) -> 'ReviewScope':
        """Build a scope from evidence attached to the components of a CycloneDX BOM."""
        return cls(bom)

    def __iter__(self) -> Iterable[ReviewScopeEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


def _witness_to_entry(value: Any) -> 'PhysicalWitnessEntry':
    if isinstance(value, PhysicalWitnessEntry):
        return value
    if isinstance(value, Occurrence):
        return PhysicalWitnessEntry(
            subpackage=_text(value.bom_ref.value) or _text(value.location),
            location=_text(value.location),
        )
    if isinstance(value, ComponentEvidence):
        raise TypeError('a ComponentEvidence may contain several occurrences; pass them explicitly')
    if isinstance(value, Component):
        evidence = value.evidence
        if evidence is None or not evidence.occurrences:
            return PhysicalWitnessEntry(
                subpackage=_component_subpackage(value),
                delivery_batch=_component_delivery_batch(value),
                lot=_component_lot(value),
                evidence_ref=_single_evidence_ref(value),
                quantity=_component_quantity(value),
            )
        return PhysicalWitnessEntry(
            subpackage=_component_subpackage(value),
            delivery_batch=_component_delivery_batch(value),
            lot=_component_lot(value),
            evidence_ref=_single_evidence_ref(value),
            quantity=_component_quantity(value),
            location=next(iter(evidence.occurrences)).location,
        )
    if not isinstance(value, Mapping):
        raise TypeError(f'unsupported physical witness {value!r}')

    raw_quantity = _mapping_value(value, 'quantity', 'qty', 'count', 'observed_quantity', 'units')
    return PhysicalWitnessEntry(
        subpackage=_first_text(
            value,
            'subpackage',
            'subpackage_id',
            'packaging',
            'package',
            'package_id',
            'serial',
            'serial_number',
            'id',
        ),
        delivery_batch=_first_text(value, 'delivery_batch', 'deliveryBatch', 'delivery', 'order', 'batch'),
        lot=_first_text(value, 'lot', 'lot_id', 'lotId', 'lot_number', 'batch_lot'),
        evidence_ref=_first_text(
            value,
            'evidence_ref',
            'evidenceRef',
            'certificate',
            'certificate_ref',
            'record',
            'record_id',
            'proof',
            'ref',
        ),
        quantity=(
            None if raw_quantity is _MISSING or raw_quantity is None
            else _decimal(raw_quantity, field_name='witness quantity')
        ),
        location=_first_text(value, 'location', 'path', 'uri', 'witness'),
    )


def _looks_like_witness_entry(value: Mapping[str, Any]) -> bool:
    return any(
        _mapping_value(value, name) is not _MISSING
        for name in (
            'subpackage', 'package', 'package_id', 'serial', 'serial_number', 'delivery_batch',
            'lot', 'lot_id', 'evidence_ref', 'certificate', 'quantity', 'location',
        )
    )


def _iter_grouped_witness_entries(package: str, group: Any) -> Iterable['PhysicalWitnessEntry']:
    if isinstance(group, Mapping):
        member = dict(group)
        member.setdefault('package', package)
        yield _witness_to_entry(member)
        return
    if isinstance(group, Iterable) and not isinstance(group, (str, bytes)):
        for member in group:
            if isinstance(member, Mapping):
                data = dict(member)
                data.setdefault('package', package)
                yield _witness_to_entry(data)
            else:
                yield _witness_to_entry({'package': package, 'location': member})
        return
    yield _witness_to_entry({'package': package, 'location': group})


def _iter_witness_entries(source: Any) -> Iterable['PhysicalWitnessEntry']:
    if source is None:
        return
    if isinstance(source, PhysicalWitness):
        yield from source.entries
        return
    if isinstance(source, ComponentEvidence):
        for occurrence in source.occurrences:
            yield _witness_to_entry(occurrence)
        return
    if isinstance(source, Component):
        evidence = source.evidence
        if evidence is None or not evidence.occurrences:
            yield _witness_to_entry(source)
            return
        for occurrence in evidence.occurrences:
            yield PhysicalWitnessEntry(
                subpackage=_text(occurrence.bom_ref.value) or _component_subpackage(source),
                delivery_batch=_component_delivery_batch(source),
                lot=_component_lot(source),
                evidence_ref=_single_evidence_ref(source),
                quantity=_component_quantity(source),
                location=_text(occurrence.location),
            )
        return
    if isinstance(source, (PhysicalWitnessEntry, Occurrence)):
        yield _witness_to_entry(source)
        return
    components = getattr(source, 'components', None)
    if components is not None and not isinstance(source, Mapping):
        for component in components:
            yield from _iter_witness_entries(component)
        return
    if isinstance(source, Mapping):
        wrapped = _mapping_value(source, 'entries', 'witnesses', 'occurrences', 'items')
        if wrapped is not _MISSING:
            yield from _iter_witness_entries(wrapped)
            return
        if _looks_like_witness_entry(source):
            yield _witness_to_entry(source)
            return
        for package, group in source.items():
            yield from _iter_grouped_witness_entries(str(package), group)
        return
    if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
        for entry in source:
            yield from _iter_witness_entries(entry)
        return
    raise TypeError(f'unsupported physical witness source {source!r}')


@dataclass(frozen=True, init=False)
class PhysicalWitnessEntry:
    """A concrete sub-package observed during physical verification."""

    subpackage: Optional[str] = None
    delivery_batch: Optional[str] = None
    lot: Optional[str] = None
    evidence_ref: Optional[str] = None
    quantity: Optional[Decimal] = None
    location: Optional[str] = None

    def __init__(
        self,
        *,
        subpackage: Optional[str] = None,
        package: Optional[str] = None,
        delivery_batch: Optional[str] = None,
        lot: Optional[str] = None,
        evidence_ref: Optional[str] = None,
        quantity: Any = None,
        location: Optional[str] = None,
    ) -> None:
        object.__setattr__(self, 'subpackage', subpackage or package)
        object.__setattr__(self, 'delivery_batch', delivery_batch)
        object.__setattr__(self, 'lot', lot)
        object.__setattr__(self, 'evidence_ref', evidence_ref)
        object.__setattr__(self, 'quantity', quantity)
        object.__setattr__(self, 'location', location)
        self.__post_init__()

    def __post_init__(self) -> None:
        object.__setattr__(self, 'subpackage', _text(self.subpackage))
        object.__setattr__(self, 'delivery_batch', _text(self.delivery_batch))
        object.__setattr__(self, 'lot', _text(self.lot))
        object.__setattr__(self, 'evidence_ref', _text(self.evidence_ref))
        object.__setattr__(self, 'quantity', _optional_decimal(self.quantity, field_name='witness quantity'))
        object.__setattr__(self, 'location', _text(self.location))

    @property
    def package(self) -> Optional[str]:
        return self.subpackage


class PhysicalWitness:
    """Physical observations of concrete sub-packages."""

    def __init__(self, entries: Any = None) -> None:
        self._entries = tuple(_iter_witness_entries(entries))

    @property
    def entries(self) -> tuple[PhysicalWitnessEntry, ...]:
        return self._entries

    @classmethod
    def from_evidence(cls, evidence: Any) -> 'PhysicalWitness':
        return cls(evidence)

    @classmethod
    def from_occurrences(cls, occurrences: Iterable[Occurrence]) -> 'PhysicalWitness':
        return cls(occurrences)

    @classmethod
    def from_bom(cls, bom: Any) -> 'PhysicalWitness':
        """Build physical witnesses from component evidence occurrences in a CycloneDX BOM."""
        return cls(bom)

    def __iter__(self) -> Iterable[PhysicalWitnessEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


@dataclass(frozen=True)
class VerificationIssue:
    """A non-fatal finding produced during reconciliation."""

    code: str
    message: str
    severity: IssueSeverity = IssueSeverity.WARNING
    delivery_batch: Optional[str] = None
    subpackage: Optional[str] = None
    evidence_ref: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            'code': self.code,
            'message': self.message,
            'severity': self.severity.value,
            'delivery_batch': self.delivery_batch,
            'subpackage': self.subpackage,
            'evidence_ref': self.evidence_ref,
        }


@dataclass(frozen=True)
class SubpackageCoverage:
    """Coverage assigned to one concrete sub-package."""

    delivery_batch: str
    subpackage: str
    declared_quantity: Decimal
    eligible_quantity: Decimal
    covered_quantity: Decimal
    status: CoverageStatus
    lots: frozenset[str] = field(default_factory=frozenset)
    evidence_refs: tuple[str, ...] = ()
    allocated_evidence_ref: Optional[str] = None

    @property
    def covered(self) -> bool:
        return self.covered_quantity > 0

    @property
    def fully_covered(self) -> bool:
        return self.covered_quantity >= self.declared_quantity

    @property
    def qualified_quantity(self) -> Decimal:
        return self.eligible_quantity

    def as_dict(self) -> dict[str, Any]:
        return {
            'delivery_batch': self.delivery_batch,
            'subpackage': self.subpackage,
            'lots': sorted(self.lots),
            'declared_quantity': str(self.declared_quantity),
            'eligible_quantity': str(self.eligible_quantity),
            'covered_quantity': str(self.covered_quantity),
            'status': self.status.value,
            'evidence_refs': list(self.evidence_refs),
            'allocated_evidence_ref': self.allocated_evidence_ref,
        }


@dataclass(frozen=True)
class DeliveryCoverage:
    """Aggregated valid coverage for a delivery batch."""

    delivery_batch: str
    declared_quantity: Decimal
    eligible_quantity: Decimal
    covered_quantity: Decimal
    subpackages: tuple[SubpackageCoverage, ...] = ()

    @property
    def coverage_ratio(self) -> Decimal:
        return _ZERO if self.declared_quantity == 0 else self.covered_quantity / self.declared_quantity

    @property
    def effective_coverage(self) -> Decimal:
        return self.covered_quantity

    @property
    def valid_coverage(self) -> Decimal:
        return self.covered_quantity

    def as_dict(self) -> dict[str, Any]:
        return {
            'delivery_batch': self.delivery_batch,
            'declared_quantity': str(self.declared_quantity),
            'eligible_quantity': str(self.eligible_quantity),
            'covered_quantity': str(self.covered_quantity),
            'coverage_ratio': str(self.coverage_ratio),
            'subpackages': [subpackage.as_dict() for subpackage in self.subpackages],
        }


@dataclass(frozen=True)
class CoverageChange:
    """Coverage change for a delivery batch present in both reports."""

    delivery_batch: str
    before: Decimal
    after: Decimal

    @property
    def delta(self) -> Decimal:
        return self.after - self.before


@dataclass(frozen=True)
class CoverageDelta:
    """Difference between two verification reports."""

    changes: tuple[CoverageChange, ...]
    added_delivery_batches: tuple[str, ...] = ()
    removed_delivery_batches: tuple[str, ...] = ()

    @property
    def decreased(self) -> tuple[str, ...]:
        """Delivery batches whose effective coverage decreased, in report order."""
        return tuple(change.delivery_batch for change in self.changes if change.delta < 0)

    @property
    def decreased_delivery_batches(self) -> tuple[str, ...]:
        return self.decreased

    @property
    def decreased_batches(self) -> tuple[str, ...]:
        return self.decreased

    @property
    def increased_batches(self) -> tuple[str, ...]:
        return self.increased

    @property
    def added_batches(self) -> tuple[str, ...]:
        return self.added_delivery_batches

    @property
    def removed_batches(self) -> tuple[str, ...]:
        return self.removed_delivery_batches

    @property
    def increased(self) -> tuple[str, ...]:
        return tuple(change.delivery_batch for change in self.changes if change.delta > 0)

    def describe(self) -> str:
        if not self.decreased:
            return 'No existing delivery batch lost effective coverage.'
        details = ', '.join(
            f'{change.delivery_batch} ({change.before} -> {change.after})'
            for change in self.changes
            if change.delta < 0
        )
        return f'Effective coverage decreased for {len(self.decreased)} delivery batches: {details}.'

    def as_dict(self) -> dict[str, Any]:
        return {
            'decreased': list(self.decreased),
            'increased': list(self.increased),
            'added_delivery_batches': list(self.added_delivery_batches),
            'removed_delivery_batches': list(self.removed_delivery_batches),
            'changes': [
                {
                    'delivery_batch': change.delivery_batch,
                    'before': str(change.before),
                    'after': str(change.after),
                    'delta': str(change.delta),
                }
                for change in self.changes
            ],
        }


@dataclass(frozen=True)
class BatchVerificationReport:
    """Result of reconciling a batch list, review scope, and physical witness."""

    delivery_batches: Mapping[str, DeliveryCoverage]
    subpackages: tuple[SubpackageCoverage, ...]
    issues: tuple[VerificationIssue, ...]
    evidence_allocations: Mapping[str, Decimal]
    unconfirmed_quantity: Decimal = _ZERO

    @property
    def declared_quantity(self) -> Decimal:
        return sum((batch.declared_quantity for batch in self.delivery_batches.values()), _ZERO)

    @property
    def eligible_quantity(self) -> Decimal:
        return sum((batch.eligible_quantity for batch in self.delivery_batches.values()), _ZERO)

    @property
    def covered_quantity(self) -> Decimal:
        return sum((batch.covered_quantity for batch in self.delivery_batches.values()), _ZERO)

    @property
    def effective_coverage(self) -> Decimal:
        return self.covered_quantity

    @property
    def coverage_by_batch(self) -> Mapping[str, DeliveryCoverage]:
        return self.delivery_batches

    def coverage_for(self, delivery_batch: str) -> Optional[DeliveryCoverage]:
        return self.delivery_batches.get(delivery_batch)

    def compare(self, previous: 'BatchVerificationReport') -> CoverageDelta:
        """Compare this report with an earlier report."""
        changes = tuple(
            CoverageChange(
                delivery_batch=delivery_batch,
                before=previous.delivery_batches[delivery_batch].covered_quantity,
                after=coverage.covered_quantity,
            )
            for delivery_batch, coverage in self.delivery_batches.items()
            if delivery_batch in previous.delivery_batches
        )
        return CoverageDelta(
            changes=changes,
            added_delivery_batches=tuple(
                delivery_batch
                for delivery_batch in self.delivery_batches
                if delivery_batch not in previous.delivery_batches
            ),
            removed_delivery_batches=tuple(
                delivery_batch
                for delivery_batch in previous.delivery_batches
                if delivery_batch not in self.delivery_batches
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            'declared_quantity': str(self.declared_quantity),
            'eligible_quantity': str(self.eligible_quantity),
            'covered_quantity': str(self.covered_quantity),
            'unconfirmed_quantity': str(self.unconfirmed_quantity),
            'delivery_batches': {
                delivery_batch: coverage.as_dict()
                for delivery_batch, coverage in self.delivery_batches.items()
            },
            'evidence_allocations': {
                evidence_ref: str(quantity)
                for evidence_ref, quantity in self.evidence_allocations.items()
            },
            'issues': [issue.as_dict() for issue in self.issues],
        }

    def render(self) -> str:
        lines = [
            f'Declared: {self.declared_quantity}; eligible: {self.eligible_quantity}; '
            f'covered: {self.covered_quantity}; unconfirmed: {self.unconfirmed_quantity}'
        ]
        for delivery_batch, coverage in self.delivery_batches.items():
            lines.append(
                f'{delivery_batch}: {coverage.covered_quantity}/{coverage.declared_quantity} '
                f'({coverage.coverage_ratio:.2%})'
            )
            for subpackage in coverage.subpackages:
                lines.append(
                    f'  {subpackage.subpackage}: {subpackage.covered_quantity}/'
                    f'{subpackage.declared_quantity} {subpackage.status.value}'
                )
        if self.issues:
            lines.append('Issues:')
            lines.extend(f'  [{issue.severity.value}] {issue.code}: {issue.message}' for issue in self.issues)
        return '\n'.join(lines)


@dataclass
class _ManifestPackage:
    delivery_batch: str
    subpackage: str
    declared_quantity: Decimal
    lots: frozenset[str]
    evidence_refs: frozenset[str]
    first_index: int


def _merge_manifest_entries(entries: Sequence[BatchEntry]) -> tuple[list[_ManifestPackage], list[VerificationIssue]]:
    packages: dict[tuple[str, str], _ManifestPackage] = {}
    issues: list[VerificationIssue] = []
    for index, entry in enumerate(entries):
        key = (entry.delivery_batch, entry.subpackage)
        existing = packages.get(key)
        if existing is None:
            packages[key] = _ManifestPackage(
                delivery_batch=entry.delivery_batch,
                subpackage=entry.subpackage,
                declared_quantity=entry.quantity,
                lots=entry.lots,
                evidence_refs=entry.evidence_refs,
                first_index=index,
            )
            continue
        if entry.quantity != existing.declared_quantity:
            issues.append(VerificationIssue(
                code='quantity-conflict',
                message=(
                    f'Overlapping registrations for {entry.subpackage!r} declare '
                    f'{existing.declared_quantity} and {entry.quantity}; the larger value is used once.'
                ),
                delivery_batch=entry.delivery_batch,
                subpackage=entry.subpackage,
            ))
        issues.append(VerificationIssue(
            code='overlapping-registration',
            message=(
                f'Sub-package {entry.subpackage!r} was registered more than once; '
                'overlapping quantities are not added together.'
            ),
            severity=IssueSeverity.INFO,
            delivery_batch=entry.delivery_batch,
            subpackage=entry.subpackage,
        ))
        existing.declared_quantity = max(existing.declared_quantity, entry.quantity)
        existing.lots = existing.lots | entry.lots
        existing.evidence_refs = existing.evidence_refs | entry.evidence_refs
    return list(packages.values()), issues


def _scope_budgets(
    scope_entries: Sequence[ReviewScopeEntry],
) -> tuple[dict[str, Optional[Decimal]], dict[str, int], list[VerificationIssue]]:
    grouped: dict[str, list[ReviewScopeEntry]] = {}
    for entry in scope_entries:
        grouped.setdefault(entry.evidence_ref, []).append(entry)
    budgets: dict[str, Optional[Decimal]] = {}
    counts: dict[str, int] = {}
    issues: list[VerificationIssue] = []
    for evidence_ref, entries in grouped.items():
        counts[evidence_ref] = len(entries)
        quantities = {entry.quantity for entry in entries if entry.quantity is not None}
        budgets[evidence_ref] = max(quantities) if quantities else None
        if len(entries) > 1:
            issues.append(VerificationIssue(
                code='reused-evidence',
                message=(
                    f'Record {evidence_ref!r} is referenced {len(entries)} times; '
                    'its quantity is shared rather than multiplied.'
                ),
                severity=IssueSeverity.INFO,
                evidence_ref=evidence_ref,
            ))
        if len(quantities) > 1:
            issues.append(VerificationIssue(
                code='evidence-quantity-conflict',
                message=(
                    f'Record {evidence_ref!r} declares different review quantities {sorted(quantities)}; '
                    f'{budgets[evidence_ref]} is used as the shared upper bound.'
                ),
                evidence_ref=evidence_ref,
            ))
    return budgets, counts, issues


def _scope_matches(scope: ReviewScopeEntry, package: _ManifestPackage) -> bool:
    if scope.packages and package.subpackage not in scope.packages:
        return False
    if scope.lots and not (scope.lots & package.lots):
        return False
    if scope.delivery_batches and package.delivery_batch not in scope.delivery_batches:
        return False
    return True


def _scope_is_unconfirmed(scope: ReviewScopeEntry, matches: Sequence[_ManifestPackage]) -> bool:
    if scope.consolidated and len(matches) != 1:
        return True
    if not scope.packages and len(matches) != 1:
        return True
    return scope.consolidated and scope.quantity is None


def _scope_candidates(
    packages: Sequence[_ManifestPackage],
    scope_entries: Sequence[ReviewScopeEntry],
) -> tuple[dict[tuple[str, str], list[ReviewScopeEntry]], list[ReviewScopeEntry], list[VerificationIssue]]:
    candidates: dict[tuple[str, str], list[ReviewScopeEntry]] = {}
    unconfirmed: list[ReviewScopeEntry] = []
    issues: list[VerificationIssue] = []
    known_packages = {package.subpackage for package in packages}
    for scope in scope_entries:
        matches = [package for package in packages if _scope_matches(scope, package)]
        if not matches:
            if scope.packages:
                unknown = sorted(scope.packages - known_packages)
                if unknown:
                    issues.append(VerificationIssue(
                        code='unknown-scope-target',
                        message=f'Review scope {scope.evidence_ref!r} names unknown sub-packages {unknown}.',
                        evidence_ref=scope.evidence_ref,
                    ))
            continue
        if _scope_is_unconfirmed(scope, matches):
            unconfirmed.append(scope)
            for package in matches:
                issues.append(VerificationIssue(
                    code='consolidated-unconfirmed',
                    message=(
                        f'Record {scope.evidence_ref!r} is a consolidated declaration that cannot '
                        f'confirm a quantity for sub-package {package.subpackage!r}.'
                    ),
                    delivery_batch=package.delivery_batch,
                    subpackage=package.subpackage,
                    evidence_ref=scope.evidence_ref,
                ))
            continue
        for package in matches:
            key = (package.delivery_batch, package.subpackage)
            candidates.setdefault(key, []).append(scope)
    return candidates, unconfirmed, issues


def _witness_matches(witness: PhysicalWitnessEntry, package: _ManifestPackage) -> bool:
    if witness.subpackage is not None and witness.subpackage != package.subpackage:
        return False
    if witness.delivery_batch is not None and witness.delivery_batch != package.delivery_batch:
        return False
    if witness.lot is not None and witness.lot not in package.lots:
        return False
    return True


def _match_witnesses(
    packages: Sequence[_ManifestPackage],
    witnesses: Sequence[PhysicalWitnessEntry],
) -> tuple[dict[tuple[str, str], list[PhysicalWitnessEntry]], list[VerificationIssue]]:
    matches: dict[tuple[str, str], list[PhysicalWitnessEntry]] = {}
    issues: list[VerificationIssue] = []
    known_packages = {package.subpackage for package in packages}
    for witness in witnesses:
        candidates = [package for package in packages if _witness_matches(witness, package)]
        if not candidates:
            if witness.subpackage and witness.subpackage not in known_packages:
                issues.append(VerificationIssue(
                    code='unknown-witness-target',
                    message=f'Physical witness {witness.location or witness.subpackage!r} has no batch-list entry.',
                    subpackage=witness.subpackage,
                    evidence_ref=witness.evidence_ref,
                ))
            continue
        if witness.subpackage is None and len(candidates) != 1:
            for package in candidates:
                issues.append(VerificationIssue(
                    code='witness-unconfirmed',
                    message=(
                        'Physical witness identifies a lot/batch but not one concrete sub-package; '
                        'no quantity is assigned from it.'
                    ),
                    delivery_batch=package.delivery_batch,
                    subpackage=package.subpackage,
                ))
            continue
        for package in candidates:
            key = (package.delivery_batch, package.subpackage)
            matches.setdefault(key, []).append(witness)
    return matches, issues


def _dedupe_witnesses(
    witness_matches: Mapping[tuple[str, str], list[PhysicalWitnessEntry]],
) -> tuple[dict[tuple[str, str], list[PhysicalWitnessEntry]], list[VerificationIssue]]:
    deduped: dict[tuple[str, str], list[PhysicalWitnessEntry]] = {}
    issues: list[VerificationIssue] = []
    for key, entries in witness_matches.items():
        seen: dict[tuple[Optional[str], Optional[str], Optional[str]], PhysicalWitnessEntry] = {}
        for entry in entries:
            identity = (entry.evidence_ref, entry.location, entry.subpackage)
            existing = seen.get(identity)
            if existing is None:
                seen[identity] = entry
                continue
            max_quantity = max(
                quantity for quantity in (existing.quantity, entry.quantity) if quantity is not None
                ) if existing.quantity is not None or entry.quantity is not None else None
            seen[identity] = PhysicalWitnessEntry(
                subpackage=existing.subpackage,
                delivery_batch=existing.delivery_batch,
                lot=existing.lot,
                evidence_ref=existing.evidence_ref,
                quantity=max_quantity,
                location=existing.location,
            )
            issues.append(VerificationIssue(
                code='duplicate-witness',
                message=f'Witness for {key[1]!r} was recorded more than once; it is counted once.',
                severity=IssueSeverity.INFO,
                delivery_batch=key[0],
                subpackage=key[1],
                evidence_ref=entry.evidence_ref,
            ))
        deduped[key] = list(seen.values())
    return deduped, issues


def _valid_witness_quantity(
    witnesses: Sequence[PhysicalWitnessEntry],
    scope_refs: Sequence[str],
    declared_quantity: Decimal,
) -> Optional[Decimal]:
    relevant = [
        witness
        for witness in witnesses
        if witness.evidence_ref is None or witness.evidence_ref in scope_refs
    ]
    if not relevant:
        return None
    quantities = [witness.quantity for witness in relevant if witness.quantity is not None]
    if not quantities:
        return declared_quantity
    return min(declared_quantity, max(quantities))


def _ordered_scope_candidates(scopes: Sequence[ReviewScopeEntry]) -> list[ReviewScopeEntry]:
    return sorted(
        scopes,
        key=lambda scope: (
            0 if scope.packages else 1,
            scope.consolidated,
        ),
    )


def _allocate_package(
    package: _ManifestPackage,
    scopes: Sequence[ReviewScopeEntry],
    witnesses: Sequence[PhysicalWitnessEntry],
    budgets: dict[str, Optional[Decimal]],
) -> tuple[SubpackageCoverage, Optional[VerificationIssue]]:
    scope_refs = tuple(scope.evidence_ref for scope in scopes)
    witness_quantity = _valid_witness_quantity(witnesses, scope_refs, package.declared_quantity)
    if package.declared_quantity == 0:
        return SubpackageCoverage(
            delivery_batch=package.delivery_batch,
            subpackage=package.subpackage,
            declared_quantity=_ZERO,
            eligible_quantity=_ZERO,
            covered_quantity=_ZERO,
            status=CoverageStatus.ZERO_QUANTITY,
            lots=package.lots,
            evidence_refs=scope_refs,
        ), None
    if not scopes:
        return SubpackageCoverage(
            delivery_batch=package.delivery_batch,
            subpackage=package.subpackage,
            declared_quantity=package.declared_quantity,
            eligible_quantity=_ZERO,
            covered_quantity=_ZERO,
            status=CoverageStatus.UNSCOPED,
            lots=package.lots,
            evidence_refs=(),
        ), None
    if witness_quantity is None:
        return SubpackageCoverage(
            delivery_batch=package.delivery_batch,
            subpackage=package.subpackage,
            declared_quantity=package.declared_quantity,
            eligible_quantity=_ZERO,
            covered_quantity=_ZERO,
            status=CoverageStatus.UNWITNESSED,
            lots=package.lots,
            evidence_refs=scope_refs,
        ), None

    eligible = min(package.declared_quantity, witness_quantity)
    for scope in _ordered_scope_candidates(scopes):
        budget = budgets[scope.evidence_ref]
        available = eligible if budget is None else min(eligible, budget)
        if available <= 0:
            continue
        if budget is not None:
            budgets[scope.evidence_ref] = budget - available
        status = CoverageStatus.VERIFIED if available >= package.declared_quantity else CoverageStatus.PARTIAL
        return SubpackageCoverage(
            delivery_batch=package.delivery_batch,
            subpackage=package.subpackage,
            declared_quantity=package.declared_quantity,
            eligible_quantity=eligible,
            covered_quantity=available,
            status=status,
            lots=package.lots,
            evidence_refs=scope_refs,
            allocated_evidence_ref=scope.evidence_ref,
        ), None

    return SubpackageCoverage(
        delivery_batch=package.delivery_batch,
        subpackage=package.subpackage,
        declared_quantity=package.declared_quantity,
        eligible_quantity=eligible,
        covered_quantity=_ZERO,
        status=CoverageStatus.EVIDENCE_EXHAUSTED,
        lots=package.lots,
        evidence_refs=scope_refs,
    ), VerificationIssue(
        code='evidence-exhausted',
        message=(
            f'Qualified quantity for {package.subpackage!r} is {eligible}, but its record coverage '
            'is already exhausted by other sub-packages.'
        ),
        delivery_batch=package.delivery_batch,
        subpackage=package.subpackage,
        evidence_ref=scope_refs[0] if scope_refs else None,
    )


def _delivery_coverages(subpackages: Sequence[SubpackageCoverage]) -> dict[str, DeliveryCoverage]:
    grouped: dict[str, list[SubpackageCoverage]] = {}
    for subpackage in subpackages:
        grouped.setdefault(subpackage.delivery_batch, []).append(subpackage)
    return {
        delivery_batch: DeliveryCoverage(
            delivery_batch=delivery_batch,
            declared_quantity=sum((item.declared_quantity for item in items), _ZERO),
            eligible_quantity=sum((item.eligible_quantity for item in items), _ZERO),
            covered_quantity=sum((item.covered_quantity for item in items), _ZERO),
            subpackages=tuple(items),
        )
        for delivery_batch, items in grouped.items()
    }


def _unconfirmed_quantity(
    packages: Sequence[_ManifestPackage],
    subpackages: Sequence[SubpackageCoverage],
) -> Decimal:
    unconfirmed_keys = {
        (item.delivery_batch, item.subpackage)
        for item in subpackages
        if item.status is CoverageStatus.CONSOLIDATED_UNCONFIRMED
    }
    return sum(
        (package.declared_quantity for package in packages
         if (package.delivery_batch, package.subpackage) in unconfirmed_keys),
        _ZERO,
    )


def _apply_unconfirmed_status(
    coverages: Sequence[SubpackageCoverage],
    unconfirmed_scopes: Sequence[ReviewScopeEntry],
    packages: Sequence[_ManifestPackage],
) -> list[SubpackageCoverage]:
    if not unconfirmed_scopes:
        return list(coverages)
    unconfirmed_keys = {
        (package.delivery_batch, package.subpackage)
        for package in packages
        if any(_scope_matches(scope, package) for scope in unconfirmed_scopes)
    }
    return [
        SubpackageCoverage(
            delivery_batch=coverage.delivery_batch,
            subpackage=coverage.subpackage,
            declared_quantity=coverage.declared_quantity,
            eligible_quantity=_ZERO,
            covered_quantity=_ZERO,
            status=CoverageStatus.CONSOLIDATED_UNCONFIRMED,
            lots=coverage.lots,
            evidence_refs=coverage.evidence_refs,
        )
        if (coverage.delivery_batch, coverage.subpackage) in unconfirmed_keys
        and coverage.status is CoverageStatus.UNSCOPED
        else coverage
        for coverage in coverages
    ]


class BatchNumberVerifier:
    """Reconcile batch quantities against review scope and physical witness."""

    def __init__(
        self,
        batch_list: Any,
        review_scope: Any = None,
        physical_witness: Any = None,
    ) -> None:
        self.batch_list = batch_list if isinstance(batch_list, BatchList) else BatchList(batch_list)
        self.review_scope = review_scope if isinstance(review_scope, ReviewScope) else ReviewScope(review_scope)
        self.physical_witness = (
            physical_witness
            if isinstance(physical_witness, PhysicalWitness)
            else PhysicalWitness(physical_witness)
        )

    def verify(
        self,
        batch_list: Any = None,
        review_scope: Any = None,
        physical_witness: Any = None,
    ) -> BatchVerificationReport:
        """Run reconciliation, optionally overriding one or more inputs for this call."""
        selected_batch_list = self.batch_list if batch_list is None else BatchList(batch_list)
        selected_scope = self.review_scope if review_scope is None else ReviewScope(review_scope)
        selected_witness = (
            self.physical_witness
            if physical_witness is None
            else PhysicalWitness(physical_witness)
        )

        packages, manifest_issues = _merge_manifest_entries(selected_batch_list.entries)
        initial_budgets, _, scope_issues = _scope_budgets(selected_scope.entries)
        budgets = dict(initial_budgets)
        candidates, unconfirmed_scopes, candidate_issues = _scope_candidates(packages, selected_scope.entries)
        witness_matches, witness_issues = _match_witnesses(packages, selected_witness.entries)
        witness_matches, duplicate_issues = _dedupe_witnesses(witness_matches)

        coverages: list[SubpackageCoverage] = []
        allocation_issues: list[VerificationIssue] = []
        for package in sorted(packages, key=lambda item: item.first_index):
            key = (package.delivery_batch, package.subpackage)
            coverage, issue = _allocate_package(
                package,
                candidates.get(key, ()),
                witness_matches.get(key, ()),
                budgets,
            )
            coverages.append(coverage)
            if issue is not None:
                allocation_issues.append(issue)

        coverages = _apply_unconfirmed_status(coverages, unconfirmed_scopes, packages)
        delivery_batches = _delivery_coverages(coverages)
        unconfirmed = _unconfirmed_quantity(packages, coverages)
        evidence_allocations: dict[str, Decimal] = {}
        for evidence_ref, initial in initial_budgets.items():
            if initial is None:
                evidence_allocations[evidence_ref] = sum(
                    (coverage.covered_quantity for coverage in coverages
                     if coverage.allocated_evidence_ref == evidence_ref),
                    _ZERO,
                )
            else:
                remaining = budgets[evidence_ref]
                evidence_allocations[evidence_ref] = max(
                    _ZERO,
                    initial - (remaining if remaining is not None else initial),
                )

        issues = tuple(
            manifest_issues
            + scope_issues
            + candidate_issues
            + witness_issues
            + duplicate_issues
            + allocation_issues
        )
        return BatchVerificationReport(
            delivery_batches=delivery_batches,
            subpackages=tuple(coverages),
            issues=issues,
            evidence_allocations=evidence_allocations,
            unconfirmed_quantity=unconfirmed,
        )
BatchVerifier = BatchNumberVerifier
BatchChecker = BatchNumberVerifier
BatchNumberChecker = BatchNumberVerifier
BatchReconciler = BatchNumberVerifier
LotVerifier = BatchNumberVerifier


def verify_batches(
    batch_list: Any,
    review_scope: Any = None,
    physical_witness: Any = None,
) -> BatchVerificationReport:
    """Convenience wrapper around :class:`BatchNumberVerifier`."""
    return BatchNumberVerifier(batch_list, review_scope, physical_witness).verify()


def check_batches(
    batch_list: Any,
    review_scope: Any = None,
    physical_witness: Any = None,
) -> BatchVerificationReport:
    return verify_batches(batch_list, review_scope, physical_witness)


def reconcile_batches(
    batch_list: Any,
    review_scope: Any = None,
    physical_witness: Any = None,
) -> BatchVerificationReport:
    """Alias of :func:`verify_batches`."""
    return verify_batches(batch_list, review_scope, physical_witness)
