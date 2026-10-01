"""Structured reports describing where validated values came from."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

ValidationPath = tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class ValidationInputPath:
    """A source path in the input that supplied a field value."""

    path: ValidationPath
    type: Literal['input'] = 'input'


@dataclass(frozen=True, slots=True)
class DefaultSource:
    """The static default supplied a field value."""

    type: Literal['default'] = 'default'


@dataclass(frozen=True, slots=True)
class DefaultFactorySource:
    """The default factory supplied a field value."""

    type: Literal['default_factory'] = 'default_factory'


ValidationSource = ValidationInputPath | DefaultSource | DefaultFactorySource


@dataclass(frozen=True, slots=True)
class ValidationValueReport:
    """Provenance for one validated scalar or structured value."""

    sources: list[ValidationSource]
    unconsumed_aliases: list[ValidationPath] = field(default_factory=list)
    fields: dict[str, ValidationValueReport] | None = None
    items: list[ValidationValueReport | None] | None = None
    union_choice: int | None = None


@dataclass(frozen=True, slots=True)
class ValidationReport:
    """Field provenance recorded while validating one model instance."""

    fields: dict[str, ValidationValueReport]

    @classmethod
    def _from_core(cls, raw: dict[str, Any]) -> ValidationReport:
        return cls(_parse_fields(raw))


def _parse_fields(raw: dict[str, Any]) -> dict[str, ValidationValueReport]:
    fields_raw = raw.get('fields', {})
    return {name: _parse_value(value['value']) for name, value in fields_raw.items()}


def _parse_value(raw: dict[str, Any]) -> ValidationValueReport:
    sources = [_parse_source(source) for source in raw.get('sources', [])]
    fields = _parse_fields(raw) if 'fields' in raw else None
    items = (
        [_parse_value(item['value']) if item is not None else None for item in raw['items']] if 'items' in raw else None
    )
    return ValidationValueReport(
        sources=sources,
        unconsumed_aliases=[tuple(path) for path in raw.get('unconsumed_aliases', [])],
        fields=fields,
        items=items,
        union_choice=raw.get('union_choice'),
    )


def _parse_source(raw: dict[str, Any]) -> ValidationSource:
    source_type = raw['type']
    if source_type == 'input':
        return ValidationInputPath(tuple(raw['path']))
    if source_type == 'default':
        return DefaultSource()
    if source_type == 'default_factory':
        return DefaultFactorySource()
    raise ValueError(f'Unknown validation source type: {source_type!r}')


__all__ = (
    'DefaultFactorySource',
    'DefaultSource',
    'ValidationInputPath',
    'ValidationReport',
    'ValidationValueReport',
)
