"""Optional content (layers) inspection for forensic use.

The PDF specification allows a document to contain several optional content
configurations.  This module deliberately reports visibility as a three-state
value.  Missing references, cyclic expressions and unsupported view
expressions are ``unknown`` instead of being silently treated as visible or
hidden.
"""

from __future__ import annotations

import builtins
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, cast, overload

if TYPE_CHECKING:
    from ._protocols import PdfCommonDocProtocol
from .constants import StrEnum
from .generic import (
    ArrayObject,
    ContentStream,
    DictionaryObject,
    IndirectObject,
    NameObject,
    PdfObject,
    StreamObject,
    TextStringObject,
)


class OptionalContentVisibilityState(StrEnum):
    """Conditional visibility of optional content."""

    VISIBLE = "visible"
    HIDDEN = "hidden"
    UNKNOWN = "unknown"

    @property
    def visible(self) -> bool | None:
        """Return the boolean visibility, or ``None`` when it is unknown."""
        if self is OptionalContentVisibilityState.VISIBLE:
            return True
        if self is OptionalContentVisibilityState.HIDDEN:
            return False
        return None


# Short aliases are convenient when writing rules in a forensic pipeline.
VISIBLE = OptionalContentVisibilityState.VISIBLE
HIDDEN = OptionalContentVisibilityState.HIDDEN
UNKNOWN = OptionalContentVisibilityState.UNKNOWN


@dataclass(eq=False)
class OptionalContentGroup:
    """An optional content group (OCG) and the location of its original object."""

    name: str | None
    dictionary: DictionaryObject
    reference: IndirectObject | None = None
    valid: bool = True

    @property
    def object(self) -> DictionaryObject:
        """The original OCG dictionary."""
        return self.dictionary

    @property
    def ocg(self) -> DictionaryObject:
        """The original OCG dictionary."""
        return self.dictionary

    @property
    def raw(self) -> DictionaryObject:
        """The original OCG dictionary."""
        return self.dictionary

    @property
    def indirect_reference(self) -> IndirectObject | None:
        """The indirect reference to the OCG, if the object is indirect."""
        return self.reference

    def get_visibility(
        self,
        reader: PdfCommonDocProtocol,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
        *,
        event: str = "view",
    ) -> OptionalContentVisibilityReport:
        """Return this group's visibility in the requested configuration(s)."""
        return get_optional_content_visibility(
            reader,
            self,
            configuration=configuration,
            event=event,
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Return a value from the original OCG dictionary."""
        return self.dictionary.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self.dictionary[key]

    def __contains__(self, key: object) -> bool:
        return key in self.dictionary

    @property
    def type(self) -> Any:
        """The original /Type entry."""
        return self.dictionary.get("/Type")

    @property
    def intent(self) -> Any:
        """The original /Intent entry."""
        return self.dictionary.get("/Intent")

    def is_visible_in(
        self,
        reader: PdfCommonDocProtocol,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
        *,
        event: str = "view",
    ) -> bool | None:
        """Return True or False, or None when visibility is unknown."""
        report = self.get_visibility(reader, configuration=configuration, event=event)
        if configuration is not None:
            return report.visible_in(configuration)
        return report[0].visible if report else None


@dataclass(eq=False)
class OptionalContentConfiguration:
    """An optional content configuration dictionary."""

    name: str
    dictionary: DictionaryObject | None
    reference: IndirectObject | None = None
    is_default: bool = False
    index: int = 0

    @property
    def object(self) -> DictionaryObject | None:
        """The original configuration dictionary."""
        return self.dictionary

    @property
    def raw(self) -> DictionaryObject | None:
        """The original configuration dictionary."""
        return self.dictionary

    @property
    def indirect_reference(self) -> IndirectObject | None:
        """The indirect reference to the configuration, if any."""
        return self.reference

    def get(self, key: str, default: Any = None) -> Any:
        """Return a value from the original configuration dictionary."""
        if self.dictionary is None:
            return default
        return self.dictionary.get(key, default)

    def __getitem__(self, key: str) -> Any:
        if self.dictionary is None:
            raise KeyError(key)
        return self.dictionary[key]

    def __contains__(self, key: object) -> bool:
        return self.dictionary is not None and key in self.dictionary


@dataclass(eq=False)
class OptionalContentEvidence:
    """Original PDF objects that led to a visibility result.

    References are retained instead of resolved values so a caller can report
    the exact object number and generation in the source document.
    """

    ocg: DictionaryObject | None = None
    ocg_reference: IndirectObject | None = None
    property_object: PdfObject | None = None
    property_reference: IndirectObject | None = None
    property_name: str | None = None
    expression: PdfObject | None = None
    page_number: int | None = None
    source: PdfObject | None = None
    source_reference: IndirectObject | None = None
    resource: DictionaryObject | None = None
    resource_reference: IndirectObject | None = None
    content_stream: StreamObject | None = None
    content_stream_reference: IndirectObject | None = None
    content_streams: list[StreamObject] = field(default_factory=list)
    content_stream_references: list[IndirectObject] = field(default_factory=list)
    operation_index: int | None = None
    marker_index: int | None = None
    source_kind: str = "content"
    enclosing_expressions: list[PdfObject] = field(default_factory=list)

    @builtins.property
    def property(self) -> PdfObject | None:
        """The original marked-content property entry."""
        return self.property_object

    @builtins.property
    def object(self) -> PdfObject | None:
        """The original object in the PDF, preferring the OCG object."""
        return self.ocg if self.ocg is not None else self.property_object

    @builtins.property
    def indirect_reference(self) -> IndirectObject | None:
        """Alias of :attr:`reference`."""
        return self.reference

    @builtins.property
    def expression_reference(self) -> IndirectObject | None:
        """The reference to the original /OC expression object."""
        return _reference_of(self.expression) or self.property_reference

    @builtins.property
    def reference(self) -> IndirectObject | None:
        """The most specific indirect reference available."""
        return self.ocg_reference or self.property_reference or self.content_stream_reference or self.source_reference

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly summary while references stay explicit."""
        reference = self.reference
        return {
            "source_kind": self.source_kind,
            "page": self.page_number,
            "property_name": self.property_name,
            "ocg_name": self.ocg.get("/Name") if self.ocg is not None else None,
            "ocg_reference": _reference_dict(self.ocg_reference),
            "property_reference": _reference_dict(self.property_reference),
            "expression_reference": _reference_dict(self.expression_reference),
            "content_stream_reference": _reference_dict(self.content_stream_reference),
            "reference": _reference_dict(reference),
        }


@dataclass(eq=False)
class OptionalContentVisibility:
    """Visibility of one marked-content expression in one configuration."""

    state: OptionalContentVisibilityState
    configuration: OptionalContentConfiguration
    groups: list[OptionalContentGroup] = field(default_factory=list)
    expression: PdfObject | None = None
    evidence: list[OptionalContentEvidence] = field(default_factory=list)

    @property
    def group(self) -> OptionalContentGroup | None:
        """The only OCG in the expression, or ``None`` for a multi-group expression."""
        return self.groups[0] if len(self.groups) == 1 else None

    @property
    def ocg(self) -> DictionaryObject | None:
        """The original OCG dictionary for a single-group expression."""
        group = self.group
        return group.dictionary if group is not None else None

    @property
    def expression_reference(self) -> IndirectObject | None:
        """The indirect reference of the original marked-content expression."""
        return _reference_of(self.expression)

    @property
    def indirect_reference(self) -> IndirectObject | None:
        """Alias of :attr:`reference`."""
        return self.reference

    @property
    def reference(self) -> IndirectObject | None:
        """The original OCG or expression reference."""
        group = self.group
        if group is not None and group.reference is not None:
            return group.reference
        return self.expression_reference

    @property
    def name(self) -> str | None:
        """The OCG name for a single-group expression."""
        group = self.group
        return group.name if group is not None else None

    @property
    def configuration_name(self) -> str:
        """The name of the configuration used for this result."""
        return self.configuration.name

    @property
    def config_name(self) -> str:
        """Alias of :attr:`configuration_name`."""
        return self.configuration.name

    @property
    def configuration_reference(self) -> IndirectObject | None:
        """The indirect reference to the configuration dictionary."""
        return self.configuration.reference

    @property
    def visible(self) -> bool | None:
        """``True``, ``False`` or ``None`` when visibility is unknown."""
        return self.state.visible

    @property
    def is_visible(self) -> bool | None:
        """Alias of :attr:`visible`."""
        return self.visible

    @property
    def is_hidden(self) -> bool | None:
        """Whether the expression is hidden, or None when unknown."""
        return None if self.visible is None else not self.visible

    @property
    def visibility(self) -> OptionalContentVisibilityState:
        """Alias of :attr:`state`."""
        return self.state

    @property
    def config(self) -> OptionalContentConfiguration:
        """Alias of :attr:`configuration`."""
        return self.configuration

    @property
    def ocg_reference(self) -> IndirectObject | None:
        """Alias of :attr:`reference`."""
        return self.reference

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly visibility record."""
        return {
            "state": str(self.state),
            "visible": self.visible,
            "configuration": self.configuration.name,
            "configuration_reference": _reference_dict(self.configuration_reference),
            "is_default": self.configuration.is_default,
            "group_names": [group.name for group in self.groups],
            "reference": _reference_dict(self.reference),
            "evidence": [item.to_dict() for item in self.evidence],
        }


class OptionalContentVisibilityReport(list[OptionalContentVisibility]):
    """Visibility results ordered by configuration.

    The report is a normal list for compatibility, with helpers for the common
    case where a caller wants one state per configuration.
    """

    def __init__(
        self,
        values: Iterable[OptionalContentVisibility] = (),
        *,
        target: Any = None,
    ) -> None:
        super().__init__(values)
        self.target = target

    @property
    def state(self) -> OptionalContentVisibilityState:
        """A single state when all results agree, otherwise ``unknown``."""
        states = {item.state for item in self}
        if len(states) == 1:
            return next(iter(states))
        return UNKNOWN

    @property
    def visible(self) -> bool | None:
        """Whether the report is visible, or ``None`` when it is not uniform."""
        return self.state.visible

    @property
    def group(self) -> OptionalContentGroup | None:
        """The only group represented by this report, if there is exactly one."""
        groups = self.groups
        return groups[0] if len(groups) == 1 else None

    @property
    def ocg(self) -> DictionaryObject | None:
        """The dictionary of the only represented group."""
        group = self.group
        return group.dictionary if group is not None else None

    @property
    def indirect_reference(self) -> IndirectObject | None:
        """Alias of :attr:`reference`."""
        return self.reference

    @property
    def reference(self) -> IndirectObject | None:
        """The reference of the only represented group or expression."""
        group = self.group
        if group is not None and group.reference is not None:
            return group.reference
        if len(self) == 1:
            return self[0].reference
        return None

    @property
    def name(self) -> str | None:
        """The name of the only represented group."""
        group = self.group
        return group.name if group is not None else None

    @property
    def hidden(self) -> list[OptionalContentVisibility]:
        """Results whose state is explicitly hidden."""
        return [item for item in self if item.state is HIDDEN]

    @property
    def unknown(self) -> list[OptionalContentVisibility]:
        """Results whose conditional visibility could not be established."""
        return [item for item in self if item.state is UNKNOWN]

    @property
    def configurations(self) -> list[OptionalContentConfiguration]:
        """Configurations represented in this report, without duplicates."""
        seen: set[int] = set()
        result: list[OptionalContentConfiguration] = []
        for item in self:
            if id(item.configuration) not in seen:
                seen.add(id(item.configuration))
                result.append(item.configuration)
        return result

    @property
    def groups(self) -> list[OptionalContentGroup]:
        """OCGs represented in this report, without duplicates."""
        seen: set[int] = set()
        result: list[OptionalContentGroup] = []
        for item in self:
            for group in item.groups:
                if id(group) not in seen:
                    seen.add(id(group))
                    result.append(group)
        return result

    @property
    def configuration(self) -> OptionalContentConfiguration | None:
        """The only configuration represented by this report, if unique."""
        configs = self.configurations
        return configs[0] if len(configs) == 1 else None

    @property
    def configuration_name(self) -> str | None:
        """The configuration name when the report covers only one configuration."""
        config = self.configuration
        return config.name if config is not None else None

    @property
    def evidence(self) -> list[OptionalContentEvidence]:
        """All evidence records, flattened in report order."""
        result: list[OptionalContentEvidence] = []
        seen: set[int] = set()
        for item in self:
            for evidence in item.evidence:
                if id(evidence) not in seen:
                    seen.add(id(evidence))
                    result.append(evidence)
        return result

    def for_configuration(
        self,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject,
    ) -> list[OptionalContentVisibility]:
        """Return all results for one configuration."""
        return [item for item in self if _configuration_matches(item.configuration, configuration)]

    def state_for(
        self,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject,
    ) -> OptionalContentVisibilityState | None:
        """Return the first state for a configuration."""
        values = self.for_configuration(configuration)
        return values[0].state if values else None

    def visible_in(
        self,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject,
    ) -> bool | None:
        """Return a boolean, or ``None`` if the state is unknown or missing."""
        state = self.state_for(configuration)
        return None if state is None else state.visible

    def as_dict(self) -> dict[str, OptionalContentVisibilityState]:
        """Return configuration name to state for single-expression reports."""
        result: dict[str, OptionalContentVisibilityState] = {}
        for item in self:
            result.setdefault(item.configuration.name, item.state)
        return result

    @property
    def states(self) -> dict[str, OptionalContentVisibilityState]:
        """Configuration name to state for single-expression reports."""
        return self.as_dict()

    @property
    def visibility(self) -> dict[str, OptionalContentVisibilityState]:
        """Alias of :attr:`states`."""
        return self.as_dict()

    @property
    def by_configuration(self) -> dict[str, list[OptionalContentVisibility]]:
        """Group results by configuration name without dropping duplicates."""
        result: dict[str, list[OptionalContentVisibility]] = {}
        for item in self:
            result.setdefault(item.configuration.name, []).append(item)
        return result

    @property
    def default(self) -> list[OptionalContentVisibility]:
        """Results for the default configuration."""
        return [item for item in self if item.configuration.is_default]

    def to_dict(self) -> list[dict[str, Any]]:
        """Return all visibility records as JSON-friendly dictionaries."""
        return [item.to_dict() for item in self]

    def get(
        self,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject,
        default: Any = None,
    ) -> Any:
        """Return one result for a configuration, or *default* when absent."""
        values = self.for_configuration(configuration)
        if not values:
            return default
        return values[0] if len(values) == 1 else values

    @overload
    def __getitem__(self, key: int) -> OptionalContentVisibility: ...

    @overload
    def __getitem__(self, key: slice) -> list[OptionalContentVisibility]: ...

    @overload
    def __getitem__(self, key: str) -> Any: ...

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            return self.get(key)
        return super().__getitem__(key)


def _reference_dict(reference: IndirectObject | None) -> dict[str, int] | None:
    if reference is None:
        return None
    return {"idnum": reference.idnum, "generation": reference.generation}


def _resolve(obj: Any) -> Any:
    """Resolve one object level without propagating malformed references."""
    if obj is None:
        return None
    try:
        return obj.get_object()
    except Exception:
        return None


def _as_dictionary(obj: Any) -> DictionaryObject | None:
    resolved = _resolve(obj)
    return resolved if isinstance(resolved, DictionaryObject) else None


def _as_array(obj: Any) -> ArrayObject | None:
    resolved = _resolve(obj)
    return resolved if isinstance(resolved, ArrayObject) else None


def _reference_of(obj: Any) -> IndirectObject | None:
    if isinstance(obj, IndirectObject):
        return obj
    return cast(IndirectObject | None, getattr(obj, "indirect_reference", None))


def _key_from_reference(reference: IndirectObject) -> tuple[str, int, int, int]:
    return ("ref", id(reference.pdf), reference.idnum, reference.generation)


def _object_key(obj: Any) -> tuple[Any, ...] | None:
    if isinstance(obj, IndirectObject):
        return _key_from_reference(obj)
    reference = _reference_of(obj)
    if reference is not None:
        return _key_from_reference(reference)
    resolved = _resolve(obj)
    if resolved is None:
        return None
    return ("obj", id(resolved))


def _name_string(value: Any) -> str | None:
    if isinstance(value, (NameObject, TextStringObject, str)):
        return str(value)
    return None


def _bare_name(value: str) -> str:
    return value.removeprefix("/")


def _is_ocmd(dictionary: DictionaryObject) -> bool:
    return "/OCGs" in dictionary


def _looks_like_ocg(dictionary: DictionaryObject) -> bool:
    if _is_ocmd(dictionary):
        return False
    object_type = dictionary.get("/Type")
    if object_type == "/OCG":
        return True
    if object_type is not None:
        return False
    return "/Name" in dictionary


class _GroupRegistry:
    def __init__(self) -> None:
        self._groups: dict[tuple[Any, ...], OptionalContentGroup] = {}
        self._order: list[OptionalContentGroup] = []

    def add(self, entry: Any, *, force: bool = False) -> OptionalContentGroup | None:
        dictionary = _as_dictionary(entry)
        if dictionary is None:
            return None
        key = _object_key(entry)
        if key is None:
            return None
        group = self._groups.get(key)
        if group is not None:
            if group.name is None:
                group.name = _name_string(dictionary.get("/Name"))
            return group
        if not force and not _looks_like_ocg(dictionary):
            return None
        reference = _reference_of(entry)
        object_type = dictionary.get("/Type")
        group = OptionalContentGroup(
            name=_name_string(dictionary.get("/Name")),
            dictionary=dictionary,
            reference=reference,
            valid=object_type is None or object_type == "/OCG",
        )
        self._groups[key] = group
        self._order.append(group)
        return group

    def get(self, entry: Any) -> OptionalContentGroup | None:
        key = _object_key(entry)
        return self._groups.get(key) if key is not None else None

    def __iter__(self) -> Iterator[OptionalContentGroup]:
        return iter(self._order)

    def __len__(self) -> int:
        return len(self._order)


def _walk_ocg_entries(
    value: Any,
    registry: _GroupRegistry,
    *,
    force: bool = False,
    depth: int = 0,
) -> None:
    if depth > 128:
        return
    resolved = _resolve(value)
    if isinstance(resolved, ArrayObject):
        for item in resolved:
            _walk_ocg_entries(item, registry, force=force, depth=depth + 1)
        return
    dictionary = resolved if isinstance(resolved, DictionaryObject) else None
    if dictionary is None:
        return
    if _is_ocmd(dictionary):
        _walk_ocg_entries(dictionary.get("/OCGs"), registry, force=True, depth=depth + 1)
        return
    if registry.add(value, force=force) is not None:
        return
    for key in ("/OCGs", "/ON", "/OFF", "/Locked", "/Order", "/RBGroups"):
        if key in dictionary:
            _walk_ocg_entries(dictionary[key], registry, force=force, depth=depth + 1)


def _parse_oc_properties(
    reader: PdfCommonDocProtocol,
) -> tuple[DictionaryObject | None, _GroupRegistry]:
    registry = _GroupRegistry()
    catalog = cast(DictionaryObject, reader.root_object)
    oc_properties = _as_dictionary(catalog.get("/OCProperties"))
    if oc_properties is None:
        return None, registry

    _walk_ocg_entries(oc_properties.get("/OCGs"), registry, force=True)
    default = _as_dictionary(oc_properties.get("/D"))
    if default is not None:
        _walk_ocg_entries(default.get("/ON"), registry, force=True)
        _walk_ocg_entries(default.get("/OFF"), registry, force=True)
        _walk_ocg_entries(default.get("/Locked"), registry, force=True)
        _walk_ocg_entries(default.get("/Order"), registry)
        _walk_ocg_entries(default.get("/RBGroups"), registry, force=True)
        for usage in _as_array(default.get("/AS")) or ():
            usage_dictionary = _as_dictionary(usage)
            if usage_dictionary is not None:
                _walk_ocg_entries(usage_dictionary.get("/OCGs"), registry, force=True)

    for config in _as_array(oc_properties.get("/Configs")) or ():
        config_dictionary = _as_dictionary(config)
        if config_dictionary is None:
            continue
        _walk_ocg_entries(config_dictionary.get("/OCGs"), registry, force=True)
        _walk_ocg_entries(config_dictionary.get("/ON"), registry, force=True)
        _walk_ocg_entries(config_dictionary.get("/OFF"), registry, force=True)
        _walk_ocg_entries(config_dictionary.get("/Locked"), registry, force=True)
        _walk_ocg_entries(config_dictionary.get("/Order"), registry)
        _walk_ocg_entries(config_dictionary.get("/RBGroups"), registry, force=True)
        for usage in _as_array(config_dictionary.get("/AS")) or ():
            usage_dictionary = _as_dictionary(usage)
            if usage_dictionary is not None:
                _walk_ocg_entries(usage_dictionary.get("/OCGs"), registry, force=True)
    return oc_properties, registry


def _configuration_name(dictionary: DictionaryObject | None, fallback: str) -> str:
    if dictionary is not None:
        name = _name_string(dictionary.get("/Name"))
        if name is not None:
            return name
    return fallback


def _parse_configurations(
    oc_properties: DictionaryObject | None,
) -> list[OptionalContentConfiguration]:
    if oc_properties is None:
        return [
            OptionalContentConfiguration(
                name="Default",
                dictionary=None,
                is_default=True,
            )
        ]

    result: list[OptionalContentConfiguration] = []
    default_entry = oc_properties.get("/D")
    default_dictionary = _as_dictionary(default_entry)
    if default_entry is not None:
        result.append(
            OptionalContentConfiguration(
                name=_configuration_name(default_dictionary, "Default"),
                dictionary=default_dictionary,
                reference=_reference_of(default_entry),
                is_default=True,
                index=0,
            )
        )

    configs = oc_properties.get("/Configs")
    configs_array = _as_array(configs)
    if configs_array is not None:
        for config in configs_array:
            dictionary = _as_dictionary(config)
            if dictionary is None:
                continue
            result.append(
                OptionalContentConfiguration(
                    name=_configuration_name(
                        dictionary,
                        f"Configuration {len(result)}",
                    ),
                    dictionary=dictionary,
                    reference=_reference_of(config),
                    index=len(result),
                )
            )

    if not result:
        result.append(
            OptionalContentConfiguration(
                name="Default",
                dictionary=None,
                is_default=True,
            )
        )
    return result


def _configuration_matches(
    configuration: OptionalContentConfiguration,
    value: Any,
) -> bool:
    if isinstance(value, OptionalContentConfiguration):
        return configuration is value or configuration.index == value.index
    if isinstance(value, int):
        return configuration.index == value
    if isinstance(value, str):
        if configuration.name == value:
            return True
        if value.casefold() == configuration.name.casefold():
            return True
        return configuration.is_default and value.casefold() in {"default", "d", "/d"}
    if isinstance(value, DictionaryObject):
        return configuration.dictionary is value
    if isinstance(value, IndirectObject):
        return configuration.reference == value
    return False


def _configurations_for(
    all_configurations: list[OptionalContentConfiguration],
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None,
) -> list[OptionalContentConfiguration]:
    if configuration is None:
        return all_configurations
    return [item for item in all_configurations if _configuration_matches(item, configuration)]


def _resources_from(
    entry: Any,
    fallback: DictionaryObject | None = None,
) -> tuple[DictionaryObject | None, IndirectObject | None]:
    if entry is None:
        return fallback, _reference_of(fallback) if fallback is not None else None
    dictionary = _as_dictionary(entry)
    if dictionary is None:
        return None, _reference_of(entry)
    return dictionary, _reference_of(entry)


def _properties_from(
    resources: DictionaryObject | None,
) -> DictionaryObject | None:
    if resources is None:
        return None
    return _as_dictionary(resources.get("/Properties"))


def _property_entry(
    resources: DictionaryObject | None,
    property_operand: Any,
) -> tuple[PdfObject | None, str | None, PdfObject | None]:
    if isinstance(property_operand, (DictionaryObject, IndirectObject)):
        resolved = _resolve(property_operand)
        return property_operand, None, resolved
    name = _name_string(property_operand)
    if name is None:
        return property_operand, None, None
    properties = _properties_from(resources)
    if properties is None:
        return None, name, None
    if name not in properties:
        return None, name, None
    entry = properties.raw_get(name)
    return entry, name, _resolve(entry)


def _groups_in_expression(
    expression: Any,
    registry: _GroupRegistry,
    *,
    visited: set[tuple[Any, ...]] | None = None,
) -> list[OptionalContentGroup]:
    expression_key = _object_key(expression)
    if expression_key is None:
        return []
    if visited is None:
        visited = set()
    if expression_key in visited:
        return []
    visited.add(expression_key)

    group = registry.get(expression)
    if group is not None:
        return [group]
    dictionary = _as_dictionary(expression)
    if dictionary is None:
        return []
    if _looks_like_ocg(dictionary):
        registered = registry.add(expression)
        return [registered] if registered is not None else []
    if _is_ocmd(dictionary):
        result: list[OptionalContentGroup] = []
        members = _as_array(dictionary.get("/OCGs"))
        if members is not None:
            for member in members:
                for item in _groups_in_expression(member, registry, visited=visited):
                    if all(item is not existing for existing in result):
                        result.append(item)
        return result
    return []


def _expression_key(expression: Any) -> tuple[Any, ...] | None:
    return _object_key(expression)


@dataclass
class _Marker:
    evidence: OptionalContentEvidence
    expression: PdfObject | None
    groups: list[OptionalContentGroup]
    ancestors: list[_Marker] = field(default_factory=list)


class _ContentScanner:
    _MAX_FORM_DEPTH = 64
    _MAX_FORM_INVOCATIONS = 10_000
    _MAX_MARKERS = 100_000

    def __init__(
        self,
        reader: PdfCommonDocProtocol,
        registry: _GroupRegistry,
        page_number: int | None,
    ) -> None:
        self.reader = reader
        self.registry = registry
        self.page_number = page_number
        self.markers: list[_Marker] = []
        self._form_invocations = 0

    def scan(self) -> list[_Marker]:
        pages = self.reader.pages
        if self.page_number is None:
            page_numbers = range(len(pages))
        else:
            index = self.page_number
            if index < 0:
                index += len(pages)
            if index < 0 or index >= len(pages):
                raise IndexError("Page number out of range")
            page_numbers = (index,)
        for index in page_numbers:
            page = pages[index]
            resources_entry = page.get_inherited("/Resources")
            resources, resources_reference = _resources_from(resources_entry)
            contents = page.get("/Contents")
            if contents is None:
                continue
            self._scan_stream(
                contents,
                resources=resources,
                resources_reference=resources_reference,
                page_number=index,
                source=page,
                source_reference=_reference_of(page),
                source_kind="page",
                form_path=(),
                depth=0,
                inherited=(),
            )
        return self.markers

    def _scan_stream(
        self,
        contents: Any,
        *,
        resources: DictionaryObject | None,
        resources_reference: IndirectObject | None,
        page_number: int,
        source: PdfObject,
        source_reference: IndirectObject | None,
        source_kind: str,
        form_path: tuple[int, ...],
        depth: int,
        inherited: Sequence[_Marker] = (),
    ) -> None:
        if depth > self._MAX_FORM_DEPTH:
            return
        try:
            stream = ContentStream(contents, self.reader)
        except Exception:
            return
        try:
            operations = stream.operations
        except Exception:
            return
        content_streams: list[StreamObject] = []
        content_references: list[IndirectObject] = []
        resolved_contents = _resolve(contents)
        content_entries = resolved_contents if isinstance(resolved_contents, ArrayObject) else [contents]
        for content_entry in content_entries:
            resolved_entry = _resolve(content_entry)
            if isinstance(resolved_entry, StreamObject):
                content_streams.append(resolved_entry)
                reference = _reference_of(content_entry)
                if reference is not None:
                    content_references.append(reference)
        content_stream = content_streams[0] if content_streams else None
        content_reference = content_references[0] if content_references else None

        conditions: list[_Marker | None] = list(inherited)
        for operation_index, (operands, operator) in enumerate(operations):
            if operator in (b"BDC", b"BMC"):
                marker: _Marker | None = None
                if operands and _name_string(operands[0]) == "/OC":
                    property_operand = operands[1] if len(operands) > 1 else None
                    marker = self._make_marker(
                        property_operand,
                        resources=resources,
                        resources_reference=resources_reference,
                        page_number=page_number,
                        source=source,
                        source_reference=source_reference,
                        content_stream=content_stream,
                        content_stream_reference=content_reference,
                        content_streams=content_streams,
                        content_stream_references=content_references,
                        operation_index=operation_index,
                        source_kind=source_kind,
                        form_path=form_path,
                        ancestors=[item for item in conditions if item is not None],
                    )
                conditions.append(marker)
            elif operator == b"EMC":
                if conditions:
                    conditions.pop()
            elif operator == b"Do" and operands:
                form_name = _name_string(operands[0])
                if form_name is None:
                    continue
                xobjects = _as_dictionary(resources.get("/XObject")) if resources is not None else None
                if xobjects is None or form_name not in xobjects:
                    continue
                xobject_entry = xobjects.raw_get(form_name)
                xobject = _resolve(xobject_entry)
                if not isinstance(xobject, StreamObject) or xobject.get("/Subtype") != "/Form":
                    continue
                xobject_key = id(xobject)
                if xobject_key in form_path:
                    continue
                self._form_invocations += 1
                if self._form_invocations > self._MAX_FORM_INVOCATIONS:
                    continue
                if "/Resources" in xobject:
                    form_resources, form_resources_reference = _resources_from(
                        xobject.raw_get("/Resources"),
                        fallback=resources,
                    )
                else:
                    form_resources, form_resources_reference = resources, resources_reference
                self._scan_stream(
                    xobject,
                    resources=form_resources,
                    resources_reference=form_resources_reference,
                    page_number=page_number,
                    source=xobject,
                    source_reference=_reference_of(xobject_entry),
                    source_kind="form",
                    form_path=(*form_path, xobject_key),
                    depth=depth + 1,
                    inherited=tuple(item for item in conditions if item is not None),
                )

    def _make_marker(  # noqa: PLR0913
        self,
        property_operand: Any,
        *,
        resources: DictionaryObject | None,
        resources_reference: IndirectObject | None,
        page_number: int,
        source: PdfObject,
        source_reference: IndirectObject | None,
        content_stream: StreamObject | None,
        content_stream_reference: IndirectObject | None,
        content_streams: list[StreamObject],
        content_stream_references: list[IndirectObject],
        operation_index: int,
        source_kind: str,
        form_path: tuple[int, ...],
        ancestors: list[_Marker],
    ) -> _Marker:
        property_entry, property_name, expression = _property_entry(
            resources,
            property_operand,
        )
        groups = _groups_in_expression(expression, self.registry)
        if len(groups) == 1 and groups[0].reference is None:
            groups[0].reference = _reference_of(property_entry)
        evidence = OptionalContentEvidence(
            ocg=groups[0].dictionary if len(groups) == 1 else None,
            ocg_reference=groups[0].reference if len(groups) == 1 else None,
            property_object=property_entry,
            property_reference=_reference_of(property_entry),
            property_name=property_name,
            expression=expression,
            page_number=page_number,
            source=source,
            source_reference=source_reference,
            resource=resources,
            resource_reference=resources_reference,
            content_stream=content_stream,
            content_stream_reference=content_stream_reference,
            content_streams=content_streams,
            content_stream_references=content_stream_references,
            operation_index=operation_index,
            marker_index=len(self.markers),
            source_kind=source_kind,
            enclosing_expressions=[item.expression for item in ancestors],
        )
        marker = _Marker(
            evidence=evidence,
            expression=expression,
            groups=groups,
            ancestors=list(ancestors),
        )
        if len(self.markers) < self._MAX_MARKERS:
            self.markers.append(marker)
        return marker


class _VisibilityEvaluator:
    _STATE_KEYS: ClassVar[dict[str, tuple[str, str]]] = {
        "view": ("/View", "/ViewState"),
        "print": ("/Print", "/PrintState"),
        "export": ("/Export", "/ExportState"),
    }

    def __init__(
        self,
        configuration: OptionalContentConfiguration,
        registry: _GroupRegistry,
        *,
        event: str,
    ) -> None:
        self.configuration = configuration
        self.registry = registry
        self.event = event.lower().lstrip("/")
        self._group_cache: dict[tuple[Any, ...], OptionalContentVisibilityState] = {}
        self._expression_cache: dict[tuple[Any, ...], OptionalContentVisibilityState] = {}

    def expression(self, expression: Any) -> OptionalContentVisibilityState:
        key = _expression_key(expression)
        if key is None:
            return UNKNOWN
        cached = self._expression_cache.get(key)
        if cached is not None:
            return cached
        self._expression_cache[key] = UNKNOWN
        state = self._evaluate_expression(expression)
        self._expression_cache[key] = state
        return state

    def group(self, group: OptionalContentGroup) -> OptionalContentVisibilityState:
        key = _object_key(group.dictionary)
        if key is None:
            return UNKNOWN
        return self._evaluate_group(group, key, set())

    def _evaluate_expression(  # noqa: PLR0911
        self, expression: Any
    ) -> OptionalContentVisibilityState:
        if expression is None:
            return UNKNOWN
        group = self.registry.get(expression)
        if group is not None:
            key = _object_key(group.dictionary)
            return self._evaluate_group(group, key, set()) if key is not None else UNKNOWN
        dictionary = _as_dictionary(expression)
        if dictionary is None:
            return UNKNOWN
        if _looks_like_ocg(dictionary):
            group = self.registry.add(expression)
            key = _object_key(expression)
            return self._evaluate_group(group, key, set()) if group is not None and key is not None else UNKNOWN
        if not _is_ocmd(dictionary):
            return UNKNOWN

        view_expressions = dictionary.get("/VE")
        if view_expressions is not None:
            resolved = _resolve(view_expressions)
            if isinstance(resolved, ArrayObject) and len(resolved) > 0:
                return UNKNOWN
            if resolved is not None and not isinstance(resolved, (ArrayObject, type(None))):
                return UNKNOWN

        members = _as_array(dictionary.get("/OCGs"))
        if members is None:
            return UNKNOWN
        member_states = [self._evaluate_expression_with_cycle(member, set()) for member in members]
        if "/P" in dictionary:
            policy = _name_string(dictionary.get("/P"))
            if policy is None:
                return UNKNOWN
        else:
            policy = "/AllOn"
        return _apply_policy(policy, member_states)

    def _evaluate_expression_with_cycle(  # noqa: PLR0911
        self,
        expression: Any,
        active: set[tuple[Any, ...]],
    ) -> OptionalContentVisibilityState:
        key = _object_key(expression)
        if key is None or key in active:
            return UNKNOWN
        cached = self._expression_cache.get(key)
        if cached is not None:
            return cached
        dictionary = _as_dictionary(expression)
        if dictionary is None:
            return UNKNOWN
        if self.registry.get(expression) is not None or _looks_like_ocg(dictionary):
            group = self.registry.get(expression) or self.registry.add(expression)
            group_key = _object_key(group.dictionary) if group is not None else None
            if group is None or group_key is None:
                return UNKNOWN
            return self._evaluate_group(group, group_key, active)
        if not _is_ocmd(dictionary):
            return UNKNOWN
        view_expressions = dictionary.get("/VE")
        if view_expressions is not None:
            resolved = _resolve(view_expressions)
            if isinstance(resolved, ArrayObject):
                if resolved:
                    return UNKNOWN
            elif resolved is not None:
                return UNKNOWN
        members = _as_array(dictionary.get("/OCGs"))
        if members is None:
            return UNKNOWN
        active.add(key)
        try:
            states = [self._evaluate_expression_with_cycle(member, active) for member in members]
        finally:
            active.discard(key)
        if "/P" in dictionary:
            policy = _name_string(dictionary.get("/P"))
            if policy is None:
                return UNKNOWN
        else:
            policy = "/AllOn"
        state = _apply_policy(policy, states)
        self._expression_cache[key] = state
        return state

    def _evaluate_group(
        self,
        group: OptionalContentGroup,
        key: tuple[Any, ...],
        active: set[tuple[Any, ...]],
    ) -> OptionalContentVisibilityState:
        cached = self._group_cache.get(key)
        if cached is not None:
            return cached
        if key in active:
            return UNKNOWN
        active.add(key)
        try:
            raw = self._raw_group_state(group, key)
            if raw is not UNKNOWN:
                raw = self._apply_radio_groups(group, key, raw, active)
            self._group_cache[key] = raw
            return raw
        finally:
            active.discard(key)

    def _raw_group_state(
        self,
        group: OptionalContentGroup,
        key: tuple[Any, ...],
    ) -> OptionalContentVisibilityState:
        if not group.valid:
            return UNKNOWN
        config = self.configuration.dictionary
        if config is None:
            return UNKNOWN

        if "/OCGs" in config:
            controlled = _as_array(config.get("/OCGs"))
            if controlled is None:
                return UNKNOWN
            if not any(_object_key(item) == key for item in controlled):
                return UNKNOWN

        on_members = _as_array(config.get("/ON"))
        off_members = _as_array(config.get("/OFF"))
        if "/ON" in config and on_members is None:
            return UNKNOWN
        if "/OFF" in config and off_members is None:
            return UNKNOWN
        on = on_members is not None and any(_object_key(item) == key for item in on_members)
        off = off_members is not None and any(_object_key(item) == key for item in off_members)
        if on and off:
            return UNKNOWN
        if on:
            state = VISIBLE
        elif off:
            state = HIDDEN
        else:
            if "/BaseState" in config:
                base_state = _name_string(config.get("/BaseState"))
            else:
                base_state = "/ON"
            if base_state == "/ON":
                state = VISIBLE
            elif base_state == "/OFF":
                state = HIDDEN
            else:
                state = UNKNOWN

        usage = self._usage_override(group)
        return usage if usage is not None else state

    def _usage_override(  # noqa: PLR0911
        self,
        group: OptionalContentGroup,
    ) -> OptionalContentVisibilityState | None:
        config = self.configuration.dictionary
        if config is None or "/AS" not in config:
            return None
        applications = _as_array(config.get("/AS"))
        if applications is None:
            return UNKNOWN
        group_key = _object_key(group.dictionary)
        if group_key is None:
            return UNKNOWN
        matched_application = False
        application_state: OptionalContentVisibilityState | None = None
        for application in applications:
            dictionary = _as_dictionary(application)
            if dictionary is None:
                return UNKNOWN
            event = _name_string(dictionary.get("/Event"))
            if event is None:
                return UNKNOWN
            if _bare_name(event).lower() != self.event:
                continue
            categories = _as_array(dictionary.get("/Category"))
            if "/Category" in dictionary and categories is None:
                return UNKNOWN
            if categories and not any(
                _bare_name(_name_string(category) or "").lower() == self.event for category in categories
            ):
                continue
            members = dictionary.get("/OCGs")
            if members is not None:
                resolved_members = _as_array(members)
                if resolved_members is None:
                    return UNKNOWN
                if not any(_object_key(member) == group_key for member in resolved_members):
                    continue
            matched_application = True
            usage = _as_dictionary(group.dictionary.get("/Usage"))
            if usage is None:
                return UNKNOWN
            keys = self._STATE_KEYS.get(self.event)
            if keys is None:
                return UNKNOWN
            state_dictionary = _as_dictionary(usage.get(keys[0]))
            if state_dictionary is None:
                return UNKNOWN
            state_name = _name_string(state_dictionary.get(keys[1]))
            if state_name == "/ON":
                application_state = VISIBLE
            elif state_name == "/OFF":
                application_state = HIDDEN
            else:
                return UNKNOWN
        if not matched_application:
            return None
        return application_state if application_state is not None else UNKNOWN

    def _apply_radio_groups(
        self,
        group: OptionalContentGroup,
        key: tuple[Any, ...],
        raw: OptionalContentVisibilityState,
        active: set[tuple[Any, ...]],
    ) -> OptionalContentVisibilityState:
        config = self.configuration.dictionary
        if config is None:
            return raw
        radio_groups = _as_array(config.get("/RBGroups"))
        if radio_groups is None:
            return UNKNOWN if "/RBGroups" in config else raw
        result = raw
        for radio_group in radio_groups:
            members = _as_array(radio_group)
            if members is None:
                result = UNKNOWN
                continue
            member_keys = [_object_key(member) for member in members]
            if key not in member_keys:
                continue
            states = [
                raw if member_key == key else self._evaluate_member_state(member, member_key, active)
                for member, member_key in zip(members, member_keys)
            ]
            visible_count = sum(state is VISIBLE for state in states)
            has_unknown = any(state is UNKNOWN for state in states)
            if visible_count > 1:
                candidate = HIDDEN
            elif visible_count == 1 and not has_unknown:
                candidate = raw
            elif raw is HIDDEN:
                candidate = HIDDEN
            else:
                candidate = UNKNOWN
            if candidate is HIDDEN:
                return HIDDEN
            if candidate is UNKNOWN:
                result = UNKNOWN
        return result

    def _evaluate_member_state(
        self,
        member: Any,
        key: tuple[Any, ...] | None,
        active: set[tuple[Any, ...]],
    ) -> OptionalContentVisibilityState:
        if key is None:
            return UNKNOWN
        group = self.registry.get(member)
        if group is None:
            dictionary = _as_dictionary(member)
            if dictionary is None:
                return UNKNOWN
            group = self.registry.add(member, force=True)
        if group is None:
            return UNKNOWN
        if key in active:
            return UNKNOWN
        active.add(key)
        try:
            return self._raw_group_state(group, key)
        finally:
            active.discard(key)


def _apply_policy(  # noqa: PLR0911
    policy: str,
    states: Sequence[OptionalContentVisibilityState],
) -> OptionalContentVisibilityState:
    if not states:
        return UNKNOWN
    if policy == "/AllOn":
        if any(state is HIDDEN for state in states):
            return HIDDEN
        return VISIBLE if all(state is VISIBLE for state in states) else UNKNOWN
    if policy == "/AnyOn":
        if any(state is VISIBLE for state in states):
            return VISIBLE
        return HIDDEN if all(state is HIDDEN for state in states) else UNKNOWN
    if policy == "/NoneOn":
        if any(state is VISIBLE for state in states):
            return HIDDEN
        return VISIBLE if all(state is HIDDEN for state in states) else UNKNOWN
    if policy == "/AllOff":
        if any(state is VISIBLE for state in states):
            return HIDDEN
        return VISIBLE if all(state is HIDDEN for state in states) else UNKNOWN
    if policy == "/AnyOff":
        if any(state is HIDDEN for state in states):
            return VISIBLE
        return HIDDEN if all(state is VISIBLE for state in states) else UNKNOWN
    return UNKNOWN


@dataclass
class _Target:
    match_all: bool = False
    names: set[str] = field(default_factory=set)
    group_keys: set[tuple[Any, ...]] = field(default_factory=set)
    expression_keys: set[tuple[Any, ...]] = field(default_factory=set)
    expressions: dict[tuple[Any, ...], Any] = field(default_factory=dict)

    def matches_evidence(self, marker: _Marker, registry: _GroupRegistry) -> bool:
        if self.match_all:
            return True
        evidence = marker.evidence
        if evidence.property_name is not None:
            if _bare_name(evidence.property_name) in self.names:
                return True
            if evidence.property_name in self.names:
                return True
        for group in marker.groups:
            if group.name is not None and group.name in self.names:
                return True
            group_key = _object_key(group.dictionary)
            if group_key is not None and group_key in self.group_keys:
                return True
        expression_key = _expression_key(marker.expression)
        return expression_key is not None and expression_key in self.expression_keys

    def matches_group(self, group: OptionalContentGroup) -> bool:
        if self.match_all:
            return True
        if group.name is not None and group.name in self.names:
            return True
        group_key = _object_key(group.dictionary)
        return group_key is not None and group_key in self.group_keys


def _build_target(
    target: Any,
    registry: _GroupRegistry,
) -> _Target:
    result = _Target()
    if target is None or (isinstance(target, str) and target == "*"):
        result.match_all = True
        return result
    values: Iterable[Any]
    if isinstance(target, (str, bytes, DictionaryObject, IndirectObject, OptionalContentGroup)):
        values = (target,)
    elif isinstance(target, Sequence):
        values = target
    else:
        values = (target,)
    for value in values:
        if isinstance(value, OptionalContentGroup):
            key = _object_key(value.dictionary)
            if key is not None:
                result.group_keys.add(key)
            if value.name is not None:
                result.names.add(value.name)
            continue
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            result.names.add(value)
            result.names.add(_bare_name(value))
            continue
        if isinstance(value, (DictionaryObject, IndirectObject)):
            dictionary = _as_dictionary(value)
            if dictionary is None:
                expression_key = _expression_key(value)
                if expression_key is not None:
                    result.expression_keys.add(expression_key)
                    result.expressions[expression_key] = value
                continue
            if _is_ocmd(dictionary) or not _looks_like_ocg(dictionary):
                expression_key = _expression_key(value)
                if expression_key is not None:
                    result.expression_keys.add(expression_key)
                    result.expressions[expression_key] = value
                if _is_ocmd(dictionary):
                    _walk_ocg_entries(dictionary.get("/OCGs"), registry, force=True)
                continue
            group = registry.add(value)
            if group is None:
                continue
            key = _object_key(value)
            if key is not None:
                result.group_keys.add(key)
            if group.name is not None:
                result.names.add(group.name)
    return result


def _group_evidence(group: OptionalContentGroup) -> OptionalContentEvidence:
    return OptionalContentEvidence(
        ocg=group.dictionary,
        ocg_reference=group.reference,
        expression=group.dictionary,
        source=group.dictionary,
        source_reference=group.reference,
        source_kind="ocg",
    )


def get_optional_content_groups(
    reader: PdfCommonDocProtocol,
) -> list[OptionalContentGroup]:
    """Return every OCG in the document, including groups hidden by default."""
    _, registry = _parse_oc_properties(reader)
    _ContentScanner(reader, registry, None).scan()
    return list(registry)


def get_optional_content_group(
    reader: PdfCommonDocProtocol,
    identifier: Any,
) -> OptionalContentGroup | None:
    """Find an OCG by name, dictionary, or indirect reference."""
    groups = get_optional_content_groups(reader)
    if isinstance(identifier, OptionalContentGroup):
        identifier = identifier.dictionary
    if isinstance(identifier, str):
        bare = _bare_name(identifier)
        for group in groups:
            if group.name is not None and _bare_name(group.name) == bare:
                return group
        return None
    key = _object_key(identifier)
    if key is None:
        return None
    for group in groups:
        if _object_key(group.dictionary) == key:
            return group
    return None


def get_visible_optional_content_groups(
    reader: PdfCommonDocProtocol,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None = None,
    *,
    event: str = "view",
) -> list[OptionalContentGroup]:
    """Return only groups whose state is known to be visible.

    Unknown states are deliberately excluded.  The complete inventory remains
    available through :func:`get_optional_content_groups`.
    """
    oc_properties, registry = _parse_oc_properties(reader)
    _ContentScanner(reader, registry, None).scan()
    configurations = _configurations_for(
        _parse_configurations(oc_properties),
        configuration,
    )
    if not configurations:
        return []
    evaluator = _VisibilityEvaluator(configurations[0], registry, event=event)
    return [group for group in registry if evaluator.group(group) is VISIBLE]


def get_optional_content_configurations(
    reader: PdfCommonDocProtocol,
) -> list[OptionalContentConfiguration]:
    """Return the default and alternate optional content configurations."""
    oc_properties, _ = _parse_oc_properties(reader)
    return _parse_configurations(oc_properties)


def get_optional_content_visibility(
    reader: PdfCommonDocProtocol,
    target: Any = None,
    page: int | Any | None = None,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None = None,
    *,
    page_number: int | None = None,
    event: str = "view",
    name: str | None = None,
    marker: str | None = None,
    ocg: Any = None,
    ocg_name: str | None = None,
    config: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None = None,
) -> OptionalContentVisibilityReport:
    """Report conditional visibility for marked content or an OCG.

    ``target`` may be an OCG name, an object-number reference, an OCG
    dictionary, a marked-content property name such as ``/ReviewStamp``, or
    ``None`` to inspect everything.  A page may be supplied as a zero-based
    page number or a page object; if it is omitted, all pages and nested form
    XObjects are searched.

    Each result is produced for every requested optional content configuration.
    The state is ``visible``, ``hidden`` or ``unknown``.  ``unknown`` is used
    for unresolved groups, unsupported expressions and malformed
    configuration entries; it is never folded into either boolean state.

    The evidence attached to each result retains object references to the OCG,
    the ``/Properties`` entry, the resource dictionary and the content stream.
    """
    if page_number is not None and page is None:
        page = page_number
    if target is None:
        target = name if name is not None else marker if marker is not None else ocg if ocg is not None else ocg_name
    if configuration is None:
        configuration = config

    oc_properties, registry = _parse_oc_properties(reader)
    all_configurations = _parse_configurations(oc_properties)
    configurations = _configurations_for(all_configurations, configuration)
    target_spec = _build_target(target, registry)

    page_index: int | None
    if page is None:
        page_index = None
    elif isinstance(page, int):
        page_index = page
    else:
        page_index = getattr(page, "page_number", None)
        if page_index is None:
            raise TypeError("page must be a page number or a PageObject")

    markers = _ContentScanner(reader, registry, page_index).scan()
    selected: list[_Marker] = [marker for marker in markers if target_spec.matches_evidence(marker, registry)]

    # Aggregate marker results by expression.  For a name lookup this preserves
    # an OCMD expression as one result instead of reporting only its members.
    expression_results: dict[
        tuple[Any, ...],
        tuple[
            PdfObject | None,
            list[OptionalContentGroup],
            list[OptionalContentEvidence],
            list[PdfObject | None],
        ],
    ] = {}
    group_results: dict[
        tuple[Any, ...],
        tuple[OptionalContentGroup, list[OptionalContentEvidence]],
    ] = {}

    for marker_item in selected:
        evidence = marker_item.evidence
        named_groups = [
            group for group in marker_item.groups if group.name is not None and group.name in target_spec.names
        ]
        if named_groups and not target_spec.match_all:
            for group in named_groups:
                key = _object_key(group.dictionary)
                if key is None:
                    continue
                _, evidence_list = group_results.setdefault(key, (group, []))
                if evidence not in evidence_list:
                    evidence_list.append(evidence)
            continue

        expression_key = _expression_key(marker_item.expression)
        if expression_key is None:
            expression_key = ("unresolved", id(evidence))
        ancestor_expressions: list[PdfObject | None] = [item.expression for item in marker_item.ancestors]
        result_key = (
            expression_key,
            tuple(_expression_key(value) for value in ancestor_expressions),
        )
        expression, groups, evidence_list, _stored_ancestors = expression_results.setdefault(
            result_key,
            (marker_item.expression, marker_item.groups, [], ancestor_expressions),
        )
        if evidence not in evidence_list:
            evidence_list.append(evidence)
        if not groups:
            groups.extend(group for group in marker_item.groups if all(group is not existing for existing in groups))

    represented_expressions = {key[0] for key in expression_results}
    for expression_key, expression in target_spec.expressions.items():
        if expression_key in represented_expressions:
            continue
        expression_results[(expression_key, ())] = (
            expression,
            _groups_in_expression(expression, registry),
            [],
            [],
        )

    # A group lookup must remain useful even when no content stream references
    # the group (for example an OCG that is hidden by default).  Avoid adding a
    # second record when an expression result already represents the group.
    represented_groups = {
        group_key
        for _, groups, _, _ in expression_results.values()
        for group in groups
        if (group_key := _object_key(group.dictionary)) is not None
    }
    for group in registry:
        if not target_spec.matches_group(group):
            continue
        key = _object_key(group.dictionary)
        if key is None or key in represented_groups:
            continue
        group_results.setdefault(key, (group, []))

    report = OptionalContentVisibilityReport(target=target)
    for config_item in configurations:
        evaluator = _VisibilityEvaluator(config_item, registry, event=event)
        for expression, groups, evidence_list, ancestor_expressions in expression_results.values():
            state = evaluator.expression(expression)
            for ancestor_expression in ancestor_expressions:
                state = _combine_and(state, evaluator.expression(ancestor_expression))
            report.append(
                OptionalContentVisibility(
                    state=state,
                    configuration=config_item,
                    groups=list(groups),
                    expression=expression,
                    evidence=list(evidence_list),
                )
            )
        for group, evidence_list in group_results.values():
            selected_evidence = evidence_list or [_group_evidence(group)]
            report.append(
                OptionalContentVisibility(
                    state=evaluator.group(group),
                    configuration=config_item,
                    groups=[group],
                    expression=group.dictionary,
                    evidence=list(selected_evidence),
                )
            )
    return report


def _combine_and(
    left: OptionalContentVisibilityState,
    right: OptionalContentVisibilityState,
) -> OptionalContentVisibilityState:
    if left is HIDDEN or right is HIDDEN:
        return HIDDEN
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    return VISIBLE


def get_optional_content_state(
    reader: PdfCommonDocProtocol,
    target: Any,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
    *,
    page: int | Any | None = None,
    event: str = "view",
) -> OptionalContentVisibilityState:
    """Return one state, or ``unknown`` when no result can be established."""
    report = get_optional_content_visibility(
        reader,
        target,
        page=page,
        configuration=configuration,
        event=event,
    )
    return report[0].state if report else UNKNOWN


def find_optional_content(
    reader: PdfCommonDocProtocol,
    target: Any = None,
    page: int | Any | None = None,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None = None,
    *,
    event: str = "view",
) -> OptionalContentVisibilityReport:
    """Alias of :func:`get_optional_content_visibility`."""
    return get_optional_content_visibility(
        reader,
        target,
        page=page,
        configuration=configuration,
        event=event,
    )


def get_ocg_visibility(
    reader: PdfCommonDocProtocol,
    target: Any = None,
    page: int | Any | None = None,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None = None,
    *,
    event: str = "view",
) -> OptionalContentVisibilityReport:
    """Alias of :func:`get_optional_content_visibility`."""
    return get_optional_content_visibility(
        reader,
        target,
        page=page,
        configuration=configuration,
        event=event,
    )


def is_optional_content_visible(
    reader: PdfCommonDocProtocol,
    target: Any,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
    *,
    page: int | Any | None = None,
    event: str = "view",
) -> bool | None:
    """Return True/False, or None when conditional visibility is unknown."""
    state = get_optional_content_state(
        reader,
        target,
        configuration=configuration,
        page=page,
        event=event,
    )
    return state.visible


def get_marked_content_visibility(
    reader: PdfCommonDocProtocol,
    target: Any = None,
    page: int | Any | None = None,
    configuration: str | int | OptionalContentConfiguration | DictionaryObject | IndirectObject | None = None,
    *,
    event: str = "view",
) -> OptionalContentVisibilityReport:
    """Alias of :func:`get_optional_content_visibility`."""
    return get_optional_content_visibility(
        reader,
        target,
        page=page,
        configuration=configuration,
        event=event,
    )


class OptionalContent:
    """Convenience facade for optional content inspection."""

    def __init__(self, reader: PdfCommonDocProtocol) -> None:
        self.reader = reader

    @property
    def groups(self) -> list[OptionalContentGroup]:
        """All OCGs, including hidden ones."""
        return get_optional_content_groups(self.reader)

    @property
    def configurations(self) -> list[OptionalContentConfiguration]:
        """Default and alternate configurations."""
        return get_optional_content_configurations(self.reader)

    @property
    def evidence(self) -> list[OptionalContentEvidence]:
        """Evidence for every group, including hidden groups."""
        return self.visibility().evidence

    def get_groups(self) -> list[OptionalContentGroup]:
        """Alias of :attr:`groups`."""
        return self.groups

    def get_configurations(self) -> list[OptionalContentConfiguration]:
        """Alias of :attr:`configurations`."""
        return self.configurations

    def state(
        self,
        target: Any,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
        *,
        page: int | Any | None = None,
        event: str = "view",
    ) -> OptionalContentVisibilityState:
        """Return one optional content visibility state."""
        return get_optional_content_state(
            self.reader,
            target,
            configuration=configuration,
            page=page,
            event=event,
        )

    def visibility(
        self,
        target: Any = None,
        page: int | Any | None = None,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
        *,
        event: str = "view",
    ) -> OptionalContentVisibilityReport:
        """Alias of :func:`get_optional_content_visibility`."""
        return get_optional_content_visibility(
            self.reader,
            target,
            page=page,
            configuration=configuration,
            event=event,
        )

    def get_visibility(
        self,
        target: Any = None,
        page: int | Any | None = None,
        configuration: str | int | OptionalContentConfiguration | DictionaryObject | None = None,
        *,
        event: str = "view",
    ) -> OptionalContentVisibilityReport:
        """Alias of :func:`get_optional_content_visibility`."""
        return self.visibility(
            target,
            page=page,
            configuration=configuration,
            event=event,
        )


__all__ = [
    "HIDDEN",
    "UNKNOWN",
    "VISIBLE",
    "OptionalContent",
    "OptionalContentConfiguration",
    "OptionalContentEvidence",
    "OptionalContentGroup",
    "OptionalContentVisibility",
    "OptionalContentVisibilityReport",
    "OptionalContentVisibilityState",
    "find_optional_content",
    "get_marked_content_visibility",
    "get_ocg_visibility",
    "get_optional_content_configurations",
    "get_optional_content_group",
    "get_optional_content_groups",
    "get_optional_content_state",
    "get_optional_content_visibility",
    "get_visible_optional_content_groups",
    "is_optional_content_visible",
]
