from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any
import re

from referencing.jsonschema import ObjectSchema

from jsonschema import _keywords, _legacy_keywords, _utils
from jsonschema.exceptions import ValidationError


class IncrementalValidationError(ValueError):
    """A change set cannot be represented or applied."""


class ValidationObserver:
    def on_keyword_evaluated(
        self,
        keyword: str,
        path: tuple[str | int, ...],
        schema_path: tuple[str | int, ...],
    ) -> None:
        pass

    def on_keyword_skipped(
        self,
        keyword: str,
        path: tuple[str | int, ...],
        schema_path: tuple[str | int, ...],
    ) -> None:
        pass


class CountingValidator(ValidationObserver):
    def __init__(self) -> None:
        self.evaluated = 0
        self.skipped = 0

    @property
    def total(self) -> int:
        return self.evaluated + self.skipped

    def on_keyword_evaluated(self, keyword, path, schema_path):
        self.evaluated += 1

    def on_keyword_skipped(self, keyword, path, schema_path):
        self.skipped += 1

    def reset(self) -> None:
        self.evaluated = 0
        self.skipped = 0


def incremental_keyword(scope: str = "local") -> Callable:
    if scope not in {"local", "full"}:
        raise ValueError("scope must be either 'local' or 'full'")

    def decorate(function: Callable) -> Callable:
        function.__jsonschema_incremental_scope__ = scope
        return function

    return decorate


def full_validation_keyword(function: Callable) -> Callable:
    return incremental_keyword("full")(function)


local_keyword = incremental_keyword("local")

_SUBSCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "additionalItems",
        "additionalProperties",
        "contains",
        "definitions",
        "dependentSchemas",
        "else",
        "if",
        "items",
        "not",
        "patternProperties",
        "prefixItems",
        "properties",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    },
)
_SUBSCHEMA_ARRAY_KEYWORDS = frozenset({"allOf", "anyOf", "oneOf", "extends"})


_FORCE_KEYWORD_FUNCTIONS = frozenset(
    {
        _keywords.if_,
        _keywords.anyOf,
        _keywords.oneOf,
        _keywords.not_,
        _keywords.contains,
        _keywords.dependentSchemas,
        _keywords.unevaluatedItems,
        _keywords.unevaluatedProperties,
        _legacy_keywords.dependencies_draft3,
        _legacy_keywords.dependencies_draft4_draft6_draft7,
        _legacy_keywords.disallow_draft3,
        _legacy_keywords.type_draft3,
        _legacy_keywords.contains_draft6_draft7,
        _legacy_keywords.unevaluatedItems_draft2019,
        _legacy_keywords.unevaluatedProperties_draft2019,
    },
)

_COLLECTOR_FUNCTIONS = frozenset(
    {
        _keywords.anyOf,
        _keywords.oneOf,
        _keywords.contains,
        _keywords.unevaluatedProperties,
        _legacy_keywords.disallow_draft3,
        _legacy_keywords.type_draft3,
        _legacy_keywords.contains_draft6_draft7,
        _legacy_keywords.unevaluatedProperties_draft2019,
    },
)

_SUPPRESSED_DESCENDANT_FUNCTIONS = _COLLECTOR_FUNCTIONS | frozenset(
    {
        _keywords.unevaluatedItems,
        _keywords.unevaluatedProperties,
        _legacy_keywords.unevaluatedItems_draft2019,
    },
)

def _current_run(validator: Any):
    return _utils._INCREMENTAL_VALIDATION.get()


def _child_should_run(validator: Any, child_path: tuple[str | int, ...]) -> bool:
    run = _current_run(validator)
    if run is None or run.forced:
        return True
    if any(child_path == exact or run._starts_with(child_path, exact)
           for exact in run.zones.exact):
        return True
    for array_path, index in run.zones.suffixes.items():
        if (
            len(child_path) > len(array_path)
            and child_path[:len(array_path)] == array_path
            and isinstance(child_path[len(array_path)], int)
            and child_path[len(array_path)] >= index
        ):
            return True
    return False


def _record_container_skip(validator: Any, keyword: str,
                           path: tuple[str | int, ...],
                           schema_path: tuple[str | int, ...]) -> None:
    run = _current_run(validator)
    if run is not None and not run.forced:
        run.skipped += 1
        run.session.events.append(("skipped", keyword, path, schema_path))


def _selective_properties(validator, properties, instance, schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "object"):
        return
    current_path = run.nodes[-1].path if run is not None else ()
    for property, subschema in properties.items():
        if property not in instance:
            continue
        child_path = (*current_path, property)
        if not _child_should_run(validator, child_path):
            _record_container_skip(
                validator,
                "properties",
                child_path,
                (*run.nodes[-1].schema_path, "properties", property)
                if run is not None else (),
            )
            continue
        yield from validator.descend(
            instance[property],
            subschema,
            path=property,
            schema_path=property,
        )


def _selective_pattern_properties(validator, patternProperties, instance,
                                  schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "object"):
        return
    current_path = run.nodes[-1].path if run is not None else ()
    for pattern, subschema in patternProperties.items():
        for key, value in instance.items():
            child_path = (*current_path, key)
            if re.search(pattern, key) and not _child_should_run(
                validator,
                child_path,
            ):
                _record_container_skip(
                    validator,
                    "patternProperties",
                    child_path,
                    ("patternProperties", pattern, key),
                )
                continue
            if re.search(pattern, key):
                yield from validator.descend(
                    value,
                    subschema,
                    path=key,
                    schema_path=pattern,
                )


def _selective_additional_properties(validator, additional, instance, schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "object"):
        return
    current_path = run.nodes[-1].path if run is not None else ()
    extras = set(_utils.find_additional_properties(instance, schema))
    if not validator.is_type(additional, "object"):
        if not additional and extras:
            yield ValidationError(
                "Additional properties are not allowed (%s %s unexpected)"
                % _utils.extras_msg(sorted(extras, key=str)),
            )
        return
    for extra in sorted(extras, key=str):
        child_path = (*current_path, extra)
        if not _child_should_run(validator, child_path):
            _record_container_skip(
                validator,
                "additionalProperties",
                child_path,
                ("additionalProperties", extra),
            )
            continue
        yield from validator.descend(
            instance[extra],
            additional,
            path=extra,
        )


def _selective_items_2020(validator, items, instance, schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "array"):
        return
    prefix = len(schema.get("prefixItems", []))
    total = len(instance)
    extra = total - prefix
    if extra <= 0:
        return
    current_path = run.nodes[-1].path if run is not None else ()
    if run is not None and not run.forced and any(
        array_path == current_path
        for array_path in run.zones.suffixes
    ):
        yield from _keywords.items(validator, items, instance, schema)
        return
    if items is False:
        rest = instance[prefix:] if extra != 1 else instance[prefix]
        item = "items" if prefix != 1 else "item"
        yield ValidationError(
            f"Expected at most {prefix} {item} but found {extra} "
            f"extra: {rest!r}",
        )
        return
    for index in range(prefix, total):
        child_path = (*current_path, index)
        if not _child_should_run(validator, child_path):
            _record_container_skip(
                validator,
                "items",
                child_path,
                ("items", index),
            )
            continue
        yield from validator.descend(
            instance=instance[index],
            schema=items,
            path=index,
        )


def _selective_items_tuple(validator, items, instance, schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "array"):
        return
    current_path = run.nodes[-1].path if run is not None else ()
    for index, item in enumerate(instance[:len(items)]):
        subschema = items[index]
        child_path = (*current_path, index)
        if not _child_should_run(validator, child_path):
            _record_container_skip(
                validator,
                "items",
                child_path,
                ("items", index),
            )
            continue
        yield from validator.descend(
            item,
            subschema,
            path=index,
            schema_path=index,
        )


def _selective_items_single(validator, items, instance, schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "array"):
        return
    current_path = run.nodes[-1].path if run is not None else ()
    for index, item in enumerate(instance):
        child_path = (*current_path, index)
        if not _child_should_run(validator, child_path):
            _record_container_skip(
                validator,
                "items",
                child_path,
                ("items", index),
            )
            continue
        yield from validator.descend(item, items, path=index)


def _selective_items(validator, items, instance, schema):
    if validator.is_type(items, "array"):
        yield from _selective_items_tuple(validator, items, instance, schema)
    else:
        yield from _selective_items_single(validator, items, instance, schema)


def _selective_legacy_tuple_items(validator, items, instance, schema):
    run = _current_run(validator)
    current_path = run.nodes[-1].path
    if validator.is_type(items, "object"):
        if any(array_path == current_path
               for array_path in run.zones.suffixes):
            yield from _legacy_keywords.items_draft3_draft4(
                validator, items, instance, schema,
            )
            return
        yield from _selective_items_single(
            validator, items, instance, schema,
        )
    else:
        if any(array_path == current_path
               for array_path in run.zones.suffixes):
            yield from _legacy_keywords.items_draft3_draft4(
                validator, items, instance, schema,
            )
            return
        yield from _selective_items_tuple(
            validator, items, instance, schema,
        )


def _selective_legacy_items(validator, items, instance, schema):
    run = _current_run(validator)
    current_path = run.nodes[-1].path
    if any(array_path == current_path
           for array_path in run.zones.suffixes):
        yield from _legacy_keywords.items_draft6_draft7_draft201909(
            validator, items, instance, schema,
        )
        return
    yield from _selective_items(validator, items, instance, schema)


def _selective_additional_items(validator, additional_items, instance,
                                schema):
    run = _current_run(validator)
    current_path = run.nodes[-1].path
    if any(array_path == current_path
           for array_path in run.zones.suffixes):
        yield from _legacy_keywords.additionalItems(
            validator, additional_items, instance, schema,
        )
        return
    yield from _legacy_keywords.additionalItems(
        validator, additional_items, instance, schema,
    )


def _selective_prefix_items(validator, prefix_items, instance, schema):
    run = _current_run(validator)
    if not validator.is_type(instance, "array"):
        return
    current_path = run.nodes[-1].path if run is not None else ()
    if any(
        array_path == current_path
        for array_path in run.zones.suffixes
    ):
        yield from _keywords.prefixItems(
            validator,
            prefix_items,
            instance,
            schema,
        )
        return
    for index, item in enumerate(instance[:len(prefix_items)]):
        subschema = prefix_items[index]
        child_path = (*current_path, index)
        if not _child_should_run(validator, child_path):
            _record_container_skip(
                validator,
                "prefixItems",
                child_path,
                ("prefixItems", index),
            )
            continue
        yield from validator.descend(
            item,
            subschema,
            path=index,
            schema_path=index,
        )


def _selective_all_of(validator, all_of, instance, schema):
    run = _current_run(validator)
    current_path = run.nodes[-1].path if run is not None else ()
    for index, subschema in enumerate(all_of):
        affected_exact = any(
            run._starts_with(exact, current_path)
            for exact in run.zones.exact
        )
        affected_suffix = any(
            run._starts_with(array_path, current_path)
            or run._starts_with(current_path, array_path)
            for array_path in run.zones.suffixes
        )
        if not run or run.forced or affected_exact or affected_suffix:
            yield from validator.descend(instance, subschema, schema_path=index)
        else:
            _record_container_skip(
                validator,
                "allOf",
                current_path,
                (*run.nodes[-1].schema_path, "allOf", index),
            )


def _selective_unevaluated_properties(validator, unevaluated,
                                      instance, schema):
    run = _current_run(validator)
    if run is None:
        yield from _keywords.unevaluatedProperties(
            validator,
            unevaluated,
            instance,
            schema,
        )
        return
    run.begin_probe()
    try:
        errors = list(
            _keywords.unevaluatedProperties(
                validator,
                unevaluated,
                instance,
                schema,
            ),
        )
        for error in errors:
            error._incremental_outer_error = True
    finally:
        run.end_probe()
        for error in errors:
            error.__dict__.pop("_incremental_outer_error", None)
    yield from errors


def _selective_legacy_unevaluated_items(validator, unevaluated,
                                        instance, schema):
    run = _current_run(validator)
    if run is None:
        yield from _legacy_keywords.unevaluatedItems_draft2019(
            validator, unevaluated, instance, schema,
        )
        return
    run.begin_probe()
    try:
        errors = list(
            _legacy_keywords.unevaluatedItems_draft2019(
                validator, unevaluated, instance, schema,
            ),
        )
    finally:
        run.end_probe()
    yield from errors


_SELECTIVE_WRAPPERS = {
    _keywords.properties: _selective_properties,
    _keywords.patternProperties: _selective_pattern_properties,
    _keywords.additionalProperties: _selective_additional_properties,
    _keywords.items: _selective_items_2020,
    _keywords.prefixItems: _selective_prefix_items,
    _keywords.allOf: _selective_all_of,
    _keywords.unevaluatedProperties: _selective_unevaluated_properties,
    _legacy_keywords.additionalItems: _selective_additional_items,
    _legacy_keywords.properties_draft3: _selective_properties,
    _legacy_keywords.items_draft3_draft4: _selective_legacy_tuple_items,
    _legacy_keywords.items_draft6_draft7_draft201909: _selective_legacy_items,
    _legacy_keywords.extends_draft3: _selective_all_of,
    _legacy_keywords.unevaluatedItems_draft2019: (
        _selective_legacy_unevaluated_items
    ),
    _legacy_keywords.unevaluatedProperties_draft2019: (
        _selective_unevaluated_properties
    ),
}


class _FullFallback(Exception):
    pass


@dataclass
class _Unit:
    path: tuple[str | int, ...] = ()
    schema_path: tuple[str | int, ...] = ()
    errors: list[ValidationError] = field(default_factory=list)
    discarded: bool = False
    parent_unit: tuple | None = None


@dataclass
class _Zones:
    exact: set[tuple[str | int, ...]] = field(default_factory=set)
    structural: set[tuple[str | int, ...]] = field(default_factory=set)
    suffixes: dict[tuple[str | int, ...], int] = field(default_factory=dict)


class _KeywordFrame:
    def __init__(self, run: _IncrementalRun, node: _NodeFrame, keyword: str,
                 function: Callable, effective_function: Callable,
                 schema_path: tuple[str | int, ...], occurrence: int,
                 force: bool, collector: bool) -> None:
        self.run = run
        self.node = node
        self.keyword = keyword
        self.function = function
        self.effective_function = effective_function
        self.schema_path = schema_path
        self.occurrence = occurrence
        self.force = force
        self.collector = collector
        self.probe = False
        self.parent_frame = None
        self.id = (*node.id, "keyword", keyword, occurrence)
        self.skip = False

    def on_error(self, error: ValidationError) -> None:
        self.run.on_error(error, self)

    def exit(self) -> None:
        self.run.exit_keyword(self)


class _NodeFrame:
    def __init__(self, run: _IncrementalRun, node_id: tuple,
                 path: tuple[str | int, ...],
                 schema_path: tuple[str | int, ...],
                 runs: bool, forced: bool) -> None:
        self.run = run
        self.id = node_id
        self.path = path
        self.schema_path = schema_path
        self.runs = runs
        self.forced = forced
        self.occurrences: dict[str, int] = {}

    def enter_keyword(self, keyword: str, validator: Callable,
                      validator_value: Any, schema: ObjectSchema) -> _KeywordFrame:
        return self.run.enter_keyword(
            self,
            keyword,
            validator,
            validator_value,
            schema,
        )

    def on_error(self, error: ValidationError) -> None:
        self.run.on_error(error, None, self)

    def exit(self) -> None:
        self.run.exit_node(self)


def _unescape_pointer_token(token: str) -> str:
    result = []
    index = 0
    while index < len(token):
        character = token[index]
        if character == "~":
            if index + 1 >= len(token) or token[index + 1] not in "01":
                raise IncrementalValidationError(
                    f"Invalid JSON Pointer escape in {token!r}",
                )
            result.append("~" if token[index + 1] == "0" else "/")
            index += 2
        else:
            result.append(character)
            index += 1
    return "".join(result)


def _parse_pointer(pointer: str | Sequence[str | int]) -> tuple[str | int, ...]:
    if not isinstance(pointer, str):
        return tuple(pointer)
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise IncrementalValidationError(
            f"Non-empty JSON Pointer must start with '/': {pointer!r}",
        )
    return tuple(
        _unescape_pointer_token(each)
        for each in pointer[1:].split("/")
    )


def _parent(path: tuple[str | int, ...]) -> tuple[str | int, ...]:
    return path[:-1]


def _array_index(token: str | int, append: bool = False) -> int:
    if isinstance(token, int):
        index = token
    elif isinstance(token, str) and token.isdigit() and (
        token == "0" or not token.startswith("0")
    ):
        index = int(token)
    else:
        raise IncrementalValidationError(f"Invalid array index: {token!r}")
    if append:
        if index < 0:
            raise IncrementalValidationError(f"Invalid array index: {token!r}")
    elif index < 0:
        raise IncrementalValidationError(f"Invalid array index: {token!r}")
    return index


def _navigate(instance: Any, path: tuple[str | int, ...]) -> Any:
    current = instance
    for token in path:
        if (
            isinstance(current, list)
            and isinstance(token, str)
            and token.isdigit()
            and (token == "0" or not token.startswith("0"))
        ):
            token = int(token)
        try:
            current = current[token]
        except (KeyError, IndexError, TypeError) as error:
            raise IncrementalValidationError(
                f"JSON Pointer does not exist: {path!r}",
            ) from error
    return current


def _resolve_set_token(parent: Any, token: str | int,
                       append: bool) -> str | int:
    if append and isinstance(parent, list) and token == "-":
        return len(parent)
    return token


def _set_value(instance: Any, path: tuple[str | int, ...], value: Any,
               append: bool = False) -> None:
    parent = _navigate(instance, _parent(path))
    token = path[-1]
    if isinstance(parent, dict):
        parent[token] = value
        return
    if isinstance(parent, list):
        token = _resolve_set_token(parent, token, append)
        index = _array_index(token, append=append)
        if append:
            if index > len(parent):
                raise IncrementalValidationError(
                    f"Array index out of range: {token!r}",
                )
            parent.insert(index, value)
        else:
            if index >= len(parent):
                raise IncrementalValidationError(
                    f"Array index out of range: {token!r}",
                )
            parent[index] = value
        return
    raise IncrementalValidationError(
        "JSON Pointer parent is neither an object nor an array",
    )


def _remove_value(instance: Any, path: tuple[str | int, ...]) -> None:
    parent = _navigate(instance, _parent(path))
    token = path[-1]
    if isinstance(parent, dict):
        if token not in parent:
            raise IncrementalValidationError(
                f"JSON Pointer does not exist: {path!r}",
            )
        del parent[token]
    elif isinstance(parent, list):
        index = _array_index(token)
        if index >= len(parent):
            raise IncrementalValidationError(
                f"Array index out of range: {token!r}",
            )
        del parent[index]
    else:
        raise IncrementalValidationError(
            "JSON Pointer parent is neither an object nor an array",
        )


def _exists(instance: Any, path: tuple[str | int, ...]) -> bool:
    try:
        _navigate(instance, path)
    except IncrementalValidationError:
        return False
    return True


def _canonical_path(instance: Any,
                    path: tuple[str | int, ...]) -> tuple[str | int, ...]:
    canonical = []
    for index, token in enumerate(path):
        parent = _navigate(instance, tuple(canonical))
        if isinstance(parent, list):
            if token == "-":
                canonical.append(len(parent))
                continue
            canonical.append(_array_index(token))
        else:
            canonical.append(token)
    return tuple(canonical)


def _structural_paths(path: tuple[str | int, ...]) -> set[tuple[str | int, ...]]:
    return {path[:index] for index in range(len(path) + 1)}


def _suffix(path: tuple[str | int, ...]) -> tuple[tuple[str | int, ...], int]:
    return _parent(path), _array_index(path[-1])


def _normalise_changes(changes: Any) -> list[dict[str, Any]]:
    if isinstance(changes, Mapping):
        if "path" in changes or "pointer" in changes:
            changes = [changes]
        else:
            changes = [
                {"op": "replace", "path": path, "value": value}
                for path, value in changes.items()
            ]
    result = []
    for change in changes:
        if isinstance(change, Sequence) and not isinstance(change, (str, bytes)):
            if len(change) == 2:
                change = {"op": "replace", "path": change[0],
                          "value": change[1]}
            elif len(change) == 3:
                change = {"op": change[0], "path": change[1],
                          "value": change[2]}
        if not isinstance(change, Mapping):
            raise IncrementalValidationError("Each change must be a mapping")
        normalised = dict(change)
        pointer = normalised.pop("pointer", None)
        if "path" not in normalised:
            if pointer is None:
                raise IncrementalValidationError("A JSON Pointer is required")
            normalised["path"] = pointer
        normalised["path"] = _parse_pointer(normalised["path"])
        if "from" in normalised:
            normalised["from"] = _parse_pointer(normalised["from"])
        op = normalised.get("op")
        if op is None:
            op = "add" if "value" in normalised else "remove"
        normalised["op"] = op
        result.append(normalised)
    return result


def _zones_for_change(change: Mapping[str, Any], instance: Any) -> _Zones:
    zones = _Zones()
    path = change["path"]
    op = change["op"]
    target_paths = [path]
    if op in {"move", "copy"}:
        target_paths.append(change["from"])
    for target_path in target_paths:
        zones.structural.update(_structural_paths(target_path))
    if op == "replace":
        zones.exact.add(_canonical_path(instance, path))
    elif op == "add":
        if not path:
            zones.exact.add(())
        else:
            canonical_path = _canonical_path(instance, path)
            parent = _navigate(instance, _parent(canonical_path))
            if isinstance(parent, list):
                token = _resolve_set_token(parent, path[-1], True)
                canonical_path = (
                    *canonical_path[:-1],
                    _array_index(token, append=True),
                )
                array_path, index = _suffix(canonical_path)
                zones.suffixes[array_path] = index
            else:
                zones.exact.add(canonical_path)
    elif op == "remove":
        canonical_path = _canonical_path(instance, path)
        parent = _navigate(instance, _parent(canonical_path))
        if isinstance(parent, list):
            array_path, index = _suffix(canonical_path)
            zones.suffixes[array_path] = index
        elif path:
            zones.exact.add(path)
        else:
            raise IncrementalValidationError("Cannot remove the root document")
    elif op in {"move", "copy"}:
        source = _canonical_path(instance, change["from"])
        zones.exact.add(source)
        destination_parent = (
            _navigate(instance, _parent(path)) if path else None
        )
        if isinstance(destination_parent, list):
            canonical_path = _canonical_path(instance, path)
            token = _resolve_set_token(
                destination_parent,
                canonical_path[-1],
                True,
            )
            canonical_path = (
                *canonical_path[:-1],
                _array_index(token, append=True),
            )
            array_path, index = _suffix(canonical_path)
            zones.suffixes[array_path] = index
        else:
            zones.exact.add(_canonical_path(instance, path))
    elif op == "test":
        pass
    else:
        raise IncrementalValidationError(f"Unsupported change operation: {op!r}")
    return zones


def _merge_zones(target: _Zones, source: _Zones) -> None:
    target.exact.update(source.exact)
    target.structural.update(source.structural)
    for path, index in source.suffixes.items():
        target.suffixes[path] = min(target.suffixes.get(path, index), index)


def _discard_zone_units(units: dict[tuple, _Unit], zones: _Zones) -> None:
    for exact in zones.exact:
        for unit in units.values():
            if unit.path == exact or (
                len(unit.path) > len(exact)
                and unit.path[:len(exact)] == exact
            ):
                unit.discarded = True
    for array_path, index in zones.suffixes.items():
        for unit in units.values():
            if (
                len(unit.path) > len(array_path)
                and unit.path[:len(array_path)] == array_path
                and isinstance(unit.path[len(array_path)], int)
                and unit.path[len(array_path)] >= index
            ):
                unit.discarded = True


def _apply_changes(
    instance: Any,
    changes: Iterable[Mapping[str, Any]],
) -> tuple[Any, _Zones]:
    candidate = deepcopy(instance)
    zones = _Zones()
    for change in changes:
        _merge_zones(zones, _zones_for_change(change, candidate))
        op = change["op"]
        path = change["path"]
        if op == "test":
            actual = _navigate(candidate, path)
            if not _utils.equal(actual, change.get("value")):
                raise IncrementalValidationError("JSON Patch test failed")
            continue
        if op == "replace":
            if not path:
                candidate = deepcopy(change["value"])
            else:
                _navigate(candidate, path)
                _set_value(candidate, path, change["value"])
        elif op == "add":
            if not path:
                candidate = deepcopy(change["value"])
            else:
                _set_value(candidate, path, change["value"], append=True)
        elif op == "remove":
            _remove_value(candidate, path)
        elif op in {"move", "copy"}:
            value = deepcopy(_navigate(candidate, change["from"]))
            if op == "move":
                _remove_value(candidate, change["from"])
            if not path:
                candidate = value
            elif _exists(candidate, path):
                _set_value(candidate, path, value)
            else:
                _set_value(candidate, path, value, append=True)
    return candidate, zones


def _walk_schema(schema: Any) -> Iterable[Any]:
    if not isinstance(schema, Mapping):
        return
    yield schema
    for keyword, value in schema.items():
        if isinstance(value, Mapping) and keyword in _SUBSCHEMA_KEYWORDS:
            yield from _walk_schema(value)
        elif (
            isinstance(value, Sequence)
            and not isinstance(value, str)
            and keyword in _SUBSCHEMA_ARRAY_KEYWORDS
        ):
            for each in value:
                if isinstance(each, Mapping):
                    yield from _walk_schema(each)


def _schema_needs_full_fallback(
    schema: Any,
    validator_class: Any,
    builtins: frozenset[Callable],
) -> bool:
    for subschema in _walk_schema(schema):
        for keyword in subschema:
            function = validator_class.VALIDATORS.get(keyword)
            if function is None or function in builtins:
                continue
            scope = getattr(function, "__jsonschema_incremental_scope__", None)
            if scope != "local":
                return True
    return False


def _registry_needs_full_fallback(
    registry: Any,
    validator_class: Any,
    builtins: frozenset[Callable],
) -> bool:
    try:
        crawled = registry.crawl()
        for uri in crawled:
            resource = crawled[uri]
            if _schema_needs_full_fallback(
                resource.contents,
                validator_class,
                builtins,
            ):
                return True
    except Exception:
        return True
    return False


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted(
            (key, _canonical_value(item)) for key, item in value.items()
        ))
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(_canonical_value(each) for each in value)
    return value


def _error_signature(error: ValidationError) -> tuple:
    return (
        error.message,
        error.validator,
        tuple(error.absolute_path),
        tuple(error.absolute_schema_path),
        _canonical_value(error.validator_value),
        _canonical_value(error.instance),
    )


class IncrementalValidationSession:
    def __init__(
        self,
        instance: Any,
        validator_class: Any,
        schema: ObjectSchema | bool,
        *,
        registry: Any = None,
        format_checker: Any = None,
        observer: ValidationObserver | None = None,
        **validator_arguments: Any,
    ) -> None:
        self.schema = schema
        builtins = frozenset(
            function
            for name in dir(_keywords)
            if callable(function := getattr(_keywords, name))
        ) | frozenset(
            function
            for name in dir(_legacy_keywords)
            if callable(function := getattr(_legacy_keywords, name))
        )
        self.builtin_keyword_functions = builtins
        validator_kwargs = dict(validator_arguments)
        if registry is not None:
            validator_kwargs["registry"] = registry
        if format_checker is not None:
            validator_kwargs["format_checker"] = format_checker
        self.validator = validator_class(schema, **validator_kwargs)
        self.observer = observer or ValidationObserver()
        self.requires_full_fallback = (
            _schema_needs_full_fallback(
                schema,
                validator_class,
                builtins,
            ) or _registry_needs_full_fallback(
                self.validator._registry,
                validator_class,
                builtins,
            )
        )
        self.instance = deepcopy(instance)
        self.units: dict[tuple, _Unit] = {}
        self.events: list[tuple] = []
        self.errors = self._run_full()

    def _run_validation(self, run: _IncrementalRun) -> list[ValidationError]:
        self.events = []
        run.events = self.events
        run.start()
        errors_iterator = self.validator.iter_errors(self.instance)
        try:
            errors = []
            while True:
                try:
                    error = next(errors_iterator)
                except StopIteration:
                    break
                errors.append(error)
            run.finish()
        except BaseException:
            run.abort()
            raise
        return errors

    def _run_full(self) -> list[ValidationError]:
        run = _IncrementalRun(self, full=True)
        run.events = []
        self.units = {}
        errors = self._run_validation(run)
        collected = self._collect_errors()
        if len({_error_signature(error) for error in collected}) != len(collected):
            return sorted(errors, key=lambda error: _error_signature(error))
        return collected

    def _run_selective(self, zones: _Zones) -> list[ValidationError]:
        run = _IncrementalRun(self, full=False, zones=zones)
        old_units = deepcopy(self.units)
        _discard_zone_units(self.units, zones)
        try:
            self._run_validation(run)
        except _FullFallback:
            run.abort()
            self.units = old_units
            return self._run_full()
        return self._collect_errors()

    def _collect_errors(self) -> list[ValidationError]:
        signatures = set()
        errors = []
        for unit in self.units.values():
            if unit.discarded:
                continue
            for error in unit.errors:
                signature = _error_signature(error)
                if signature in signatures:
                    continue
                signatures.add(signature)
                errors.append(error)
        return errors

    def apply(self, changes: Any) -> list[ValidationError]:
        normalised = _normalise_changes(changes)
        candidate, zones = _apply_changes(self.instance, normalised)
        old_instance = deepcopy(self.instance)
        old_units = deepcopy(self.units)
        self.instance = candidate
        try:
            if self.requires_full_fallback:
                errors = self._run_full()
            else:
                errors = self._run_selective(zones)
        except BaseException:
            self.instance = old_instance
            self.units = old_units
            raise
        self.errors = errors
        return errors

    def update(self, changes: Any) -> list[ValidationError]:
        return self.apply(changes)

    def iter_errors(self, changes: Any | None = None) -> list[ValidationError]:
        if changes is None:
            return list(self.errors)
        return self.apply(changes)

    def validate(self, changes: Any | None = None) -> None:
        for error in self.apply(changes) if changes is not None else self.errors:
            raise error


def session(
    instance: Any,
    schema: ObjectSchema | bool,
    cls: Any = None,
    *,
    registry: Any = None,
    format_checker: Any = None,
    observer: ValidationObserver | None = None,
    **kwargs: Any,
) -> IncrementalValidationSession:
    if cls is None:
        from jsonschema.validators import validator_for

        cls = validator_for(schema)
    return IncrementalValidationSession(
        instance,
        cls,
        schema,
        registry=registry,
        format_checker=format_checker,
        observer=observer,
        **kwargs,
    )


incremental_session = session
begin_incremental_validation = session


class _IncrementalRun:
    def __init__(self, session: IncrementalValidationSession,
                 *, full: bool, zones: _Zones | None = None) -> None:
        self.session = session
        self.full = full
        self.zones = zones or _Zones()
        self.nodes: list[_NodeFrame] = []
        self.units: dict[tuple, _Unit] = {}
        self.probe_depth = 0
        self.force_depth = 0
        self.node_occurrences = 0
        self.evaluated = 0
        self.skipped = 0
        self.events: list[tuple[str, str, tuple[str | int, ...],
                               tuple[str | int, ...]]] = []
        self.frame: _KeywordFrame | None = None
        self.token = None

    @property
    def forced(self) -> bool:
        return self.full or self.probe_depth > 0 or self.force_depth > 0

    def _is_structural(self, path: tuple[str | int, ...]) -> bool:
        if self.full:
            return True
        if path in self.zones.structural or path in self.zones.exact:
            return True
        return any(self._starts_with(path, exact)
                   for exact in self.zones.exact)

    def _is_forced(self, path: tuple[str | int, ...]) -> bool:
        if self.full:
            return True
        if any(path == exact or self._starts_with(path, exact)
               for exact in self.zones.exact):
            return True
        for array_path, index in self.zones.suffixes.items():
            if (
                len(path) > len(array_path)
                and path[:len(array_path)] == array_path
                and isinstance(path[len(array_path)], int)
                and path[len(array_path)] >= index
            ):
                return True
        return False

    @staticmethod
    def _starts_with(path: tuple[str | int, ...],
                     prefix: tuple[str | int, ...]) -> bool:
        return path[:len(prefix)] == prefix

    def begin_probe(self) -> None:
        self.probe_depth += 1

    def end_probe(self) -> None:
        self.probe_depth -= 1

    def enter_node(self, validator: Any, schema: Any, instance: Any,
                   path: str | int | None,
                   schema_path: str | int | None = None) -> _NodeFrame:
        if self.nodes:
            parent = self.nodes[-1]
            current_path = parent.path
            current_schema_path = parent.schema_path
            parent_id = parent.id
        else:
            current_path = ()
            current_schema_path = ()
            parent_id = ()

        node_path = (
            current_path if path is None else (*current_path, path)
        )
        node_schema_path = (
            current_schema_path
            if schema_path is None
            else (*current_schema_path, schema_path)
        )

        forced = self.forced
        runs = self.full or forced or self._is_structural(node_path)
        if not forced:
            forced = runs and self._is_forced(node_path)

        schema_id = (getattr(validator._resolver, "_base_uri", None), id(schema))
        if parent_id:
            node_id = (
                *parent_id,
                "node",
                schema_id,
                node_schema_path,
                node_path,
            )
        else:
            self.node_occurrences += 1
            node_id = (
                "root",
                self.node_occurrences,
                schema_id,
                node_schema_path,
                node_path,
            )

        unit: _Unit | None = None
        if runs and self.probe_depth == 0:
            old_unit = self.session.units.get(node_id)
            unit = _Unit(
                node_path,
                node_schema_path,
                parent_unit=(
                    self.frame.id if self.frame is not None else None
                ),
            )
            if old_unit is not None and not old_unit.discarded:
                unit.errors = list(old_unit.errors)
            self.units[node_id] = unit

        node = _NodeFrame(
            self,
            node_id,
            node_path,
            node_schema_path,
            runs,
            forced,
        )
        node.unit = unit
        self.nodes.append(node)
        if forced:
            self.force_depth += 1
        return node

    def exit_node(self, node: _NodeFrame) -> None:
        if node.forced:
            self.force_depth -= 1
        self.nodes.pop()

    def _scope(self, keyword: str, function: Callable) -> str:
        marked = getattr(function, "__jsonschema_incremental_scope__", None)
        if marked is not None:
            return marked
        if function in _FORCE_KEYWORD_FUNCTIONS:
            return "force"
        if function in self.session.builtin_keyword_functions:
            return "local"
        if self.full:
            self.session.requires_full_fallback = True
            return "full"
        raise _FullFallback(keyword)

    def enter_keyword(self, node: _NodeFrame, keyword: str,
                      function: Callable, validator_value: Any,
                      schema: ObjectSchema) -> _KeywordFrame:
        occurrence = node.occurrences.get(keyword, 0)
        node.occurrences[keyword] = occurrence + 1
        schema_path = (*node.schema_path, keyword)

        skip = False
        force = self.forced
        collector = function in _COLLECTOR_FUNCTIONS
        if not self.full and node.runs and not force:
            scope = self._scope(keyword, function)
            force = scope in {"force", "full"}
        elif not self.full and not node.runs:
            skip = True
        else:
            scope = self._scope(keyword, function)
            force = scope in {"force", "full"}

        frame = _KeywordFrame(
            self,
            node,
            keyword,
            function,
            _SELECTIVE_WRAPPERS.get(function, function),
            schema_path,
            occurrence,
            force,
            collector,
        )

        if skip:
            self.skipped += 1
            self.session.events.append(
                ("skipped", keyword, node.path, schema_path),
            )
            return frame

        if self.probe_depth:
            frame.probe = True

        self.evaluated += 1
        self.session.events.append(
            ("evaluated", keyword, node.path, schema_path),
        )
        if force:
            self._discard_prefix(frame.id)
            descendants = [frame.id]
            while descendants:
                parent = descendants.pop()
                for unit_id, unit in self.session.units.items():
                    if unit.parent_unit == parent and not unit.discarded:
                        unit.discarded = True
                        descendants.append(unit_id)
            self.force_depth += 1
        unit = self.units.get(node.id)
        if unit is not None:
            unit.errors = [
                error for error in unit.errors
                if getattr(error, "_incremental_unit", None) != frame.id
            ]
        if self.probe_depth == 0:
            self.units[frame.id] = _Unit(
                node.path,
                schema_path,
                parent_unit=node.id,
            )
        frame.parent_frame = self.frame
        self.frame = frame
        return frame

    def exit_keyword(self, frame: _KeywordFrame) -> None:
        if frame.force:
            self.force_depth -= 1
        self.frame = frame.parent_frame

    def _discard_prefix(self, prefix: tuple) -> None:
        for unit_id, unit in self.session.units.items():
            if unit_id[:len(prefix)] == prefix:
                unit.discarded = True

    def on_error(self, error: ValidationError, frame: _KeywordFrame | None,
                 node: _NodeFrame | None = None) -> None:
        if self.probe_depth and not getattr(
            error,
            "_incremental_outer_error",
            False,
        ):
            return
        if getattr(error, "_incremental_unit", None) is not None:
            return

        if frame is not None:
            collector = None
            ancestor = frame.parent_frame
            while ancestor is not None and collector is None:
                if (
                    ancestor.collector
                    or ancestor.function in _SUPPRESSED_DESCENDANT_FUNCTIONS
                ):
                    collector = ancestor
                ancestor = ancestor.parent_frame
            if collector is not None:
                return
            target = frame
        elif node is not None:
            if self.probe_depth:
                return
            target = node
        else:
            return

        unit = self.units.get(target.id)
        if unit is None:
            return
        error._incremental_unit = target.id
        unit.errors.append(error)

    def start(self) -> None:
        self.token = _utils._INCREMENTAL_VALIDATION.set(self)

    def abort(self) -> None:
        if self.token is not None:
            _utils._INCREMENTAL_VALIDATION.reset(self.token)
            self.token = None

    def finish(self) -> None:
        self.abort()
        if self.full:
            self.session.units = self.units
        else:
            self.session.units.update(self.units)
        for event in self.session.events:
            kind, keyword, path, schema_path = event
            if kind == "evaluated":
                self.session.observer.on_keyword_evaluated(
                    keyword,
                    path,
                    schema_path,
                )
            else:
                self.session.observer.on_keyword_skipped(
                    keyword,
                    path,
                    schema_path,
                )
