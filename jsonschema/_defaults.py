"""
Explicitly fill in missing object properties from :kw:`default` annotations.

Validation treats :kw:`default` purely as an annotation and never mutates
the instance. This module provides an opt-in way to produce a *copy* of an
instance with missing properties filled in.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import TYPE_CHECKING, Any

from attrs import define
from referencing.exceptions import Unresolvable as _Unresolvable

from jsonschema import _utils
from jsonschema.exceptions import _WrappedReferencingError

if TYPE_CHECKING:
    from collections.abc import Callable

    from jsonschema.protocols import Validator as _ValidatorProtocol

JSON = dict[str, Any] | list[Any] | str | int | float | bool | None
_Path = tuple[str | int, ...]
_Schema = JSON


class DefaultFillError(Exception):
    """Filling in defaults could not be completed."""


@define(eq=False)
class DefaultConflictError(DefaultFillError):
    """
    Applicable subschemas declare different ``default`` values for one
    missing property (e.g. across the branches of :kw:`allOf`).
    """

    path: _Path
    values: tuple[object, ...]
    sources: tuple[_Path, ...]

    def __str__(self) -> str:
        location = _format_path(self.path) or "the instance root"
        joined = ", ".join(repr(value) for value in self.values)
        return (
            f"Conflicting defaults {joined} were found for the property "
            f"at {location}."
        )


@define(eq=False)
class DefaultFillLoopError(DefaultFillError):
    """
    Filling defaults did not reach a fixed point.

    This protects against schemas whose ``default`` values keep introducing
    new locations to fill (for example mutually recursive defaults).
    """

    path: _Path

    def __str__(self) -> str:
        location = _format_path(self.path)
        suffix = f" at {location}" if location else ""
        return (
            "Filling defaults did not stabilize; a default value appears to "
            f"recursively introduce further defaults{suffix}."
        )


@define(frozen=True)
class FilledDefault:
    """
    A single default value that was filled in.

    Attributes:

    value:

        the inserted value (a deep copy of the schema's ``default``)

    schema_path:

        the path of keywords from the root schema to the subschema that
        declared the used ``default``
    """

    value: object
    schema_path: _Path


@define(frozen=True)
class FilledDefaultsResult:
    """
    The result of filling defaults.

    Attributes:

    instance:

        a copy of the original instance with missing properties filled in

    defaults:

        a mapping from the instance path of every newly added value to the
        `FilledDefault` describing its value and schema source
    """

    instance: object
    defaults: dict[_Path, FilledDefault]

    def __iter__(self):
        yield self.instance
        yield self.defaults


_MAX_PASSES = 100


def fill_defaults(
    validator: _ValidatorProtocol, instance: JSON,
) -> FilledDefaultsResult:
    """
    Return a copy of ``instance`` with missing object properties filled in.

    The original instance is never mutated. See
    `jsonschema.protocols.Validator.fill_defaults` for the detailed
    semantics.
    """
    filled = deepcopy(instance)
    filler = _Filler(validator)

    # Expand missing defaults until nothing changes. Conditional keywords
    # are evaluated against the current instance, so a later pass may make
    # an earlier, conditionally-introduced default inapplicable; such
    # values are pruned and expansion runs again until the result is stable.
    for _ in range(_MAX_PASSES):
        expansions = 0
        while filler.apply(filled):
            expansions += 1
            if expansions > _MAX_PASSES:
                raise DefaultFillLoopError(path=filler.deepest_path)
        removed = filler.prune(filled)
        if not removed:
            break
    else:
        raise DefaultFillLoopError(path=filler.deepest_path)

    # Never return a half-completed result: the filled instance must itself
    # be valid under the original schema.
    error = next(validator.iter_errors(filled), None)
    if error is not None:
        raise error

    return FilledDefaultsResult(instance=filled, defaults=filler.applied)


def _format_path(path: _Path) -> str:
    return "".join(
        f"[{each!r}]" if isinstance(each, str) else f"[{each}]"
        for each in path
    )


class _Filler:
    def __init__(self, validator: _ValidatorProtocol) -> None:
        self._root = validator
        self.applied: dict[_Path, FilledDefault] = {}
        self.deepest_path = ()
        self._added = False
        # Maps id() of a container inserted from a default to the chain of
        # default-introduction edges that led to it (persisted across passes).
        self._default_origin: dict[int, tuple[Any, ...]] = {}

    def apply(self, instance: JSON) -> bool:
        self._added = False
        self._visit(
            validator=self._root,
            schema=self._root.schema,
            resolver=self._root._resolver,
            instance=instance,
            instance_path=(),
            schema_path=(),
            default_chain=(),
        )
        return self._added

    def prune(self, instance: JSON) -> bool:
        """
        Remove filled values whose default is no longer applicable.

        Conditional branches are re-evaluated against the *current*
        (already filled) instance. A value inserted while a different branch
        temporarily matched is removed together with anything nested inside
        it that was only reachable through it.
        """
        self._removed: bool = False
        self._prune(
            validator=self._root,
            schema=self._root.schema,
            resolver=self._root._resolver,
            instance=instance,
            instance_path=(),
        )
        return self._removed

    def _prune(
        self,
        validator: _ValidatorProtocol,
        schema: _Schema,
        resolver: Any,
        instance: JSON,
        instance_path: _Path,
    ) -> None:
        if schema is True or schema is False or not isinstance(schema, dict):
            return
        if not (
            validator.is_type(instance, "object")
            or validator.is_type(instance, "array")
        ):
            return

        child_frames: list[tuple[str | int, _Schema, Any]] = []
        seen_frames: set[tuple[Any, ...]] = set()

        def add_child(
            key: str | int,
            sub_schema: _Schema,
            sub_resolver: Any,
            sub_path: _Path,
        ) -> None:
            frame = (key, id(sub_schema), id(sub_resolver))
            if frame not in seen_frames:
                seen_frames.add(frame)
                child_frames.append((key, sub_schema, sub_resolver))

        def ignore_candidate(*_args: Any) -> None:
            return None

        self._collect(
            validator=validator,
            schema=schema,
            resolver=resolver,
            instance=instance,
            schema_path=(),
            add_candidate=ignore_candidate,
            add_child=add_child,
        )

        if validator.is_type(instance, "object"):
            applicable = self._applicable_properties(
                validator, schema, resolver, instance, set(),
            )
            for name in list(instance):
                path = instance_path + (name,)
                if path in self.applied and name not in applicable:
                    del instance[name]
                    self._drop_applied(path)
                    self._removed = True
                    continue
                for key, sub_schema, sub_resolver in child_frames:
                    if key != name:
                        continue
                    self._prune(
                        validator=validator,
                        schema=sub_schema,
                        resolver=sub_resolver,
                        instance=instance[name],
                        instance_path=path,
                    )
        else:
            for index, value in enumerate(instance):
                for key, sub_schema, sub_resolver in child_frames:
                    if key is not None and key != index:
                        continue
                    self._prune(
                        validator=validator,
                        schema=sub_schema,
                        resolver=sub_resolver,
                        instance=value,
                        instance_path=instance_path + (index,),
                    )

    def _drop_applied(self, root_path: _Path) -> None:
        for path in list(self.applied):
            if path[: len(root_path)] == root_path:
                del self.applied[path]

    def _applicable_properties(
        self,
        validator: _ValidatorProtocol,
        schema: dict[str, Any],
        resolver: Any,
        instance: JSON,
        found: set[str],
    ) -> set[str]:
        applicable = dict(
            validator.__class__._APPLICABLE_VALIDATORS(schema),
        )
        for keyword in ("$ref", "$recursiveRef", "$dynamicRef"):
            if keyword in applicable:
                resolved_schema, resolved_resolver = self._resolve(
                    validator, resolver, applicable[keyword],
                )
                if isinstance(resolved_schema, dict):
                    self._applicable_properties(
                        validator,
                        resolved_schema,
                        resolved_resolver,
                        instance,
                        found,
                    )
        for keyword, value in applicable.items():
            if keyword in {"$ref", "$recursiveRef", "$dynamicRef"}:
                continue
            if keyword == "allOf":
                for each in value:
                    if isinstance(each, dict):
                        self._applicable_properties(
                            validator, each, resolver, instance, found,
                        )
            elif keyword == "extends":
                values = value if isinstance(value, list) else [value]
                for each in values:
                    if isinstance(each, dict):
                        self._applicable_properties(
                            validator, each, resolver, instance, found,
                        )
            elif keyword in {"anyOf", "oneOf"}:
                valid = [
                    each
                    for each in value
                    if self._is_valid(validator, each, resolver, instance)
                ]
                if len(valid) == 1 and isinstance(valid[0], dict):
                    self._applicable_properties(
                        validator, valid[0], resolver, instance, found,
                    )
            elif keyword == "if":
                if self._is_valid(validator, value, resolver, instance):
                    chosen = schema.get("then")
                else:
                    chosen = schema.get("else")
                if isinstance(chosen, dict):
                    self._applicable_properties(
                        validator, chosen, resolver, instance, found,
                    )
            elif keyword == "dependentSchemas" and validator.is_type(
                instance, "object",
            ):
                for name, each in value.items():
                    if name in instance and isinstance(each, dict):
                        self._applicable_properties(
                            validator, each, resolver, instance, found,
                        )
            elif keyword == "dependencies" and validator.is_type(
                instance, "object",
            ):
                for name, dependency in value.items():
                    if name in instance and isinstance(dependency, dict):
                        self._applicable_properties(
                            validator, dependency, resolver, instance, found,
                        )
            elif keyword == "properties" and validator.is_type(
                instance, "object",
            ):
                for name, subschema in value.items():
                    if name in instance and isinstance(subschema, dict):
                        found.add(name)
        return found

    def _sub_validator(
        self,
        validator: _ValidatorProtocol,
        schema: _Schema,
        resolver: Any,
    ) -> _ValidatorProtocol:
        evolved = validator.evolve(schema=schema)
        if validator._ref_resolver is None and resolver is not None:
            evolved._resolver = resolver
        return evolved

    def _is_valid(
        self,
        validator: _ValidatorProtocol,
        schema: _Schema,
        resolver: Any,
        instance: JSON,
    ) -> bool:
        return self._sub_validator(
            validator, schema, resolver,
        ).is_valid(instance)

    def _effective(
        self,
        validator: _ValidatorProtocol,
        schema: _Schema,
        resolver: Any,
    ) -> tuple[_Schema, Any]:
        """
        Resolve a chain of leading references to the effective schema.
        """
        seen = set()
        while isinstance(schema, dict):
            keyword = next(
                (
                    each
                    for each in ("$ref", "$recursiveRef", "$dynamicRef")
                    if each in dict(
                        validator.__class__._APPLICABLE_VALIDATORS(schema),
                    )
                ),
                None,
            )
            if keyword is None or id(schema) in seen:
                break
            seen.add(id(schema))
            schema, resolver = self._resolve(
                validator, resolver, schema[keyword],
            )
        return schema, resolver

    def _resolve(
        self,
        validator: _ValidatorProtocol,
        resolver: Any,
        ref: str,
    ) -> tuple[_Schema, Any]:
        if validator._ref_resolver is not None:
            legacy = validator._ref_resolver
            resolve = getattr(legacy, "resolve", None)
            if resolve is None:
                with legacy.resolving(ref) as resolved:
                    return resolved, legacy
            scope, resolved = resolve(ref)
            legacy.push_scope(scope)
            return resolved, legacy
        try:
            resolved = resolver.lookup(ref)
        except _Unresolvable as err:
            raise _WrappedReferencingError(err) from err
        return resolved.contents, resolved.resolver

    def _visit(
        self,
        validator: _ValidatorProtocol,
        schema: _Schema,
        resolver: Any,
        instance: JSON,
        instance_path: _Path,
        schema_path: _Path,
        default_chain: tuple[tuple[int, str], ...],
    ) -> None:
        if schema is True or schema is False or not isinstance(schema, dict):
            return

        candidates: dict[
            str, list[tuple[JSON, _Path, dict[str, Any]]],
        ] = {}
        child_frames: list[
            tuple[str | int, _Schema, Any, _Path],
        ] = []
        seen_frames: set[tuple[Any, ...]] = set()

        def add_candidate(
            name: str,
            value: JSON,
            source_path: _Path,
            source_schema: dict[str, Any],
        ) -> None:
            candidates.setdefault(name, []).append(
                (value, source_path, source_schema),
            )

        def add_child(
            key: str | int,
            subschema: _Schema,
            sub_resolver: Any,
            sub_schema_path: _Path,
        ) -> None:
            frame = (
                key,
                id(subschema),
                id(sub_resolver),
                sub_schema_path,
            )
            if frame in seen_frames:
                return
            seen_frames.add(frame)
            child_frames.append(
                (key, subschema, sub_resolver, sub_schema_path),
            )

        self._collect(
            validator=validator,
            schema=schema,
            resolver=resolver,
            instance=instance,
            schema_path=schema_path,
            add_candidate=add_candidate,
            add_child=add_child,
        )

        is_object = validator.is_type(instance, "object")
        is_array = validator.is_type(instance, "array")

        default_steps: dict[str, tuple[tuple[int, str], ...]] = {}
        if is_object:
            # The edge used to detect cycles is the effective schema that
            # will govern a newly inserted value together with the property
            # name. That effective schema is the candidate's declaring
            # schema, resolved through any leading references.
            edges: dict[str, int] = {}
            for name, options in candidates.items():
                declarer = options[0][2]
                effective_schema, _effective_resolver = self._effective(
                    validator, declarer, resolver,
                )
                edges[name] = id(effective_schema)
            default_steps = self._fill(
                instance=instance,
                instance_path=instance_path,
                candidates=candidates,
                edges=edges,
                default_chain=default_chain,
            )
            for name in list(instance):
                for key, subschema, sub_resolver, sub_path in child_frames:
                    if key != name:
                        continue
                    if name in default_steps:
                        chain = default_steps[name]
                    else:
                        chain = self._default_origin.get(
                            id(instance[name]), default_chain,
                        )
                    self._visit(
                        validator=validator,
                        schema=subschema,
                        resolver=sub_resolver,
                        instance=instance[name],
                        instance_path=instance_path + (name,),
                        schema_path=sub_path,
                        default_chain=chain,
                    )
        elif is_array:
            for index, value in enumerate(instance):
                for key, subschema, sub_resolver, sub_path in child_frames:
                    if key is not None and key != index:
                        continue
                    self._visit(
                        validator=validator,
                        schema=subschema,
                        resolver=sub_resolver,
                        instance=value,
                        instance_path=instance_path + (index,),
                        schema_path=sub_path,
                        default_chain=default_chain,
                    )

    def _fill(
        self,
        instance: dict[str, Any],
        instance_path: _Path,
        candidates: dict[str, list[tuple[JSON, _Path, dict[str, Any]]]],
        edges: dict[str, int],
        default_chain: tuple[tuple[int, str], ...],
    ) -> dict[str, tuple[tuple[int, str], ...]]:
        default_steps: dict[str, tuple[tuple[int, str], ...]] = {}
        for name, options in candidates.items():
            if name in instance:
                continue
            new_step = (edges[name], name)
            if new_step in default_chain:
                raise DefaultFillLoopError(path=instance_path + (name,))
            chain = default_chain + (new_step,)
            value, source_path, _source_schema = self._choose(
                name=name, options=options, instance_path=instance_path,
            )
            inserted = deepcopy(value)
            instance[name] = inserted
            default_steps[name] = chain
            if isinstance(inserted, (dict, list)):
                self._default_origin[id(inserted)] = chain
            path = instance_path + (name,)
            self.applied[path] = FilledDefault(
                value=deepcopy(inserted), schema_path=source_path,
            )
            self._added = True
            self.deepest_path = path
        return default_steps

    def _choose(
        self,
        name: str,
        options: list[tuple[JSON, _Path, dict[str, Any]]],
        instance_path: _Path,
    ) -> tuple[JSON, _Path, dict[str, Any]]:
        value, first_source, _source_schema = options[0]
        for candidate, candidate_source, _ in options[1:]:
            if not _utils.equal(candidate, value):
                raise DefaultConflictError(
                    path=instance_path + (name,),
                    values=(value, candidate),
                    sources=(first_source, candidate_source),
                )
        return value, first_source, _source_schema

    def _collect(
        self,
        validator: _ValidatorProtocol,
        schema: dict[str, Any],
        resolver: Any,
        instance: JSON,
        schema_path: _Path,
        add_candidate: Callable[[str, JSON, _Path, dict[str, Any]], None],
        add_child: Callable[[str | int, _Schema, Any, _Path], None],
    ) -> None:
        is_object = validator.is_type(instance, "object")
        is_array = validator.is_type(instance, "array")
        applicable = dict(
            validator.__class__._APPLICABLE_VALIDATORS(schema),
        )

        for keyword in ("$ref", "$recursiveRef", "$dynamicRef"):
            if keyword not in applicable:
                continue
            resolved_schema, resolved_resolver = self._resolve(
                validator, resolver, applicable[keyword],
            )
            self._collect(
                validator=validator,
                schema=resolved_schema,
                resolver=resolved_resolver,
                instance=instance,
                schema_path=schema_path + (keyword,),
                add_candidate=add_candidate,
                add_child=add_child,
            )

        def recurse(subschema, sub_path, sub_resolver=None):
            self._collect(
                validator=validator,
                schema=subschema,
                resolver=resolver if sub_resolver is None else sub_resolver,
                instance=instance,
                schema_path=sub_path,
                add_candidate=add_candidate,
                add_child=add_child,
            )

        for keyword, keyword_value in applicable.items():
            if keyword in {"$ref", "$recursiveRef", "$dynamicRef"}:
                continue
            path_with_key = schema_path + (keyword,)

            if keyword == "allOf":
                for index, subschema in enumerate(keyword_value):
                    recurse(subschema, path_with_key + (index,))
            elif keyword == "extends":
                values = (
                    keyword_value
                    if isinstance(keyword_value, list)
                    else [keyword_value]
                )
                for index, subschema in enumerate(values):
                    recurse(subschema, path_with_key + (index,))
            elif keyword in {"anyOf", "oneOf"}:
                valid = [
                    (index, subschema)
                    for index, subschema in enumerate(keyword_value)
                    if self._is_valid(validator, subschema, resolver, instance)
                ]
                if len(valid) == 1:
                    index, subschema = valid[0]
                    recurse(subschema, path_with_key + (index,))
            elif keyword == "if":
                if self._is_valid(
                    validator, keyword_value, resolver, instance,
                ):
                    if "then" in schema:
                        recurse(schema["then"], schema_path + ("then",))
                elif "else" in schema:
                    recurse(schema["else"], schema_path + ("else",))
            elif keyword == "dependentSchemas" and is_object:
                for name, subschema in keyword_value.items():
                    if name in instance:
                        recurse(subschema, path_with_key + (name,))
            elif keyword == "dependencies" and is_object:
                for name, dependency in keyword_value.items():
                    if name in instance and isinstance(dependency, dict):
                        recurse(dependency, path_with_key + (name,))
            elif keyword == "properties" and is_object:
                for name, subschema in keyword_value.items():
                    if not isinstance(subschema, dict):
                        continue
                    if name in instance:
                        add_child(
                            name, subschema, resolver, path_with_key + (name,),
                        )
                    if "default" in subschema and name not in instance:
                        add_candidate(
                            name,
                            subschema["default"],
                            path_with_key + (name, "default"),
                            subschema,
                        )
            elif keyword == "patternProperties" and is_object:
                for pattern, subschema in keyword_value.items():
                    for name in instance:
                        if re.search(pattern, name):
                            add_child(
                                name,
                                subschema,
                                resolver,
                                path_with_key + (pattern,),
                            )
            elif keyword == "additionalProperties" and is_object:
                if isinstance(keyword_value, dict):
                    for name in _utils.find_additional_properties(
                        instance, schema,
                    ):
                        add_child(
                            name, keyword_value, resolver, path_with_key,
                        )
            elif keyword == "prefixItems" and is_array:
                for index, subschema in enumerate(
                    keyword_value[: len(instance)],
                ):
                    add_child(
                        index, subschema, resolver, path_with_key + (index,),
                    )
            elif keyword == "items" and is_array:
                if isinstance(keyword_value, dict):
                    prefix = len(schema.get("prefixItems", ()))
                    for index in range(prefix, len(instance)):
                        add_child(
                            index,
                            keyword_value,
                            resolver,
                            path_with_key,
                        )
                else:  # tuple form (draft 4 and 6/7)
                    for index, subschema in enumerate(
                        list(keyword_value)[: len(instance)],
                    ):
                        add_child(
                            index,
                            subschema,
                            resolver,
                            path_with_key + (index,),
                        )
            elif keyword == "additionalItems" and is_array:
                if isinstance(keyword_value, dict):
                    tuple_items = schema.get("items")
                    prefix = (
                        len(tuple_items)
                        if isinstance(tuple_items, list)
                        else 0
                    )
                    for index in range(prefix, len(instance)):
                        add_child(
                            index,
                            keyword_value,
                            resolver,
                            path_with_key,
                        )
