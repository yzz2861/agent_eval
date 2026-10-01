"""
Explicit, opt-in application of the :kw:`default` annotation.

The :kw:`default` keyword is an annotation: plain validation never adds
default values to an instance. The entry point provided here,
`apply_defaults`, deliberately keeps that behavior and instead returns a
deep-copied, completed instance along with the schema location each newly
inserted value originated from.

Only genuinely missing locations are filled; an explicit ``null`` is
preserved. Conflicting defaults (e.g. between ``allOf`` branches) and
defaults that would require guessing between ``anyOf``/``oneOf`` branches
are reported rather than silently resolved. The completed copy is finally
successfully validated against the original schema before it is returned.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from attrs import define, field
from referencing.exceptions import Unresolvable as _Unresolvable
import referencing.jsonschema

from jsonschema import _legacy_keywords, _utils, exceptions


@define(eq=False)
class AppliedDefault:
    """
    A single value inserted by `apply_defaults`.

    Attributes:

        path: the location within the instance where ``value`` was inserted.
        value: the inserted value (the same object held in the completed
            instance, not an additional copy).
        schema: the subschema carrying the used :kw:`default` keyword.
        schema_path: the location of that subschema from the root schema.
            References are represented explicitly in the path.
        schema_uri: the base URI of the resource containing ``schema``.
    """

    path: tuple[Any, ...]
    value: Any
    schema: Mapping[str, Any]
    schema_path: tuple[Any, ...]
    schema_uri: str


@define
class Completion:
    """
    The result of `apply_defaults`.

    Attributes:

        instance: the completed deep copy of the original instance.
        applied: every value newly inserted into ``instance``, in schema
            traversal order. The original instance is never mutated.
    """

    instance: Any
    applied: list[AppliedDefault] = field(factory=list)

    @property
    def defaults(self) -> dict[tuple[Any, ...], AppliedDefault]:
        """The inserted values keyed by their location in the instance."""
        return {each.path: each for each in self.applied}


class DefaultsConflict(Exception):
    """
    Applicable subschemas provide unequal defaults for one location.

    Attributes:

        path: the instance location at which the conflict was found.
        values: the unequal proposed values, in traversal order.
        sources: the schema paths of the conflicting :kw:`default` keywords.
    """

    def __init__(self, path, values, sources):
        self.path = tuple(path)
        self.values = list(values)
        self.sources = [tuple(source) for source in sources]
        location = "/" + "/".join(str(part) for part in self.path) or "/"
        super().__init__(
            f"Conflicting defaults at {location}: "
            f"{self.values!r} from {self.sources!r}",
        )


def apply_defaults(instance, schema, cls=None, *args, **kwargs):
    """
    Return a deep copy of ``instance`` completed with applicable defaults.

    The :kw:`default` JSON Schema keyword is only an annotation, so
    `jsonschema.validate` never mutates or completes an instance. This
    function provides that behavior explicitly and never mutates
    ``instance`` itself.

    Defaults are added only at genuinely missing locations: an explicitly
    present ``null`` is not missing and is preserved. When several
    applicable subschemas (e.g. ``allOf`` branches or ``then``/``else``)
    provide a default for the same missing location the values must be
    equal, otherwise `DefaultsConflict` is raised. ``anyOf``/``oneOf``
    branch defaults are applied only when a single branch unambiguously
    matches the (partially completed) instance. References (including
    ``$dynamicRef`` / ``$recursiveRef``), conditional branches and nested
    object defaults are followed, with cycle protection so recursive
    schemas always terminate.

    Before returning, the completed copy is validated against the original
    schema; if it is invalid, the first
    `~jsonschema.exceptions.ValidationError` is raised rather than
    returning a partially completed result.

    Returns:

        Completion: the completed copy and provenance of each added value.

    Raises:

        DefaultsConflict: applicable defaults disagree at a location.
        jsonschema.exceptions.ValidationError: the completed instance does
            not validate under the original schema.
        jsonschema.exceptions.SchemaError: the schema itself is invalid.
    """
    if cls is None:
        from jsonschema.validators import validator_for

        cls = validator_for(schema)
    cls.check_schema(schema)
    validator = cls(schema, *args, **kwargs)
    return validator.apply_defaults(instance)


_SPECIFICATIONS_BY_META_ID = {
    "http://json-schema.org/draft-03/schema": referencing.jsonschema.DRAFT3,
    "http://json-schema.org/draft-04/schema": referencing.jsonschema.DRAFT4,
    "http://json-schema.org/draft-06/schema": referencing.jsonschema.DRAFT6,
    "http://json-schema.org/draft-07/schema": referencing.jsonschema.DRAFT7,
    "https://json-schema.org/draft/2019-09/schema": (
        referencing.jsonschema.DRAFT201909
    ),
    "https://json-schema.org/draft/2020-12/schema": (
        referencing.jsonschema.DRAFT202012
    ),
}


class _Completer:
    def __init__(self, validator):
        self._validator = validator
        self._specification = self._detect_specification(validator)
        self.applied: list[AppliedDefault] = []

    @staticmethod
    def _detect_specification(validator):
        meta_schema = validator.META_SCHEMA
        meta_id = (
            validator.ID_OF(meta_schema)
            if isinstance(meta_schema, Mapping)
            else None
        )
        if meta_id is not None:
            from urllib.parse import urldefrag

            meta_id, _ = urldefrag(meta_id)
            specification = _SPECIFICATIONS_BY_META_ID.get(meta_id)
            if specification is not None:
                return specification
        return referencing.jsonschema.DRAFT202012

    def complete(self, instance):
        original = deepcopy(instance)
        result = deepcopy(instance)
        self._original = original
        self._result = result
        self._sources: dict[tuple[Any, ...], AppliedDefault] = {}
        self._traverse(
            schema=self._validator.schema,
            instance=result,
            validator=self._validator,
            path=(),
            schema_trail=(),
            synthetic_chain=frozenset(),
            local_visited=None,
        )
        error = exceptions.best_match(self._validator.iter_errors(result))
        if error is not None:
            raise error
        return Completion(instance=result, applied=self.applied)

    # -- reference / resolver helpers ---------------------------------

    def _evolved(self, validator, schema, resolver):
        return validator.evolve(schema=schema, _resolver=resolver)

    def _subvalidator(self, validator, schema):
        if validator._ref_resolver is not None:
            return validator.evolve(schema=schema)
        resolver = self._in_subresource(validator, schema)
        return validator.evolve(schema=schema, _resolver=resolver)

    def _in_subresource(self, validator, schema):
        return validator._resolver.in_subresource(
            self._specification.create_resource(schema),
        )

    def _resolve(self, validator, keyword, ref):
        if validator._ref_resolver is not None:
            resolve = getattr(validator._ref_resolver, "resolve", None)
            if resolve is None:
                with validator._ref_resolver.resolving(ref) as resolved:
                    return resolved, validator.evolve(schema=resolved)
            scope, resolved = resolve(ref)
            validator._ref_resolver.push_scope(scope)
            try:
                evolved = validator.evolve(schema=resolved)
            finally:
                validator._ref_resolver.pop_scope()
            return resolved, evolved

        if keyword == "$recursiveRef":
            from referencing.jsonschema import lookup_recursive_ref

            resolved = lookup_recursive_ref(validator._resolver)
        else:
            try:
                resolved = validator._resolver.lookup(ref)
            except _Unresolvable as error:
                raise exceptions._WrappedReferencingError(error) from error
        evolved = self._evolved(
            validator, resolved.contents, resolved.resolver,
        )
        return resolved.contents, evolved

    def _base_uri(self, validator):
        if validator._resolver is not None:
            return validator._resolver._base_uri
        if validator._ref_resolver is not None:
            return validator._ref_resolver.resolution_scope
        return ""  # pragma: no cover

    def _schema_key(self, schema, validator):
        return (id(schema), self._base_uri(validator))

    def _legacy_refs(self, validator):
        applicable = getattr(
            validator._APPLICABLE_VALIDATORS, "__func__", None,
        )
        return applicable is _legacy_keywords.ignore_ref_siblings

    # -- proposal handling --------------------------------------------

    def _record_default(
        self, *, path, value, schema, validator, schema_trail, chain,
    ):
        """Insert ``value`` at missing ``path`` and remember its source."""
        source_key = self._schema_key(schema, validator)
        if source_key in chain:
            return
        container_path, name = path[:-1], path[-1]
        if self._present_in_original(container_path, name):
            return
        container = self._navigate(self._result, container_path)
        if name in container:
            existing = container[name]
            if not _utils.equal(existing, value):
                raise DefaultsConflict(
                    path,
                    [existing, value],
                    [self._source_of(container_path, name), schema_trail],
                )
            return
        inserted = deepcopy(value)
        container[name] = inserted
        applied = AppliedDefault(
            path=path,
            value=inserted,
            schema=schema,
            schema_path=tuple(schema_trail),
            schema_uri=self._base_uri(validator),
        )
        self.applied.append(applied)
        self._sources[path] = applied
        # Descend into the newly inserted value, allowing its (acyclic on
        # this chain) subschema to contribute further nested defaults.
        self._traverse(
            schema=schema,
            instance=inserted,
            validator=validator,
            path=path,
            schema_trail=schema_trail,
            synthetic_chain=chain | {source_key},
            local_visited=None,
        )

    def _present_in_original(self, container_path, name):
        try:
            container = self._navigate(self._original, container_path)
        except (KeyError, IndexError, TypeError):
            return False
        return isinstance(container, dict) and name in container

    def _source_of(self, path, name):
        applied = self._sources.get((*path, name))
        if applied is not None:
            return applied.schema_path
        return ()

    def _navigate(self, root, path):
        current = root
        for part in path:
            current = current[part]
        return current

    # -- traversal -----------------------------------------------------

    def _traverse(
        self,
        *,
        schema,
        instance,
        validator,
        path,
        schema_trail,
        synthetic_chain,
        local_visited,
        ref_is_shadowing=False,
    ):
        if (
            schema is True
            or schema is False
            or not isinstance(schema, Mapping)
        ):
            return

        # Cycle protection is scoped to one descent. Descents into values
        # present in the original instance start fresh; descents into
        # inserted values share the set with their synthetic chain.
        if local_visited is None:
            local_visited = set()
        key = self._schema_key(schema, validator)
        if key in local_visited:
            return
        local_visited.add(key)

        # Reference keywords. Resolve first so their resolved scope is used
        # for everything below; pre-2019-09 ``$ref`` shadows siblings.
        ref = schema.get("$ref")
        if ref is not None:
            target, evolved = self._resolve(validator, "$ref", ref)
            # Shadowing persists down the reference chain.
            shadows = ref_is_shadowing or self._legacy_refs(validator)
            self._traverse(
                schema=target,
                instance=instance,
                validator=evolved,
                path=path,
                schema_trail=(*schema_trail, "$ref"),
                synthetic_chain=synthetic_chain,
                local_visited=local_visited,
                ref_is_shadowing=shadows,
            )
            if self._legacy_refs(validator):
                # Pre-2019-09: a ``$ref`` shadows every sibling keyword,
                # including (recursively) the siblings of its target.
                return

        if not ref_is_shadowing:
            for keyword in ("$dynamicRef", "$recursiveRef"):
                reference = schema.get(keyword)
                if reference is None:
                    continue
                target, evolved = self._resolve(validator, keyword, reference)
                self._traverse(
                    schema=target,
                    instance=instance,
                    validator=evolved,
                    path=path,
                    schema_trail=(*schema_trail, keyword),
                    synthetic_chain=synthetic_chain,
                    local_visited=local_visited,
                    ref_is_shadowing=ref_is_shadowing,
                )

        if isinstance(instance, dict):
            self._traverse_object(
                schema=schema,
                instance=instance,
                validator=validator,
                path=path,
                schema_trail=schema_trail,
                synthetic_chain=synthetic_chain,
                local_visited=local_visited,
                ref_is_shadowing=ref_is_shadowing,
            )
        elif isinstance(instance, list):
            self._traverse_array(
                schema=schema,
                instance=instance,
                validator=validator,
                path=path,
                schema_trail=schema_trail,
                synthetic_chain=synthetic_chain,
                local_visited=local_visited,
            )

        self._traverse_applicators(
            schema=schema,
            instance=instance,
            validator=validator,
            path=path,
            schema_trail=schema_trail,
            synthetic_chain=synthetic_chain,
            local_visited=local_visited,
            ref_is_shadowing=ref_is_shadowing,
        )

    def _traverse_object(
        self,
        *,
        schema,
        instance,
        validator,
        path,
        schema_trail,
        synthetic_chain,
        local_visited,
        ref_is_shadowing,
    ):
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return

        for name, subschema in properties.items():
            property_trail = (*schema_trail, "properties", name)
            subvalidator = self._subvalidator(validator, subschema)
            if name in instance:
                # Values present in the original instance (including an
                # explicit ``null``) are never replaced. Defaults proposed
                # for a value that was itself inserted must still agree with
                # what was inserted, otherwise that is a real conflict.
                originally_present = self._present_in_original(path, name)
                if not originally_present:
                    candidates = self._gather_defaults(
                        schema=subschema,
                        validator=subvalidator,
                        schema_trail=property_trail,
                        chain=synthetic_chain,
                        seen=set(),
                        ref_is_shadowing=ref_is_shadowing,
                    )
                    for candidate in candidates:
                        if not _utils.equal(candidate[0], instance[name]):
                            raise DefaultsConflict(
                                (*path, name),
                                [instance[name], candidate[0]],
                                [
                                    self._source_of(path, name),
                                    candidate[1],
                                ],
                            )
                self._traverse(
                    schema=subschema,
                    instance=instance[name],
                    validator=subvalidator,
                    path=(*path, name),
                    schema_trail=property_trail,
                    synthetic_chain=(
                        frozenset()
                        if originally_present
                        else synthetic_chain
                    ),
                    local_visited=None,
                )
                continue

            candidates = self._gather_defaults(
                schema=subschema,
                validator=subvalidator,
                schema_trail=property_trail,
                chain=synthetic_chain,
                seen=set(),
                ref_is_shadowing=ref_is_shadowing,
            )
            if not candidates:
                continue
            chosen_value, chosen_trail, chosen_schema, chosen_validator = (
                candidates[0]
            )
            unequal = [
                candidate
                for candidate in candidates[1:]
                if not _utils.equal(candidate[0], chosen_value)
            ]
            if unequal:
                raise DefaultsConflict(
                    (*path, name),
                    [candidate[0] for candidate in candidates],
                    [candidate[1] for candidate in candidates],
                )
            self._record_default(
                path=(*path, name),
                value=chosen_value,
                schema=chosen_schema,
                validator=chosen_validator,
                schema_trail=chosen_trail,
                chain=synthetic_chain,
            )

    def _gather_defaults(
        self,
        *,
        schema,
        validator,
        schema_trail,
        chain,
        seen,
        ref_is_shadowing=False,
    ):
        """
        Collect unconditional ``default`` candidates for a missing value.

        Only unconditional structure is considered: ``if``/``then``/``else``
        and ``anyOf``/``oneOf`` cannot be evaluated without a value and do
        not contribute here.
        """
        if (
            schema is True
            or schema is False
            or not isinstance(schema, Mapping)
        ):
            return []

        key = self._schema_key(schema, validator)
        if key in seen or key in chain:
            return []
        seen.add(key)

        candidates = []

        def add_ref(keyword, reference, ref_validator):
            target, evolved = self._resolve(ref_validator, keyword, reference)
            candidates.extend(
                self._gather_defaults(
                    schema=target,
                    validator=evolved,
                    schema_trail=(*schema_trail, keyword),
                    chain=chain,
                    seen=seen,
                    ref_is_shadowing=(
                        keyword == "$ref"
                        and (
                            ref_is_shadowing
                            or self._legacy_refs(ref_validator)
                        )
                    ),
                ),
            )

        ref = schema.get("$ref")
        if ref is not None:
            add_ref("$ref", ref, validator)
            if ref_is_shadowing or self._legacy_refs(validator):
                return candidates
        for keyword in ("$dynamicRef", "$recursiveRef"):
            reference = schema.get(keyword)
            if reference is not None:
                add_ref(keyword, reference, validator)

        for index, branch in enumerate(schema.get("allOf", ())):
            branch_validator = self._subvalidator(validator, branch)
            candidates.extend(
                self._gather_defaults(
                    schema=branch,
                    validator=branch_validator,
                    schema_trail=(*schema_trail, "allOf", index),
                    chain=chain,
                    seen=seen,
                    ref_is_shadowing=ref_is_shadowing,
                ),
            )

        extends = schema.get("extends")  # draft 3
        if extends is not None:
            branches = extends if isinstance(extends, list) else [extends]
            for index, branch in enumerate(branches):
                branch_validator = self._subvalidator(validator, branch)
                candidates.extend(
                    self._gather_defaults(
                        schema=branch,
                        validator=branch_validator,
                        schema_trail=(*schema_trail, "extends", index),
                        chain=chain,
                        seen=seen,
                        ref_is_shadowing=ref_is_shadowing,
                    ),
                )

        if "default" in schema:
            candidates.append(
                (schema["default"], schema_trail, schema, validator),
            )
        return candidates

    def _traverse_array(
        self,
        *,
        schema,
        instance,
        validator,
        path,
        schema_trail,
        synthetic_chain,
        local_visited,
    ):
        # Arrays have no named, missing positions to fill. Existing elements
        # can still carry nested object defaults.
        for index, element in enumerate(instance):
            subschema, element_trail = self._item_schema_at(
                schema, index, schema_trail,
            )
            if subschema is None:
                continue
            if subschema is True or subschema is False:
                continue
            subvalidator = self._subvalidator(validator, subschema)
            self._traverse(
                schema=subschema,
                instance=element,
                validator=subvalidator,
                path=(*path, index),
                schema_trail=element_trail,
                synthetic_chain=frozenset(),
                local_visited=None,
            )

    @staticmethod
    def _item_schema_at(schema, index, schema_trail):
        """Return ``(subschema, schema_path)`` for array item ``index``."""
        prefix_items = schema.get("prefixItems")
        if isinstance(prefix_items, list):
            if index < len(prefix_items):
                return prefix_items[index], (
                    *schema_trail, "prefixItems", index,
                )
            items = schema.get("items", True)
            if isinstance(items, Mapping):
                return items, (*schema_trail, "items")
            return None, None

        items = schema.get("items")
        if isinstance(items, list):  # draft 3 / 4 tuple form
            if index < len(items):
                return items[index], (*schema_trail, "items", index)
            additional = schema.get("additionalItems", True)
            if isinstance(additional, Mapping):
                return additional, (*schema_trail, "additionalItems")
            return None, None
        if isinstance(items, Mapping):
            return items, (*schema_trail, "items")
        return None, None

    def _traverse_applicators(
        self,
        *,
        schema,
        instance,
        validator,
        path,
        schema_trail,
        synthetic_chain,
        local_visited,
        ref_is_shadowing,
    ):
        if ref_is_shadowing:
            return
        for index, branch in enumerate(schema.get("allOf", ())):
            branch_validator = self._subvalidator(validator, branch)
            self._traverse(
                schema=branch,
                instance=instance,
                validator=branch_validator,
                path=path,
                schema_trail=(*schema_trail, "allOf", index),
                synthetic_chain=synthetic_chain,
                local_visited=local_visited,
            )

        extends = schema.get("extends")  # draft 3
        if extends is not None:
            branches = extends if isinstance(extends, list) else [extends]
            for index, branch in enumerate(branches):
                branch_validator = self._subvalidator(validator, branch)
                self._traverse(
                    schema=branch,
                    instance=instance,
                    validator=branch_validator,
                    path=path,
                    schema_trail=(*schema_trail, "extends", index),
                    synthetic_chain=synthetic_chain,
                    local_visited=local_visited,
                )

        if "if" in schema:
            if_validator = self._subvalidator(validator, schema["if"])
            if if_validator.is_valid(instance):
                then = schema.get("then")
                if then is not None:
                    self._traverse(
                        schema=then,
                        instance=instance,
                        validator=self._subvalidator(validator, then),
                        path=path,
                        schema_trail=(*schema_trail, "then"),
                        synthetic_chain=synthetic_chain,
                        local_visited=local_visited,
                    )
            else:
                otherwise = schema.get("else")
                if otherwise is not None:
                    self._traverse(
                        schema=otherwise,
                        instance=instance,
                        validator=self._subvalidator(validator, otherwise),
                        path=path,
                        schema_trail=(*schema_trail, "else"),
                        synthetic_chain=synthetic_chain,
                        local_visited=local_visited,
                    )

        dependencies = schema.get("dependentSchemas")
        legacy_dependencies = schema.get("dependencies")
        if dependencies is None and isinstance(
            legacy_dependencies, Mapping,
        ):
            dependencies = {
                name: value
                for name, value in legacy_dependencies.items()
                if isinstance(value, Mapping)
            }
        if isinstance(dependencies, Mapping) and isinstance(instance, dict):
            for name, branch in dependencies.items():
                if name not in instance:
                    continue
                self._traverse(
                    schema=branch,
                    instance=instance,
                    validator=self._subvalidator(validator, branch),
                    path=path,
                    schema_trail=(
                        *schema_trail,
                        "dependentSchemas"
                        if "dependentSchemas" in schema
                        else "dependencies",
                        name,
                    ),
                    synthetic_chain=synthetic_chain,
                    local_visited=local_visited,
                )

        for keyword in ("anyOf", "oneOf"):
            branches = schema.get(keyword)
            if not isinstance(branches, list):
                continue
            matching = []
            for index, branch in enumerate(branches):
                branch_validator = self._subvalidator(validator, branch)
                if branch_validator.is_valid(instance):
                    matching.append((index, branch, branch_validator))
                    if keyword == "anyOf" and len(matching) > 1:
                        break
            if len(matching) != 1:
                continue
            index, branch, branch_validator = matching[0]
            self._traverse(
                schema=branch,
                instance=instance,
                validator=branch_validator,
                path=path,
                schema_trail=(*schema_trail, keyword, index),
                synthetic_chain=synthetic_chain,
                local_visited=local_visited,
            )
