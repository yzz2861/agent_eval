from collections import defaultdict
from typing import Any, Callable, TypeVar, Union

from attrs import NOTHING, NothingType

from .. import BaseConverter
from .._compat import (
    NoneType,
    adapted_fields,
    get_args,
    get_newtype_base,
    get_origin,
    has,
    is_annotated,
    is_literal,
    is_subclass,
    is_union_type,
)
from .._generics import deep_copy_with
from ..converters import UnstructureStrategy
from ..disambiguators import create_default_dis_func
from ..errors import (
    AmbiguousUnionError,
    AttributeValidationNote,
    ClassValidationError,
    IterableValidationNote,
    UnionValidationError,
)
from ..gen._generics import generate_mapping
from ..typealiases import get_type_alias_base, is_type_alias

__all__ = [
    "configure_strict_union",
    "configure_tagged_union",
    "configure_union_passthrough",
    "default_tag_generator",
]


def _format_type(type_: Any) -> str:
    if type_ is NoneType:
        return "None"
    if get_origin(type_) is not None:
        return repr(type_)
    return getattr(type_, "__name__", repr(type_))


def _validate_input(
    value: Any, type_: Any, converter: BaseConverter | None = None
) -> None:
    if isinstance(type_, TypeVar) or is_annotated(type_):
        if is_annotated(type_):
            _validate_input(value, type_.__origin__, converter)
        return
    if is_type_alias(type_):
        _validate_input(value, get_type_alias_base(type_), converter)
        return
    if is_union_type(type_):
        if (
            converter is not None
            and type_ in converter._union_struct_registry
            and not getattr(
                converter._union_struct_registry[type_],
                "__cattrs_strict_union__",
                False,
            )
        ):
            return
        errors = []
        failed_types = []
        for arg in type_.__args__:
            try:
                if (
                    converter is not None
                    and is_union_type(arg)
                    and arg in converter._union_struct_registry
                    and not getattr(
                        converter._union_struct_registry[arg],
                        "__cattrs_strict_union__",
                        False,
                    )
                ):
                    continue
                _validate_input(value, arg, converter)
            except Exception as exc:
                errors.append(exc)
                failed_types.append(arg)
        if errors:
            raise UnionValidationError(
                f"While structuring {type_!r}", errors, type_, tuple(failed_types)
            )
        return
    if is_literal(type_):
        if value not in type_.__args__:
            raise TypeError(f"{value!r} is not in {type_!r}")
        return

    origin = get_origin(type_)
    if origin is tuple:
        args = get_args(type_)
        if not isinstance(value, tuple):
            raise TypeError(f"{value!r} is not a tuple")
        for index, item in enumerate(value):
            if len(args) == 2 and args[1] is Ellipsis:
                item_type = args[0]
            elif index < len(args):
                item_type = args[index]
            else:
                raise TypeError(f"Extra tuple value {item!r}")
            try:
                _validate_input(item, item_type, converter)
            except Exception as exc:
                note = IterableValidationNote(
                    f"Structuring {type_} @ index {index}", index, item_type
                )
                exc.__notes__ = [*getattr(exc, "__notes__", []), note]
                raise
        if not (len(args) == 2 and args[1] is Ellipsis) and len(value) < len(args):
            raise TypeError("Not enough tuple values")
        return
    if origin in (list, set, frozenset):
        item_type = get_args(type_)[0]
        if not isinstance(value, origin):
            raise TypeError(f"{value!r} is not a {origin.__name__}")
        for index, item in enumerate(value):
            try:
                _validate_input(item, item_type, converter)
            except Exception as exc:
                note = IterableValidationNote(
                    f"Structuring {type_} @ index {index}", index, item_type
                )
                exc.__notes__ = [*getattr(exc, "__notes__", []), note]
                raise
        return
    if origin is dict:
        if not isinstance(value, dict):
            raise TypeError(f"{value!r} is not a dict")
        key_type, value_type = get_args(type_)
        for key, item in value.items():
            try:
                _validate_input(item, value_type, converter)
            except Exception as exc:
                note = IterableValidationNote(
                    f"Structuring mapping value @ key {key!r}", key, value_type
                )
                exc.__notes__ = [*getattr(exc, "__notes__", []), note]
                raise
            _validate_input(key, key_type, converter)
        return

    newtype_base = get_newtype_base(type_)
    if newtype_base is not None:
        _validate_input(value, newtype_base, converter)
        return
    if type_ is bool:
        valid = isinstance(value, bool)
    elif type_ in (int, float):
        valid = isinstance(value, type_) and not isinstance(value, bool)
    elif type_ in (str, bytes):
        valid = isinstance(value, type_)
    else:
        valid = True

    if not valid:
        raise TypeError(f"{value!r} is not {_format_type(type_)}")

    target_origin = origin or type_
    if not has(target_origin):
        return
    mapping = generate_mapping(type_)
    if (
        converter is not None
        and converter.unstruct_strat is UnstructureStrategy.AS_TUPLE
    ):
        if not isinstance(value, tuple):
            raise TypeError(f"{value!r} is not a tuple")
        for index, (attribute, item) in enumerate(
            zip(adapted_fields(target_origin), value, strict=False)
        ):
            attribute_type = (
                mapping[attribute.type.__name__]
                if isinstance(attribute.type, TypeVar)
                else deep_copy_with(attribute.type, mapping)
            )
            try:
                _validate_input(item, attribute_type, converter)
            except Exception as exc:
                note = IterableValidationNote(
                    f"Structuring {type_} @ index {index}", index, attribute_type
                )
                exc.__notes__ = [*getattr(exc, "__notes__", []), note]
                raise
        required_count = sum(
            attribute.default is NOTHING for attribute in adapted_fields(target_origin)
        )
        if len(value) < required_count:
            raise TypeError("Not enough tuple values")
        if len(value) > len(adapted_fields(target_origin)):
            raise TypeError("Too many tuple values")
        return
    if isinstance(value, dict):
        errors = []
        for attribute in adapted_fields(target_origin):
            if attribute.name not in value:
                if attribute.default is NOTHING:
                    exc = KeyError(attribute.name)
                    note = AttributeValidationNote(
                        f"Structuring class {target_origin.__name__} @ attribute {attribute.name}",
                        attribute.name,
                        attribute.type,
                    )
                    exc.__notes__ = [*getattr(exc, "__notes__", []), note]
                    errors.append(exc)
                continue
            attribute_type = (
                mapping[attribute.type.__name__]
                if isinstance(attribute.type, TypeVar)
                else deep_copy_with(attribute.type, mapping)
            )
            try:
                _validate_input(value[attribute.name], attribute_type, converter)
            except Exception as exc:
                note = AttributeValidationNote(
                    f"Structuring class {target_origin.__name__} @ attribute {attribute.name}",
                    attribute.name,
                    attribute_type,
                )
                exc.__notes__ = [*getattr(exc, "__notes__", []), note]
                errors.append(exc)
        if errors:
            raise ClassValidationError(f"While structuring {type_!r}", errors, type_)


def configure_strict_union(union: Any, converter: BaseConverter) -> None:
    """Configure a converter to structure ``union`` strictly.

    Literal fields are still used when they can explicitly identify a member.
    Otherwise every member hook is attempted once. If exactly one member
    succeeds, its result is returned. Zero or multiple successes produce
    structured validation errors.

    Nested unions and generic classes are configured recursively. Existing
    explicit union hooks, including tagged-union hooks, take precedence over
    the generated strict hook.

    :param union: The union, or type alias of a union, to configure.
    :param converter: The converter to configure.
    """
    resolved_union = get_type_alias_base(union) if is_type_alias(union) else union
    _register_strict_union(resolved_union, converter, set())
    if is_type_alias(union):
        converter.register_structure_hook(
            union,
            lambda val, _, _union=resolved_union: converter.structure(val, _union),
        )


def _register_strict_union(
    resolved_union: Any, converter: BaseConverter, seen: set[Any]
) -> None:
    if resolved_union in seen:
        return
    seen.add(resolved_union)

    args = resolved_union.__args__
    non_none_args = tuple(arg for arg in args if arg is not NoneType)

    literal_dis = None
    if len(non_none_args) >= 2 and all(
        has(get_origin(arg) or arg) for arg in non_none_args
    ):
        try:
            literal_dis = create_default_dis_func(
                converter, *non_none_args, use_literals=True, use_unique_fields=False
            )
        except TypeError:
            literal_dis = None

    def structure_strict_union(val: Any, _: Any = resolved_union) -> Any:
        if val is None and NoneType in args:
            return None

        cache: dict[Any, tuple[bool, Any]] = {}

        def attempt_candidate(candidate: Any) -> None:
            if candidate in cache:
                return

            if candidate is NoneType:
                cache[candidate] = (False, TypeError("Expected a non-None value"))
                return

            if is_type_alias(candidate):
                candidate_base = get_type_alias_base(candidate)
                if is_union_type(candidate_base):
                    try:
                        result = evaluate_union(candidate_base)
                    except Exception as exc:
                        cache[candidate] = (False, exc)
                    else:
                        cache[candidate] = (True, result)
                        cache[candidate_base] = (True, result)
                    return
                candidate_to_structure = candidate_base
            elif is_union_type(candidate):
                try:
                    result = evaluate_union(candidate)
                except Exception as exc:
                    cache[candidate] = (False, exc)
                else:
                    cache[candidate] = (True, result)
                return
            else:
                candidate_to_structure = candidate

            try:
                _validate_input(val, candidate_to_structure, converter)
                result = converter.get_structure_hook(candidate)(val, candidate)
            except Exception as exc:
                cache[candidate] = (False, exc)
            else:
                cache[candidate] = (True, result)
                cache[candidate_to_structure] = (True, result)

        def evaluate_union(union_type: Any) -> Any:
            successes = []
            errors = []
            evaluated_types = []

            for candidate in union_type.__args__:
                attempt_candidate(candidate)
                is_success, result = cache[candidate]
                evaluated_types.append(candidate)
                if is_success:
                    successes.append((candidate, result))
                else:
                    errors.append(result)

            if len(successes) == 1:
                return successes[0][1]
            if not successes:
                raise UnionValidationError(
                    f"While structuring {union_type!r}",
                    errors,
                    union_type,
                    tuple(evaluated_types),
                )

            successful_types = tuple(candidate for candidate, _ in successes)
            raise AmbiguousUnionError(
                "Ambiguous union "
                f"{union_type!r}: {', '.join(_format_type(t) for t in successful_types)} "
                "all structured successfully",
                union_type,
                successful_types,
            )

        if literal_dis is not None:
            selected_type = literal_dis(val)
            if is_union_type(selected_type):
                return evaluate_union(selected_type)
            attempt_candidate(selected_type)
            is_success, result = cache[selected_type]
            if is_success:
                return result
            raise result

        return evaluate_union(resolved_union)

    structure_strict_union.__cattrs_strict_union__ = True
    converter.register_structure_hook(resolved_union, structure_strict_union)

    for arg in non_none_args:
        _register_nested_strict_unions(arg, converter, seen)


def _register_nested_strict_unions(
    type_: Any, converter: BaseConverter, seen: set[Any]
) -> None:
    if type_ in seen:
        return
    seen.add(type_)

    if is_type_alias(type_):
        _register_nested_strict_unions(get_type_alias_base(type_), converter, seen)
        return

    if is_union_type(type_):
        if type_ not in converter._union_struct_registry:
            _register_strict_union(type_, converter, seen)
        return

    for arg in get_args(type_):
        _register_nested_strict_unions(arg, converter, seen)

    origin = get_origin(type_) or type_
    if has(origin):
        mapping = generate_mapping(type_)
        for attribute in adapted_fields(origin):
            if attribute.type is not None:
                attribute_type = (
                    mapping[attribute.type.__name__]
                    if isinstance(attribute.type, TypeVar)
                    else deep_copy_with(attribute.type, mapping)
                )
                _register_nested_strict_unions(attribute_type, converter, seen)


def default_tag_generator(typ: type) -> str:
    """Return the class name."""
    return typ.__name__


def configure_tagged_union(
    union: Any,
    converter: BaseConverter,
    tag_generator: Callable[[type], str] = default_tag_generator,
    tag_name: str = "_type",
    default: Union[type, NothingType] = NOTHING,
) -> None:
    """
    Configure the converter so that `union` (which should be a union, or a type alias
    of one) is un/structured with the help of an additional piece of data in the
    unstructured payload, the tag.

    :param converter: The converter to apply the strategy to.
    :param tag_generator: A `tag_generator` function is used to map each
        member of the union to a tag, which is then included in the
        unstructured payload. The default tag generator returns the name of
        the class.
    :param tag_name: The key under which the tag will be set in the
        unstructured payload. By default, `'_type'`.
    :param default: An optional class to be used if the tag information
        is not present when structuring.

    The tagged union strategy currently only works with the dict
    un/structuring base strategy.

    .. versionadded:: 23.1.0

    ..  versionchanged:: 25.1
        Type aliases of unions are now also supported.
    """
    if is_type_alias(union):
        union = union.__value__
    args = union.__args__

    tag_to_hook = {}
    exact_cl_unstruct_hooks = {}
    cl_to_tag = {}

    if default is not NOTHING:
        default_handler = converter.get_structure_hook(default)

        def structure_default(val: dict, _cl=default, _h=default_handler):
            return _h(val, _cl)

        tag_to_hook = defaultdict(lambda: structure_default)
        cl_to_tag = defaultdict(lambda: default)

        if getattr(converter, "forbid_extra_keys", False):

            def structure_tagged_union(
                val: dict,
                _,
                _tag_to_hook=tag_to_hook,
                _tag_name=tag_name,
                _dh=default_handler,
                _default=default,
            ) -> union:
                if _tag_name in val:
                    val = val.copy()
                    return _tag_to_hook[val.pop(_tag_name)](val)
                return _dh(val, _default)

        else:

            def structure_tagged_union(
                val: dict,
                _,
                _tag_to_hook=tag_to_hook,
                _tag_name=tag_name,
                _dh=default_handler,
                _default=default,
            ) -> union:
                if _tag_name in val:
                    return _tag_to_hook[val[_tag_name]](val)
                return _dh(val, _default)

    else:
        if getattr(converter, "forbid_extra_keys", False):

            def structure_tagged_union(
                val: dict, _, _tag_to_cl=tag_to_hook, _tag_name=tag_name
            ) -> union:
                val = val.copy()
                return _tag_to_cl[val.pop(_tag_name)](val)

        else:

            def structure_tagged_union(
                val: dict, _, _tag_to_cl=tag_to_hook, _tag_name=tag_name
            ) -> union:
                return _tag_to_cl[val[_tag_name]](val)

    def unstructure_tagged_union(
        val: union,
        _exact_cl_unstruct_hooks=exact_cl_unstruct_hooks,
        _cl_to_tag=cl_to_tag,
        _tag_name=tag_name,
    ) -> dict:
        res = _exact_cl_unstruct_hooks[val.__class__](val)
        res[_tag_name] = _cl_to_tag[val.__class__]
        return res

    converter.register_unstructure_hook(union, unstructure_tagged_union)
    converter.register_structure_hook(union, structure_tagged_union)

    for cl in args:
        tag = tag_generator(cl)
        struct_handler = converter.get_structure_hook(cl)
        unstruct_handler = converter.get_unstructure_hook(cl)

        def structure_union_member(val: dict, _cl=cl, _h=struct_handler) -> cl:
            return _h(val, _cl)

        def unstructure_union_member(val: union, _h=unstruct_handler) -> dict:
            return _h(val)

        tag_to_hook[tag] = structure_union_member
        exact_cl_unstruct_hooks[cl] = unstructure_union_member
        cl_to_tag[cl] = tag


def configure_union_passthrough(
    union: Any, converter: BaseConverter, accept_ints_as_floats: bool = True
) -> None:
    """
    Configure the converter to support validating and passing through unions of the
    provided types and their subsets.

    For example, all mature JSON libraries natively support producing unions of ints,
    floats, Nones, and strings. Using this strategy, a converter can be configured
    to efficiently validate and pass through unions containing these types.

    The most important point is that another library (in this example the JSON
    library) handles producing the union, and the converter is configured to just
    validate it.

    Literals of provided types are also supported, and are checked by value.

    NewTypes of provided types are also supported.

    The strategy is designed to be O(1) in execution time, and independent of the
    ordering of types in the union.

    If the union contains a class and one or more of its subclasses, the subclasses
    will also be included when validating the superclass.

    :param accept_ints_as_floats: When set (the default), if the provided union
        contains both ints and floats, actual unions containing only floats will also accept
        ints. See https://typing.python.org/en/latest/spec/special-types.html#special-cases-for-float-and-complex
        for more information.

    .. versionadded:: 23.2.0
    .. versionchanged:: 25.2.0
        Introduced the `accept_ints_as_floats` parameter.
    .. versionchanged:: 26.2.0
        PEP 695 type aliases are now supported as union members.
    """

    def get_passthrough_base(type: Any) -> Any:
        return get_type_alias_base(type) if is_type_alias(type) else type

    args = {get_passthrough_base(type) for type in union.__args__}

    def make_structure_native_union(exact_type: Any) -> Callable:
        # `exact_type` is likely to be a subset of the entire configured union (`args`).
        literal_values = {
            v for t in exact_type.__args__ if is_literal(t) for v in t.__args__
        }

        # We have no idea what the actual type of `val` will be, so we can't
        # use it blindly with an `in` check since it might not be hashable.
        # So we do an additional check when handling literals.
        # Note: do no use `literal_values` here, since {0, False} gets reduced to {0}
        literal_classes = {
            v.__class__
            for t in exact_type.__args__
            if is_literal(t)
            for v in t.__args__
        }

        non_literal_classes = {
            get_newtype_base(t) or get_passthrough_base(t)
            for t in exact_type.__args__
            if not is_literal(t)
            and ((get_newtype_base(t) or get_passthrough_base(t)) in args)
        }

        # We augment the set of allowed classes with any configured subclasses of
        # the exact subclasses.
        non_literal_classes |= {
            a for a in args if any(is_subclass(a, c) for c in non_literal_classes)
        }

        # We check for spillover - union types not handled by the strategy.
        # If spillover exists and we fail to validate our types, we call
        # further into the converter with the rest.
        spillover = {
            a
            for a in exact_type.__args__
            if (get_newtype_base(a) or get_passthrough_base(a))
            not in non_literal_classes
            and not is_literal(a)
        }

        # By default, when floats are part of the union, accept ints too.
        if (
            accept_ints_as_floats
            and int in args
            and float in args
            and float in non_literal_classes
            and int not in non_literal_classes
        ):
            non_literal_classes.add(int)

        if spillover:
            spillover_type = (
                Union[tuple(spillover)] if len(spillover) > 1 else next(iter(spillover))
            )

            def structure_native_union(
                val: Any,
                _: Any,
                classes=non_literal_classes,
                vals=literal_values,
                converter=converter,
                spillover=spillover_type,
            ) -> exact_type:
                if val.__class__ in literal_classes and val in vals:
                    return val
                if val.__class__ in classes:
                    return val
                return converter.structure(val, spillover)

        else:

            def structure_native_union(
                val: Any, _: Any, classes=non_literal_classes, vals=literal_values
            ) -> exact_type:
                if val.__class__ in literal_classes and val in vals:
                    return val
                if val.__class__ in classes:
                    return val
                raise TypeError(f"{val} ({val.__class__}) not part of {_}")

        return structure_native_union

    def contains_native_union(exact_type: Any) -> bool:
        """Can we handle this type?"""
        if is_union_type(exact_type):
            type_args = set(exact_type.__args__)
            # We special case optionals, since they are very common
            # and are handled a little more efficiently by default.
            if len(type_args) == 2 and type(None) in type_args:
                return False

            literal_classes = {
                lit_arg.__class__
                for t in type_args
                if is_literal(t)
                for lit_arg in t.__args__
            }
            non_literal_types = {
                get_newtype_base(t) or get_passthrough_base(t)
                for t in type_args
                if not is_literal(t)
            }

            return (literal_classes | non_literal_types) & args
        return False

    converter.register_structure_hook_factory(
        contains_native_union, make_structure_native_union
    )
