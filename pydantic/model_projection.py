"""Derive independent field views from Pydantic models."""

from __future__ import annotations

import dataclasses
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import copy
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from itertools import count as itertools_count
from types import UnionType
from typing import TYPE_CHECKING, Any, ForwardRef, Generic, Literal, TypeVar, Union, cast
from typing import get_args as get_typing_args
from typing import get_origin as get_typing_origin

from pydantic_core import PydanticUndefined
from typing_extensions import TypeAliasType

from ._internal._decorators import (
    PydanticDescriptorProxy,
)
from ._internal._forward_ref import PydanticRecursiveRef
from ._internal._model_construction import ModelMetaclass, build_lenient_weakvaluedict, unpack_lenient_weakvaluedict
from ._internal._namespace_utils import NsResolver
from ._internal._type_refs import model_type_ref
from ._internal._typing_extra import parent_frame_namespace, try_eval_type
from .errors import PydanticUserError
from .main import BaseModel

__all__ = (
    'ModelProjection',
    'depends_on',
    'derive_model',
)

DependencyPolicy = Literal['error', 'exclude', 'include']
if TYPE_CHECKING:
    NestedModelSelector = Callable[[type[BaseModel], tuple[str, ...]], Sequence[str] | 'ModelProjection']
    NestedModels = Literal['none', 'all'] | NestedModelSelector
else:
    NestedModelSelector = Any
    NestedModels = Any

_DEPENDS_ON_ATTR = '_pydantic_depends_on'
_T = TypeVar('_T')
_PLACEHOLDER_IDS = itertools_count(1)


def depends_on(*fields: str) -> Callable[[_T], _T]:
    """Declare fields used by a validator, serializer, or computed field."""

    def decorate(value: _T) -> _T:
        if isinstance(value, property):
            return property(
                value.fget and _mark(value.fget, fields),
                value.fset and _mark(value.fset, fields),
                value.fdel and _mark(value.fdel, fields),
                value.__doc__,
            )
        return _mark(value, fields)

    return decorate


def _mark(value: Any, fields: tuple[str, ...]) -> Any:
    try:
        setattr(value, _DEPENDS_ON_ATTR, fields)
    except (AttributeError, TypeError):
        return _DependencyProxy(value, fields)
    return value


class _DependencyProxy:
    def __init__(self, wrapped: Any, fields: tuple[str, ...]) -> None:
        self.wrapped = wrapped
        self._pydantic_depends_on = fields

    def __getattr__(self, name: str) -> Any:
        return getattr(self.wrapped, name)

    def __get__(self, instance: Any, owner: type[Any] | None = None) -> Any:
        return self.wrapped.__get__(instance, owner)

    @property
    def __class__(self) -> type[Any]:
        return self.wrapped.__class__


@dataclass(frozen=True)
class ModelProjection:
    """Field-view configuration used by :func:`derive_model`."""

    fields: Sequence[str]
    computed_fields: Sequence[str] = ()
    model_name: str | None = None
    dependencies: Mapping[str, Iterable[str] | None] | None = None
    missing_dependencies: DependencyPolicy = 'error'
    undeclared_model_decorators: DependencyPolicy = 'error'
    nested_models: NestedModels = 'none'


@dataclass
class _OriginBuild:
    source: type[BaseModel]
    projected: type[BaseModel]
    spec: ModelProjection
    fields: tuple[str, ...]
    computed_fields: tuple[str, ...]
    forward_refs: dict[str, ForwardRef | Any]
    type_namespace: dict[str, Any]
    decorator_types: dict[tuple[str, str], tuple[str, str, Any]]
    recursive_refs: dict[str, str] = dataclass_field(default_factory=dict)


@dataclass
class _Context:
    nested_models: NestedModels
    globalns: dict[str, Any] = dataclass_field(default_factory=dict)
    model_name: str | None = None
    localns: dict[type[BaseModel], dict[str, Any]] = dataclass_field(default_factory=dict)
    origins: dict[Any, _OriginBuild] = dataclass_field(default_factory=dict)
    builds: list[_OriginBuild] = dataclass_field(default_factory=list)
    active: set[Any] = dataclass_field(default_factory=set)
    ids: itertools_count = dataclass_field(default_factory=lambda: itertools_count(1))


def derive_model(
    model: type[BaseModel],
    /,
    fields: Sequence[str],
    *,
    computed_fields: Sequence[str] = (),
    model_name: str | None = None,
    dependencies: Mapping[str, Iterable[str] | None] | None = None,
    missing_dependencies: DependencyPolicy = 'error',
    undeclared_model_decorators: DependencyPolicy = 'error',
    nested_models: NestedModels = 'none',
) -> type[BaseModel]:
    """Create an independent model containing a selected view of ``model``.

    The source model and its :class:`~pydantic.fields.FieldInfo` instances are not modified.
    Field aliases, constraints, defaults, default factories, metadata, and annotations are all
    copied. Nested Pydantic models are rewritten only when ``nested_models`` enables projection.
    """
    spec = ModelProjection(
        fields=tuple(fields),
        computed_fields=tuple(computed_fields),
        model_name=model_name,
        dependencies=dependencies,
        missing_dependencies=missing_dependencies,
        undeclared_model_decorators=undeclared_model_decorators,
        nested_models=nested_models,
    )
    source_globalns = sys.modules.get(model.__module__).__dict__ if model.__module__ in sys.modules else {}
    source_parent_ns = {
        **(unpack_lenient_weakvaluedict(getattr(model, '__pydantic_parent_namespace__', None)) or {}),
        **(parent_frame_namespace(parent_depth=2) or {}),
    }
    origin = model.__pydantic_generic_metadata__['origin'] or model
    context = _Context(nested_models=nested_models, globalns=source_globalns, model_name=model_name)
    context.localns[origin] = source_parent_ns
    build = _ensure_origin(origin, spec, context, ())
    _finalize(context)

    args = model.__pydantic_generic_metadata__['args']
    if not args:
        return build.projected
    transformed_args = tuple(_transform_type(arg, context, ()) for arg in args)
    return build.projected[transformed_args]


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _validate_fields(source: type[BaseModel], names: Sequence[str], *, computed: bool) -> tuple[str, ...]:
    result = _dedupe(names)
    available = source.model_computed_fields if computed else source.model_fields
    label = 'Computed field' if computed else 'Field'
    for name in result:
        if name not in available:
            raise PydanticUserError(
                f'{label} {name!r} is not defined on {source.__name__!r}.',
                code='projection-config',
            )
    return result


def _new_ref(context: _Context) -> ForwardRef:
    return ForwardRef(f'__pydantic_projection_ref_{next(_PLACEHOLDER_IDS)}__', is_argument=False, is_class=True)


def _nested_spec(source: type[BaseModel], path: tuple[str, ...], context: _Context) -> ModelProjection | None:
    selector = context.nested_models
    if selector == 'none':
        return None
    if selector == 'all':
        return ModelProjection(fields=tuple(source.model_fields), computed_fields=tuple(source.model_computed_fields))
    selected = selector(source, path)
    if isinstance(selected, ModelProjection):
        return selected
    return ModelProjection(fields=tuple(selected))


def _ensure_origin(
    source: type[BaseModel],
    spec: ModelProjection,
    context: _Context,
    path: tuple[str, ...],
) -> _OriginBuild:
    context.localns.setdefault(
        source,
        unpack_lenient_weakvaluedict(getattr(source, '__pydantic_parent_namespace__', None)) or {},
    )
    cache_key = (
        source,
        tuple(spec.fields),
        tuple(spec.computed_fields),
        spec.missing_dependencies,
        spec.undeclared_model_decorators,
        spec.nested_models,
    )
    cached = context.origins.get(cache_key)
    if cached is not None:
        return cached

    fields = _validate_fields(source, spec.fields, computed=False)
    computed_names = _validate_fields(source, spec.computed_fields, computed=True)
    forward_refs = {name: _new_ref(context) for name in fields}
    creation_spec = spec if spec.model_name is not None else dataclasses.replace(spec, model_name=context.model_name)
    projected = _create_projected_model(source, creation_spec, fields, computed_names, forward_refs)
    build = _OriginBuild(
        source=source,
        projected=projected,
        spec=spec,
        fields=fields,
        computed_fields=computed_names,
        forward_refs=forward_refs,
        type_namespace={},
        decorator_types={},
    )
    context.origins[cache_key] = build

    if source in context.active:
        return build

    context.active.add(source)
    try:
        for name in fields:
            annotation = source.__annotations__.get(name, source.model_fields[name].annotation)
            forward_refs[name] = _transform_type(annotation, context, path + (name,))
        build.type_namespace = _transform_decorator_types(build, context, path)
    finally:
        context.active.remove(source)
    context.builds.append(build)
    return build


def _create_projected_model(
    source: type[BaseModel],
    spec: ModelProjection,
    fields: Sequence[str],
    computed_names: Sequence[str],
    forward_refs: Mapping[str, ForwardRef | Any],
) -> type[BaseModel]:
    field_definitions: dict[str, Any] = {}
    for name in fields:
        field_info = source.model_fields[name]._copy()
        field_info.annotation = forward_refs[name]
        field_info._original_annotation = forward_refs[name]
        field_info._complete = isinstance(forward_refs[name], ForwardRef)
        field_definitions[name] = (forward_refs[name], field_info)

    namespace = _selected_decorators(source, tuple(fields), tuple(computed_names), spec)
    parameters = source.__pydantic_generic_metadata__['parameters']
    if not parameters:
        bases: Any = (BaseModel,)
    else:
        bases = (BaseModel, Generic)

    config = dict(source.model_config)
    config['defer_build'] = True
    model_namespace = {
        '__annotations__': dict(forward_refs),
        '__module__': source.__module__,
        '__doc__': source.__doc__,
        '__orig_bases__': (Generic[parameters],) if parameters else (),
        'model_config': config,
        **{name: field_info for name, (_, field_info) in field_definitions.items()},
        **namespace,
    }
    projected_model = cast(
        type[BaseModel],
        ModelMetaclass(
            spec.model_name or f'{source.__name__}Projection',
            tuple(bases),
            model_namespace,
            __pydantic_reset_parent_namespace__=False,
        ),
    )
    return projected_model


def _finalize(context: _Context) -> None:
    namespace: dict[str, Any] = {}
    recursive_namespace = _recursive_namespace(context)
    for build in reversed(context.builds):
        namespace.update(build.type_namespace)

    for build in context.builds:
        for name, annotation in build.forward_refs.items():
            field_info = build.projected.model_fields[name]
            field_info.annotation = annotation
            field_info._original_annotation = annotation
            field_info._complete = False
            build.projected.__annotations__[name] = annotation
        _apply_decorator_types(build)
    for build in context.builds:
        build_namespace = {**namespace, **recursive_namespace, **_build_recursive_namespace(build)}
        local_namespace = {
            build.projected.__name__: build.projected,
            **{
                parameter.__name__: parameter
                for parameter in build.projected.__pydantic_generic_metadata__['parameters']
            },
        }
        build_namespace = {**build_namespace, **local_namespace}
        build.projected.__pydantic_parent_namespace__ = build_lenient_weakvaluedict(build_namespace)
        build.projected.model_rebuild(
            force=True, raise_errors=True, _parent_namespace_depth=0, _types_namespace=build_namespace
        )


def _recursive_namespace(context: _Context) -> dict[str, Any]:
    result = {}
    for build in context.builds:
        projected = build.projected
        result[_recursive_ref_name(projected)] = PydanticRecursiveRef(model_type_ref(projected))
    return result


def _build_recursive_namespace(build: _OriginBuild) -> dict[str, Any]:
    return {name: PydanticRecursiveRef(ref) for name, ref in build.recursive_refs.items()}


def _get_source_proxy(source: type[BaseModel], name: str) -> PydanticDescriptorProxy[Any]:
    for base in source.__mro__:
        proxy = base.__dict__.get(name)
        if isinstance(proxy, _DependencyProxy):
            return proxy
        if name in base.__dict__:
            for collection in (
                base.__dict__.get('__pydantic_decorators__')
                and (
                    base.__dict__['__pydantic_decorators__'].field_validators,
                    base.__dict__['__pydantic_decorators__'].validators,
                    base.__dict__['__pydantic_decorators__'].root_validators,
                    base.__dict__['__pydantic_decorators__'].field_serializers,
                    base.__dict__['__pydantic_decorators__'].model_serializers,
                    base.__dict__['__pydantic_decorators__'].model_validators,
                    base.__dict__['__pydantic_decorators__'].computed_fields,
                )
                or ()
            ):
                if name in collection:
                    if isinstance(proxy, PydanticDescriptorProxy):
                        return proxy
                    wrapped = proxy.wrapped if isinstance(proxy, _DependencyProxy) else proxy
                    return PydanticDescriptorProxy(wrapped, copy(collection[name].info), collection[name].shim)
        if isinstance(proxy, PydanticDescriptorProxy):
            return proxy
    decorators = source.__pydantic_decorators__
    for collection in (
        decorators.field_validators,
        decorators.validators,
        decorators.root_validators,
        decorators.field_serializers,
        decorators.model_serializers,
        decorators.model_validators,
        decorators.computed_fields,
    ):
        decorator = collection.get(name)
        if decorator is not None:
            return PydanticDescriptorProxy(source.__dict__[name], copy(decorator.info), decorator.shim)
    raise PydanticUserError(f'Unable to locate decorator {name!r} on {source.__name__!r}.', code=None)


def _declared_dependencies(
    proxy: PydanticDescriptorProxy[Any],
    name: str,
    spec: ModelProjection,
) -> tuple[str, ...] | None:
    explicit = (spec.dependencies or {}).get(name)
    if explicit is None and name in (spec.dependencies or {}):
        return ()
    if explicit is not None:
        return tuple(explicit)

    candidates = []
    current: Any = proxy
    for _ in range(6):
        candidates.append(current)
        if isinstance(current, _DependencyProxy):
            current = current.wrapped
        elif isinstance(current, PydanticDescriptorProxy):
            current = current.wrapped
        elif isinstance(current, (classmethod, staticmethod)):
            nested = getattr(current.__func__, _DEPENDS_ON_ATTR, None)
            if nested is not None:
                current = current.__func__
            else:
                break
        elif isinstance(current, property):
            current = current.fget
        else:
            break
    for candidate in candidates:
        dependencies = getattr(candidate, _DEPENDS_ON_ATTR, None)
        if dependencies is not None:
            return tuple(dependencies)
    return None


def _policy_include(
    name: str,
    dependencies: tuple[str, ...] | None,
    selected: tuple[str, ...],
    policy: DependencyPolicy,
    *,
    require_declaration: bool,
) -> bool:
    available = set(selected)
    if require_declaration and dependencies is None:
        if policy == 'include':
            return True
        if policy == 'exclude':
            return False
        raise PydanticUserError(
            f'Decorator {name!r} must declare its field dependencies with @depends_on(...) to be projected.',
            code='projection-config',
        )

    declared = dependencies or ()
    missing = [field_name for field_name in declared if field_name not in available]
    if missing and policy == 'error':
        raise PydanticUserError(
            f'Decorator {name!r} depends on fields that are not projected: {", ".join(missing)}.',
            code='projection-config',
        )
    if missing and policy == 'exclude':
        return False
    return True


def _copy_proxy(proxy: PydanticDescriptorProxy[Any]) -> PydanticDescriptorProxy[Any]:
    if isinstance(proxy, _DependencyProxy):
        if isinstance(proxy.wrapped, PydanticDescriptorProxy):
            inner = proxy.wrapped
            copied_inner = PydanticDescriptorProxy(inner.wrapped, copy(inner.decorator_info), inner.shim)
            return _DependencyProxy(copied_inner, proxy._pydantic_depends_on)
        return _DependencyProxy(proxy.wrapped, proxy._pydantic_depends_on)
    return PydanticDescriptorProxy(proxy.wrapped, copy(proxy.decorator_info), proxy.shim)


def _selected_decorators(
    source: type[BaseModel],
    selected_fields: tuple[str, ...],
    selected_computed: tuple[str, ...],
    spec: ModelProjection,
) -> dict[str, PydanticDescriptorProxy[Any]]:
    selected = selected_fields + selected_computed
    selected_set = set(selected)
    result: dict[str, PydanticDescriptorProxy[Any]] = {}

    field_categories = (
        source.__pydantic_decorators__.field_validators,
        source.__pydantic_decorators__.validators,
        source.__pydantic_decorators__.field_serializers,
    )
    for category in field_categories:
        for name in category:
            proxy = _get_source_proxy(source, name)
            copied = _copy_proxy(proxy)
            info = copied.decorator_info
            targets = info.fields
            if '*' in targets:
                copied_targets = selected_fields
            else:
                copied_targets = tuple(target for target in targets if target in selected_set)
            if not copied_targets:
                continue
            dependencies = _declared_dependencies(copied, name, spec)
            if '*' in targets and dependencies is None:
                if spec.undeclared_model_decorators == 'error':
                    raise PydanticUserError(
                        f"Decorator {name!r} uses '*' and must declare dependencies to be projected.",
                        code='projection-config',
                    )
                if spec.undeclared_model_decorators == 'exclude':
                    continue
            if dependencies is not None and not _policy_include(
                name,
                dependencies,
                selected,
                spec.missing_dependencies,
                require_declaration=False,
            ):
                continue
            info.fields = copied_targets
            result[name] = copied

    for name in source.__pydantic_decorators__.root_validators:
        proxy = _get_source_proxy(source, name)
        dependencies = _declared_dependencies(proxy, name, spec)
        if _policy_include(
            name,
            dependencies,
            selected,
            spec.undeclared_model_decorators if dependencies is None else spec.missing_dependencies,
            require_declaration=True,
        ):
            result[name] = _copy_proxy(proxy)

    model_categories = (
        source.__pydantic_decorators__.model_validators,
        source.__pydantic_decorators__.model_serializers,
    )
    for category in model_categories:
        for name in category:
            proxy = _get_source_proxy(source, name)
            dependencies = _declared_dependencies(proxy, name, spec)
            if _policy_include(
                name,
                dependencies,
                selected,
                spec.undeclared_model_decorators if dependencies is None else spec.missing_dependencies,
                require_declaration=True,
            ):
                result[name] = _copy_proxy(proxy)

    for name in selected_computed:
        proxy = _get_source_proxy(source, name)
        dependencies = _declared_dependencies(proxy, name, spec)
        if _policy_include(
            name,
            dependencies,
            selected_fields,
            spec.missing_dependencies,
            require_declaration=True,
        ):
            result[name] = _copy_proxy(proxy)

    return result


def _transform_decorator_types(
    build: _OriginBuild,
    context: _Context,
    path: tuple[str, ...],
) -> dict[str, Any]:
    result: dict[str, tuple[str, str, Any]] = {}

    def remember(category: str, name: str, annotation: Any) -> None:
        if annotation is not None and annotation is not PydanticUndefined:
            result[(category, name)] = (category, name, _transform_type(annotation, context, path))

    decorators = build.source.__pydantic_decorators__
    for name, decorator in decorators.computed_fields.items():
        if name in build.computed_fields:
            remember('computed_field', name, decorator.info.return_type)
    for name, decorator in decorators.field_validators.items():
        remember('field_validator', name, decorator.info.json_schema_input_type)
    for category_name, category in (
        ('field_serializer', decorators.field_serializers),
        ('model_serializer', decorators.model_serializers),
    ):
        for name, decorator in category.items():
            remember(category_name, name, decorator.info.return_type)
    return result


def _apply_decorator_types(build: _OriginBuild) -> None:
    decorators = build.projected.__pydantic_decorators__
    for category_name, name, annotation in build.decorator_types.values():
        if category_name == 'computed_field':
            decorator = decorators.computed_fields[name]
            decorator.info = dataclasses.replace(decorator.info, return_type=annotation)
            build.projected.__pydantic_computed_fields__[name] = decorator.info
        elif category_name == 'field_validator':
            decorator = decorators.field_validators[name]
            decorator.info = dataclasses.replace(decorator.info, json_schema_input_type=annotation)
        else:
            category = (
                decorators.field_serializers if category_name == 'field_serializer' else decorators.model_serializers
            )
            decorator = category[name]
            decorator.info = dataclasses.replace(decorator.info, return_type=annotation)


def _is_model(value: Any) -> bool:
    return isinstance(value, type) and issubclass(value, BaseModel) and value is not BaseModel


def _origin(value: type[BaseModel]) -> type[BaseModel]:
    return value.__pydantic_generic_metadata__['origin'] or value


def _transform_forward_ref(
    value: ForwardRef,
    context: _Context,
    path: tuple[str, ...],
    source: type[BaseModel] | None,
) -> Any:
    if source is None:
        return value
    if source.__name__ in value.__forward_arg__:
        return _rewrite_self_forward_ref(value, source, build_for_source(context, source))
    ns_resolver = NsResolver(
        namespaces_tuple=(context.globalns, context.localns.get(source, {})),
        parent_namespace={**context.globalns, **context.localns.get(source, {})},
    )
    with ns_resolver.push(source):
        evaluated, evaluated_ok = try_eval_type(value, *ns_resolver.types_namespace)
    if not evaluated_ok:
        return value
    if _is_model(evaluated) and _origin(evaluated) is source:
        return _rewrite_self_forward_ref(
            value,
            source,
            build_for_source(context, source),
        )
    return _transform_type(evaluated, context, path)


def build_for_source(context: _Context, source: type[BaseModel]) -> _OriginBuild:
    for build in context.origins.values():
        if build.source is source:
            return build
    raise PydanticUserError(f'Missing projection for {source.__name__!r}.', code=None)


def _rewrite_self_forward_ref(
    value: ForwardRef,
    source: type[BaseModel],
    build: _OriginBuild,
) -> ForwardRef:
    expression = value.__forward_arg__
    projected_name = build.projected.__name__
    expression = expression.replace(source.__name__, projected_name)
    ref = ForwardRef(expression, is_argument=value.__forward_is_argument__, is_class=value.__forward_is_class__)
    ref.__forward_evaluated__ = False
    return ref


def _transform_type(value: Any, context: _Context, path: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        value = ForwardRef(value, is_argument=False, is_class=True)
    if isinstance(value, ForwardRef):
        source = list(context.active)[-1] if context.active else None
        return _transform_forward_ref(value, context, path, source)
    if isinstance(value, TypeAliasType):
        transformed_value = _transform_type(value.__value__, context, path)
        if transformed_value is value.__value__:
            return value
        return TypeAliasType(value.__name__, transformed_value, type_params=value.__type_params__)
    if _is_model(value):
        source_origin = _origin(value)
        spec = _nested_spec(source_origin, path, context)
        if spec is None:
            return value
        build = _ensure_origin(source_origin, spec, context, path)
        args = value.__pydantic_generic_metadata__['args']
        transformed_args = tuple(_transform_type(arg, context, path) for arg in args)
        if source_origin in context.active:
            return _recursive_ref(build, transformed_args, context)
        if not transformed_args:
            return build.projected
        return build.projected[transformed_args]

    origin = get_typing_origin(value)
    args = get_typing_args(value)
    if origin is None or not args:
        return value

    transformed_args = tuple(_transform_type(arg, context, path) for arg in args)
    if all(new is old for new, old in zip(transformed_args, args, strict=True)):
        return value
    if isinstance(value, UnionType):
        result: Any = transformed_args[0]
        for arg in transformed_args[1:]:
            result |= arg
        return result
    try:
        return origin[transformed_args]
    except TypeError:
        if origin is Union:
            return Union[transformed_args]  # noqa: UP007
        raise


def _recursive_ref(build: _OriginBuild, args: tuple[Any, ...], context: _Context) -> Any:
    type_ref = model_type_ref(build.projected) if not args else model_type_ref(build.projected, args_override=args)
    name = f'__pydantic_recursive_{next(_PLACEHOLDER_IDS)}__'
    build.recursive_refs[name] = type_ref
    return PydanticRecursiveRef(type_ref)


def _recursive_ref_name(projected: type[BaseModel]) -> str:
    return f'__pydantic_recursive_{id(projected)}__'
