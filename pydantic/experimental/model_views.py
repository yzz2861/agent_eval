"""Experimental utilities for deriving input models from existing models."""

from __future__ import annotations

import copy
import hashlib
import inspect
import types
import typing
from collections.abc import Callable, Iterable, Mapping
from functools import cached_property, wraps
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Generic,
    Literal,
    TypeAlias,
    TypeVar,
    Union,
    get_args,
    get_origin,
)

from pydantic_core import PydanticUndefined
from typing_extensions import TypeAliasType

from pydantic._internal import _decorators, _generics, _utils
from pydantic._internal._forward_ref import PydanticRecursiveRef as _PydanticRecursiveRef
from pydantic._internal._model_construction import ModelMetaclass as _ModelMetaclass
from pydantic._internal._model_construction import unpack_lenient_weakvaluedict as _unpack_lenient_weakvaluedict
from pydantic._internal._repr import display_as_type as _display_as_type
from pydantic.errors import PydanticUserError
from pydantic.fields import ComputedFieldInfo

if TYPE_CHECKING:
    from pydantic.main import BaseModel

__all__ = ('MissingDependencyPolicy', 'depends_on', 'derive_model')

MissingDependencyPolicy: TypeAlias = Literal['error', 'exclude']
FieldSelection: TypeAlias = 'Iterable[str] | bool | type(Ellipsis)'
NestedModelSelection: TypeAlias = 'Mapping[type[BaseModel], FieldSelection] | bool | None'

_MARKER = '__pydantic_view_depends_on__'
_MISSING_DEPENDENCY_POLICY: MissingDependencyPolicy = 'error'


def depends_on(*fields: str) -> Callable[[Any], Any]:
    """Declare fields used by a validator, serializer, or computed field."""

    def decorator(value: Any) -> Any:
        dependencies = frozenset(fields)
        if isinstance(value, _decorators.PydanticDescriptorProxy):
            if isinstance(value.wrapped, property) and value.wrapped.fget is not None:
                setattr(value.wrapped.fget, _MARKER, dependencies)
            elif isinstance(value.wrapped, cached_property):
                setattr(value.wrapped.func, _MARKER, dependencies)
            else:
                _set_marker(value.wrapped, dependencies)
            return value
        if isinstance(value, property):
            getter = value.fget
            if getter is None:
                return value

            @wraps(getter)
            def property_wrapper(*args: Any, **kwargs: Any) -> Any:
                return getter(*args, **kwargs)

            setattr(property_wrapper, _MARKER, dependencies)
            return property(property_wrapper, value.fset, value.fdel, value.__doc__)
        if isinstance(value, cached_property):

            @wraps(value.func)
            def cached_wrapper(*args: Any, **kwargs: Any) -> Any:
                return value.func(*args, **kwargs)

            setattr(cached_wrapper, _MARKER, dependencies)
            return cached_property(cached_wrapper)
        if isinstance(value, (classmethod, staticmethod)):
            wrapped = value.__func__
            setattr(wrapped, _MARKER, dependencies)
            return type(value)(wrapped)
        _set_marker(value, dependencies)
        return value

    return decorator


def _set_marker(value: Any, dependencies: frozenset[str]) -> None:
    setattr(value, _MARKER, dependencies)


def _explicit_dependencies(value: Any) -> frozenset[str] | None:
    target = value
    if isinstance(target, _decorators.PydanticDescriptorProxy):
        target = target.wrapped
    target = _decorators.unwrap_wrapped_function(target)
    if isinstance(target, types.MethodType):
        target = target.__func__
    dependencies = getattr(target, _MARKER, None)
    return frozenset(dependencies) if dependencies is not None else None


def _field_names(model: type[BaseModel]) -> tuple[frozenset[str], frozenset[str]]:
    return frozenset(model.model_fields), frozenset(model.model_computed_fields)


def _resolve_selection(model: type[BaseModel], selection: FieldSelection | None) -> frozenset[str]:
    regular_fields, computed_fields = _field_names(model)
    available = regular_fields | computed_fields
    if selection is ... or selection is True:
        return available
    if selection is False or selection is None:
        return frozenset()
    requested = frozenset(selection) if not isinstance(selection, str) else frozenset({selection})
    unknown = requested - available
    if unknown:
        raise PydanticUserError(
            f'Unknown field(s) selected for {model.__name__}: {sorted(unknown)}.',
            code='model-view-invalid-fields',
        )
    return requested


def _policy_message(kind: str, name: str, missing: Iterable[str]) -> str:
    fields = ', '.join(repr(field) for field in sorted(missing))
    return f'{kind} {name!r} depends on field(s) not included in the derived model: {fields}.'


def _uses_validation_info(value: Any) -> bool:
    if isinstance(value, _decorators.PydanticDescriptorProxy):
        value = value.wrapped
    unwrapped = _decorators.unwrap_wrapped_function(value)
    if isinstance(unwrapped, types.MethodType):
        unwrapped = unwrapped.__func__
    try:
        parameters = tuple(inspect.signature(unwrapped).parameters.values())
    except (TypeError, ValueError):
        return True
    return any(parameter.name in {'info', 'validation_info', 'serialization_info'} for parameter in parameters)


class _ModelViewBuilder:
    def __init__(
        self,
        *,
        nested_models: NestedModelSelection = None,
        recursive_nested: bool = False,
        missing_dependency: MissingDependencyPolicy = _MISSING_DEPENDENCY_POLICY,
        module: str | None,
    ) -> None:
        self.nested_models = nested_models
        self.recursive_nested = recursive_nested
        self.missing_dependency = missing_dependency
        self.module = module
        self.models: dict[type[BaseModel], type[BaseModel]] = {}
        self.pending: dict[type[BaseModel], type[BaseModel]] = {}
        self.active: set[type[BaseModel]] = set()
        self.active_names: dict[type[BaseModel], str] = {}
        self.namespace: dict[str, Any] = {}
        self.order: list[type[BaseModel]] = []

    def selection_for(self, model: type[BaseModel]) -> frozenset[str]:
        if isinstance(self.nested_models, Mapping):
            key = model if model in self.nested_models else model.__pydantic_generic_metadata__.get('origin')
            selected = self.nested_models.get(key)
            if selected is None and key is not None:
                selected = self.nested_models.get(key.__name__)
            if selected is None:
                return frozenset()
            return _resolve_selection(model, selected)
        if self.recursive_nested:
            return _field_names(model)[0] | _field_names(model)[1]
        return frozenset()

    def derive(
        self,
        source: type[BaseModel],
        *,
        selection: FieldSelection | None,
        name: str | None,
    ) -> type[BaseModel]:
        if source in self.models:
            return self.models[source]

        selected = _resolve_selection(source, selection)
        regular_fields, computed_fields = _field_names(source)
        selected_regular = tuple(field for field in source.model_fields if field in selected)
        selected_computed = tuple(field for field in source.model_computed_fields if field in selected)

        origin = source.__pydantic_generic_metadata__.get('origin')
        parameters = source.__pydantic_generic_metadata__.get('parameters', ())
        if origin is not None:
            parameters = ()

        class_name = self._class_name(source, selected, name)
        self.active_names[source] = class_name
        if origin is not None:
            self.active_names[origin] = class_name
        self.active.add(source)
        if origin is not None:
            self.active.add(origin)
        self.pending[source] = None
        try:
            view = self._create_deferred_model(source, class_name, selected_regular, selected_computed, parameters)
        finally:
            self.active.discard(source)
            if origin is not None:
                self.active.discard(origin)
            self.active_names.pop(source, None)
            self.active_names.pop(origin, None)
            self.pending.pop(source, None)

        self.models[source] = view
        self.pending[source] = view
        self.order.append(source)
        self.namespace[class_name] = view

        return view

    def finish(self) -> None:
        rebuilt: set[type[BaseModel]] = set()
        for source in reversed(list(self.order)):
            view = self.models[source]
            if view in rebuilt:
                continue
            namespace = dict(self.namespace)
            parent_namespace = _unpack_lenient_weakvaluedict(getattr(source, '__pydantic_parent_namespace__', None))
            if parent_namespace:
                namespace = {**parent_namespace, **namespace}
            for parameter in source.__pydantic_generic_metadata__.get('parameters', ()):
                namespace.setdefault(parameter.__name__, parameter)
            view.model_rebuild(force=True, _parent_namespace_depth=0, _types_namespace=namespace)
            view.model_config = {
                **view.model_config,
                'defer_build': source.model_config.get('defer_build', False),
            }
            rebuilt.add(view)
        self.pending.clear()

    def _class_name(self, source: type[BaseModel], selected: frozenset[str], explicit_name: str | None) -> str:
        if explicit_name is not None:
            if not explicit_name.isidentifier():
                raise PydanticUserError(
                    f'Derived model name {explicit_name!r} must be a valid Python identifier.',
                    code='model-view-invalid-name',
                )
            return explicit_name

        basis = f'{source.__module__}.{source.__qualname__}:{",".join(sorted(selected))}'
        args = source.__pydantic_generic_metadata__.get('args', ())
        if args:
            basis += ':' + ','.join(_display_as_type(argument) for argument in args)
        digest = hashlib.sha1(basis.encode()).hexdigest()[:10]
        name_basis = source.__pydantic_generic_metadata__.get('origin') or source
        safe_name = ''.join(
            character if character.isalnum() or character == '_' else '_' for character in name_basis.__name__
        )
        return f'{safe_name}_View_{digest}'

    def _create_deferred_model(
        self,
        source: type[BaseModel],
        class_name: str,
        selected_regular: tuple[str, ...],
        selected_computed: tuple[str, ...],
        parameters: tuple[Any, ...],
    ) -> type[BaseModel]:
        from pydantic import BaseModel

        selected = frozenset(selected_regular) | frozenset(selected_computed)
        regular_fields, computed_fields = _field_names(source)
        annotations: dict[str, Any] = {}
        namespace: dict[str, Any] = {
            '__module__': self.module or source.__module__,
            '__qualname__': class_name,
            '__doc__': source.__doc__,
            'model_config': {**source.model_config, 'defer_build': True},
        }

        for field_name in selected_regular:
            field_info = source.model_fields[field_name]._copy()
            annotation = self._rewrite(field_info.annotation, source)
            field_info.annotation = annotation
            field_info._original_annotation = annotation
            field_info._complete = False
            annotations[field_name] = annotation
            namespace[field_name] = field_info

        namespace['__annotations__'] = annotations
        namespace.update(self._selected_decorators(source, selected, regular_fields, computed_fields))

        if parameters:

            @classmethod
            def __class_getitem__(cls: type[BaseModel], typevar_values: Any) -> type[BaseModel]:
                values = typevar_values if isinstance(typevar_values, tuple) else (typevar_values,)
                if values == parameters:
                    return cls
                concrete_source = source[typevar_values]
                concrete_selected = frozenset(name for name in concrete_source.model_fields if name in selected)
                concrete_selected |= frozenset(
                    name for name in concrete_source.model_computed_fields if name in selected
                )
                return self.derive(concrete_source, selection=concrete_selected, name=None)

            namespace['__class_getitem__'] = __class_getitem__

        generic_base = Generic[parameters[0]] if len(parameters) == 1 else types.GenericAlias(Generic, parameters)
        bases: tuple[type[Any], ...] = (BaseModel, generic_base) if parameters else (BaseModel,)
        resolved_bases = types.resolve_bases(bases)
        _, prepared_namespace, kwargs = types.prepare_class(class_name, resolved_bases)
        if resolved_bases is not bases:
            prepared_namespace['__orig_bases__'] = bases
        namespace.update(prepared_namespace)
        generic_metadata = {
            'origin': None,
            'args': (),
            'parameters': parameters,
        }
        return _ModelMetaclass(
            class_name,
            resolved_bases,
            namespace,
            __pydantic_generic_metadata__=generic_metadata,
            __pydantic_reset_parent_namespace__=False,
            _create_model_module=namespace['__module__'],
            **kwargs,
        )

    def _selected_decorators(
        self,
        source: type[BaseModel],
        selected: frozenset[str],
        regular_fields: frozenset[str],
        computed_fields: frozenset[str],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        raw_proxies = self._raw_decorators(source)
        for name, proxy in raw_proxies.items():
            info = proxy.decorator_info
            if isinstance(info, ComputedFieldInfo):
                if name not in selected:
                    continue
                replacement = self._computed_proxy(
                    proxy,
                    source=source,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                )
            elif isinstance(info, _decorators.FieldValidatorDecoratorInfo):
                replacement = self._field_target_proxy(
                    proxy,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                    kind='field_validator',
                    allow_computed=False,
                )
            elif isinstance(info, _decorators.ValidatorDecoratorInfo):
                replacement = self._field_target_proxy(
                    proxy,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                    kind='field_validator',
                    allow_computed=False,
                )
            elif isinstance(info, _decorators.RootValidatorDecoratorInfo):
                replacement = self._model_target_proxy(
                    proxy,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                    kind='model_validator',
                )
            elif isinstance(info, _decorators.ModelValidatorDecoratorInfo):
                replacement = self._model_target_proxy(
                    proxy,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                    kind='model_validator',
                )
            elif isinstance(info, _decorators.FieldSerializerDecoratorInfo):
                replacement = self._field_target_proxy(
                    proxy,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                    kind='field_serializer',
                    allow_computed=True,
                )
            elif isinstance(info, _decorators.ModelSerializerDecoratorInfo):
                replacement = self._model_target_proxy(
                    proxy,
                    selected=selected,
                    regular_fields=regular_fields,
                    computed_fields=computed_fields,
                    kind='model_serializer',
                )
            else:
                replacement = None

            if replacement is not None:
                result[name] = replacement

        return result

    def _raw_decorators(self, source: type[BaseModel]) -> dict[str, _decorators.PydanticDescriptorProxy[Any]]:
        result: dict[str, _decorators.PydanticDescriptorProxy[Any]] = {}
        for base in source.__mro__:
            for name, value in vars(base).items():
                if isinstance(value, _decorators.PydanticDescriptorProxy):
                    result.setdefault(name, value)
        decorators = source.__pydantic_decorators__
        fallback = {
            name: _decorators.PydanticDescriptorProxy(decorator.func, copy.copy(decorator.info), decorator.shim)
            for group in (
                decorators.validators,
                decorators.field_validators,
                decorators.root_validators,
                decorators.field_serializers,
                decorators.model_serializers,
                decorators.model_validators,
                decorators.computed_fields,
            )
            for name, decorator in group.items()
        }
        for name, proxy in fallback.items():
            result.setdefault(name, proxy)
        return result

    def _dependencies(
        self,
        proxy: Any,
        *,
        targets: frozenset[str] | None,
        regular_fields: frozenset[str],
        kind: str,
    ) -> frozenset[str] | None:
        explicit = _explicit_dependencies(proxy)
        if explicit is not None:
            return explicit
        if kind == 'computed_field':
            return None
        if targets is not None:
            if kind == 'field_validator' and _uses_validation_info(proxy.wrapped):
                return regular_fields
            return targets
        return regular_fields

    def _handle_missing(self, *, kind: str, name: str, missing: Iterable[str]) -> bool:
        missing_fields = frozenset(missing)
        if not missing_fields:
            return True
        if self.missing_dependency == 'exclude':
            return False
        raise PydanticUserError(_policy_message(kind, name, missing_fields), code='model-view-missing-dependency')

    def _field_target_proxy(
        self,
        proxy: _decorators.PydanticDescriptorProxy[Any],
        *,
        selected: frozenset[str],
        regular_fields: frozenset[str],
        computed_fields: frozenset[str],
        kind: str,
        allow_computed: bool,
    ) -> Any | None:
        original_targets = frozenset(getattr(proxy.decorator_info, 'fields', ()))
        target_fields = regular_fields | (computed_fields if allow_computed else frozenset())
        if '*' in original_targets:
            targets = selected & target_fields
        else:
            targets = original_targets & selected & target_fields
        if not targets:
            return None

        dependencies = (
            self._dependencies(
                proxy,
                targets=targets,
                regular_fields=regular_fields,
                kind=kind,
            )
            or frozenset()
        )
        missing = (targets | dependencies) - selected
        if not self._handle_missing(kind=kind, name=getattr(proxy.decorator_info, 'fields', targets), missing=missing):
            return None

        info = copy.copy(proxy.decorator_info)
        info.fields = tuple(
            field for field in getattr(proxy.decorator_info, 'fields', ()) if field == '*' or field in targets
        )
        wrapped = proxy.wrapped
        if isinstance(info, _decorators.FieldValidatorDecoratorInfo) and not isinstance(wrapped, classmethod):
            if isinstance(wrapped, types.MethodType):
                wrapped = classmethod(wrapped.__func__)
            else:
                unwrapped = _decorators.unwrap_wrapped_function(wrapped, unwrap_class_static_method=False)
                first_parameter = next(iter(inspect.signature(unwrapped).parameters), None)
                if first_parameter == 'cls':
                    wrapped = classmethod(unwrapped)
        return _decorators.PydanticDescriptorProxy(wrapped, info, proxy.shim)

    def _model_target_proxy(
        self,
        proxy: _decorators.PydanticDescriptorProxy[Any],
        *,
        selected: frozenset[str],
        regular_fields: frozenset[str],
        computed_fields: frozenset[str],
        kind: str,
    ) -> Any | None:
        dependencies = self._dependencies(
            proxy,
            targets=None,
            regular_fields=regular_fields,
            kind=kind,
        )
        unknown = dependencies - (regular_fields | computed_fields)
        if unknown:
            raise PydanticUserError(
                f'{kind} {getattr(proxy.wrapped, "__name__", "model validator")!r} declares unknown field(s): {sorted(unknown)}.',
                code='model-view-invalid-dependency',
            )
        missing = dependencies - selected
        validator_name = getattr(proxy.wrapped, '__name__', 'model validator')
        if not self._handle_missing(kind=kind, name=validator_name, missing=missing):
            return None
        return proxy

    def _computed_proxy(
        self,
        proxy: _decorators.PydanticDescriptorProxy[Any],
        *,
        source: type[BaseModel],
        selected: frozenset[str],
        regular_fields: frozenset[str],
        computed_fields: frozenset[str],
    ) -> Any | None:
        computed_name = getattr(proxy.wrapped, '__name__', 'computed field')
        dependencies = self._dependencies(
            proxy,
            targets=None,
            regular_fields=regular_fields,
            kind='computed_field',
        )
        if dependencies is None:
            raise PydanticUserError(
                f'Computed field {computed_name!r} must declare its field dependencies with @depends_on.',
                code='model-view-missing-dependency',
            )
        unknown = dependencies - (regular_fields | computed_fields)
        if unknown:
            raise PydanticUserError(
                f'Computed field {computed_name!r} declares unknown field(s): {sorted(unknown)}.',
                code='model-view-invalid-dependency',
            )
        missing = dependencies - selected
        if not self._handle_missing(kind='Computed field', name=computed_name, missing=missing):
            return None

        info: ComputedFieldInfo = copy.copy(proxy.decorator_info)
        return_type = info.return_type if info.return_type is not PydanticUndefined else self._return_type(proxy)
        info.return_type = self._rewrite(return_type, source)
        wrapped = self._wrap_computed_property(info.wrapped_property, computed_name, info.return_type)
        info.wrapped_property = wrapped
        return _decorators.PydanticDescriptorProxy(wrapped, info, proxy.shim)

    def _return_type(self, proxy: Any) -> Any:
        try:
            return _decorators.get_callable_return_type(proxy.func)
        except Exception:
            return Any

    def _wrap_computed_property(self, prop: Any, name: str, return_type: Any) -> Any:
        if isinstance(prop, cached_property):
            original = prop.func

            def cached_wrapper(self: Any) -> Any:
                return _coerce_value(original(self), return_type)

            cached_wrapper.__name__ = getattr(original, '__name__', name)
            cached_wrapper.__doc__ = getattr(original, '__doc__', None)
            return cached_property(cached_wrapper)

        if isinstance(prop, property):
            getter = prop.fget
            if getter is None:
                return prop

            def getter_wrapper(self: Any) -> Any:
                return _coerce_value(getter(self), return_type)

            getter_wrapper.__name__ = getattr(getter, '__name__', name)
            getter_wrapper.__doc__ = getattr(getter, '__doc__', None)
            return property(getter_wrapper, prop.fset, prop.fdel, prop.__doc__)

        return prop

    def _rewrite(self, annotation: Any, source: type[BaseModel]) -> Any:
        origin = source.__pydantic_generic_metadata__.get('origin')
        typevars_map = _generics.get_model_typevars_map(source)
        if typevars_map:
            annotation = _generics.replace_types(annotation, typevars_map)

        if isinstance(annotation, TypeVar):
            return annotation
        if isinstance(annotation, _PydanticRecursiveRef):
            active_origin = origin if origin in self.active_names else source
            if active_origin in self.active_names:
                return typing.ForwardRef(self.active_names[active_origin], is_class=True)
            return annotation
        if isinstance(annotation, typing.ForwardRef):
            return annotation

        annotation_origin = get_origin(annotation)
        annotation_args = get_args(annotation)

        if isinstance(annotation, TypeAliasType):
            rewritten_value = self._rewrite(annotation.__value__, source)
            if rewritten_value is annotation.__value__:
                return annotation
            return TypeAliasType(annotation.__name__, rewritten_value, type_params=annotation.__type_params__)

        if _utils.is_model_class(annotation):
            annotation_origin = annotation.__pydantic_generic_metadata__.get('origin')
            parameters = annotation.__pydantic_generic_metadata__.get('parameters', ())
            concrete_args = annotation.__pydantic_generic_metadata__.get('args', ())
            selection = self.selection_for(annotation)

            if concrete_args and annotation not in self.active and annotation_origin not in self.active:
                origin_selection = self.selection_for(annotation_origin)
                rewritten_arguments = tuple(self._rewrite(argument, source) for argument in concrete_args)
                if origin_selection:
                    generic_view = self._build_model(annotation_origin, origin_selection, None)
                    return generic_view[rewritten_arguments if len(rewritten_arguments) > 1 else rewritten_arguments[0]]
                return annotation_origin[
                    rewritten_arguments if len(rewritten_arguments) > 1 else rewritten_arguments[0]
                ]

            if annotation in self.active or annotation_origin in self.active:
                active_origin = annotation if annotation in self.active_names else annotation_origin
                pending_view = self.pending.get(annotation)
                if pending_view is None and annotation_origin is not None:
                    pending_view = self.pending.get(annotation_origin)
                if pending_view is not None:
                    name = pending_view.__name__
                else:
                    name = self.active_names[active_origin]
                expression = name if parameters else name
                return typing.ForwardRef(expression, is_class=True)

            if parameters:
                if not selection:
                    arguments = tuple(self._rewrite(parameter, source) for parameter in parameters)
                    return annotation_origin[arguments if len(arguments) > 1 else arguments[0]]
                return annotation
            if not selection:
                return annotation
            return self._build_model(annotation, selection, None)

        if not annotation_args:
            return annotation

        rewritten_args = tuple(self._rewrite_argument(argument, source) for argument in annotation_args)
        if all(original is rewritten for original, rewritten in zip(annotation_args, rewritten_args, strict=True)):
            return annotation

        if annotation_origin is typing.Annotated:
            return Annotated[tuple(rewritten_args)]
        if isinstance(annotation, types.UnionType):
            result: Any = None
            for argument in rewritten_args:
                result = argument if result is None else result | argument
            return result
        if annotation_origin is Union:
            return Union[rewritten_args]  # noqa: UP007
        if annotation_origin is getattr(typing, 'Callable', None):
            first, *remaining = rewritten_args
            transformed_first = tuple(first) if isinstance(first, list) else first
            return annotation_origin[(transformed_first, *remaining)]
        try:
            return annotation_origin[rewritten_args if len(rewritten_args) > 1 else rewritten_args[0]]
        except (TypeError, KeyError):
            return annotation

    def _rewrite_argument(self, annotation: Any, source: type[BaseModel]) -> Any:
        if isinstance(annotation, list):
            return [self._rewrite_argument(item, source) for item in annotation]
        return self._rewrite(annotation, source)

    def _build_model(self, source: type[BaseModel], selection: frozenset[str], name: str | None) -> type[BaseModel]:
        return self.derive(source, selection=selection, name=name)

    def bind_forward_refs(self) -> None:
        for view in self.models.values():
            for decorator in view.__pydantic_decorators__.computed_fields.values():
                _bind_forward_refs(decorator.info.return_type, self.namespace)


def _bind_forward_refs(annotation: Any, namespace: Mapping[str, Any]) -> None:
    if isinstance(annotation, typing.ForwardRef):
        resolved = eval(annotation.__forward_code__, namespace, namespace)
        annotation.__forward_value__ = resolved
        return
    for argument in get_args(annotation):
        if isinstance(argument, list):
            for item in argument:
                _bind_forward_refs(item, namespace)
        else:
            _bind_forward_refs(argument, namespace)


def _coerce_value(value: Any, annotation: Any) -> Any:
    if value is None or isinstance(annotation, TypeVar):
        return value
    if isinstance(annotation, typing.ForwardRef):
        annotation = getattr(annotation, '__forward_value__', annotation)
        if isinstance(annotation, typing.ForwardRef):
            return value

    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin is typing.Annotated and args:
        return _coerce_value(value, args[0])
    if origin in (Union, getattr(types, 'UnionType', None)):
        model_args = [argument for argument in args if _utils.is_model_class(argument)]
        if _utils.is_model_class(type(value)) and model_args:
            return _coerce_value(value, model_args[0])
        return value
    if _utils.is_model_class(annotation):
        if isinstance(value, annotation):
            return value
        if _utils.is_model_class(type(value)):
            return annotation.model_validate(value, from_attributes=True)
        return annotation.model_validate(value)
    if origin in (list, tuple, set, frozenset) and isinstance(value, (list, tuple, set, frozenset)):
        coerced = [_coerce_value(item, args[0]) for item in value]
        return type(value)(coerced) if isinstance(value, (list, tuple)) else annotation.__origin__(coerced)
    if origin is dict and isinstance(value, Mapping):
        return {_coerce_value(key, args[0]): _coerce_value(item, args[1]) for key, item in value.items()}
    return value


def derive_model(  # noqa: PLR0913
    source: type[BaseModel],
    fields: FieldSelection = ...,
    /,
    *,
    name: str | None = None,
    nested_models: NestedModelSelection = None,
    recursive_nested: bool = False,
    on_missing_dependency: MissingDependencyPolicy = _MISSING_DEPENDENCY_POLICY,
    __module__: str | None = None,
) -> type[BaseModel]:
    """Create an independent model containing the selected fields and compatible decorators."""
    if on_missing_dependency not in ('error', 'exclude'):
        raise PydanticUserError(
            f'Invalid missing dependency policy {on_missing_dependency!r}; expected "error" or "exclude".',
            code='model-view-invalid-policy',
        )

    builder = _ModelViewBuilder(
        nested_models=nested_models,
        recursive_nested=recursive_nested,
        missing_dependency=on_missing_dependency,
        module=__module__,
    )
    view = builder.derive(source, selection=fields, name=name)
    builder.finish()
    builder.bind_forward_refs()
    return view
