# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Dataclass-based query string binding."""

from __future__ import annotations

from collections.abc import Callable
import dataclasses
from dataclasses import field as dataclass_field
from dataclasses import MISSING
from functools import lru_cache
from functools import wraps
import inspect
from typing import (
    Any,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
    TypeVar,
    Union,
)

try:
    from types import UnionType
except ImportError:  # pragma: no cover py39
    UnionType = type(None)

from falcon.constants import FALSE_STRINGS
from falcon.constants import TRUE_STRINGS
from falcon.errors import QueryBindingError
from falcon.errors import QueryErrorDetail
from falcon.util.uri import decode

__all__ = (
    'QueryBindingError',
    'bind_query',
    'bind_query_model',
    'query_field',
)

_MODEL_T = TypeVar('_MODEL_T')
_RESPONDER_T = TypeVar('_RESPONDER_T', bound=Callable[..., Any])

_ALIAS_METADATA = 'falcon.query.alias'
_CONVERTER_METADATA = 'falcon.query.converter'

_SCALAR = 1
_OBJECT = 2
_LIST = 3


class _QueryNode:
    """Store all values encountered for one parsed parameter path."""

    __slots__ = ('children', 'explicit_empty_list', 'kind', 'values')

    def __init__(self, kind: int | None = None) -> None:
        self.children: dict[str, _QueryNode] = {}
        self.explicit_empty_list = False
        self.kind = kind
        self.values: list[str] = []


class _FieldModel:
    """Describe one supported dataclass field."""

    __slots__ = (
        'alias',
        'converter',
        'has_default',
        'kind',
        'model',
        'name',
        'optional',
    )

    def __init__(
        self,
        *,
        alias: str,
        converter: Callable[[str], Any] | None,
        has_default: bool,
        kind: int,
        model: Any,
        name: str,
        optional: bool,
    ) -> None:
        self.alias = alias
        self.converter = converter
        self.has_default = has_default
        self.kind = kind
        self.model = model
        self.name = name
        self.optional = optional


class _ObjectModel:
    """Describe the fields of a bound dataclass."""

    __slots__ = ('fields', 'fields_by_alias', 'object_type')

    def __init__(self, object_type: type[Any]) -> None:
        self.object_type = object_type
        self.fields: list[_FieldModel] = []
        self.fields_by_alias: dict[str, _FieldModel] = {}


@overload
def query_field(*, default: Any) -> Any: ...


@overload
def query_field(
    *,
    alias: str | None = ...,
    converter: Callable[[str], Any] | None = ...,
    default: Any = ...,
    default_factory: Callable[[], Any] | None = ...,
) -> Any: ...


def query_field(
    *,
    alias: str | None = None,
    converter: Callable[[str], Any] | None = None,
    default: Any = MISSING,
    default_factory: Callable[[], Any] | None = None,
) -> Any:
    """Create a dataclass field with query binding metadata.

    Keyword Args:
        alias: Query parameter name to use instead of the dataclass field
            name.
        converter: Callable that converts one raw string value to the field's
            Python type. It is called separately for each list item.
        default: Default value used when the parameter is absent.
        default_factory: Zero-argument callable used to create a default value when
            the parameter is absent.

    Returns:
        A dataclass field containing the query-specific metadata.
    """

    metadata: dict[str, Any] = {}
    if alias is not None:
        metadata[_ALIAS_METADATA] = alias
    if converter is not None:
        metadata[_CONVERTER_METADATA] = converter

    kwargs: dict[str, Any] = {'metadata': metadata}
    if default is not MISSING:
        kwargs['default'] = default
    if default_factory is not None:
        kwargs['default_factory'] = default_factory

    return dataclass_field(**kwargs)


def bind_query(
    model: type[_MODEL_T],
    *,
    param_name: str = 'query',
    unknown: str = 'strict',
    max_depth: int = 5,
    max_errors: int = 10,
    max_params: int = 100,
) -> Callable[[_RESPONDER_T], _RESPONDER_T]:
    """Decorate a responder with dataclass query-string binding.

    Args:
        model: Dataclass type used to describe and bind the query string.

    Keyword Args:
        param_name: Keyword argument name used when calling the responder
            (default ``'query'``).
        unknown: Set to ``'strict'`` to reject unknown parameters, or
            ``'ignore'`` to leave them out of the model.
        max_depth: Maximum number of nested bracket segments.
        max_errors: Maximum number of parameter errors to report.
        max_params: Maximum number of query parameters to accept.

    Returns:
        A decorator that binds both WSGI and ASGI responders.

    Raises:
        ValueError: One of the supplied options is invalid.
        TypeError: The model or responder signature is unsupported.
        QueryBindingError: Raised at request time when the query string is invalid.
    """

    _validate_options(unknown, max_depth, max_errors, max_params)
    _compile_model(model)

    def decorator(responder: _RESPONDER_T) -> _RESPONDER_T:
        signature = inspect.signature(responder)

        if param_name not in signature.parameters and not any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        ):
            raise TypeError(
                f'Responder {responder.__qualname__!r} must accept a '
                f'{param_name!r} keyword argument.'
            )
        if inspect.iscoroutinefunction(responder):

            async def async_wrapper(
                resource: Any,
                req: Any,
                resp: Any,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                if param_name in kwargs:
                    raise RuntimeError(
                        f'Query parameter {param_name!r} conflicts with a '
                        'route parameter.'
                    )
                kwargs[param_name] = bind_query_model(
                    req.query_string,
                    model,
                    unknown=unknown,
                    max_depth=max_depth,
                    max_errors=max_errors,
                    max_params=max_params,
                )
                return await responder(resource, req, resp, *args, **kwargs)

            return cast('_RESPONDER_T', wraps(responder)(async_wrapper))

        def sync_wrapper(
            resource: Any, req: Any, resp: Any, *args: Any, **kwargs: Any
        ) -> Any:
            if param_name in kwargs:
                raise RuntimeError(
                    f'Query parameter {param_name!r} conflicts with a route parameter.'
                )
            kwargs[param_name] = bind_query_model(
                req.query_string,
                model,
                unknown=unknown,
                max_depth=max_depth,
                max_errors=max_errors,
                max_params=max_params,
            )
            return responder(resource, req, resp, *args, **kwargs)

        return cast('_RESPONDER_T', wraps(responder)(sync_wrapper))

    return decorator


def bind_query_model(
    query_string: str,
    model: type[_MODEL_T],
    *,
    unknown: str = 'strict',
    max_depth: int = 5,
    max_errors: int = 10,
    max_params: int = 100,
) -> _MODEL_T:
    """Bind a raw query string to a dataclass model instance.

    Args:
        query_string: Raw query string, without the leading ``?`` character.
        model: Dataclass type used to describe and bind the query string.

    Keyword Args:
        unknown: Set to ``'strict'`` to reject unknown parameters, or
            ``'ignore'`` to leave them out of the model.
        max_depth: Maximum number of nested bracket segments.
        max_errors: Maximum number of parameter errors to report.
        max_params: Maximum number of query parameters to accept.

    Returns:
        The populated dataclass instance.

    Raises:
        ValueError: One of the supplied options is invalid.
        QueryBindingError: The query string could not be bound to `model`.
    """

    _validate_options(unknown, max_depth, max_errors, max_params)
    try:
        root = _parse_query_tree(query_string, max_depth, max_params)
    except _QueryBindingFailure as ex:
        raise QueryBindingError([ex.detail]) from ex
    value, errors = _bind_object(root, _compile_model(model), [], unknown, max_errors)
    if errors:
        raise QueryBindingError(errors)
    return cast('_MODEL_T', value)


def _validate_options(
    unknown: str, max_depth: int, max_errors: int, max_params: int
) -> None:
    """Validate binding options supplied by application code."""

    if unknown not in ('strict', 'ignore'):
        raise ValueError("unknown must be either 'strict' or 'ignore'.")
    if max_depth < 1:
        raise ValueError('max_depth must be at least 1.')
    if max_errors < 1:
        raise ValueError('max_errors must be at least 1.')
    if max_params < 1:
        raise ValueError('max_params must be at least 1.')


def _parse_query_tree(query_string: str, max_depth: int, max_params: int) -> _QueryNode:
    """Parse a form-encoded query string into a conflict-detecting tree."""

    root = _QueryNode(_OBJECT)
    if not query_string:
        return root

    parameter_count = 0
    for pair in query_string.split('&'):
        if not pair:
            continue
        parameter_count += 1
        if parameter_count > max_params:
            raise QueryBindingError(
                [QueryErrorDetail('', 'Too many query parameters.')],
                description=f'No more than {max_params} query parameters are allowed.',
            )

        raw_key, has_equals, raw_value = pair.partition('=')
        decoded_key = decode(raw_key) if '%' in raw_key or '+' in raw_key else raw_key
        try:
            segments, explicit_empty_list = _parse_path(decoded_key, max_depth)
        except _QueryBindingFailure as ex:
            raise QueryBindingError([ex.detail]) from ex
        value = decode(raw_value) if raw_value else ''
        if explicit_empty_list and has_equals and raw_value:
            explicit_empty_list = False
        try:
            _add_parameter(
                root,
                segments,
                explicit_empty_list,
                value,
                _render_path(segments),
            )
        except _QueryBindingFailure as ex:
            raise QueryBindingError([ex.detail]) from ex

    return root


def _parse_path(raw_key: str, max_depth: int) -> tuple[list[str], bool]:
    """Parse bracket notation in one raw parameter name."""

    if not raw_key:
        raise _QueryBindingFailure('', 'Query parameter names must not be empty.')

    root, _, tail = raw_key.partition('[')
    if not root:
        raise _QueryBindingFailure(raw_key, 'Query parameter names must not be empty.')
    if ']' in root:
        raise _QueryBindingFailure(raw_key, 'Unexpected closing bracket.')
    if not tail:
        if '[' in raw_key:
            raise _QueryBindingFailure(
                raw_key, 'Query parameter path is missing a closing bracket.'
            )
        return [root], False

    segments = [root]
    while tail:  # pragma: no branch
        name, separator, tail = tail.partition(']')
        if not separator:  # pragma: no cover
            raise _QueryBindingFailure(raw_key, 'Missing closing bracket.')
        if '[' in name or ']' in name or not name:
            if name == '' and not tail:
                return segments, True
            raise _QueryBindingFailure(raw_key, 'Bracket segment must not be empty.')
        segments.append(name)
        if len(segments) > max_depth:
            raise _QueryBindingFailure(
                raw_key, f'Query parameter depth must not exceed {max_depth}.'
            )
        if not tail:
            break
        if not tail.startswith('['):
            raise _QueryBindingFailure(raw_key, 'Expected an opening bracket.')
        tail = tail[1:]
        if not tail:
            raise _QueryBindingFailure(
                raw_key, 'Query parameter path is missing a closing bracket.'
            )

    return segments, False


def _add_parameter(
    node: _QueryNode,
    segments: list[str],
    explicit_empty_list: bool,
    value: str,
    raw_path: str,
) -> None:
    """Add one parameter value to the tree while detecting shape conflicts."""

    segment = segments[0]
    remaining = segments[1:]

    if not remaining:
        if explicit_empty_list:
            child = node.children.get(segment)
            if child is None:
                child = _QueryNode(_LIST)
                node.children[segment] = child
            elif child.kind in (_SCALAR, _OBJECT):
                raise _QueryBindingFailure(
                    raw_path, 'Parameter cannot be both a value and a list.'
                )
            else:
                child.kind = _LIST
            if child.values:
                raise _QueryBindingFailure(
                    raw_path, 'Parameter cannot be both a value and an empty list.'
                )
            child.explicit_empty_list = True
            return

        child = node.children.get(segment)
        if child is None:
            child = _QueryNode()
            node.children[segment] = child
        elif child.kind == _OBJECT:
            raise _QueryBindingFailure(
                raw_path, 'Parameter cannot be both an object and a value.'
            )
        if child.explicit_empty_list:
            raise _QueryBindingFailure(
                raw_path, 'Parameter cannot be both a value and a list.'
            )
        child.values.append(value)
        child.kind = _LIST if len(child.values) > 1 else _SCALAR
        return

    child = node.children.get(segment)
    if child is None:
        child = _QueryNode()
        node.children[segment] = child
    elif child.kind in (_SCALAR, _LIST):
        raise _QueryBindingFailure(
            raw_path, 'Parameter cannot be both an object and a value.'
        )
    child.kind = _OBJECT
    _add_parameter(child, remaining, explicit_empty_list, value, raw_path)


class _QueryBindingFailure(Exception):
    """Signal a malformed query shape before model binding begins."""

    def __init__(self, path: str, description: str) -> None:
        self.detail = QueryErrorDetail(path, description)
        super().__init__(description)


@lru_cache(maxsize=None)  # noqa: UP033
def _compile_model(object_type: type[Any]) -> _ObjectModel:
    """Compile the fields supported by a dataclass model."""

    if not dataclasses.is_dataclass(object_type):
        raise TypeError('Query models must be dataclass types.')

    try:
        hints = get_type_hints(object_type)
    except (NameError, TypeError):
        hints = {}

    compiled = _ObjectModel(object_type)
    for spec in dataclasses.fields(object_type):
        if not spec.init:
            continue

        alias = spec.metadata.get(_ALIAS_METADATA, spec.name)
        if not isinstance(alias, str) or not alias:
            raise TypeError(f'Field {spec.name!r} has an invalid alias.')
        if '[' in alias or ']' in alias:
            raise TypeError(f'Field {spec.name!r} alias must not contain brackets.')
        if alias in compiled.fields_by_alias:
            raise TypeError(f'Query alias {alias!r} is used by more than one field.')

        converter = spec.metadata.get(_CONVERTER_METADATA)
        if converter is not None and not callable(converter):
            raise TypeError(f'Converter for field {spec.name!r} must be callable.')

        annotation = hints.get(spec.name, spec.type)
        kind, model, optional = _analyze_annotation(
            annotation,
            converter,
            spec.name,
        )
        has_default = (
            optional
            or spec.default is not MISSING
            or spec.default_factory is not MISSING
        )
        field_model = _FieldModel(
            alias=alias,
            converter=model if kind in (_SCALAR, _LIST) else None,
            has_default=has_default,
            kind=kind,
            model=model,
            name=spec.name,
            optional=optional,
        )
        compiled.fields.append(field_model)
        compiled.fields_by_alias[alias] = field_model

    return compiled


def _analyze_annotation(
    annotation: Any,
    converter: Callable[[str], Any] | None,
    field_name: str,
) -> tuple[int, Any, bool]:
    """Resolve one dataclass field annotation into a supported binding shape."""

    origin = get_origin(annotation)
    if origin is Union or origin is UnionType:
        arguments = get_args(annotation)
        non_none = [argument for argument in arguments if argument is not type(None)]
        if len(arguments) != 2 or len(non_none) != 1:
            raise TypeError(
                f'Field {field_name!r} must be optional or use one non-None type.'
            )
        kind, model, _ = _analyze_annotation(non_none[0], converter, field_name)
        return kind, model, True

    if dataclasses.is_dataclass(annotation):
        if converter is not None:
            raise TypeError(
                f'Nested object field {field_name!r} cannot use a converter.'
            )
        return _OBJECT, _compile_model(annotation), False

    if origin in (list,):
        arguments = get_args(annotation)
        if len(arguments) != 1 or dataclasses.is_dataclass(arguments[0]):
            raise TypeError(f'List field {field_name!r} must contain one scalar type.')
        item_kind, item_model, _ = _analyze_annotation(
            arguments[0], converter, field_name
        )
        if item_kind != _SCALAR:
            raise TypeError(f'List field {field_name!r} must contain scalar values.')
        return _LIST, item_model, False

    if converter is not None:
        return _SCALAR, converter, False

    builtin_converter = {
        str: str,
        int: int,
        float: float,
        bool: _convert_bool,
    }.get(annotation)
    if builtin_converter is None:
        raise TypeError(
            f'Field {field_name!r} uses unsupported query type {annotation!r}. '
            'Use query_field(converter=...) to provide a converter.'
        )
    return _SCALAR, builtin_converter, False


def _convert_bool(value: str) -> bool:
    """Convert common truthy and falsey query values to a boolean."""

    if value in TRUE_STRINGS:
        return True
    if value in FALSE_STRINGS:
        return False
    raise ValueError('Value must be a boolean.')


def _bind_object(
    node: _QueryNode,
    model: _ObjectModel,
    path: list[str],
    unknown: str,
    max_errors: int,
    errors: list[QueryErrorDetail] | None = None,
) -> tuple[Any, list[QueryErrorDetail]]:
    """Bind a parsed object node to a compiled dataclass model."""

    if errors is None:
        errors = []
    values: dict[str, Any] = {}

    for field in model.fields:
        child = node.children.get(field.alias)
        rendered_path = _render_path(path + [field.alias])
        if child is None:
            default = _field_default(
                field, model, rendered_path, path, unknown, max_errors, errors
            )
            if len(errors) >= max_errors:
                return None, errors
            values[field.name] = default
            continue

        if _bind_present_field(
            field,
            child,
            values,
            path + [field.alias],
            rendered_path,
            unknown,
            max_errors,
            errors,
        ):
            return None, errors

    if _append_unknown_errors(node, model, path, unknown, max_errors, errors):
        return None, errors

    if errors:
        return None, errors
    return model.object_type(**values), errors


def _bind_present_field(
    field: _FieldModel,
    child: _QueryNode,
    values: dict[str, Any],
    model_path: list[str],
    rendered_path: str,
    unknown: str,
    max_errors: int,
    errors: list[QueryErrorDetail],
) -> bool:
    """Bind one field that was present, returning whether the error limit was hit."""

    if field.kind == _OBJECT:
        return _bind_object_field(
            field,
            child,
            values,
            model_path,
            unknown,
            max_errors,
            errors,
        )
    if child.children:
        errors.append(QueryErrorDetail(rendered_path, 'Expected a scalar value.'))
        return len(errors) >= max_errors
    if field.kind == _SCALAR:
        return _bind_scalar_field(
            field, child, values, rendered_path, max_errors, errors
        )
    return _bind_list_field(field, child, values, rendered_path, max_errors, errors)


def _bind_object_field(
    field: _FieldModel,
    child: _QueryNode,
    values: dict[str, Any],
    model_path: list[str],
    unknown: str,
    max_errors: int,
    errors: list[QueryErrorDetail],
) -> bool:
    """Bind a present nested object field."""

    rendered_path = _render_path(model_path)
    if child.kind != _OBJECT:
        errors.append(QueryErrorDetail(rendered_path, 'Expected a nested object.'))
        return len(errors) >= max_errors

    value, nested_errors = _bind_object(
        child,
        cast('_ObjectModel', field.model),
        model_path,
        unknown,
        max_errors,
        errors,
    )
    if not nested_errors:
        values[field.name] = value
    return bool(nested_errors) and len(errors) >= max_errors


def _bind_scalar_field(
    field: _FieldModel,
    child: _QueryNode,
    values: dict[str, Any],
    rendered_path: str,
    max_errors: int,
    errors: list[QueryErrorDetail],
) -> bool:
    """Bind a present scalar field."""

    if child.explicit_empty_list:
        errors.append(QueryErrorDetail(rendered_path, 'Expected a scalar value.'))
    elif len(child.values) != 1:
        errors.append(QueryErrorDetail(rendered_path, 'Expected one value.'))
    else:
        values[field.name] = _convert_scalar(
            field, child.values[0], rendered_path, errors
        )
    return len(errors) >= max_errors


def _bind_list_field(
    field: _FieldModel,
    child: _QueryNode,
    values: dict[str, Any],
    rendered_path: str,
    max_errors: int,
    errors: list[QueryErrorDetail],
) -> bool:
    """Bind a present list field."""

    if child.explicit_empty_list:
        values[field.name] = []
        return False

    converted_values: list[Any] = []
    for value in child.values:
        converted_values.append(_convert_scalar(field, value, rendered_path, errors))
        if len(errors) >= max_errors:
            return True
    values[field.name] = converted_values
    return False


def _append_unknown_errors(
    node: _QueryNode,
    model: _ObjectModel,
    path: list[str],
    unknown: str,
    max_errors: int,
    errors: list[QueryErrorDetail],
) -> bool:
    """Append unknown-parameter errors in strict mode."""

    if unknown != 'strict':
        return False

    known_aliases = set(model.fields_by_alias)
    for alias in node.children:
        if alias not in known_aliases:
            errors.append(
                QueryErrorDetail(_render_path(path + [alias]), 'Unknown parameter.')
            )
            if len(errors) >= max_errors:
                return True
    return False


def _field_default(
    field: _FieldModel,
    model: _ObjectModel,
    rendered_path: str,
    path: list[str],
    unknown: str,
    max_errors: int,
    errors: list[QueryErrorDetail],
) -> Any:
    """Return the configured or implicit default for a missing field."""

    dataclass_spec = next(
        spec
        for spec in dataclasses.fields(model.object_type)
        if spec.name == field.name
    )
    if dataclass_spec.default_factory is not MISSING:
        return dataclass_spec.default_factory()
    if dataclass_spec.default is not MISSING:
        return dataclass_spec.default
    if field.optional:
        return None
    if field.kind == _OBJECT:
        value, _ = _bind_object(
            _QueryNode(_OBJECT),
            cast('_ObjectModel', field.model),
            path + [field.alias],
            unknown,
            max_errors,
            errors,
        )
        if len(errors) < max_errors:
            return value
    else:
        errors.append(QueryErrorDetail(rendered_path, 'Parameter is required.'))
    return None


def _convert_scalar(
    field: _FieldModel,
    value: str,
    path: str,
    errors: list[QueryErrorDetail],
) -> Any:
    """Convert one scalar value and record a parameter-specific error."""

    converter = cast(Callable[[str], Any], field.converter)
    try:
        return converter(value)
    except (TypeError, ValueError) as ex:
        errors.append(QueryErrorDetail(path, str(ex) or 'Invalid value.'))
        return None


def _render_path(path: list[str]) -> str:
    """Render a model field path using query bracket notation."""

    if len(path) == 1:
        return path[0]
    return path[0] + ''.join(f'[{segment}]' for segment in path[1:])
