"""Declarative binding of query string parameters to dataclasses."""

from __future__ import annotations

from collections.abc import Iterable
import dataclasses
from dataclasses import MISSING
from functools import wraps
from inspect import iscoroutinefunction
import types
from typing import (
    Any,
    Callable,
    get_origin,
    get_type_hints,
    NamedTuple,
    Union,
)

from falcon.constants import FALSE_STRINGS
from falcon.constants import TRUE_STRINGS
from falcon.errors import HTTPBadRequest
from falcon.request import Request
from falcon.util.uri import parse_query_string

# NOTE: types.UnionType (i.e. "X | Y" syntax) only exists on Python 3.10+.
_UNION_TYPES = {Union, getattr(types, 'UnionType', Union)}
_NONE_TYPE = type(None)

_EMPTY_LIST_MARKER = '[]'


class QueryParamError(NamedTuple):
    """A single query parameter binding error."""

    path: str
    """Parameter path, e.g. ``'filter[price][min]'``."""

    message: str
    """Human-readable description of the problem."""


class QueryBindingError(HTTPBadRequest):
    """Query string could not be bound to the declared model.

    This error is raised as an HTTP 400 response by
    :func:`~falcon.querybinding.bind_query` when the query string cannot be
    bound to the declared dataclass model. The individual parameter errors
    are available via the :attr:`errors` attribute.

    Args:
        errors (list): Sequence of :class:`QueryParamError` items.
        truncated (bool): Whether additional errors were omitted because
            the configured error limit was reached (default ``False``).
    """

    def __init__(
        self, errors: Iterable[QueryParamError], truncated: bool = False
    ) -> None:
        self.errors: tuple[QueryParamError, ...] = tuple(errors)
        description = '\n'.join(
            '{}: {}'.format(error.path, error.message) for error in self.errors
        )
        if truncated:
            description += '\n(further errors omitted)'
        super().__init__(title='Invalid query parameter', description=description)


def query_field(
    *,
    alias: str | None = None,
    converter: Callable[[str], Any] | None = None,
    default: Any = MISSING,
    default_factory: Any = MISSING,
) -> Any:
    """Declare extra metadata for a query model dataclass field.

    This helper is a thin wrapper over :func:`dataclasses.field` that
    attaches query-binding metadata understood by
    :func:`~falcon.querybinding.bind_query`.

    Args:
        alias (str): Name of the query string parameter to bind to this
            field when it differs from the field name.
        converter (callable): Custom converter invoked with the raw
            parameter string (or each element string for list fields).
            Any exception it raises is collected as a binding error.
        default: Default value used when the parameter is missing.
        default_factory (callable): Zero-argument callable producing the
            default value used when the parameter is missing.

    Returns:
        A :func:`dataclasses.field` instance carrying the metadata.
    """
    metadata: dict[str, Any] = {}
    if alias is not None:
        metadata['alias'] = alias
    if converter is not None:
        metadata['converter'] = converter

    kwargs: dict[str, Any] = {'metadata': metadata}
    if default is not MISSING:
        kwargs['default'] = default
    if default_factory is not MISSING:
        kwargs['default_factory'] = default_factory

    return dataclasses.field(**kwargs)


def bind_query(
    model: type,
    *,
    param: str = 'query',
    strict: bool = True,
    max_params: int = 100,
    max_depth: int = 5,
    max_errors: int = 10,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Bind the query string to a dataclass model before the responder.

    This decorator wraps a responder so that the request's query string is
    parsed and bound to an instance of the given dataclass `model`, which is
    then passed to the responder as the `param` keyword argument. Both WSGI
    (synchronous) and ASGI (asynchronous) responders are supported.

    The binder understands the following shapes:

    *   Scalar fields: ``page=2``.
    *   List fields: repeated parameters, e.g. ``tags=a&tags=b``. A single
        empty value (``tags=``) yields a list containing one empty string,
        while the explicit marker ``tags[]=`` (on its own) yields an empty
        list. Mixing the two shapes for the same parameter is an error.
    *   Nested dataclasses: bracketed keys, e.g. ``filter[price][min]=10``.

    Conflicting shapes for the same parameter prefix, such as
    ``a=1&a[b]=2``, are rejected with :class:`QueryBindingError` rather
    than being silently resolved by dict ordering.

    Note:
        The request's own parsed parameters (``req.params``) are never
        modified; the query string is parsed independently.

    Args:
        model (type): A :mod:`dataclasses` dataclass to bind to.
        param (str): Name of the keyword argument used to pass the bound
            model instance to the responder (default ``'query'``).
        strict (bool): Reject unknown query string parameters with an
            error when ``True``; silently ignore them when ``False``
            (default ``True``).
        max_params (int): Maximum number of query string parameters
            (counting repeated values individually) allowed before the
            request is rejected (default ``100``).
        max_depth (int): Maximum bracket nesting depth allowed in parameter
            names (default ``5``).
        max_errors (int): Maximum number of individual parameter errors
            collected before further errors are omitted (default ``10``).
    """
    if not dataclasses.is_dataclass(model):
        raise TypeError('bind_query() model must be a dataclass')

    hints_cache: dict[type, dict[str, Any]] = {}

    def bind(req: Request) -> Any:
        return _bind(
            req.query_string,
            model,
            hints_cache,
            strict=strict,
            max_params=max_params,
            max_depth=max_depth,
            max_errors=max_errors,
        )

    def decorator(responder: Callable[..., Any]) -> Callable[..., Any]:
        if iscoroutinefunction(responder):

            @wraps(responder)
            async def async_responder(*args: Any, **kwargs: Any) -> Any:
                kwargs[param] = bind(_find_request(args))
                return await responder(*args, **kwargs)

            return async_responder

        @wraps(responder)
        def sync_responder(*args: Any, **kwargs: Any) -> Any:
            kwargs[param] = bind(_find_request(args))
            return responder(*args, **kwargs)

        return sync_responder

    return decorator


def _find_request(args: tuple[Any, ...]) -> Request:
    for arg in args:
        if isinstance(arg, Request):
            return arg
    raise TypeError('bind_query() could not locate the Request argument')


def _bind(
    query_string: str,
    model: type,
    hints_cache: dict[type, dict[str, Any]],
    *,
    strict: bool,
    max_params: int,
    max_depth: int,
    max_errors: int,
) -> Any:
    params = parse_query_string(query_string, keep_blank=True)

    num_params = sum(
        len(value) if isinstance(value, list) else 1 for value in params.values()
    )
    if num_params > max_params:
        raise QueryBindingError(
            [
                QueryParamError(
                    '',
                    'too many parameters (got {}, limit is {})'.format(
                        num_params, max_params
                    ),
                )
            ]
        )

    errors: list[QueryParamError] = []
    collector = _ErrorCollector(errors, max_errors)
    tree = _build_tree(params, max_depth, collector)
    result = _convert_model(model, tree, '', hints_cache, strict, collector)

    if collector.errors:
        raise QueryBindingError(collector.errors, truncated=collector.truncated)

    return result


class _ErrorCollector:
    """Collect parameter errors up to a fixed limit."""

    def __init__(self, errors: list[QueryParamError], max_errors: int) -> None:
        self.errors = errors
        self.max_errors = max_errors
        self.truncated = False

    def add(self, path: str, message: str) -> None:
        if len(self.errors) < self.max_errors:
            self.errors.append(QueryParamError(path, message))
        else:
            self.truncated = True


def _split_key(key: str) -> list[str] | None:
    """Split a bracketed parameter name into path segments.

    Returns ``None`` when the key is malformed.
    """
    segments = []
    for index, part in enumerate(key.split('[')):
        if index == 0:
            segment = part
        else:
            if not part.endswith(']'):
                return None
            segment = part[:-1]
        if not segment:
            return None
        segments.append(segment)
    return segments


def _build_tree(
    params: dict[str, str | list[str]], max_depth: int, collector: _ErrorCollector
) -> dict[str, Any]:
    tree: dict[str, Any] = {}

    for key, values in params.items():
        if not isinstance(values, list):
            values = [values]

        if key.endswith(_EMPTY_LIST_MARKER):
            base = key[: -len(_EMPTY_LIST_MARKER)]
            path = _split_key(base)
            if path is None:
                collector.add(key, 'malformed parameter name')
                continue
            if any(value != '' for value in values):
                collector.add(key, 'the empty-list marker must have an empty value')
                continue
            if base in params or any(
                other != key and other.startswith(base + '[') for other in params
            ):
                collector.add(key, 'cannot mix the empty-list marker with other shapes')
                continue
            leaf_values: list[str] = []
        else:
            path = _split_key(key)
            if path is None:
                collector.add(key, 'malformed parameter name')
                continue
            leaf_values = values

        if len(path) > max_depth:
            collector.add(key, 'parameter nesting exceeds the depth limit')
            continue

        node = tree
        conflict = False
        for segment in path[:-1]:
            existing = node.get(segment)
            if existing is None:
                existing = {}
                node[segment] = existing
            elif not isinstance(existing, dict):
                collector.add(
                    key,
                    'conflicts with a scalar value for the same parameter prefix',
                )
                conflict = True
                break
            node = existing
        if conflict:
            continue

        existing = node.get(path[-1])
        if isinstance(existing, dict):
            collector.add(key, 'conflicts with nested parameters for the same prefix')
            continue
        node[path[-1]] = leaf_values

    return tree


def _get_hints(model: type, hints_cache: dict[type, dict[str, Any]]) -> dict[str, Any]:
    hints = hints_cache.get(model)
    if hints is None:
        try:
            hints = get_type_hints(model)
        except Exception:
            # NOTE: get_type_hints() requires the model's module to be
            #   importable from sys.modules; fall back to the raw field
            #   types for dynamically loaded modules.
            hints = {field.name: field.type for field in dataclasses.fields(model)}
        hints_cache[model] = hints
    return hints


def _unwrap_optional(ftype: Any) -> tuple[bool, Any]:
    """Unwrap ``Optional[X]`` to ``(True, X)``; anything else to ``(False, T)``."""
    if get_origin(ftype) in _UNION_TYPES:
        args = ftype.__args__
        if len(args) == 2 and _NONE_TYPE in args:
            inner = args[0] if args[1] is _NONE_TYPE else args[1]
            return True, inner
    return False, ftype


def _convert_model(
    model: type,
    node: dict[str, Any],
    path: str,
    hints_cache: dict[type, dict[str, Any]],
    strict: bool,
    collector: _ErrorCollector,
) -> Any:
    hints = _get_hints(model, hints_cache)
    kwargs: dict[str, Any] = {}
    known_keys: set[str] = set()

    for field in dataclasses.fields(model):
        key = field.metadata.get('alias') or field.name
        known_keys.add(key)
        child_path = '{}[{}]'.format(path, key) if path else key

        ftype = hints.get(field.name, field.type)
        optional, inner = _unwrap_optional(ftype)

        if key not in node:
            if field.default is not MISSING or field.default_factory is not MISSING:
                continue
            if optional:
                kwargs[field.name] = None
                continue
            collector.add(child_path, 'missing required parameter')
            continue

        value = node[key]
        converter = field.metadata.get('converter')
        converted = _convert_value(
            inner, value, child_path, converter, hints_cache, strict, collector
        )
        if converted is not _CONVERSION_FAILED:
            kwargs[field.name] = converted

    if strict:
        for key in node:
            if key not in known_keys:
                collector.add(
                    '{}[{}]'.format(path, key) if path else key,
                    'unknown parameter',
                )

    if collector.errors:
        return None

    return model(**kwargs)


class _ConversionFailed:
    pass


_CONVERSION_FAILED = _ConversionFailed()


def _convert_value(
    ftype: Any,
    value: Any,
    path: str,
    converter: Callable[[str], Any] | None,
    hints_cache: dict[type, dict[str, Any]],
    strict: bool,
    collector: _ErrorCollector,
) -> Any:
    origin = get_origin(ftype)

    if origin is list or ftype is list:
        if not isinstance(value, list):
            collector.add(path, 'expected a list of values')
            return _CONVERSION_FAILED
        args = getattr(ftype, '__args__', ())
        element_type = args[0] if args else str
        items: list[Any] = []
        failed = False
        for raw in value:
            item = _convert_scalar(element_type, raw, path, converter, collector)
            if item is _CONVERSION_FAILED:
                failed = True
            else:
                items.append(item)
        return _CONVERSION_FAILED if failed else items

    if isinstance(ftype, type) and dataclasses.is_dataclass(ftype):
        if not isinstance(value, dict):
            collector.add(path, 'expected an object')
            return _CONVERSION_FAILED
        result = _convert_model(ftype, value, path, hints_cache, strict, collector)
        return _CONVERSION_FAILED if result is None else result

    if not isinstance(value, list):
        collector.add(path, 'expected a single value')
        return _CONVERSION_FAILED
    if len(value) != 1:
        collector.add(path, 'expected a single value, got {}'.format(len(value)))
        return _CONVERSION_FAILED

    return _convert_scalar(ftype, value[0], path, converter, collector)


def _convert_scalar(
    ftype: Any,
    raw: str,
    path: str,
    converter: Callable[[str], Any] | None,
    collector: _ErrorCollector,
) -> Any:
    try:
        if converter is not None:
            return converter(raw)
        if ftype is str or ftype is Any:
            return raw
        if ftype is bool:
            return _parse_bool(raw)
        return ftype(raw)
    except Exception as ex:
        collector.add(path, 'could not convert {!r}: {}'.format(raw, ex))
        return _CONVERSION_FAILED


def _parse_bool(raw: str) -> bool:
    if raw in TRUE_STRINGS:
        return True
    if raw in FALSE_STRINGS:
        return False
    raise ValueError('unrecognized boolean value {!r}'.format(raw))
