"""Cattrs validation."""

from collections.abc import Callable, Sequence
from typing import Any, Union

from ._compat import NoneType
from .errors import (
    AmbiguousUnionError,
    ClassValidationError,
    ForbiddenExtraKeysError,
    IterableValidationError,
    UnionValidationError,
)

__all__ = ["format_exception", "transform_error"]
_NO_CANDIDATE = object()


def format_exception(exc: BaseException, type: Union[type, None]) -> str:
    """The default exception formatter, handling the most common exceptions.

    The following exceptions are handled specially:

    * `KeyErrors` (`required field missing`)
    * `ValueErrors` (`invalid value for type, expected <type>` or just `invalid value`)
    * `TypeErrors` (`invalid value for type, expected <type>` and a couple special
      cases for iterables)
    * `cattrs.ForbiddenExtraKeysError`
    * some `AttributeErrors` (special cased for structing mappings)
    """
    if isinstance(exc, KeyError):
        res = "required field missing"
    elif isinstance(exc, ValueError):
        if type is not None:
            tn = type.__name__ if hasattr(type, "__name__") else repr(type)
            res = f"invalid value for type, expected {tn}"
        else:
            res = "invalid value"
    elif isinstance(exc, TypeError):
        if type is None:
            if exc.args[0].endswith("object is not iterable"):
                res = "invalid value for type, expected an iterable"
            else:
                res = f"invalid type ({exc})"
        else:
            tn = type.__name__ if hasattr(type, "__name__") else repr(type)
            res = f"invalid value for type, expected {tn}"
    elif isinstance(exc, ForbiddenExtraKeysError):
        res = f"extra fields found ({', '.join(sorted(exc.extra_fields))})"
    elif isinstance(exc, AmbiguousUnionError):
        res = f"ambiguous union; successful candidates: {_format_types(exc.types)}"
    elif isinstance(exc, AttributeError) and exc.args[0].endswith(
        "object has no attribute 'items'"
    ):
        # This was supposed to be a mapping (and have .items()) but it something else.
        res = "expected a mapping"
    else:
        res = f"unknown error ({exc})"

    return res


def _format_type(type: Any) -> str:
    if type is NoneType:
        return "None"
    if getattr(type, "__origin__", None) is not None:
        return repr(type)
    return getattr(type, "__name__", repr(type))


def _format_types(types: Sequence[Any]) -> str:
    return ", ".join(_format_type(type) for type in types)


def transform_error(
    exc: Union[ClassValidationError, IterableValidationError, BaseException],
    path: str = "$",
    format_exception: Callable[
        [BaseException, Union[type, None]], str
    ] = format_exception,
) -> list[str]:
    """Transform an exception into a list of error messages.

    To get detailed error messages, the exception should be produced by a converter
    with `detailed_validation` set.

    By default, the error messages are in the form of `{description} @ {path}`.

    While traversing the exception and subexceptions, the path is formed:

    * by appending `.{field_name}` for fields in classes
    * by appending `[{int}]` for indices in iterables, like lists
    * by appending `[{str}]` for keys in mappings, like dictionaries

    :param exc: The exception to transform into error messages.
    :param path: The root path to use.
    :param format_exception: A callable to use to transform `Exceptions` into
        string descriptions of errors.

    .. versionadded:: 23.1.0
    """

    def _transform(
        exc: BaseException, path: str, candidate: str | None | object = _NO_CANDIDATE
    ) -> list[str]:
        errors = []

        def append(exc: BaseException, type: Any, path: str) -> None:
            message = format_exception(exc, type)
            if candidate is not _NO_CANDIDATE:
                message = f"{message} @ {path} as {candidate}"
            else:
                message = f"{message} @ {path}"
            errors.append(message)

        if isinstance(exc, UnionValidationError):
            for candidate_type, candidate_exc in zip(exc.types, exc.exceptions):
                errors.extend(
                    _transform(candidate_exc, path, _format_type(candidate_type))
                )
        elif isinstance(exc, IterableValidationError):
            with_notes, without = exc.group_exceptions()
            for subexc, note in with_notes:
                p = f"{path}[{note.index!r}]"
                if isinstance(
                    subexc,
                    (
                        ClassValidationError,
                        IterableValidationError,
                        UnionValidationError,
                    ),
                ):
                    errors.extend(_transform(subexc, p, candidate))
                else:
                    append(subexc, note.type, p)
            for subexc in without:
                append(subexc, None, path)
        elif isinstance(exc, ClassValidationError):
            with_notes, without = exc.group_exceptions()
            for subexc, note in with_notes:
                p = f"{path}.{note.name}"
                if isinstance(
                    subexc,
                    (
                        ClassValidationError,
                        IterableValidationError,
                        UnionValidationError,
                    ),
                ):
                    errors.extend(_transform(subexc, p, candidate))
                else:
                    append(subexc, note.type, p)
            for subexc in without:
                append(subexc, None, path)
        else:
            append(exc, None, path)
        return errors

    return _transform(exc, path)
