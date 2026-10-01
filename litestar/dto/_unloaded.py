"""Detection of unloaded fields on model instances.

When serializing ORM objects, reading an attribute that has not been loaded yet
(e.g. a deferred column, an expired attribute or a lazy relationship) may trigger
I/O - such as a SQL query - as an undesired side effect. This module provides a
registry of "unloaded fields checkers" that DTO backends consult *before* reading
an attribute, so that a configured strategy (omit the field, or raise an error)
can be applied instead.

SQLAlchemy ORM instances are supported out of the box. Support for other object
types can be added by registering additional checkers with
:func:`register_unloaded_fields_checker`, or by overriding
:meth:`AbstractDTO.get_unloaded_fields <litestar.dto.AbstractDTO.get_unloaded_fields>`
on a DTO adapter.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Collection

__all__ = (
    "UnloadedFieldsChecker",
    "detect_unloaded_fields",
    "register_unloaded_fields_checker",
)


class UnloadedFieldsChecker(Protocol):
    """A callable that inspects an instance for unloaded fields.

    Returns the names of the fields that are not currently loaded on the instance,
    or ``None`` if the instance is not of a type the checker supports. Checkers must
    not read the value of any potentially unloaded attribute on the instance, as
    doing so may trigger I/O (e.g. a SQL query) as a side effect.
    """

    def __call__(self, instance: Any) -> Collection[str] | None: ...


_unloaded_fields_checkers: list[UnloadedFieldsChecker] = []


def register_unloaded_fields_checker(checker: UnloadedFieldsChecker) -> UnloadedFieldsChecker:
    """Register a checker used to detect unloaded fields on model instances.

    Checkers are consulted in registration order; the first checker to return a
    value other than ``None`` wins.

    Args:
        checker: An :class:`UnloadedFieldsChecker` instance.

    Returns:
        The registered checker, so this can be used as a decorator.
    """
    _unloaded_fields_checkers.append(checker)
    return checker


def detect_unloaded_fields(instance: Any) -> Collection[str]:
    """Return the names of fields on ``instance`` that are not currently loaded.

    Consults the checkers registered via :func:`register_unloaded_fields_checker`.
    Returns an empty collection if no checker supports the instance.
    """
    for checker in _unloaded_fields_checkers:
        if (unloaded := checker(instance)) is not None:
            return unloaded
    return ()


@register_unloaded_fields_checker
def _sqlalchemy_unloaded_fields(instance: Any) -> Collection[str] | None:
    """Detect unloaded fields on SQLAlchemy ORM instances.

    Uses the SQLAlchemy inspection API, which reads the instance state only and
    therefore never triggers I/O. The reported names cover deferred columns,
    expired attributes and unloaded relationships (including collections). A field
    that has been loaded with a value of ``None`` is *not* considered unloaded.
    """
    if not hasattr(type(instance), "__mapper__"):
        return None

    try:
        from sqlalchemy import inspect as sa_inspect
    except ImportError:  # pragma: no cover
        return None

    try:
        state = sa_inspect(instance)
    except Exception:  # noqa: BLE001
        return None

    return state.unloaded
