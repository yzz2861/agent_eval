from __future__ import annotations

from typing import TYPE_CHECKING, Any

from attrs import NOTHING, Attribute, Factory

from .._compat import get_args, is_annotated, is_bare_final
from ..dispatch import StructureHook
from ..errors import StructureHandlerNotFoundError
from ..fns import raise_error
from ._consts import AttributeOverride

if TYPE_CHECKING:
    from ..converters import BaseConverter


PathType = tuple[str | int, ...]


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


#: Sentinel for absent path values; distinct from explicit `None`.
_missing = _Missing()

#: Internal marker for "no default given".
_raise = object()


def _normalize_path(path: Any) -> PathType:
    """Validate and normalize a path into a tuple of segments.

    A plain string is a single key (dots are not special); strings index
    mappings and integers index sequences.
    """
    if isinstance(path, str):
        path = (path,)
    else:
        try:
            path = tuple(path)
        except TypeError:
            raise ValueError(f"Invalid path: {path!r}") from None
    if not path:
        raise ValueError("Paths must not be empty.")
    for segment in path:
        if isinstance(segment, bool) or not isinstance(segment, (str, int)):
            raise ValueError(
                f"Path segments must be strings or integers, got {segment!r}."
            )
        if isinstance(segment, int) and segment < 0:
            raise ValueError(f"Negative path indices are not supported: {path!r}")
    if not isinstance(path[0], str):
        raise ValueError("The first path segment must be a string key.")
    return path


def _get_path(mapping: Any, path: PathType, default: Any = _raise) -> Any:
    """Fetch the value at `path` in nested mappings/sequences.

    Returns `default` if a segment is absent. Raises a `TypeError` if an
    intermediate value cannot be indexed (for example an explicit `None`).
    """
    current = mapping
    for segment in path:
        try:
            current = current[segment]
        except (KeyError, IndexError):
            if default is _raise:
                raise KeyError(path) from None
            return default
        except TypeError:
            raise TypeError(
                f"Cannot index {type(current).__name__} with {segment!r} "
                f"while resolving path {path!r}"
            ) from None
    return current


def _set_path(mapping: dict, path: PathType, value: Any) -> None:
    """Set `value` at `path`, creating intermediate containers as needed."""
    current = mapping
    for ix, segment in enumerate(path[:-1]):
        next_segment = path[ix + 1]
        if isinstance(segment, str):
            child = current.get(segment)
            if child is None:
                child = [] if isinstance(next_segment, int) else {}
                current[segment] = child
        else:
            while len(current) <= segment:
                current.append(None)
            child = current[segment]
            if child is None:
                child = [] if isinstance(next_segment, int) else {}
                current[segment] = child
        current = child
    last_segment = path[-1]
    if isinstance(last_segment, str):
        current[last_segment] = value
    else:
        while len(current) <= last_segment:
            current.append(None)
        current[last_segment] = value


def _check_path_conflicts(
    locations: dict[str, PathType], cl: type, hook_kind: str
) -> None:
    """Ensure no two attribute locations overlap.

    Raises if two attributes map to the same path, or if one path is a
    prefix of another.
    """
    items = sorted(locations.items(), key=lambda kv: (len(kv[1]), kv[0]))
    for ix, (name_a, path_a) in enumerate(items):
        for name_b, path_b in items[ix + 1 :]:
            if path_b[: len(path_a)] != path_a:
                continue
            if len(path_a) == len(path_b):
                raise ValueError(
                    f"Attributes {name_a!r} and {name_b!r} of {cl.__qualname__} "
                    f"map to the same path {path_a!r} when generating the "
                    f"{hook_kind} hook."
                )
            raise ValueError(
                f"Attribute {name_a!r} of {cl.__qualname__} maps to path "
                f"{path_a!r}, which is a prefix of attribute {name_b!r}'s "
                f"path {path_b!r} when generating the {hook_kind} hook."
            )


def _annotated_override_or_default(
    type: Any, default: AttributeOverride
) -> AttributeOverride:
    """
    If the type is Annotated containing an AttributeOverride, return it.
    Otherwise, return the default.
    """
    if is_annotated(type):
        for arg in get_args(type):
            if isinstance(arg, AttributeOverride):
                return arg

    return default


def find_structure_handler(
    a: Attribute, type: Any, c: BaseConverter, prefer_attrs_converters: bool = False
) -> StructureHook | None:
    """Find the appropriate structure handler to use.

    Return `None` if no handler should be used.
    """
    try:
        if a.converter is not None and prefer_attrs_converters:
            # If the user as requested to use attrib converters, use nothing
            # so it falls back to that.
            handler = None
        elif (
            a.converter is not None and not prefer_attrs_converters and type is not None
        ):
            try:
                handler = c.get_structure_hook(type, cache_result=False)
            except StructureHandlerNotFoundError:
                handler = None
            else:
                # The legacy way, should still work.
                if handler == raise_error:
                    handler = None
        elif type is not None:
            if (
                is_bare_final(type)
                and a.default is not NOTHING
                and not isinstance(a.default, Factory)
            ):
                # This is a special case where we can use the
                # type of the default to dispatch on.
                type = a.default.__class__
                handler = c.get_structure_hook(type, cache_result=False)
                if handler == c._structure_call:
                    # Finals can't really be used with _structure_call, so
                    # we wrap it so the rest of the toolchain doesn't get
                    # confused.

                    def handler(v, _, _h=handler):
                        return _h(v, type)

            else:
                handler = c.get_structure_hook(type, cache_result=False)
        else:
            handler = c.structure
        return handler
    except RecursionError:
        # This means we're dealing with a reference cycle, so use late binding.
        return c.structure
