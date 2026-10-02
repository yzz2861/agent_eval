from __future__ import annotations

from typing import TYPE_CHECKING, Any

from attrs import NOTHING, Attribute, Factory

from .._compat import get_args, is_annotated, is_bare_final
from ..dispatch import StructureHook
from ..errors import StructureHandlerNotFoundError
from ..fns import raise_error
from ._consts import AttributeOverride, neutral

if TYPE_CHECKING:
    from ..converters import BaseConverter

_RAISE = object()


def deep_get(o: Any, path: tuple, default: Any = _RAISE) -> Any:
    """Fetch a value from nested mappings/sequences by a structured path.

    Missing keys and indices produce `default` if one is given, otherwise the
    original `KeyError`/`IndexError` is raised. Explicit `None` (or otherwise
    nonsubscriptable) intermediate values raise `TypeError`, so they are not
    conflated with missing values.
    """
    for segment in path:
        try:
            o = o[segment]
        except (KeyError, IndexError):
            if default is _RAISE:
                raise
            return default
    return o


def deep_set(container: Any, path: tuple, value: Any) -> None:
    """Set `value` at `path` in `container`, creating intermediate containers.

    Intermediate dicts and lists are created fresh as needed, so shared path
    prefixes are merged and no state is shared between calls.
    """
    for i, segment in enumerate(path[:-1]):
        next_segment = path[i + 1]
        if isinstance(segment, int):
            while len(container) <= segment:
                container.append(None)
            child = container[segment]
            if child is None:
                child = [] if isinstance(next_segment, int) else {}
                container[segment] = child
        else:
            child = container.get(segment)
            if child is None:
                child = [] if isinstance(next_segment, int) else {}
                container[segment] = child
        container = child
    last = path[-1]
    if isinstance(last, int):
        while len(container) <= last:
            container.append(None)
        container[last] = value
    else:
        container[last] = value


def format_path(path: tuple) -> str:
    """Format a structured path for error messages, like `a.b[0].c`."""
    parts = []
    for segment in path:
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
        else:
            if parts:
                parts.append(".")
            parts.append(segment)
    return "".join(parts)


def normalize_path(path: Any, attr_name: str) -> tuple:
    """Validate and normalize an override path into a tuple of segments."""
    try:
        path = tuple(path)
    except TypeError:
        raise ValueError(
            f"Invalid path for attribute {attr_name!r}: {path!r} "
            "(expected an iterable of strings and integers)"
        ) from None
    if not path:
        raise ValueError(f"Empty path for attribute {attr_name!r}")
    for segment in path:
        if isinstance(segment, bool) or not isinstance(segment, (str, int)):
            raise ValueError(
                f"Invalid path segment {segment!r} for attribute {attr_name!r} "
                "(expected a string or an integer)"
            )
        if isinstance(segment, int) and segment < 0:
            raise ValueError(
                f"Invalid negative path segment {segment!r} for attribute {attr_name!r}"
            )
    if not isinstance(path[0], str):
        raise ValueError(
            f"The first path segment for attribute {attr_name!r} must be a string"
        )
    return path


def collect_effective_paths(
    attrs: list,
    overrides: dict[str, AttributeOverride],
    use_alias: bool,
    include_init_false: bool,
) -> dict[str, tuple] | None:
    """Compute the effective output path of every included attribute.

    Returns `None` if no attribute uses an explicit path, in which case no
    conflict checking is needed. Raises `ValueError` for invalid paths and
    for attributes setting both `rename` and `path`.
    """
    effective = {}
    has_explicit = False
    for a in attrs:
        if a.name in overrides:
            override = overrides[a.name]
        else:
            override = _annotated_override_or_default(a.type, neutral)
        if override.omit:
            continue
        if override.omit is None and not a.init and not include_init_false:
            continue
        if override.path is not None:
            if override.rename is not None:
                raise ValueError(
                    f"Attribute {a.name!r} sets both `rename` and `path`; "
                    "they are mutually exclusive"
                )
            has_explicit = True
            effective[a.name] = normalize_path(override.path, a.name)
        else:
            if override.rename is not None:
                kn = override.rename
            else:
                kn = a.alias if use_alias else a.name
            effective[a.name] = (kn,)
    return effective if has_explicit else None


def check_path_conflicts(paths: dict[str, tuple]) -> None:
    """Raise a `ValueError` if any two effective paths conflict.

    Paths conflict when they are identical, when one is a prefix of another,
    or when they require different container types (mapping vs sequence) at
    the same position.
    """
    items = list(paths.items())
    for i, (name_a, path_a) in enumerate(items):
        for name_b, path_b in items[i + 1 :]:
            for segment_a, segment_b in zip(path_a, path_b):
                if segment_a == segment_b and type(segment_a) is type(segment_b):
                    continue
                if isinstance(segment_a, str) != isinstance(segment_b, str):
                    raise ValueError(
                        f"Conflicting paths for attributes {name_a!r} and "
                        f"{name_b!r}: {format_path(path_a)} and "
                        f"{format_path(path_b)} require different container "
                        "types at the same position"
                    )
                # Sibling keys or indices; no conflict.
                break
            else:
                raise ValueError(
                    f"Conflicting paths for attributes {name_a!r} and "
                    f"{name_b!r}: {format_path(path_a)} and "
                    f"{format_path(path_b)} overlap"
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
