from typing import Any, Protocol, TypeVar

__all__ = [
    "Context",
    "ContextualStructureHook",
    "ContextualUnstructureHook",
    "SimpleStructureHook",
]

In = TypeVar("In")
T = TypeVar("T")

#: Application-specific data passed to a single structure/unstructure call.
Context = Any


class SimpleStructureHook(Protocol[In, T]):
    """A structure hook with an optional (ignored) second argument."""

    def __call__(self, _: In, /, cl=...) -> T: ...


class ContextualStructureHook(Protocol[In, T]):
    """A structure hook that receives the current conversion context."""

    def __call__(self, _: In, cl: Any, *, context: Any) -> T: ...


class ContextualUnstructureHook(Protocol[In, T]):
    """An unstructure hook that receives the current conversion context."""

    def __call__(self, _: In, *, context: Any) -> T: ...
