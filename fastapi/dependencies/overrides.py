from collections import ChainMap
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import (
    AbstractAsyncContextManager,
    AbstractContextManager,
    asynccontextmanager,
)
from contextvars import ContextVar
from typing import Any, TypeVar

DependencyCallable = Callable[..., Any]
DependencyOverrides = dict[DependencyCallable, DependencyCallable]
DependencyOverrideLayers = tuple[
    Mapping[DependencyCallable, DependencyCallable],
    ...,
]

T = TypeVar("T")


class _FrozenDependencyOverrides(dict[DependencyCallable, DependencyCallable]):
    pass


class DependencyOverridesContext(
    AbstractContextManager["DependencyOverridesContext"],
    AbstractAsyncContextManager["DependencyOverridesContext"],
):
    def __init__(
        self,
        provider: Any,
        overrides: Mapping[DependencyCallable, DependencyCallable],
    ) -> None:
        self._provider = provider
        self._overrides = dict(overrides)
        self._layer = self._overrides

    def __enter__(self) -> "DependencyOverridesContext":
        context_var = getattr(
            self._provider, "_dependency_overrides_context_var", None
        )
        if context_var is not None:
            context_var.set(context_var.get() + (self._layer,))
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        context_var = getattr(
            self._provider, "_dependency_overrides_context_var", None
        )
        if context_var is not None:
            layers = tuple(
                layer for layer in context_var.get() if layer is not self._layer
            )
            context_var.set(layers)

    async def __aenter__(self) -> "DependencyOverridesContext":
        return self.__enter__()

    async def __aexit__(
        self, exc_type: Any, exc_value: Any, traceback: Any
    ) -> None:
        self.__exit__(exc_type, exc_value, traceback)


def get_dependency_overrides(
    provider: Any,
) -> Mapping[DependencyCallable, DependencyCallable]:
    if provider is None:
        return {}

    default_overrides: Mapping[DependencyCallable, DependencyCallable] = (
        getattr(provider, "dependency_overrides", None) or {}
    )
    context_var: ContextVar[DependencyOverrideLayers] | None = getattr(
        provider, "_dependency_overrides_context_var", None
    )
    layers = context_var.get() if context_var is not None else ()
    if not layers:
        return default_overrides
    if len(layers) == 1 and isinstance(layers[0], _FrozenDependencyOverrides):
        return layers[0]
    return ChainMap(*reversed(layers), default_overrides)


@asynccontextmanager
async def preserve_dependency_overrides_context(
    provider: Any, context_manager: AbstractAsyncContextManager[T]
) -> AsyncIterator[T]:
    context_var: ContextVar[DependencyOverrideLayers] | None = getattr(
        provider, "_dependency_overrides_context_var", None
    )
    if context_var is None:
        async with context_manager as value:
            yield value
        return

    snapshot = _FrozenDependencyOverrides(dict(get_dependency_overrides(provider)))
    active_layers = context_var.get()
    context_var.set((snapshot,))
    try:
        value = await context_manager.__aenter__()
    finally:
        context_var.set(active_layers)

    try:
        yield value
    except BaseException as exc:
        cleanup_layers = context_var.get()
        context_var.set((snapshot,))
        try:
            suppressed = await context_manager.__aexit__(
                type(exc), exc, exc.__traceback__
            )
        finally:
            context_var.set(cleanup_layers)
        if not suppressed:
            raise
    else:
        cleanup_layers = context_var.get()
        context_var.set((snapshot,))
        try:
            await context_manager.__aexit__(None, None, None)
        finally:
            context_var.set(cleanup_layers)
