import weakref
from collections.abc import AsyncGenerator, Callable, Iterator, Mapping
from contextlib import (
    AbstractAsyncContextManager,
    AbstractContextManager,
    asynccontextmanager,
    contextmanager,
)
from contextvars import ContextVar
from types import TracebackType
from typing import Any, cast

import anyio

DependencyOverrides = Mapping[Callable[..., Any], Callable[..., Any]]
DependencyOverrideLayers = tuple[DependencyOverrides, ...]
DependencyOverrideContexts = weakref.WeakKeyDictionary[Any, DependencyOverrideLayers]

_dependency_override_contexts: ContextVar[DependencyOverrideContexts | None] = (
    ContextVar("dependency_override_contexts", default=None)
)


def _get_contexts() -> DependencyOverrideContexts:
    contexts = _dependency_override_contexts.get()
    if contexts is None:
        return weakref.WeakKeyDictionary()
    return contexts


@contextmanager
def dependency_overrides_context(
    provider: Any, overrides: DependencyOverrides
) -> Iterator[None]:
    contexts = weakref.WeakKeyDictionary(_get_contexts())
    contexts[provider] = (*contexts.get(provider, ()), dict(overrides))
    token = _dependency_override_contexts.set(contexts)
    try:
        yield
    finally:
        _dependency_override_contexts.reset(token)


def get_dependency_override(
    provider: Any, dependency: Callable[..., Any]
) -> Callable[..., Any]:
    for overrides in reversed(_get_contexts().get(provider, ())):
        override = overrides.get(dependency)
        if override is not None:
            return override

    default_overrides = getattr(provider, "dependency_overrides", None)
    if isinstance(default_overrides, Mapping):
        return cast(Callable[..., Any], default_overrides.get(dependency, dependency))
    return dependency


class _PersistentAsyncDependencyOverridesContext(AbstractAsyncContextManager[Any]):
    __slots__ = ("context_manager", "provider", "overrides_layers")

    def __init__(
        self,
        context_manager: AbstractAsyncContextManager[Any],
        provider: Any,
        overrides_layers: DependencyOverrideLayers,
    ) -> None:
        self.context_manager = context_manager
        self.provider = provider
        self.overrides_layers = overrides_layers

    async def __aenter__(self) -> Any:
        async with _dependency_overrides_layers(self.provider, self.overrides_layers):
            return await self.context_manager.__aenter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        async with _dependency_overrides_layers(self.provider, self.overrides_layers):
            return await self.context_manager.__aexit__(exc_type, exc_value, traceback)


class _PersistentSyncDependencyOverridesContext(AbstractAsyncContextManager[Any]):
    __slots__ = (
        "context_manager",
        "provider",
        "overrides_layers",
        "exit_limiter",
    )

    def __init__(
        self,
        context_manager: AbstractContextManager[Any],
        provider: Any,
        overrides_layers: DependencyOverrideLayers,
    ) -> None:
        self.context_manager = context_manager
        self.provider = provider
        self.overrides_layers = overrides_layers
        self.exit_limiter = anyio.CapacityLimiter(1)

    async def __aenter__(self) -> Any:
        async with _dependency_overrides_layers(self.provider, self.overrides_layers):
            return await anyio.to_thread.run_sync(
                self.context_manager.__enter__, limiter=self.exit_limiter
            )

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        async with _dependency_overrides_layers(self.provider, self.overrides_layers):
            if exc_value is None:
                await anyio.to_thread.run_sync(
                    self.context_manager.__exit__,
                    None,
                    None,
                    None,
                    limiter=self.exit_limiter,
                )
                return None

            suppressed = await anyio.to_thread.run_sync(
                self.context_manager.__exit__,
                exc_type,
                exc_value,
                traceback,
                limiter=self.exit_limiter,
            )
            if not suppressed:
                raise exc_value
            return True


@asynccontextmanager
async def _dependency_overrides_layers(
    provider: Any, overrides_layers: DependencyOverrideLayers
) -> AsyncGenerator[None, None]:
    contexts = weakref.WeakKeyDictionary(_get_contexts())
    contexts[provider] = overrides_layers
    token = _dependency_override_contexts.set(contexts)
    try:
        yield
    finally:
        _dependency_override_contexts.reset(token)


def preserve_dependency_overrides_context(
    context_manager: Any, *, provider: Any, is_async: bool
) -> Any:
    overrides_layers = _get_contexts().get(provider, ())
    if not overrides_layers:
        return context_manager

    if is_async:
        return _PersistentAsyncDependencyOverridesContext(
            context_manager, provider, overrides_layers
        )
    return _PersistentSyncDependencyOverridesContext(
        context_manager, provider, overrides_layers
    )
