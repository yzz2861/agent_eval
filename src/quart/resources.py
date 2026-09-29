from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable
from collections.abc import Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import Quart  # noqa: F401


class ResourceError(RuntimeError):
    """Base class for errors raised by request-scoped resources."""


class ResourceNotFoundError(ResourceError, KeyError):
    """Raised when acquiring a resource that has not been registered."""

    def __init__(self, name: str) -> None:
        self.name = name
        super().__init__(f"No resource named {name!r} has been registered.")


class ResourceDependencyError(ResourceError):
    """Raised when resources depend on each other in a cycle.

    The ``chain`` attribute contains the full dependency chain,
    ending with the resource that closes the cycle.
    """

    def __init__(self, chain: list[str]) -> None:
        self.chain = chain
        super().__init__(
            "Circular resource dependency: " + " -> ".join(repr(name) for name in chain)
        )


@dataclass
class ResourceDefinition:
    """A registered resource factory and its optional cleanup."""

    factory: Callable[[RequestResources], Any]
    cleanup: Callable[[Any], Any] | None = None


@dataclass
class _Resolution:
    """Tracks a single (possibly nested) resource resolution."""

    chain: list[str]
    created: list[str]


_cv_resolution: ContextVar[_Resolution | None] = ContextVar(
    "quart.resource_resolution", default=None
)


class RequestResources:
    """Request-scoped registry of lazily created async resources.

    Resources are registered with an async factory and optional
    cleanup logic, then created the first time get is called within a
    request. The same instance is shared by every caller within the
    request, and all created resources are cleaned up in reverse
    creation order when the request (including any streaming response)
    has finished.

    Factories receive this registry and may acquire other resources
    from it, thereby declaring dependencies. Circular dependencies
    raise ResourceDependencyError with the full chain, and a factory
    that fails part way rolls back whatever it already opened.
    """

    def __init__(self, app: Quart) -> None:
        self._app = app
        self._definitions: dict[str, ResourceDefinition] = {}
        self._values: dict[str, Any] = {}
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._cleanups: list[tuple[str, Callable[[], Awaitable[None]]]] = []
        self._closed = False

    @property
    def closed(self) -> bool:
        """True once close has been called."""
        return self._closed

    def register(
        self,
        name: str,
        factory: Callable[[RequestResources], Any] | None = None,
        *,
        cleanup: Callable[[Any], Any] | None = None,
    ) -> Callable:
        """Register a resource factory for this request.

        Can be used directly or as a decorator. The factory is called
        with this registry and may be a sync or async function
        returning the resource, or an async generator that yields the
        resource once - any code after the yield then acts as the
        cleanup. Alternatively a separate cleanup callable may be
        given, which is called with the created resource.
        """
        if factory is None:
            return lambda func: self.register(name, func, cleanup=cleanup)

        if self._closed:
            raise ResourceError(f"Cannot register resource {name!r}, already closed.")

        self._definitions[name] = ResourceDefinition(factory, cleanup)
        return factory

    def __contains__(self, name: str) -> bool:
        return name in self._definitions or name in self._app.resource_definitions

    async def get(self, name: str) -> Any:
        """Return the resource name, creating it on first use.

        Concurrent callers share a single creation; a caller being
        cancelled does not cancel the creation for the others.
        """
        if name in self._values:
            return self._values[name]

        if self._closed:
            raise ResourceError(f"Cannot acquire resource {name!r}, already closed.")

        resolution = _cv_resolution.get()
        if resolution is not None and name in resolution.chain:
            raise ResourceDependencyError([*resolution.chain, name])

        task = self._tasks.get(name)
        if task is None:
            task = asyncio.ensure_future(self._create(name, resolution))
            self._tasks[name] = task

        # Shield so that a waiter being cancelled does not cancel the
        # shared creation for the other callers.
        return await asyncio.shield(task)

    async def close(self) -> None:
        """Clean up every created resource in reverse creation order.

        Runs at most once; subsequent calls are no-ops. If any cleanup
        fails the remaining cleanups still run, then the first error is
        re-raised.
        """
        if self._closed:
            return

        self._closed = True
        errors: list[BaseException] = []

        while self._cleanups:
            name, cleanup = self._cleanups.pop()
            self._values.pop(name, None)
            self._tasks.pop(name, None)
            try:
                await cleanup()
            except Exception as error:
                errors.append(error)

        self._values.clear()
        self._tasks.clear()

        if errors:
            raise errors[0]

    async def _create(self, name: str, parent: _Resolution | None) -> Any:
        try:
            definition = self._definitions[name]
        except KeyError:
            try:
                definition = self._app.resource_definitions[name]
            except KeyError:
                raise ResourceNotFoundError(name) from None

        resolution = _Resolution(
            chain=[*(parent.chain if parent is not None else []), name],
            created=parent.created if parent is not None else [],
        )
        token = _cv_resolution.set(resolution)
        try:
            value, cleanup = await self._open(definition)

            if self._closed:
                # The request ended whilst this resource was being
                # created; clean it up immediately rather than leak it.
                if cleanup is not None:
                    await cleanup()
                raise ResourceError(
                    f"Resource {name!r} was created after the resources were closed."
                )

            self._values[name] = value
            if cleanup is not None:
                self._cleanups.append((name, cleanup))
            resolution.created.append(name)
            return value
        except BaseException:
            self._tasks.pop(name, None)
            if parent is None:
                await self._rollback(resolution.created)
            raise
        finally:
            _cv_resolution.reset(token)

    async def _open(
        self, definition: ResourceDefinition
    ) -> tuple[Any, Callable[[], Awaitable[None]] | None]:
        factory = definition.factory

        if inspect.isasyncgenfunction(factory):
            manager = asynccontextmanager(factory)(self)
            value = await manager.__aenter__()

            async def cleanup() -> None:
                await manager.__aexit__(None, None, None)

            return value, cleanup

        value = factory(self)
        if inspect.isawaitable(value):
            value = await value

        if definition.cleanup is None:
            return value, None

        async def cleanup() -> None:
            result = definition.cleanup(value)
            if inspect.isawaitable(result):
                await result

        return value, cleanup

    async def _rollback(self, created: list[str]) -> None:
        """Undo a failed resolution, closing what it already opened."""
        for name in reversed(created):
            self._values.pop(name, None)
            self._tasks.pop(name, None)
            cleanup = None
            for index in range(len(self._cleanups) - 1, -1, -1):
                if self._cleanups[index][0] == name:
                    _, cleanup = self._cleanups.pop(index)
                    break

            if cleanup is not None:
                try:
                    await cleanup()
                except Exception:
                    self._app.logger.exception(
                        "Error whilst rolling back resource %r", name
                    )

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {sorted(self._values)}>"
