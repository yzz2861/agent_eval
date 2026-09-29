from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncIterable
from collections.abc import Awaitable
from collections.abc import Callable
from contextvars import ContextVar
from types import TracebackType
from typing import Any

from .wrappers.response import Response
from .wrappers.response import ResponseBody

ResourceFactory = Callable[["RequestResources"], Any | Awaitable[Any]]
ResourceCleanup = Callable[[Any], Any | Awaitable[Any]]

# The names of the resources currently being resolved by this task. Used
# to detect and report circular dependencies between resources.
_resolution_chain: ContextVar[tuple[str, ...]] = ContextVar(
    "quart.resource_resolution_chain", default=()
)


class CircularResourceError(RuntimeError):
    """Raised when resources depend on each other in a cycle.

    The :attr:`chain` attribute contains the full resolution chain,
    ending with the resource that closes the cycle.
    """

    def __init__(self, chain: tuple[str, ...]) -> None:
        self.chain = chain
        super().__init__("Circular resource dependency: " + " -> ".join(chain))


class ResourceClosedError(RuntimeError):
    """Raised when accessing a resource registry that has been closed."""


class _ResourceEntry:
    __slots__ = ("cleanup", "closed", "factory", "task")

    def __init__(
        self, factory: ResourceFactory, cleanup: ResourceCleanup | None
    ) -> None:
        self.factory = factory
        self.cleanup = cleanup
        self.task: asyncio.Task[Any] | None = None
        self.closed = False


class RequestResources:
    """Request scoped asynchronous resources with managed lifetimes.

    Resources are registered with an asynchronous factory and an
    optional cleanup, then created lazily on the first :meth:`get`
    call. The same instance is shared by every user within the
    request, and everything that was created is cleaned up in reverse
    creation order when the request (or a streaming response) has
    finished.

    A factory receives this registry and may itself call
    :meth:`get` to depend on other resources. Circular dependencies
    raise :exc:`CircularResourceError` with the full chain, and a
    failing resolution rolls back anything it already opened.
    """

    def __init__(self) -> None:
        self._entries: dict[str, _ResourceEntry] = {}
        self._created: list[str] = []
        self._chains: dict[str, list[str]] = {}
        self._closed = False
        self._detached = False

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {sorted(self._entries)}>"

    @property
    def closed(self) -> bool:
        """True once :meth:`aclose` has started."""
        return self._closed

    @property
    def detached(self) -> bool:
        """True if cleanup has been handed off to a streaming response."""
        return self._detached

    def __contains__(self, name: str) -> bool:
        return name in self._entries

    def register(
        self,
        name: str,
        factory: ResourceFactory,
        cleanup: ResourceCleanup | None = None,
    ) -> None:
        """Register a resource for this request.

        Arguments:
            name: The name the resource is fetched by.
            factory: Called with this registry to create the resource
                on first use. May be synchronous or return an awaitable.
            cleanup: Called with the created value when the resource is
                released. May be synchronous or return an awaitable.
        """
        if self._closed:
            raise ResourceClosedError("The request resources have been closed")
        if name in self._entries:
            raise ValueError(f"A resource named {name!r} is already registered")
        self._entries[name] = _ResourceEntry(factory, cleanup)

    async def get(self, name: str) -> Any:
        """Return the resource, creating it on first use.

        Concurrent calls share a single initialisation, and cancelling
        one waiter does not cancel the creation itself. If the
        creation fails, anything it opened within the same resolution
        is rolled back in reverse order.
        """
        chain = _resolution_chain.get()
        if name in chain:
            raise CircularResourceError((*chain, name))
        if self._closed:
            raise ResourceClosedError("The request resources have been closed")
        try:
            entry = self._entries[name]
        except KeyError:
            raise KeyError(f"No resource named {name!r} is registered") from None
        if entry.task is None:
            root = chain[0] if chain else name
            entry.closed = False
            entry.task = asyncio.ensure_future(self._create(name, entry, chain))
            self._chains.setdefault(root, []).append(name)
        # Shield so that a cancelled waiter does not cancel the shared
        # initialisation other waiters rely on.
        return await asyncio.shield(entry.task)

    async def _create(
        self, name: str, entry: _ResourceEntry, chain: tuple[str, ...]
    ) -> Any:
        token = _resolution_chain.set((*chain, name))
        try:
            result = entry.factory(self)
            if inspect.isawaitable(result):
                result = await result
        except BaseException:
            entry.task = None
            if not chain:
                # The root of this resolution failed, roll back
                # everything it managed to open.
                await self._rollback(name)
            raise
        else:
            self._created.append(name)
            if not chain:
                self._chains.pop(name, None)
            return result
        finally:
            _resolution_chain.reset(token)

    async def _rollback(self, root: str) -> None:
        members = set(self._chains.pop(root, []))
        errors = []
        tasks = {}
        for name in members:
            entry = self._entries[name]
            if entry.task is not asyncio.current_task():
                tasks[name] = entry.task
                entry.task = None
        # Close in reverse completion order so that dependents are
        # released before the resources they were built from.
        for name in reversed(self._created):
            if name not in members:
                continue
            entry = self._entries[name]
            task = tasks.get(name)
            if task is None or not task.done() or task.cancelled():
                continue
            if task.exception() is not None:
                continue
            try:
                await self._close_entry(entry, task.result())
            except Exception as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup(f"Errors rolling back resource {root!r}", errors)

    async def _close_entry(self, entry: _ResourceEntry, value: Any) -> None:
        if entry.closed or entry.cleanup is None:
            return
        entry.closed = True
        result = entry.cleanup(value)
        if inspect.isawaitable(result):
            await result

    async def aclose(self) -> None:
        """Release every created resource in reverse creation order.

        This runs at most once, further calls are no-ops. Cleanup
        errors are collected and raised together as an
        :exc:`ExceptionGroup` once everything has been released.
        """
        if self._closed:
            return
        self._closed = True
        errors = []
        cancelled: asyncio.CancelledError | None = None
        # Wait for any in-flight creations so their values are released too.
        for entry in self._entries.values():
            task = entry.task
            if task is not None and not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError as error:
                    if not task.cancelled() and cancelled is None:
                        cancelled = error
                except Exception:
                    pass
        for name in reversed(self._created):
            entry = self._entries[name]
            task = entry.task
            if task is None or not task.done() or task.cancelled():
                continue
            if task.exception() is not None:
                continue
            try:
                await self._close_entry(entry, task.result())
            except asyncio.CancelledError as error:
                if cancelled is None:
                    cancelled = error
            except Exception as error:
                errors.append(error)
        self._created.clear()
        self._chains.clear()
        if errors:
            raise ExceptionGroup("Errors closing request resources", errors)
        if cancelled is not None:
            raise cancelled

    def attach_to(self, response: Response) -> None:
        """Defer cleanup until the response body has finished streaming.

        Wraps the response body so that the resources are released
        when the body is exhausted, errors, or the client disconnects,
        rather than when the request context is popped.
        """
        if self._closed or self._detached or not self._entries:
            return
        if not isinstance(response, Response):
            return
        response.response = ResourceResponseBody(response.response, self)
        self._detached = True


class ResourceResponseBody(ResponseBody):
    """Wraps a response body to close request resources when it closes."""

    def __init__(self, body: ResponseBody, resources: RequestResources) -> None:
        self._body = body
        self.resources = resources

    def __getattr__(self, name: str) -> Any:
        return getattr(self._body, name)

    async def __aenter__(self) -> AsyncIterable:
        return await self._body.__aenter__()

    async def __aexit__(
        self,
        exc_type: type | None,
        exc_value: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await self._body.__aexit__(exc_type, exc_value, tb)
        finally:
            await self.resources.aclose()
