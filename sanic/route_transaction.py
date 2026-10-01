from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from sanic_routing.route import Route

from sanic.exceptions import RouteUpdateError, ServerError
from sanic.models.futures import FutureRoute
from sanic.models.handler_types import RouteHandler
from sanic.router import Router


if TYPE_CHECKING:
    from sanic.app import Sanic


class RouteTransaction:
    """A transactional, all-or-nothing update of an application's routes.

    A transaction stages a set of route additions and removals while the
    application keeps serving traffic on the current router version. When
    the transaction is committed, a brand new router version is built and
    validated first; only if every change is valid does the application
    atomically swap to the new version. If anything is invalid, an exception
    is raised and the previous version keeps working untouched.

    Requests that already entered the application keep using the router
    version that was active when they started (including url_for calls
    made while the handler is running). Requests that arrive after the swap
    see the full result of the transaction: added, removed, and replaced
    routes, consistently across hosts, methods, blueprint prefixes, and
    named URL lookups.

    Commits are serialized per application, and superseded router versions
    are released for garbage collection once in-flight requests no longer
    reference them.

    Example:
        async with app.route_transaction() as transaction:
            transaction.remove("old_endpoint")
            transaction.add(new_handler, "/new-endpoint", name="new_endpoint")
    """

    def __init__(self, app: Sanic) -> None:
        self._app = app
        self._additions: list[FutureRoute] = []
        self._removals: list[str | Route] = []
        self._state = "pending"

    def __await__(self):
        return self.commit().__await__()

    async def __aenter__(self) -> RouteTransaction:
        self._ensure_pending()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        if self._state != "pending":
            return
        if any(exc_info):
            self.discard()
            return
        await self.commit()

    @property
    def app(self) -> Sanic:
        """The application this transaction applies to."""
        return self._app

    @property
    def pending(self) -> bool:
        """Whether the transaction is still open for changes."""
        return self._state == "pending"

    def add(
        self,
        handler: RouteHandler,
        uri: str,
        methods: Iterable[str] | None = None,
        host: str | Iterable[str] | None = None,
        strict_slashes: bool | None = None,
        version: str | float | int | None = None,
        name: str | None = None,
        stream: bool = False,
        ignore_body: bool = False,
        unquote: bool = False,
        static: bool = False,
        version_prefix: str = "/v",
        error_format: str | None = None,
        websocket: bool = False,
        subprotocols: list[str] | None = None,
        **ctx_kwargs: Any,
    ) -> RouteTransaction:
        """Stage a route to be added by the transaction.

        Accepts the same options as Sanic.add_route. The route is not
        visible to any request until the transaction is committed.

        Args:
            handler (RouteHandler): The sync or async function to be executed.
            uri (str): The path of the route.
            methods (Optional[Iterable[str]], optional): The HTTP methods
                that should be attached. Defaults to GET.
            host (Optional[Union[str, Iterable[str]]], optional): Host or
                hosts that the route should be on. Defaults to None.
            strict_slashes (Optional[bool], optional): Whether to apply
                strict slashes. Defaults to the application's setting.
            version (Optional[Union[str, float, int]], optional): A version
                modifier for the uri. Defaults to None.
            name (Optional[str], optional): An identifying name of the
                route, used by url_for. Defaults to the handler name.
            stream (bool, optional): Whether to stream the response.
                Defaults to False.
            ignore_body (bool, optional): Whether the incoming request body
                should be read. Defaults to False.
            unquote (bool, optional): Whether to unquote the path. Defaults
                to False.
            static (bool, optional): Whether the route serves static files.
                Defaults to False.
            version_prefix (str, optional): URL path that should be before
                the version value. Defaults to "/v".
            error_format (Optional[str], optional): Custom error format
                string. Defaults to None.
            websocket (bool, optional): Whether this is a websocket route.
                Defaults to False.
            subprotocols (Optional[list[str]], optional): Websocket
                subprotocols. Defaults to None.
            **ctx_kwargs: Keyword arguments that begin with a ctx_ prefix
                will be appended to the route context.

        Returns:
            RouteTransaction: the transaction, for chaining
        """
        self._ensure_pending()
        app = self._app

        if not uri.startswith("/"):
            uri = "/" + uri
        if strict_slashes is None:
            strict_slashes = app.strict_slashes
        if not methods and not websocket:
            methods = frozenset({"GET"})

        name = app.generate_name(name, handler)

        if isinstance(host, str):
            host = frozenset([host])
        elif host and not isinstance(host, frozenset):
            host = frozenset(host)

        if isinstance(subprotocols, list):
            subprotocols = tuple(subprotocols)  # type: ignore
        elif isinstance(subprotocols, set):
            subprotocols = frozenset(subprotocols)  # type: ignore

        if not error_format or error_format == "auto":
            error_format = app._determine_error_format(handler)

        self._additions.append(
            FutureRoute(
                handler=handler,  # type: ignore
                uri=uri,
                methods=None
                if websocket
                else frozenset(map(str.upper, methods)),  # type: ignore
                host=host,  # type: ignore
                strict_slashes=strict_slashes,
                stream=stream,
                version=version,  # type: ignore
                name=name,
                ignore_body=ignore_body,
                websocket=websocket,
                subprotocols=subprotocols,  # type: ignore
                unquote=unquote,
                static=static,
                version_prefix=version_prefix,
                error_format=error_format,
                route_context=app._build_route_context(ctx_kwargs),
            )
        )
        return self

    def remove(self, *names: str | Route) -> RouteTransaction:
        """Stage routes to be removed by the transaction.

        Args:
            *names: View names (with or without the application name prefix)
                or Route objects belonging to the current router version.

        Returns:
            RouteTransaction: the transaction, for chaining
        """
        self._ensure_pending()
        if not names:
            raise RouteUpdateError(
                "Cannot remove routes: no route names were provided"
            )
        self._removals.extend(names)
        return self

    def replace(
        self,
        handler: RouteHandler,
        uri: str,
        *,
        name: str | None = None,
        **kwargs: Any,
    ) -> RouteTransaction:
        """Stage a route to be replaced by a new definition.

        This is shorthand for removing the existing route (resolved by
        name, or by the handler's name) and adding the new one in the
        same transaction.

        Args:
            handler (RouteHandler): The new handler to be executed.
            uri (str): The path of the route.
            name (Optional[str], optional): The name of the route to
                replace. Defaults to the handler name.
            **kwargs: Additional options accepted by RouteTransaction.add.

        Returns:
            RouteTransaction: the transaction, for chaining
        """
        self._ensure_pending()
        view_name = name or getattr(handler, "__name__", None)
        if not view_name:
            raise RouteUpdateError(
                "Cannot replace a route without a name; pass name=..."
            )
        self.remove(view_name)
        return self.add(handler, uri, name=name, **kwargs)

    def discard(self) -> None:
        """Discard the transaction, leaving the current router untouched."""
        self._ensure_pending()
        self._additions.clear()
        self._removals.clear()
        self._state = "discarded"

    async def commit(self) -> Router:
        """Build, validate, and atomically activate the new router version.

        The new version is fully built and validated before anything is
        swapped. If any staged change is invalid, an exception is raised
        and the currently active router version keeps serving traffic
        unchanged.

        Raises:
            RouteUpdateError: If the transaction is no longer pending, or a
                staged removal does not match the current router version.
            SanicException: If the resulting router version is invalid.

        Returns:
            Router: the newly activated router version
        """
        self._ensure_pending()
        app = self._app

        async with app._route_update_lock:
            candidate = self._build_candidate()

            # Validate the whole new version before swapping anything. Any
            # failure here leaves the current router version untouched.
            candidate.finalize()
            app.finalize_middleware(router=candidate)

            idents = [route.extra.ident for route in candidate.routes]
            duplicates = {ident for ident in idents if idents.count(ident) > 1}
            if duplicates:
                names = ", ".join(map(str, duplicates))
                raise ServerError(
                    f"Duplicate route names detected: {names}. You should "
                    "rename one or more of them explicitly by using the "
                    "'name' param, or changing the implicit name derived "
                    "from the class and function name."
                )

            # Atomic switch: requests that already started keep the previous
            # version pinned on their request object; new requests resolve
            # against the new version from this point on.
            previous = app.router
            app.router = candidate
            self._state = "committed"

            # Release the lookup caches that strongly reference the previous
            # version so it can be garbage collected once in-flight
            # requests no longer reference it.
            previous.get.cache_clear()
            previous.find_route_by_view_name.cache_clear()

        return candidate

    def _ensure_pending(self) -> None:
        if self._state != "pending":
            raise RouteUpdateError(
                f"Cannot modify a route transaction that is {self._state}"
            )

    def _build_candidate(self) -> Router:
        app = self._app
        current = app.router

        removals: list[Route] = []
        for item in self._removals:
            if isinstance(item, Route):
                name = item.name
                matches = [route for route in current.routes if route is item]
            else:
                name = app.generate_name(item)
                matches = [
                    route for route in current.routes if route.name == name
                ]
            if not matches:
                raise RouteUpdateError(
                    f"Cannot remove route '{name}': it does not exist in "
                    "the current router version"
                )
            removals.extend(matches)

        candidate = current.clone(exclude=removals)
        for future_route in self._additions:
            app._apply_route(future_route, router=candidate)
        return candidate
