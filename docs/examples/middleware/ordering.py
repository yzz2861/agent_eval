from litestar import Litestar, get
from litestar.middleware.base import ASGIMiddleware
from litestar.middleware.constraints import MiddlewareConstraints
from litestar.types import ASGIApp, Receive, Scope, Send


class SessionMiddleware(ASGIMiddleware):
    name = "session"

    async def handle(self, scope: Scope, receive: Receive, send: Send, next_app: ASGIApp) -> None:
        await next_app(scope, receive, send)


class AuthenticationMiddleware(ASGIMiddleware):
    # declare that this middleware needs to be applied after the middleware
    # named 'session', without needing to import it
    name = "authentication"
    constraints = MiddlewareConstraints(after=("session",))

    async def handle(self, scope: Scope, receive: Receive, send: Send, next_app: ASGIApp) -> None:
        await next_app(scope, receive, send)


@get("/", sync_to_thread=False)
def handler() -> dict[str, bool]:
    return {"ok": True}


# even though 'AuthenticationMiddleware' is listed first, the declared
# constraints are resolved when the application is initialized, so the final
# execution order is 'session' -> 'authentication'
app = Litestar(
    route_handlers=[handler],
    middleware=[AuthenticationMiddleware(), SessionMiddleware()],
)
