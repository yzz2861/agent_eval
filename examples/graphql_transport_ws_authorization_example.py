"""
Example: subscription-level authorization rechecks over graphql-transport-ws.

Authenticating the websocket connection is not enough when permissions can
change while a subscription is active. This example configures Ariadne's
`GraphQLTransportWSHandler` with a `subscription_authorizer` hook that
rechecks a local, switchable permission function before each event is sent
to the client. A background task flips permissions and proactively notifies
the handler through `request_authorization_recheck`, so revoked
subscriptions are terminated immediately with an `error` message - without
closing the websocket connection or affecting other subscriptions.

Run with:

    uvicorn examples.graphql_transport_ws_authorization_example:app --reload
or:
    uv run --with "uvicorn[standard]" --with ariadne \\
        uvicorn examples.graphql_transport_ws_authorization_example:app --reload

Then connect a `graphql-transport-ws` client to ws://localhost:8000/graphql
sending a `connection_init` payload like `{"user": "alice"}` and run:

    subscription { ticker }

Every 15 seconds the permission of "alice" is toggled: her subscription is
terminated with an `error` message while other users keep receiving events.
"""

import asyncio

from starlette.applications import Starlette
from starlette.websockets import WebSocket

from ariadne import SubscriptionType, make_executable_schema
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLTransportWSHandler
from ariadne.types import Operation


class LocalPermissions:
    """Switchable in-memory permission store.

    Replace `is_allowed` with a call to your real authorization service.
    """

    def __init__(self) -> None:
        self._revoked_users: set[str] = set()

    def is_allowed(self, user: str) -> bool:
        return user not in self._revoked_users

    def toggle(self, user: str) -> None:
        if self.is_allowed(user):
            self._revoked_users.add(user)
        else:
            self._revoked_users.discard(user)


permissions = LocalPermissions()
active_connections: set[WebSocket] = set()

type_defs = """
    type Query {
        _unused: Boolean
    }

    type Subscription {
        ticker: Int!
    }
"""

subscription = SubscriptionType()


@subscription.source("ticker")
async def ticker_source(*_):
    counter = 0
    while True:
        yield counter
        counter += 1
        await asyncio.sleep(1)


@subscription.field("ticker")
def resolve_ticker(counter, *_):
    return counter


schema = make_executable_schema(type_defs, subscription)


def on_connect(websocket: WebSocket, payload) -> None:
    user = (payload or {}).get("user", "anonymous")
    websocket.scope["user"] = user
    active_connections.add(websocket)
    start_switchboard()


def on_disconnect(websocket: WebSocket) -> None:
    active_connections.discard(websocket)


async def subscription_authorizer(
    websocket: WebSocket, operation: Operation
) -> bool:
    # Local permission function, checked before each event is sent and
    # whenever the application requests an authorization recheck.
    await asyncio.sleep(0)  # stand-in for an async authorization service
    return permissions.is_allowed(websocket.scope["user"])


websocket_handler = GraphQLTransportWSHandler(
    on_connect=on_connect,
    on_disconnect=on_disconnect,
    subscription_authorizer=subscription_authorizer,
)


async def permission_switchboard() -> None:
    """Flips alice's permission and pushes rechecks to active connections."""
    while True:
        await asyncio.sleep(15)
        permissions.toggle("alice")
        for websocket in list(active_connections):
            websocket_handler.request_authorization_recheck(websocket)


switchboard_task: asyncio.Task | None = None


def start_switchboard() -> None:
    global switchboard_task
    if switchboard_task is None:
        switchboard_task = asyncio.create_task(permission_switchboard())


graphql_app = GraphQL(
    schema,
    debug=True,
    websocket_handler=websocket_handler,
)

app = Starlette()
app.mount("/graphql", graphql_app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
