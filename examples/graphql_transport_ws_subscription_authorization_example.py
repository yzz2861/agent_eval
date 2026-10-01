"""Example: per-subscription authorization with graphql-transport-ws.

Run with:

    uvicorn \
      examples.graphql_transport_ws_subscription_authorization_example:app

or:

    uv run --with "uvicorn[standard]" --with ariadne uvicorn \
      examples.graphql_transport_ws_subscription_authorization_example:app

Subscribe with:

    wscat -s graphql-transport-ws ws://127.0.0.1:8000/graphql?subject=demo

Toggle that subject's local permission with:

    curl -X POST http://127.0.0.1:8000/revoke/demo
    curl -X POST http://127.0.0.1:8000/allow/demo
"""

import asyncio
from typing import Any

from graphql import GraphQLResolveInfo
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from ariadne import QueryType, SubscriptionType, make_executable_schema
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLTransportWSHandler

ALLOWED_SUBJECTS = {"demo"}
active_connections: dict[int, Any] = {}
connection_operations: dict[int, int] = {}


def get_subject(websocket: Any) -> str:
    return websocket.query_params.get("subject", "demo")


async def authorize_subscription(_websocket: Any, operation: Any) -> bool:
    subject = operation.context_value["subject"]
    return subject in ALLOWED_SUBJECTS


async def get_context_value(websocket: Any, data: dict[str, Any]) -> dict[str, Any]:
    return {"request": websocket, "subject": get_subject(websocket)}


query = QueryType()
subscription = SubscriptionType()


@query.field("status")
def resolve_status(*_: Any) -> str:
    return "ok"


@subscription.source("status")
async def status_source(_: Any, info: GraphQLResolveInfo):
    while True:
        subject = info.context["subject"]
        yield {"status": f"{subject}: {asyncio.get_running_loop().time():.0f}"}
        await asyncio.sleep(1)


@subscription.field("status")
def resolve_subscription_status(result: dict[str, str], *_: Any) -> str:
    return result["status"]


def remember_connection(websocket: Any, operation: Any) -> None:
    active_connections[id(websocket)] = websocket
    connection_operations[id(websocket)] = (
        connection_operations.get(id(websocket), 0) + 1
    )


def forget_connection(websocket: Any, operation: Any) -> None:
    connection_id = id(websocket)
    remaining = connection_operations.get(connection_id, 0) - 1
    if remaining > 0:
        connection_operations[connection_id] = remaining
    else:
        connection_operations.pop(connection_id, None)
        active_connections.pop(connection_id, None)


type_defs = """
    type Query {
        status: String!
    }

    type Subscription {
        status: String!
    }
"""

schema = make_executable_schema(type_defs, query, subscription)
websocket_handler = GraphQLTransportWSHandler(
    on_operation=remember_connection,
    on_complete=forget_connection,
    on_subscription_authorize=authorize_subscription,
)
graphql_app = GraphQL(
    schema,
    context_value=get_context_value,
    debug=True,
    websocket_handler=websocket_handler,
)


async def allow_subject(request: Request) -> PlainTextResponse:
    subject = request.path_params["subject"]
    ALLOWED_SUBJECTS.add(subject)
    for websocket in list(active_connections.values()):
        websocket_handler.notify_subscription_authorization_changed(websocket)
    return PlainTextResponse(f"Allowed {subject}\n")


async def revoke_subject(request: Request) -> PlainTextResponse:
    subject = request.path_params["subject"]
    ALLOWED_SUBJECTS.discard(subject)
    for websocket in list(active_connections.values()):
        websocket_handler.notify_subscription_authorization_changed(websocket)
    return PlainTextResponse(f"Revoked {subject}\n")


app = Starlette(
    routes=[
        Route("/allow/{subject}", allow_subject, methods=["POST"]),
        Route("/revoke/{subject}", revoke_subject, methods=["POST"]),
        Route("/graphql", graphql_app),
    ]
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
