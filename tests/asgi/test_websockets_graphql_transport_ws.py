import asyncio
import time
from unittest.mock import Mock

import pytest
from graphql import GraphQLError, parse
from graphql.language import OperationType
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from ariadne import SubscriptionType, make_executable_schema
from ariadne.asgi import GraphQL
from ariadne.asgi.handlers import GraphQLTransportWSHandler
from ariadne.exceptions import WebSocketConnectionError
from ariadne.utils import get_operation_type

from .websocket_utils import wait_for_condition


def test_field_can_be_subscribed_using_websocket_connection_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { ping }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test1"


def test_field_can_be_subscribed_using_unnamed_operation_in_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": None,
                    "query": "subscription { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test1"


def test_field_can_be_subscribed_using_named_operation_in_websocket_connection_graphql_transport_ws(  # noqa: E501
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "PingTest",
                    "query": "subscription PingTest { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test1"


def test_query_can_be_executed_using_websocket_connection_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test2",
                "payload": {
                    "operationName": None,
                    "query": "query Hello($name: String){ hello(name: $name) }",
                    "variables": {"name": "John"},
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test2"
        assert response["payload"]["data"] == {"hello": "Hello, John!"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test2"


def test_mutation_can_be_executed_using_websocket_connection_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test3",
                "payload": {
                    "operationName": None,
                    "query": "mutation($text: String!) { echo(text: $text) }",
                    "variables": {"text": "John"},
                },
            }
        )

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test3"
        assert response["payload"]["data"] == {"echo": "Echo: John"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test3"


def test_invalid_query_error_is_handled_using_websocket_connection_graphql_transport_ws(
    client_graphql_transport_ws, snapshot
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test2",
                "payload": {
                    "operationName": "Invalid",
                    "query": "query Invalid { error other }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_ERROR
        assert snapshot == response["payload"]


def test_custom_query_parser_is_used_for_subscription_over_websocket_transport_ws(
    schema,
):
    mock_parser = Mock(return_value=parse("subscription { testContext }"))
    websocket_handler = GraphQLTransportWSHandler()
    app = GraphQL(
        schema,
        query_parser=mock_parser,
        context_value={"test": "I'm context"},
        root_value={"test": "I'm root"},
        websocket_handler=websocket_handler,
    )

    with TestClient(app).websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test2",
                "payload": {
                    "operationName": None,
                    "query": "subscription { testRoot }",
                    "variables": None,
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test2"
        assert response["payload"]["data"] == {"testContext": "I'm context"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test2"


@pytest.mark.parametrize(
    ("errors"),
    [
        ([]),
        ([GraphQLError("Nope")]),
    ],
)
def test_custom_query_validator_is_used_for_subscription_over_websocket_transport_ws(
    schema, errors
):
    mock_validator = Mock(return_value=errors)
    websocket_handler = GraphQLTransportWSHandler()
    app = GraphQL(
        schema,
        query_validator=mock_validator,
        context_value={"test": "I'm context"},
        root_value={"test": "I'm root"},
        websocket_handler=websocket_handler,
    )

    with TestClient(app).websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test2",
                "payload": {
                    "operationName": None,
                    "query": "subscription { testContext }",
                    "variables": None,
                },
            }
        )
        response = ws.receive_json()
        if not errors:
            assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
            assert response["id"] == "test2"
            assert response["payload"]["data"] == {"testContext": "I'm context"}
            response = ws.receive_json()
            assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
            assert response["id"] == "test2"
        else:
            assert response["type"] == GraphQLTransportWSHandler.GQL_ERROR
            assert response["id"] == "test2"
            assert response["payload"][0]["message"] == "Nope"


def test_custom_query_parser_is_used_for_query_over_websocket_transport_ws(
    schema,
):
    mock_parser = Mock(return_value=parse("query { testContext }"))
    websocket_handler = GraphQLTransportWSHandler()
    app = GraphQL(
        schema,
        query_parser=mock_parser,
        context_value={"test": "I'm context"},
        root_value={"test": "I'm root"},
        websocket_handler=websocket_handler,
    )

    with TestClient(app).websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test2",
                "payload": {
                    "operationName": None,
                    "query": "query { testRoot }",
                    "variables": None,
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test2"
        assert response["payload"]["data"] == {"testContext": "I'm context"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert response["id"] == "test2"


def test_immediate_disconnect_on_invalid_type_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json({"type": "INVALID_TYPE"})
        with pytest.raises(WebSocketDisconnect):
            assert ws.receive_json()


def test_complete_graphql_transport_ws(client_graphql_transport_ws):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { ping }"},
            }
        )
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_COMPLETE, "id": "test1"})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { ping }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"


def test_pong_graphql_transport_ws(client_graphql_transport_ws):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_PONG,
            }
        )


def test_custom_websocket_on_connect_is_called_graphql_transport_ws(schema):
    test_payload = None

    def on_connect(websocket, payload):
        assert payload == test_payload
        websocket.scope["payload"] = payload

    websocket_handler = GraphQLTransportWSHandler(on_connect=on_connect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        assert ws.scope["payload"] == test_payload


def test_custom_websocket_on_connect_is_called_with_payload_graph_graphql_transport_ws(
    schema,
):
    test_payload = {"test": "ok"}

    def on_connect(websocket, payload):
        assert payload == test_payload
        websocket.scope["payload"] = payload

    websocket_handler = GraphQLTransportWSHandler(on_connect=on_connect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT,
                "payload": test_payload,
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        assert ws.scope["payload"] == test_payload


def test_custom_websocket_on_connect_is_awaited_if_its_async_graphql_transport_ws(
    schema,
):
    test_payload = {"test": "ok"}

    async def on_connect(websocket, payload):
        assert payload == test_payload
        websocket.scope["payload"] = payload

    websocket_handler = GraphQLTransportWSHandler(on_connect=on_connect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT,
                "payload": test_payload,
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        assert ws.scope["payload"] == test_payload


def test_error_in_custom_websocket_on_connect_closes_connection_graphql_transport_ws(
    schema,
):
    def on_connect(websocket, payload):
        raise ValueError("Oh No!")

    websocket_handler = GraphQLTransportWSHandler(on_connect=on_connect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


def test_custom_websocket_connection_error_closes_connection_graphql_transport_ws(
    schema,
):
    def on_connect(websocket, payload):
        raise WebSocketConnectionError({"msg": "Token required", "code": "auth_error"})

    websocket_handler = GraphQLTransportWSHandler(on_connect=on_connect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_json()


def test_custom_websocket_on_operation_is_called_graphql_transport_ws(schema):
    def on_operation(websocket, operation):
        assert operation.name == "TestOp"
        websocket.scope["on_operation"] = True

    websocket_handler = GraphQLTransportWSHandler(on_operation=on_operation)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
        assert ws.scope["on_operation"] is True


def test_custom_websocket_on_operation_is_awaited_if_its_async_graphql_transport_ws(
    schema,
):
    async def on_operation(websocket, operation):
        assert operation.name == "TestOp"
        websocket.scope["on_operation"] = True

    websocket_handler = GraphQLTransportWSHandler(on_operation=on_operation)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_COMPLETE, "id": "test1"})
        assert ws.scope["on_operation"] is True


def test_error_in_custom_websocket_on_operation_is_handled_graphql_transport_ws(schema):
    async def on_operation(websocket, operation):
        raise ValueError("Oh No!")

    websocket_handler = GraphQLTransportWSHandler(on_operation=on_operation)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}


def test_custom_websocket_on_complete_is_called_on_disconnect_graphql_transport_ws(
    schema,
):
    def on_complete(websocket, operation):
        assert operation.name == "TestOp"
        websocket.scope["on_complete"] = True

    websocket_handler = GraphQLTransportWSHandler(on_complete=on_complete)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )

    assert ws.scope["on_complete"] is True


def test_custom_websocket_on_complete_is_called_on_operation_complete_grapqhl_transport_ws(  # noqa: E501
    schema,
):
    def on_complete(websocket, operation):
        assert operation.name == "TestOp"
        websocket.scope["on_complete"] = True

    websocket_handler = GraphQLTransportWSHandler(on_complete=on_complete)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE

        assert ws.scope["on_complete"] is True


def test_custom_websocket_on_complete_is_awaited_if_its_async_graphql_transport_ws(
    schema,
):
    async def on_complete(websocket, operation):
        assert operation.name == "TestOp"
        websocket.scope["on_complete"] = True

    websocket_handler = GraphQLTransportWSHandler(on_complete=on_complete)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE

    assert ws.scope["on_complete"] is True


def test_error_in_custom_websocket_on_complete_is_handled_graphql_transport_ws(schema):
    async def on_complete(websocket, operation):
        raise ValueError("Oh No!")

    websocket_handler = GraphQLTransportWSHandler(on_complete=on_complete)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {
                    "operationName": "TestOp",
                    "query": "subscription TestOp { ping }",
                },
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "test1"
        assert response["payload"]["data"] == {"ping": "pong"}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE


def test_custom_websocket_on_disconnect_is_called_on_invalid_operation_graphql_transport_ws(  # noqa: E501
    schema,
    timeout=5,
    poll_interval=0.1,
):
    def on_disconnect(websocket):
        websocket.scope["on_disconnect"] = True

    websocket_handler = GraphQLTransportWSHandler(on_disconnect=on_disconnect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json({"type": "INVALID"})
        condition_met = wait_for_condition(
            lambda: "on_disconnect" in ws.scope,
            timeout,
            poll_interval,
        )

        assert condition_met and ws.scope.get("on_disconnect") is True, (
            "on_disconnect should be set in ws.scope after invalid message"
        )


def test_custom_websocket_on_disconnect_is_called_on_connection_close_graphql_transport_ws(  # noqa: E501
    schema,
):
    def on_disconnect(websocket):
        websocket.scope["on_disconnect"] = True

    websocket_handler = GraphQLTransportWSHandler(on_disconnect=on_disconnect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        assert "on_disconnect" not in ws.scope

    assert ws.scope["on_disconnect"] is True


def test_custom_websocket_on_disconnect_is_awaited_if_its_async_graphql_transport_ws(
    schema,
    timeout=5,
    poll_interval=0.1,
):
    async def on_disconnect(websocket):
        websocket.scope["on_disconnect"] = True

    websocket_handler = GraphQLTransportWSHandler(on_disconnect=on_disconnect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json({"type": "INVALID"})
        condition_met = wait_for_condition(
            lambda: "on_disconnect" in ws.scope,
            timeout,
            poll_interval,
        )

        assert condition_met and ws.scope.get("on_disconnect") is True, (
            "on_disconnect should be set in ws.scope after invalid message"
        )


def test_error_in_custom_websocket_on_disconnect_is_handled_graphql_transport_ws(
    schema,
):
    async def on_disconnect(websocket):
        raise ValueError("Oh No!")

    websocket_handler = GraphQLTransportWSHandler(on_disconnect=on_disconnect)
    app = GraphQL(schema, websocket_handler=websocket_handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json({"type": "INVALID"})


def test_too_many_connection_init_messages_graphql_transport_ws(
    schema,
):
    handler = GraphQLTransportWSHandler()
    app = GraphQL(schema, websocket_handler=handler)
    client = TestClient(app)

    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()

        assert exc_info.value.code == 4429


def test_get_operation_type():
    graphql_document = parse("subscription ping {ping} query other { dummy }")
    operation_type = get_operation_type(graphql_document, "ping")
    assert operation_type == OperationType.SUBSCRIPTION

    operation_type = get_operation_type(graphql_document, "other")
    assert operation_type == OperationType.QUERY

    operation_type = get_operation_type(graphql_document)
    assert operation_type == OperationType.SUBSCRIPTION


def test_connection_not_acknowledged_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { ping }"},
            }
        )

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()

        assert exc_info.value.code == 4401


@pytest.mark.skip(
    "This test fails intermittently with Starlette version 0.38.2,"
    "but works as expected with version 0.37.2."
)
def test_duplicate_operation_id_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { ping }"},
            }
        )
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { ping }"},
            }
        )
        ws.receive_json()

        with pytest.raises(WebSocketDisconnect) as exc_info:
            ws.receive_json()

        assert exc_info.value.code == 4409


def test_invalid_operation_id_is_handled_graphql_transport_ws(
    client_graphql_transport_ws,
):
    with client_graphql_transport_ws.websocket_connect(
        "/", ["graphql-transport-ws"]
    ) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_COMPLETE, "id": "test1"})
        ws.receive_json()


def test_schema_not_set_graphql_transport_ws(
    client_graphql_transport_ws,
):
    client_graphql_transport_ws.app.websocket_handler.schema = None
    with pytest.raises(TypeError):
        with client_graphql_transport_ws.websocket_connect(
            "/", ["graphql-transport-ws"]
        ) as ws:
            ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
            ws.send_json(
                {
                    "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                    "id": "test1",
                    "payload": {"query": "subscription { ping }"},
                }
            )


def test_http_handler_not_set_graphql_transport_ws(
    client_graphql_transport_ws,
):
    client_graphql_transport_ws.app.websocket_handler.http_handler = None
    with pytest.raises(TypeError):
        with client_graphql_transport_ws.websocket_connect(
            "/", ["graphql-transport-ws"]
        ) as ws:
            ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
            ws.send_json(
                {
                    "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                    "id": "test2",
                    "payload": {
                        "operationName": None,
                        "query": "query Hello($name: String){ hello(name: $name) }",
                        "variables": {"name": "John"},
                    },
                }
            )


auth_type_defs = """
    type Query {
        _unused: Boolean
    }

    type Subscription {
        counter: Int!
        alt: Int!
    }
"""


class ControlledSource:
    """Infinite subscription source yielding values pushed by the test."""

    def __init__(self, field):
        self.field = field
        self.values = []
        self.pulls = 0
        self.closed = 0

    async def __call__(self, *_):
        index = 0
        try:
            while True:
                while index >= len(self.values):
                    await asyncio.sleep(0.01)
                self.pulls += 1
                yield {self.field: self.values[index]}
                index += 1
        finally:
            self.closed += 1


class InstantSource:
    """Infinite subscription source yielding a value on every pull."""

    def __init__(self, field):
        self.field = field
        self.pulls = 0
        self.closed = 0

    async def __call__(self, *_):
        value = 0
        try:
            while True:
                self.pulls += 1
                yield {self.field: value}
                value += 1
        finally:
            self.closed += 1


def make_auth_schema(counter_source, alt_source=None):
    subscription = SubscriptionType()
    subscription.set_source("counter", counter_source)
    subscription.set_source("alt", alt_source or ControlledSource("alt"))
    return make_executable_schema(auth_type_defs, subscription)


def test_subscription_authorizer_is_called_before_each_event_graphql_transport_ws():
    source = ControlledSource("counter")
    calls = []

    def authorizer(websocket, operation):
        calls.append(operation.id)
        return True

    websocket_handler = GraphQLTransportWSHandler(subscription_authorizer=authorizer)
    app = GraphQL(make_auth_schema(source), websocket_handler=websocket_handler)
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { counter }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK

        source.values.extend([1, 2])
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["payload"]["data"] == {"counter": 1}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["payload"]["data"] == {"counter": 2}

    assert calls[:2] == ["test1", "test1"]


def test_revoked_subscription_is_terminated_on_recheck_request_graphql_transport_ws():
    state = {"allowed": True}
    source_closed = []

    def authorizer(websocket, operation):
        return state["allowed"]

    websocket_handler = GraphQLTransportWSHandler(subscription_authorizer=authorizer)

    async def revoking_generator(_, info):
        try:
            yield {"counter": 1}
            state["allowed"] = False
            websocket_handler.request_authorization_recheck(info.context["request"])
            while True:
                await asyncio.sleep(0.05)
        finally:
            source_closed.append(True)

    app = GraphQL(
        make_auth_schema(revoking_generator),
        websocket_handler=websocket_handler,
    )
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { counter }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["payload"]["data"] == {"counter": 1}

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_ERROR
        assert response["id"] == "test1"
        assert "not authorized" in response["payload"][0]["message"]

        # connection is not closed and still answers to protocol messages
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_PING})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_PONG

    assert wait_for_condition(lambda: len(source_closed) == 1)


def test_only_revoked_subscription_is_terminated_graphql_transport_ws():
    state = {"alt_allowed": True}
    counter_source = ControlledSource("counter")

    def authorizer(websocket, operation):
        if operation.id == "drop":
            return state["alt_allowed"]
        return True

    websocket_handler = GraphQLTransportWSHandler(subscription_authorizer=authorizer)

    async def alt_generator(_, info):
        yield {"alt": 1}
        state["alt_allowed"] = False
        websocket_handler.request_authorization_recheck(
            info.context["request"], "drop"
        )
        while True:
            await asyncio.sleep(0.05)

    app = GraphQL(
        make_auth_schema(counter_source, alt_generator),
        websocket_handler=websocket_handler,
    )
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK

        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "keep",
                "payload": {"query": "subscription { counter }"},
            }
        )
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "drop",
                "payload": {"query": "subscription { alt }"},
            }
        )

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "drop"
        assert response["payload"]["data"] == {"alt": 1}

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_ERROR
        assert response["id"] == "drop"

        # the other subscription is unaffected and keeps receiving events
        counter_source.values.append(10)
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "keep"
        assert response["payload"]["data"] == {"counter": 10}

        counter_source.values.append(11)
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["id"] == "keep"
        assert response["payload"]["data"] == {"counter": 11}


def test_events_dont_pile_up_while_async_recheck_is_pending_graphql_transport_ws():
    source = InstantSource("counter")
    state = {"allowed": True, "release": False}
    calls = []

    async def authorizer(websocket, operation):
        calls.append(operation.id)
        if len(calls) > 1:
            while not state["release"]:
                await asyncio.sleep(0.01)
        return state["allowed"]

    websocket_handler = GraphQLTransportWSHandler(subscription_authorizer=authorizer)
    app = GraphQL(make_auth_schema(source), websocket_handler=websocket_handler)
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { counter }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["payload"]["data"] == {"counter": 0}

        # the next recheck is pending; source could yield endlessly but at
        # most one already pulled event may wait for the recheck to finish
        assert wait_for_condition(lambda: len(calls) >= 2)
        time.sleep(0.3)
        assert source.pulls == 1

        state["allowed"] = False
        state["release"] = True
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_ERROR
        assert response["id"] == "test1"

    assert wait_for_condition(lambda: source.closed == 1)


def test_subscription_authorizer_error_terminates_operation_graphql_transport_ws():
    source = ControlledSource("counter")
    calls = []

    def authorizer(websocket, operation):
        calls.append(operation.id)
        if len(calls) > 1:
            raise Exception("Auth backend is down")
        return True

    websocket_handler = GraphQLTransportWSHandler(subscription_authorizer=authorizer)
    app = GraphQL(make_auth_schema(source), websocket_handler=websocket_handler)
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { counter }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK

        source.values.extend([1, 2])
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["payload"]["data"] == {"counter": 1}

        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_ERROR
        assert response["id"] == "test1"
        assert "Auth backend is down" in response["payload"][0]["message"]

    assert wait_for_condition(lambda: source.closed == 1)


def test_subscription_is_cleaned_up_once_on_concurrent_stops_graphql_transport_ws():
    source = ControlledSource("counter")
    state = {"allowed": True}
    calls = []
    completed = []

    async def authorizer(websocket, operation):
        calls.append(operation.id)
        if len(calls) > 1:
            # keep the recheck in flight long enough for the client "complete"
            # message and the connection close to land at the same time
            await asyncio.sleep(0.05)
            return state["allowed"]
        return True

    def on_complete(websocket, operation):
        completed.append(operation.id)

    websocket_handler = GraphQLTransportWSHandler(
        subscription_authorizer=authorizer,
        on_complete=on_complete,
    )
    app = GraphQL(make_auth_schema(source), websocket_handler=websocket_handler)
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "subscription { counter }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK

        source.values.append(1)
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT

        # revoke permission while client also asks to stop the operation,
        # then close the connection; all three race the in-flight recheck
        state["allowed"] = False
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_COMPLETE, "id": "test1"})

    assert wait_for_condition(lambda: source.closed == 1)
    assert wait_for_condition(lambda: len(completed) == 1)
    time.sleep(0.2)
    assert source.closed == 1
    assert completed == ["test1"]


def test_query_is_not_checked_by_subscription_authorizer_graphql_transport_ws():
    def authorizer(websocket, operation):
        return False

    websocket_handler = GraphQLTransportWSHandler(subscription_authorizer=authorizer)
    app = GraphQL(
        make_auth_schema(ControlledSource("counter")),
        websocket_handler=websocket_handler,
    )
    client = TestClient(app)
    with client.websocket_connect("/", ["graphql-transport-ws"]) as ws:
        ws.send_json({"type": GraphQLTransportWSHandler.GQL_CONNECTION_INIT})
        ws.send_json(
            {
                "type": GraphQLTransportWSHandler.GQL_SUBSCRIBE,
                "id": "test1",
                "payload": {"query": "query { _unused }"},
            }
        )
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_CONNECTION_ACK
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_NEXT
        assert response["payload"]["data"] == {"_unused": None}
        response = ws.receive_json()
        assert response["type"] == GraphQLTransportWSHandler.GQL_COMPLETE
