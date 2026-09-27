import json

from fastapi import APIRouter, Depends, FastAPI
from fastapi.openapi.utils import prune_openapi_components
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from fastapi.testclient import TestClient
from pydantic import BaseModel


class SharedItem(BaseModel):
    name: str


class CustomerItem(BaseModel):
    display_name: str


class InternalReport(BaseModel):
    secret: str
    item: SharedItem


class NodeA(BaseModel):
    peer: "NodeB | None" = None


class NodeB(BaseModel):
    peer: "NodeA | None" = None


NodeA.model_rebuild()
NodeB.model_rebuild()


class CallbackPayload(BaseModel):
    callback_url: str


class InternalCallbackPayload(BaseModel):
    secret_token: str


class HiddenModel(BaseModel):
    hidden: str


class RouterInternalModel(BaseModel):
    router_secret: str


class OpsModel(BaseModel):
    ops_status: str


class BothModel(BaseModel):
    both: str


class LateModel(BaseModel):
    late: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-Key")

callback_router = APIRouter()


@callback_router.get("{$callback_url}", response_model=CallbackPayload)
def callback_receiver():
    pass  # pragma: no cover


internal_callback_router = APIRouter()


@internal_callback_router.get("{$callback_url}", response_model=InternalCallbackPayload)
def internal_callback_receiver():
    pass  # pragma: no cover


app = FastAPI()


@app.get("/items", response_model=list[CustomerItem], callbacks=callback_router.routes)
def list_items(key: str = Depends(api_key_scheme)):
    return []  # pragma: no cover


@app.get("/shared", response_model=SharedItem)
def read_shared():
    return SharedItem(name="shared")


@app.get(
    "/internal/report",
    response_model=InternalReport,
    audiences=["internal"],
    dependencies=[Depends(oauth2_scheme)],
)
def internal_report():
    return InternalReport(secret="s3cr3t", item=SharedItem(name="shared"))


@app.get("/internal/nodes", response_model=NodeA, audiences=["internal"])
def internal_nodes():
    return NodeA()


@app.post(
    "/internal/callbacks",
    response_model=SharedItem,
    audiences=["internal"],
    callbacks=internal_callback_router.routes,
)
def internal_callbacks():
    return SharedItem(name="shared")


@app.get("/hidden", response_model=HiddenModel, include_in_schema=False)
def hidden():
    return HiddenModel(hidden="still reachable")


internal_router = APIRouter(audiences=["internal"])


@internal_router.get("/router-internal", response_model=RouterInternalModel)
def router_internal():
    return RouterInternalModel(router_secret="s3cr3t")


app.include_router(internal_router)

ops_router = APIRouter()


@ops_router.get("/ops", response_model=OpsModel)
def ops():
    return OpsModel(ops_status="ok")


app.include_router(ops_router, audiences=["ops"])

both_router = APIRouter(audiences=["internal", "ops"])


@both_router.get("/both", response_model=BothModel)
def both():
    return BothModel(both="both")


app.include_router(both_router, audiences=["ops", "customer"])


@app.webhooks.post("/new-item", response_model=SharedItem)
def webhook_new_item():
    pass  # pragma: no cover


@app.webhooks.post(
    "/internal-event", response_model=InternalReport, audiences=["internal"]
)
def webhook_internal_event():
    pass  # pragma: no cover


@app.get("/openapi/{audience}.json", include_in_schema=False)
def serve_audience_openapi(audience: str):
    return app.openapi_for_audience(audience)


client = TestClient(app)


def schema_text(schema: dict) -> str:
    return json.dumps(schema)


def test_customer_schema_only_has_customer_operations():
    schema = app.openapi_for_audience("customer")
    assert set(schema["paths"]) == {"/items", "/shared"}


def test_internal_schema_has_internal_and_public_operations():
    schema = app.openapi_for_audience("internal")
    assert set(schema["paths"]) == {
        "/items",
        "/shared",
        "/internal/report",
        "/internal/nodes",
        "/internal/callbacks",
        "/router-internal",
    }


def test_ops_schema_combines_include_router_audiences():
    schema = app.openapi_for_audience("ops")
    assert set(schema["paths"]) == {"/items", "/shared", "/ops", "/both"}


def test_audiences_intersect_between_router_and_include_router():
    # both_router declares ["internal", "ops"], include_router declares
    # ["ops", "customer"], so it is only visible to "ops"
    assert "/both" not in app.openapi_for_audience("internal")["paths"]
    assert "/both" not in app.openapi_for_audience("customer")["paths"]
    assert "/both" in app.openapi_for_audience("ops")["paths"]


def test_customer_schema_components_are_pruned():
    schema = app.openapi_for_audience("customer")
    assert set(schema["components"]["schemas"]) == {
        "CallbackPayload",
        "CustomerItem",
        "SharedItem",
    }
    text = schema_text(schema)
    for name in [
        "InternalReport",
        "InternalCallbackPayload",
        "NodeA",
        "NodeB",
        "HiddenModel",
        "RouterInternalModel",
        "OpsModel",
        "BothModel",
    ]:
        assert name not in text


def test_internal_schema_keeps_shared_and_circular_models():
    schema = app.openapi_for_audience("internal")
    schemas = schema["components"]["schemas"]
    assert "SharedItem" in schemas
    assert "InternalReport" in schemas
    assert "NodeA" in schemas
    assert "NodeB" in schemas
    # circular references are preserved
    node_a_ref = "#/components/schemas/NodeA"
    node_b_ref = "#/components/schemas/NodeB"
    assert schemas["NodeA"]["properties"]["peer"]["anyOf"][0]["$ref"] == node_b_ref
    assert schemas["NodeB"]["properties"]["peer"]["anyOf"][0]["$ref"] == node_a_ref
    # but models only used by other audiences are still pruned
    assert "OpsModel" not in schemas
    assert "BothModel" not in schemas


def test_security_schemes_are_filtered_per_audience():
    customer_schema = app.openapi_for_audience("customer")
    assert set(customer_schema["components"]["securitySchemes"]) == {"APIKeyHeader"}
    assert "OAuth2PasswordBearer" not in schema_text(customer_schema)
    internal_schema = app.openapi_for_audience("internal")
    assert set(internal_schema["components"]["securitySchemes"]) == {
        "APIKeyHeader",
        "OAuth2PasswordBearer",
    }


def test_callbacks_are_filtered_per_audience():
    customer_schema = app.openapi_for_audience("customer")
    callbacks = customer_schema["paths"]["/items"]["get"]["callbacks"]
    assert "CallbackPayload" in schema_text(callbacks)
    assert "InternalCallbackPayload" not in schema_text(customer_schema)
    internal_schema = app.openapi_for_audience("internal")
    internal_callbacks = internal_schema["paths"]["/internal/callbacks"]["post"][
        "callbacks"
    ]
    assert "InternalCallbackPayload" in schema_text(internal_callbacks)


def test_webhooks_are_filtered_per_audience():
    customer_schema = app.openapi_for_audience("customer")
    assert set(customer_schema["webhooks"]) == {"/new-item"}
    internal_schema = app.openapi_for_audience("internal")
    assert set(internal_schema["webhooks"]) == {"/new-item", "/internal-event"}


def test_default_openapi_schema_is_not_affected():
    schema = app.openapi()
    assert "/internal/report" in schema["paths"]
    assert "/ops" in schema["paths"]
    assert "/both" in schema["paths"]
    assert "/hidden" not in schema["paths"]
    assert "InternalReport" in schema["components"]["schemas"]
    assert "OpsModel" in schema["components"]["schemas"]


def test_generating_audience_schemas_does_not_mutate_routes():
    app.openapi_for_audience("customer")
    app.openapi_for_audience("internal")
    for route in app.routes:
        if getattr(route, "path", None) == "/internal/report":
            assert route.include_in_schema is True
    assert app.openapi_schema is not None
    assert "/internal/report" in app.openapi_schema["paths"]


def test_routes_stay_accessible_regardless_of_audience():
    response = client.get("/internal/nodes")
    assert response.status_code == 200, response.text
    response = client.get("/hidden")
    assert response.status_code == 200, response.text
    assert response.json() == {"hidden": "still reachable"}
    response = client.get("/shared")
    assert response.status_code == 200, response.text


def test_audience_schemas_are_cached_per_audience():
    customer_schema = app.openapi_for_audience("customer")
    internal_schema = app.openapi_for_audience("internal")
    assert app.openapi_for_audience("customer") is customer_schema
    assert app.openapi_for_audience("internal") is internal_schema
    assert app.openapi_audience_schemas["customer"] is customer_schema
    assert app.openapi_audience_schemas["internal"] is internal_schema
    assert customer_schema is not internal_schema


def test_audience_schema_cache_is_regenerated_when_routes_change():
    schema_before = app.openapi_for_audience("customer")
    assert "/late" not in schema_before["paths"]

    @app.get("/late", response_model=LateModel)
    def late():
        return LateModel(late="late")

    schema_after = app.openapi_for_audience("customer")
    assert schema_after is not schema_before
    assert "/late" in schema_after["paths"]
    assert "LateModel" in schema_after["components"]["schemas"]
    assert app.openapi_for_audience("customer") is schema_after


def test_unknown_audience_only_sees_public_operations():
    schema = app.openapi_for_audience("partner")
    assert "/items" in schema["paths"]
    assert "/internal/report" not in schema["paths"]
    assert "InternalReport" not in schema_text(schema)


def test_audience_schema_can_be_served_over_http():
    response = client.get("/openapi/customer.json")
    assert response.status_code == 200, response.text
    assert response.json() == app.openapi_for_audience("customer")


def test_prune_openapi_components_removes_unreferenced_components():
    schema = {
        "openapi": "3.1.0",
        "info": {"title": "Test", "version": "1.0.0"},
        "paths": {
            "/a": {
                "get": {
                    "security": [{"oauth": []}],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/A"}
                                }
                            }
                        }
                    },
                }
            }
        },
        "webhooks": {
            "event": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Hook"}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "A": {
                    "type": "object",
                    "properties": {"b": {"$ref": "#/components/schemas/B"}},
                },
                "B": {
                    "type": "object",
                    "properties": {"a": {"$ref": "#/components/schemas/A"}},
                },
                "Hook": {"type": "object"},
                "Unused": {"type": "object"},
            },
            "securitySchemes": {
                "oauth": {"type": "oauth2", "flows": {}},
                "unusedKey": {"type": "http", "scheme": "basic"},
            },
        },
    }
    pruned = prune_openapi_components(schema)
    # circular references A <-> B are kept, unreferenced components are removed
    assert set(pruned["components"]["schemas"]) == {"A", "B", "Hook"}
    assert set(pruned["components"]["securitySchemes"]) == {"oauth"}
    # the input schema is not mutated
    assert "Unused" in schema["components"]["schemas"]
    assert "unusedKey" in schema["components"]["securitySchemes"]


def test_prune_openapi_components_without_components():
    schema = {"openapi": "3.1.0", "info": {"title": "Test", "version": "1.0.0"}}
    assert prune_openapi_components(schema) is schema
