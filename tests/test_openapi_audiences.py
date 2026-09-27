import json

from fastapi import APIRouter, Depends, FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from fastapi.testclient import TestClient
from pydantic import BaseModel


class SharedModel(BaseModel):
    name: str


class InternalModel(BaseModel):
    secret: str
    shared: SharedModel


class CustomerModel(BaseModel):
    public: str


class RecursiveModel(BaseModel):
    value: int
    child: "RecursiveModel | None" = None


class CallbackPayload(BaseModel):
    callback_value: str


class InternalCallbackPayload(BaseModel):
    internal_callback_value: str


internal_oauth = OAuth2PasswordBearer(tokenUrl="token")
customer_bearer = HTTPBearer()

callback_router = APIRouter()
internal_callback_router = APIRouter()


@callback_router.post("{`$callback_url`}", response_model=SharedModel)
def customer_callback(payload: CallbackPayload):
    pass  # pragma: no cover


@internal_callback_router.post("{`$callback_url`}", response_model=InternalModel)
def internal_callback(payload: InternalCallbackPayload):
    pass  # pragma: no cover


def build_app() -> FastAPI:
    app = FastAPI()
    internal_router = APIRouter(audiences=["internal"])
    ops_router = APIRouter()

    @app.get("/public", response_model=CustomerModel)
    def public():
        return {"public": "x"}  # pragma: no cover

    @app.get("/both", response_model=SharedModel, audiences=["internal", "customer"])
    def both():
        return {"name": "x"}  # pragma: no cover

    @internal_router.get(
        "/internal",
        response_model=InternalModel,
        dependencies=[Depends(internal_oauth)],
    )
    def internal():
        return {"secret": "s", "shared": {"name": "n"}}  # pragma: no cover

    @app.get(
        "/customer-only",
        response_model=RecursiveModel,
        audiences=["customer"],
        dependencies=[Depends(customer_bearer)],
    )
    def customer_only():
        return {"value": 1}  # pragma: no cover

    @ops_router.get("/ops", response_model=InternalModel)
    def ops():
        return {"secret": "s", "shared": {"name": "n"}}  # pragma: no cover

    @app.post(
        "/with-callback",
        response_model=SharedModel,
        audiences=["customer"],
        callbacks=callback_router.routes,
    )
    def with_callback():
        return {"name": "x"}  # pragma: no cover

    @app.post(
        "/with-internal-callback",
        response_model=SharedModel,
        audiences=["internal"],
        callbacks=internal_callback_router.routes,
    )
    def with_internal_callback():
        return {"name": "x"}  # pragma: no cover

    app.include_router(internal_router)
    app.include_router(ops_router, audiences=["ops", "internal"])

    @app.webhooks.post("/new-item", audiences=["internal"])
    def new_item_hook(item: InternalModel):
        pass  # pragma: no cover

    @app.webhooks.post("/item-changed")
    def item_changed_hook(item: SharedModel):
        pass  # pragma: no cover

    return app


app = build_app()
client = TestClient(app)


def schema_names(schema: dict) -> set:
    return set(schema.get("components", {}).get("schemas", {}))


def test_default_openapi_includes_everything():
    schema = app.openapi()
    assert set(schema["paths"]) == {
        "/public",
        "/both",
        "/internal",
        "/customer-only",
        "/ops",
        "/with-callback",
        "/with-internal-callback",
    }
    assert set(schema["webhooks"]) == {"/new-item", "/item-changed"}
    assert {"InternalModel", "CustomerModel", "SharedModel"} <= schema_names(schema)


def test_audience_openapi_filters_operations():
    customer = app.openapi_for_audience("customer")
    assert set(customer["paths"]) == {
        "/public",
        "/both",
        "/customer-only",
        "/with-callback",
    }
    internal = app.openapi_for_audience("internal")
    assert set(internal["paths"]) == {
        "/public",
        "/both",
        "/internal",
        "/ops",
        "/with-internal-callback",
    }


def test_audience_openapi_filters_webhooks():
    customer = app.openapi_for_audience("customer")
    assert set(customer.get("webhooks", {})) == {"/item-changed"}
    internal = app.openapi_for_audience("internal")
    assert set(internal["webhooks"]) == {"/new-item", "/item-changed"}


def test_internal_only_components_do_not_leak():
    customer = app.openapi_for_audience("customer")
    assert "InternalModel" not in schema_names(customer)
    # The model name should not appear anywhere, not even in a leftover $ref
    assert "InternalModel" not in json.dumps(customer)
    assert "InternalCallbackPayload" not in json.dumps(customer)


def test_shared_and_reachable_components_are_kept():
    customer = app.openapi_for_audience("customer")
    assert {"CustomerModel", "SharedModel", "RecursiveModel", "CallbackPayload"} <= (
        schema_names(customer)
    )
    internal = app.openapi_for_audience("internal")
    assert {"InternalModel", "SharedModel", "InternalCallbackPayload"} <= schema_names(
        internal
    )
    # Customer-only model is not referenced by internal operations
    assert "RecursiveModel" not in schema_names(internal)
    assert "CustomerModel" in schema_names(internal)  # used by /public


def test_circular_references_are_preserved():
    customer = app.openapi_for_audience("customer")
    recursive_schema = customer["components"]["schemas"]["RecursiveModel"]
    assert recursive_schema["properties"]["child"]["anyOf"][0] == {
        "$ref": "#/components/schemas/RecursiveModel"
    }
    internal = app.openapi_for_audience("internal")
    internal_schema = internal["components"]["schemas"]["InternalModel"]
    assert internal_schema["properties"]["shared"] == {
        "$ref": "#/components/schemas/SharedModel"
    }


def test_security_schemes_are_filtered_per_audience():
    customer = app.openapi_for_audience("customer")
    customer_schemes = customer["components"]["securitySchemes"]
    assert set(customer_schemes) == {"HTTPBearer"}
    internal = app.openapi_for_audience("internal")
    internal_schemes = internal["components"]["securitySchemes"]
    assert set(internal_schemes) == {"OAuth2PasswordBearer"}


def test_callbacks_are_filtered_with_their_operation():
    customer = app.openapi_for_audience("customer")
    callback_op = customer["paths"]["/with-callback"]["post"]
    assert "callbacks" in callback_op
    assert "CallbackPayload" in schema_names(customer)
    assert "/with-internal-callback" not in customer["paths"]
    internal = app.openapi_for_audience("internal")
    assert "callbacks" in internal["paths"]["/with-internal-callback"]["post"]
    assert "InternalCallbackPayload" in schema_names(internal)
    assert "CallbackPayload" not in schema_names(internal)


def test_audience_schemas_are_cached_independently():
    fresh_app = build_app()
    customer = fresh_app.openapi_for_audience("customer")
    internal = fresh_app.openapi_for_audience("internal")
    assert fresh_app.openapi_for_audience("customer") is customer
    assert fresh_app.openapi_for_audience("internal") is internal
    assert set(fresh_app.openapi_audience_schemas) == {"customer", "internal"}
    assert customer is not internal


def test_audience_cache_is_invalidated_on_route_changes():
    fresh_app = build_app()
    before = fresh_app.openapi_for_audience("customer")
    assert "/late" not in before["paths"]

    @fresh_app.get("/late", audiences=["customer"])
    def late():
        return {}  # pragma: no cover

    after = fresh_app.openapi_for_audience("customer")
    assert "/late" in after["paths"]
    assert after is not before


def test_audience_generation_does_not_mutate_app_state():
    fresh_app = build_app()
    include_flags_before = {
        getattr(route, "path", None): getattr(route, "include_in_schema", None)
        for route in fresh_app.routes
    }
    full_before = fresh_app.openapi()
    fresh_app.openapi_for_audience("customer")
    fresh_app.openapi_for_audience("internal")
    include_flags_after = {
        getattr(route, "path", None): getattr(route, "include_in_schema", None)
        for route in fresh_app.routes
    }
    assert include_flags_before == include_flags_after
    assert fresh_app.openapi() == full_before
    assert set(fresh_app.openapi()["paths"]) == set(full_before["paths"])


def test_hidden_routes_are_still_accessible():
    response = client.get("/internal")
    # The route still works (401 because of the OAuth2 dependency, not 404)
    assert response.status_code == 401
    response = client.get("/customer-only")
    # 401 because of the HTTPBearer dependency, the route itself is reachable
    assert response.status_code == 401
    response = client.get("/ops")
    assert response.status_code == 200
    response = client.get("/public")
    assert response.status_code == 200


def test_router_level_and_include_level_audiences():
    router = APIRouter(audiences=["router-audience"])

    @router.get("/router-level")
    def router_level():
        return {}  # pragma: no cover

    @router.get("/route-override", audiences=["route-audience"])
    def route_override():
        return {}  # pragma: no cover

    fresh_app = FastAPI()
    fresh_app.include_router(router)
    router_audience = fresh_app.openapi_for_audience("router-audience")
    assert set(router_audience["paths"]) == {"/router-level"}
    route_audience = fresh_app.openapi_for_audience("route-audience")
    assert set(route_audience["paths"]) == {"/route-override"}

    override_app = FastAPI()
    override_app.include_router(router, audiences=["include-audience"])
    include_audience = override_app.openapi_for_audience("include-audience")
    # include_router(audiences=...) only applies to routes that didn't declare
    # audiences anywhere (both routes here already have effective audiences)
    assert set(include_audience["paths"]) == set()

    plain_router = APIRouter()

    @plain_router.get("/plain")
    def plain():
        return {}  # pragma: no cover

    include_app = FastAPI()
    include_app.include_router(plain_router, audiences=["include-audience"])
    include_audience = include_app.openapi_for_audience("include-audience")
    assert set(include_audience["paths"]) == {"/plain"}


def test_nested_include_router_audiences():
    inner = APIRouter()

    @inner.get("/inner", response_model=InternalModel)
    def inner_route():
        return {}  # pragma: no cover

    middle = APIRouter(audiences=["middle-audience"])
    middle.include_router(inner)
    nested_app = FastAPI()
    nested_app.include_router(middle)
    middle_audience = nested_app.openapi_for_audience("middle-audience")
    assert set(middle_audience["paths"]) == {"/inner"}
    other_audience = nested_app.openapi_for_audience("other-audience")
    assert set(other_audience["paths"]) == set()
    assert "InternalModel" not in json.dumps(other_audience)


def test_get_openapi_with_audience_directly():
    schema = get_openapi(
        title="App",
        version="1.0.0",
        routes=app.routes,
        webhooks=app.webhooks.routes,
        audience="customer",
    )
    assert set(schema["paths"]) == {
        "/public",
        "/both",
        "/customer-only",
        "/with-callback",
    }
    assert "InternalModel" not in json.dumps(schema)
