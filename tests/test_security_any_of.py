import base64
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import (
    AllOf,
    APIKeyHeader,
    HTTPBasic,
    HTTPBearer,
    OAuth2PasswordBearer,
    SecurityResult,
    SecurityScopes,
)
from fastapi.testclient import TestClient

app = FastAPI()

bearer_scheme = HTTPBearer()
api_key_scheme = APIKeyHeader(name="X-API-Key")
basic_scheme = HTTPBasic()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token", scopes={"read": "Read", "write": "Write"}
)


def basic_header(username: str = "user", password: str = "secret") -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@app.get("/items")
def read_items(
    auth: SecurityResult = Security(
        any_of=[
            AllOf(Security(bearer_scheme), Security(api_key_scheme)),
            Security(basic_scheme),
        ]
    ),
):
    if auth.group_index == 0:
        bearer_credentials, api_key = auth.values
        return {
            "group": 0,
            "token": bearer_credentials.credentials,
            "api_key": api_key,
        }
    (basic_credentials,) = auth.values
    return {"group": 1, "username": basic_credentials.username}


@app.get("/custom-error")
def custom_error(
    auth: SecurityResult = Security(
        any_of=[Security(bearer_scheme)],
        status_code=403,
        authenticate_header='Bearer realm="api"',
    ),
):
    return {"token": auth.values[0].credentials}


def leaky_dependency():
    raise HTTPException(status_code=500, detail="db password=hunter2")


@app.get("/no-leak")
def no_leak(
    auth: SecurityResult = Security(any_of=[Security(leaky_dependency)]),
):
    return {"auth": auth}  # pragma: no cover


counters = {"shared": 0}


def shared_counter():
    counters["shared"] += 1
    return f"call-{counters['shared']}"


def always_fail():
    raise HTTPException(status_code=403, detail="nope")


def ok_value():
    return "ok"


@app.get("/rollback")
def rollback(
    auth: SecurityResult = Security(
        any_of=[
            AllOf(Security(shared_counter), Security(always_fail)),
            Security(shared_counter),
        ]
    ),
):
    return {"group": auth.group_index, "value": auth.values[0]}


@app.get("/shared-cache")
def shared_cache(
    auth: SecurityResult = Security(any_of=[Security(shared_counter)]),
    other: str = Depends(shared_counter),
):
    return {"auth": auth.values[0], "other": other}


@app.get("/no-leak-values")
def no_leak_values(
    auth: SecurityResult = Security(
        any_of=[
            AllOf(Security(shared_counter), Security(always_fail)),
            Security(ok_value),
        ]
    ),
    other: str = Depends(shared_counter),
):
    return {"auth": auth.values[0], "other": other}


def scopes_dependency(security_scopes: SecurityScopes):
    return security_scopes.scopes


@app.get("/scopes")
def scopes(
    auth: SecurityResult = Security(
        any_of=[
            AllOf(
                Security(scopes_dependency, scopes=["read", "write"]),
                Security(bearer_scheme),
            ),
            Security(basic_scheme),
        ]
    ),
    endpoint_scopes: SecurityScopes = None,  # type: ignore[assignment]
):
    return {
        "group": auth.group_index,
        "branch_scopes": auth.values[0] if auth.group_index == 0 else None,
        "endpoint_scopes": endpoint_scopes.scopes,
    }


@app.get("/scoped-openapi")
def scoped_openapi(
    auth: SecurityResult = Security(
        any_of=[
            Security(oauth2_scheme, scopes=["read"]),
            Security(basic_scheme),
        ]
    ),
):
    return {"group": auth.group_index}


@app.get("/mixed")
def mixed(
    auth: SecurityResult = Security(
        any_of=[Security(bearer_scheme), Security(basic_scheme)]
    ),
    api_key: str = Security(api_key_scheme),
):
    return {"group": auth.group_index, "api_key": api_key}


client = TestClient(app)


def test_all_of_group_passes():
    response = client.get(
        "/items",
        headers={"Authorization": "Bearer token1", "X-API-Key": "key1"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"group": 0, "token": "token1", "api_key": "key1"}


def test_second_group_passes():
    response = client.get("/items", headers=basic_header())
    assert response.status_code == 200, response.text
    assert response.json() == {"group": 1, "username": "user"}


def test_incomplete_first_group_falls_through():
    # The bearer token is valid but the API key is missing, so the first
    # group fails and there are no Basic credentials for the second one.
    response = client.get("/items", headers={"Authorization": "Bearer token1"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}


def test_all_groups_fail():
    response = client.get("/items")
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert "WWW-Authenticate" not in response.headers


def test_custom_error_status_and_header():
    response = client.get("/custom-error")
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == 'Bearer realm="api"'


def test_custom_error_passes():
    response = client.get("/custom-error", headers={"Authorization": "Bearer t"})
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "t"}


def test_internal_exception_not_leaked():
    response = client.get("/no-leak")
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}


def test_failed_group_cache_rolled_back():
    counters["shared"] = 0
    response = client.get("/rollback")
    assert response.status_code == 200, response.text
    # The first group ran shared_counter (call-1) and then failed, its cache
    # entry was rolled back, so the second group recomputed it (call-2).
    assert response.json() == {"group": 1, "value": "call-2"}
    assert counters["shared"] == 2


def test_cache_shared_with_regular_dependencies():
    counters["shared"] = 0
    response = client.get("/shared-cache")
    assert response.status_code == 200, response.text
    assert response.json() == {"auth": "call-1", "other": "call-1"}
    assert counters["shared"] == 1


def test_failed_group_values_not_leaked():
    counters["shared"] = 0
    response = client.get("/no-leak-values")
    assert response.status_code == 200, response.text
    # shared_counter ran inside the failed first group (call-1), its cached
    # value was rolled back, so the regular dependency recomputed it (call-2).
    assert response.json() == {"auth": "ok", "other": "call-2"}
    assert counters["shared"] == 2


def test_scopes_stay_in_branch():
    response = client.get("/scopes", headers={"Authorization": "Bearer token1"})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "group": 0,
        "branch_scopes": ["read", "write"],
        "endpoint_scopes": [],
    }


def test_scopes_second_branch():
    response = client.get("/scopes", headers=basic_header())
    assert response.status_code == 200, response.text
    assert response.json() == {
        "group": 1,
        "branch_scopes": None,
        "endpoint_scopes": [],
    }


def test_mixed_flat_and_group_security():
    response = client.get(
        "/mixed", headers={"Authorization": "Bearer token1", "X-API-Key": "key1"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"group": 0, "api_key": "key1"}


def test_openapi_security_groups():
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    paths = response.json()["paths"]
    assert paths["/items"]["get"]["security"] == [
        {"HTTPBearer": [], "APIKeyHeader": []},
        {"HTTPBasic": []},
    ]
    assert paths["/scoped-openapi"]["get"]["security"] == [
        {"OAuth2PasswordBearer": ["read"]},
        {"HTTPBasic": []},
    ]
    # Security schemes declared outside of the groups always apply, so they
    # are merged into each alternative.
    assert paths["/mixed"]["get"]["security"] == [
        {"APIKeyHeader": [], "HTTPBearer": []},
        {"APIKeyHeader": [], "HTTPBasic": []},
    ]
    security_schemes = response.json()["components"]["securitySchemes"]
    assert security_schemes["HTTPBearer"] == {"type": "http", "scheme": "bearer"}
    assert security_schemes["HTTPBasic"] == {"type": "http", "scheme": "basic"}
    assert security_schemes["APIKeyHeader"] == {
        "type": "apiKey",
        "name": "X-API-Key",
        "in": "header",
    }
    assert security_schemes["OAuth2PasswordBearer"] == {
        "type": "oauth2",
        "flows": {
            "password": {
                "tokenUrl": "token",
                "scopes": {"read": "Read", "write": "Write"},
            }
        },
    }


def test_cannot_combine_dependency_and_any_of():
    with pytest.raises(ValueError, match="single dependency and any_of"):
        Security(bearer_scheme, any_of=[Security(basic_scheme)])


def test_any_of_requires_a_group():
    with pytest.raises(ValueError, match="at least one group"):
        Security(any_of=[])


def test_all_of_requires_a_requirement():
    with pytest.raises(ValueError, match="at least one security requirement"):
        AllOf()


def test_cannot_nest_any_of():
    nested_app = FastAPI()
    with pytest.raises(ValueError, match="Cannot nest Security any_of groups"):

        @nested_app.get("/nested")
        def nested(
            auth: SecurityResult = Security(
                any_of=[Security(any_of=[Security(basic_scheme)])]
            ),
        ):
            return {"auth": auth}  # pragma: no cover


def test_annotated_style():
    annotated_app = FastAPI()

    @annotated_app.get("/annotated")
    def annotated(
        auth: Annotated[
            SecurityResult,
            Security(any_of=[Security(bearer_scheme), Security(basic_scheme)]),
        ],
    ):
        return {"group": auth.group_index}

    annotated_client = TestClient(annotated_app)
    response = annotated_client.get(
        "/annotated", headers={"Authorization": "Bearer token1"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"group": 0}
    response = annotated_client.get("/annotated", headers=basic_header())
    assert response.status_code == 200, response.text
    assert response.json() == {"group": 1}
    response = annotated_client.get("/annotated")
    assert response.status_code == 401, response.text
