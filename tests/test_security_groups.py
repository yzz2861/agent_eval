import pytest
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security import (
    AllOf,
    AnyOf,
    APIKeyHeader,
    APIKeyQuery,
    HTTPBasic,
    HTTPBearer,
    SecurityScopes,
)
from fastapi.security.base import SecurityBase
from fastapi.testclient import TestClient
from starlette.requests import Request

app = FastAPI()

bearer = HTTPBearer()
api_key = APIKeyHeader(name="X-API-Key")
api_key_query = APIKeyQuery(name="api-key")
basic = HTTPBasic()


@app.get("/and")
def read_and(auth=Security(AllOf(bearer, api_key))):
    bearer_credentials, key = auth
    return {"token": bearer_credentials.credentials, "api_key": key}


@app.get("/or")
def read_or(auth=Security(AnyOf(AllOf(bearer, api_key), basic))):
    if isinstance(auth, tuple):
        bearer_credentials, key = auth
        return {
            "scheme": "bearer+api-key",
            "token": bearer_credentials.credentials,
            "api_key": key,
        }
    return {"scheme": "basic", "username": auth.username}


@app.get("/or-custom-error")
def read_or_custom_error(
    auth=Security(
        AnyOf(
            AllOf(bearer, api_key),
            basic,
            status_code=403,
            detail="Custom authentication error",
            authenticate_header="Bearer",
        )
    ),
):
    return {"ok": True}


@app.get("/nested")
def read_nested(
    auth=Security(AnyOf(AllOf(bearer, AnyOf(api_key, api_key_query)), basic)),
):
    if isinstance(auth, tuple):
        bearer_credentials, key = auth
        return {"token": bearer_credentials.credentials, "api_key": key}
    return {"basic": auth.username}


class ScopedHeaderScheme(SecurityBase):
    def __init__(self, *, name: str, scheme_name: str):
        self.model = APIKey(**{"in": APIKeyIn.header}, name=name)
        self.scheme_name = scheme_name

    async def __call__(self, request: Request, security_scopes: SecurityScopes):
        token = request.headers.get(self.model.name)
        if not token:
            raise HTTPException(status_code=401, detail="Missing token")
        return {"token": token, "scopes": security_scopes.scopes}


scopes_app = FastAPI()

scoped_a = ScopedHeaderScheme(name="X-Token-A", scheme_name="TokenA")
scoped_b = ScopedHeaderScheme(name="X-Token-B", scheme_name="TokenB")


@scopes_app.get("/scoped")
def read_scoped(
    auth=Security(
        AnyOf(
            Security(scoped_a, scopes=["read"]),
            Security(scoped_b, scopes=["write"]),
        )
    ),
):
    return auth


class CountingScheme(SecurityBase):
    def __init__(self, *, scheme_name: str, fail: bool = False):
        self.model = APIKey(**{"in": APIKeyIn.header}, name="X-Count")
        self.scheme_name = scheme_name
        self.fail = fail
        self.calls = 0

    async def __call__(self, request: Request):
        self.calls += 1
        if self.fail:
            raise HTTPException(status_code=401, detail="Nope")
        return "counted-value"


cache_app = FastAPI()

shared_scheme = CountingScheme(scheme_name="Shared")
failing_scheme = CountingScheme(scheme_name="Failing", fail=True)


@cache_app.get("/cached")
def read_cached(
    auth=Security(AnyOf(AllOf(shared_scheme, failing_scheme), shared_scheme)),
):
    return {"auth": auth}


uncached_scheme = CountingScheme(scheme_name="Uncached")
uncached_failing_scheme = CountingScheme(scheme_name="UncachedFailing", fail=True)


@cache_app.get("/not-cached")
def read_not_cached(
    auth=Security(
        AnyOf(
            AllOf(Security(uncached_scheme, use_cache=False), uncached_failing_scheme),
            Security(uncached_scheme, use_cache=False),
        )
    ),
):
    return {"auth": auth}


legacy_app = FastAPI()

legacy_bearer = HTTPBearer()
legacy_key = APIKeyHeader(name="X-Legacy-Key")


@legacy_app.get("/legacy")
def read_legacy(credentials=Security(legacy_bearer), key=Security(legacy_key)):
    return {"token": credentials.credentials, "key": key}


router_app = FastAPI()

router_bearer = HTTPBearer()
router_basic = HTTPBasic()


@router_app.get(
    "/protected", dependencies=[Security(AnyOf(router_bearer, router_basic))]
)
def read_protected():
    return {"ok": True}


client = TestClient(app)
scopes_client = TestClient(scopes_app)
cache_client = TestClient(cache_app)
legacy_client = TestClient(legacy_app)
router_client = TestClient(router_app)


def test_all_of_success():
    response = client.get(
        "/and", headers={"Authorization": "Bearer token123", "X-API-Key": "key123"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "token123", "api_key": "key123"}


def test_all_of_missing_api_key():
    response = client.get("/and", headers={"Authorization": "Bearer token123"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == "APIKey"


def test_all_of_missing_bearer():
    response = client.get("/and", headers={"X-API-Key": "key123"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_any_of_first_branch():
    response = client.get(
        "/or", headers={"Authorization": "Bearer token123", "X-API-Key": "key123"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "scheme": "bearer+api-key",
        "token": "token123",
        "api_key": "key123",
    }


def test_any_of_second_branch():
    response = client.get("/or", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 200, response.text
    assert response.json() == {"scheme": "basic", "username": "user"}


def test_any_of_all_fail_uses_single_error():
    response = client.get("/or")
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    # The internal errors of the branches are not leaked
    assert "www-authenticate" not in response.headers


def test_any_of_failed_branch_values_not_leaked():
    # Only a bearer token: the first branch fails on the missing API key and
    # its partial results are discarded, the second branch does not match
    # either, so the endpoint is never reached with partial credentials
    response = client.get("/or", headers={"Authorization": "Bearer token123"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}
    assert "www-authenticate" not in response.headers


def test_any_of_custom_error():
    response = client.get("/or-custom-error")
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": "Custom authentication error"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_any_of_custom_error_last_branch_not_leaked():
    # The last branch (HTTPBasic) would produce a 401 with a Basic
    # WWW-Authenticate header, the configured error is used instead
    response = client.get(
        "/or-custom-error", headers={"Authorization": "Bearer token123"}
    )
    assert response.status_code == 403, response.text
    assert response.json() == {"detail": "Custom authentication error"}
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_nested_groups_bearer_with_header_key():
    response = client.get(
        "/nested",
        headers={"Authorization": "Bearer token123", "X-API-Key": "key123"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "token123", "api_key": "key123"}


def test_nested_groups_bearer_with_query_key():
    response = client.get(
        "/nested",
        headers={"Authorization": "Bearer token123"},
        params={"api-key": "key123"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "token123", "api_key": "key123"}


def test_nested_groups_basic():
    response = client.get("/nested", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 200, response.text
    assert response.json() == {"basic": "user"}


def test_nested_groups_all_fail():
    response = client.get("/nested", headers={"Authorization": "Bearer token123"})
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Not authenticated"}


def test_scopes_stay_in_own_branch_first():
    response = scopes_client.get("/scoped", headers={"X-Token-A": "token-a"})
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "token-a", "scopes": ["read"]}


def test_scopes_stay_in_own_branch_second():
    response = scopes_client.get("/scoped", headers={"X-Token-B": "token-b"})
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "token-b", "scopes": ["write"]}


def test_shared_scheme_is_cached_across_branches():
    shared_scheme.calls = 0
    response = cache_client.get("/cached", headers={"X-Count": "yes"})
    assert response.status_code == 200, response.text
    assert response.json() == {"auth": "counted-value"}
    assert shared_scheme.calls == 1


def test_use_cache_false_is_respected_across_branches():
    uncached_scheme.calls = 0
    response = cache_client.get("/not-cached", headers={"X-Count": "yes"})
    assert response.status_code == 200, response.text
    assert response.json() == {"auth": "counted-value"}
    assert uncached_scheme.calls == 2


def test_legacy_single_schemes_still_work():
    response = legacy_client.get(
        "/legacy",
        headers={"Authorization": "Bearer token123", "X-Legacy-Key": "key123"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"token": "token123", "key": "key123"}
    response = legacy_client.get("/legacy")
    assert response.status_code == 401, response.text


def test_router_level_group():
    response = router_client.get("/protected")
    assert response.status_code == 401, response.text
    response = router_client.get(
        "/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True}


def test_openapi_security_all_of():
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert schema["paths"]["/and"]["get"]["security"] == [
        {"HTTPBearer": [], "APIKeyHeader": []}
    ]


def test_openapi_security_any_of():
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert schema["paths"]["/or"]["get"]["security"] == [
        {"HTTPBearer": [], "APIKeyHeader": []},
        {"HTTPBasic": []},
    ]


def test_openapi_security_nested_groups():
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert schema["paths"]["/nested"]["get"]["security"] == [
        {"HTTPBearer": [], "APIKeyHeader": []},
        {"HTTPBearer": [], "APIKeyQuery": []},
        {"HTTPBasic": []},
    ]


def test_openapi_components_include_all_schemes():
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert set(schema["components"]["securitySchemes"]) == {
        "HTTPBearer",
        "APIKeyHeader",
        "APIKeyQuery",
        "HTTPBasic",
    }


def test_openapi_scopes_stay_in_own_branch():
    response = scopes_client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert schema["paths"]["/scoped"]["get"]["security"] == [
        {"TokenA": ["read"]},
        {"TokenB": ["write"]},
    ]


def test_openapi_legacy_single_schemes_unchanged():
    response = legacy_client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert schema["paths"]["/legacy"]["get"]["security"] == [
        {"HTTPBearer": []},
        {"APIKeyHeader": []},
    ]


def test_openapi_router_level_group():
    response = router_client.get("/openapi.json")
    assert response.status_code == 200, response.text
    schema = response.json()
    assert schema["paths"]["/protected"]["get"]["security"] == [
        {"HTTPBearer": []},
        {"HTTPBasic": []},
    ]


def test_empty_group_rejected():
    with pytest.raises(ValueError, match="at least one"):
        AllOf()
    with pytest.raises(ValueError, match="at least one"):
        AnyOf()


def test_non_security_group_child_rejected():
    invalid_app = FastAPI()

    with pytest.raises(ValueError, match="security schemes"):

        @invalid_app.get("/invalid")
        def read_invalid(auth=Security(AllOf(lambda: "not-a-scheme"))):
            return {}  # pragma: no cover


def test_group_child_depends_without_dependency_rejected():
    invalid_app = FastAPI()

    with pytest.raises(ValueError, match="must have a dependency"):

        @invalid_app.get("/invalid")
        def read_invalid(auth=Security(AllOf(Depends()))):
            return {}  # pragma: no cover
