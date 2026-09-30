import time
from collections.abc import AsyncIterator, Iterator
from contextlib import AsyncExitStack

import anyio
import httpx
import pytest
from fastapi import Depends, FastAPI, Security
from fastapi.dependencies.models import Dependant
from fastapi.dependencies.overrides import get_dependency_overrides
from fastapi.dependencies.utils import _solve_generator
from fastapi.security import SecurityScopes
from fastapi.testclient import TestClient


app = FastAPI()


def value_a() -> str:
    return "default-a"


def value_b() -> str:
    return "default-b"


def value_c() -> str:
    return "default-c"


def value_d() -> str:
    return "default-d"


def sub_value() -> str:
    return "default-sub"


def parent_value(sub: str = Depends(sub_value)) -> dict[str, str]:
    return {"sub": sub}


def context_sub_value() -> str:
    return "context-sub"


def context_parent_value(
    sub: str = Depends(sub_value),
) -> dict[str, str]:
    return {"sub": sub}


def get_identity(scopes: SecurityScopes) -> dict[str, object]:
    return {"name": "default", "scopes": scopes.scopes}


def override_identity(scopes: SecurityScopes) -> dict[str, object]:
    return {"name": "context", "scopes": scopes.scopes}


@app.get("/values")
def read_values(
    a: str = Depends(value_a),
    b: str = Depends(value_b),
    c: str = Depends(value_c),
    d: str = Depends(value_d),
) -> dict[str, str]:
    return {"a": a, "b": b, "c": c, "d": d}


@app.get("/subdependency")
def read_subdependency(
    parent: dict[str, str] = Depends(parent_value),
) -> dict[str, str]:
    return parent


@app.get("/security")
def read_security(
    identity: dict[str, object] = Security(get_identity, scopes=["read"]),
) -> dict[str, object]:
    return identity


def worker_value() -> str:
    time.sleep(0.02)
    return "default-worker"


@app.get("/worker")
def read_worker(value: str = Depends(worker_value)) -> dict[str, str]:
    return {"value": value}


client = TestClient(app)


def test_nested_contexts_prefer_inner_and_fall_back_to_defaults() -> None:
    app.dependency_overrides[value_d] = lambda: "app-default-d"

    try:
        with app.dependency_overrides_context(
            {
                value_b: lambda: "outer-b",
                value_c: lambda: "outer-c",
            }
        ):
            with app.dependency_overrides_context(
                {
                    value_a: lambda: "inner-a",
                    value_c: lambda: "inner-c",
                }
            ):
                response = client.get("/values")
                assert response.json() == {
                    "a": "inner-a",
                    "b": "outer-b",
                    "c": "inner-c",
                    "d": "app-default-d",
                }

            response = client.get("/values")
            assert response.json() == {
                "a": "default-a",
                "b": "outer-b",
                "c": "outer-c",
                "d": "app-default-d",
            }

        response = client.get("/values")
        assert response.json() == {
            "a": "default-a",
            "b": "default-b",
            "c": "default-c",
            "d": "app-default-d",
        }
    finally:
        app.dependency_overrides = {}


def test_context_overrides_apply_to_subdependencies_and_security() -> None:
    with app.dependency_overrides_context(
        {
            parent_value: context_parent_value,
            sub_value: context_sub_value,
            get_identity: override_identity,
        }
    ):
        response = client.get("/subdependency")
        assert response.json() == {"sub": "context-sub"}

        response = client.get("/security")
        assert response.json() == {
            "name": "context",
            "scopes": ["read"],
        }

    assert client.get("/subdependency").json() == {"sub": "default-sub"}
    assert client.get("/security").json() == {
        "name": "default",
        "scopes": ["read"],
    }


def test_exception_exit_restores_overrides() -> None:
    with pytest.raises(RuntimeError, match="boom"):
        with app.dependency_overrides_context({value_a: lambda: "temporary"}):
            assert client.get("/values").json()["a"] == "temporary"
            raise RuntimeError("boom")

    assert client.get("/values").json()["a"] == "default-a"


@pytest.mark.anyio
async def test_internal_request_uses_nested_context() -> None:
    internal_app = FastAPI()

    def request_label() -> str:
        return "default"

    @internal_app.get("/label")
    def read_label(label: str = Depends(request_label)) -> dict[str, str]:
        return {"label": label}

    @internal_app.get("/internal")
    async def read_internal(
        outer_label: str = Depends(request_label),
    ) -> dict[str, str]:
        async with internal_app.dependency_overrides_context(
            {request_label: lambda: "inner"}
        ):
            transport = httpx.ASGITransport(app=internal_app)
            async with httpx.AsyncClient(
                base_url="http://internal", transport=transport
            ) as internal_client:
                response = await internal_client.get("/label")

        return {"outer": outer_label, "inner": response.json()["label"]}

    transport = httpx.ASGITransport(app=internal_app)
    async with internal_app.dependency_overrides_context(
        {request_label: lambda: "outer"}
    ), httpx.AsyncClient(
        base_url="http://test", transport=transport
    ) as async_client:
        response = await async_client.get("/internal")
        assert response.json() == {"outer": "outer", "inner": "inner"}

    assert TestClient(internal_app).get("/label").json() == {"label": "default"}


@pytest.mark.anyio
async def test_async_context_restores_overrides() -> None:
    async with app.dependency_overrides_context(
        {value_a: lambda: "async-temporary"}
    ):
        response = client.get("/values")
        assert response.json()["a"] == "async-temporary"

    response = client.get("/values")
    assert response.json()["a"] == "default-a"


@pytest.mark.anyio
async def test_concurrent_requests_use_isolated_threadpool_contexts() -> None:
    async def request_worker(async_client: httpx.AsyncClient, expected: str) -> None:
        def override() -> str:
            time.sleep(0.02)
            return expected

        async with app.dependency_overrides_context({worker_value: override}):
            response = await async_client.get("/worker")
            assert response.json() == {"value": expected}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        base_url="http://test", transport=transport
    ) as async_client:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(request_worker, async_client, "one")
            await anyio.sleep(0.005)
            task_group.start_soon(request_worker, async_client, "two")

    assert client.get("/worker").json() == {"value": "default-worker"}


def test_mounted_subapplication_has_isolated_override_context() -> None:
    parent_app = FastAPI()
    sub_app = FastAPI()

    def mounted_value() -> str:
        return "default-mounted"

    @parent_app.get("/mounted-parent")
    def read_mounted_parent(value: str = Depends(mounted_value)) -> dict[str, str]:
        return {"value": value}

    @sub_app.get("/mounted-sub")
    def read_mounted_sub(value: str = Depends(mounted_value)) -> dict[str, str]:
        return {"value": value}

    parent_app.mount("/sub", sub_app)
    mounted_client = TestClient(parent_app)

    with parent_app.dependency_overrides_context(
        {mounted_value: lambda: "parent-context"}
    ), sub_app.dependency_overrides_context(
        {mounted_value: lambda: "sub-context"}
    ):
        assert mounted_client.get("/mounted-parent").json() == {
            "value": "parent-context"
        }
        assert mounted_client.get("/sub/mounted-sub").json() == {
            "value": "sub-context"
        }

    assert mounted_client.get("/mounted-parent").json() == {
        "value": "default-mounted"
    }
    assert mounted_client.get("/sub/mounted-sub").json() == {
        "value": "default-mounted"
    }


@pytest.mark.anyio
@pytest.mark.parametrize("is_async", [True, False], ids=["async", "sync"])
async def test_generator_cleanup_uses_creation_layer(is_async: bool) -> None:
    generator_app = FastAPI()
    events: list[str] = []

    def original_generator() -> Iterator[str]:
        yield "original"

    def sync_override_generator() -> Iterator[str]:
        events.append("enter")
        assert (
            get_dependency_overrides(generator_app).get(original_generator)
            is sync_override_generator
        )
        yield "override"
        assert (
            get_dependency_overrides(generator_app).get(original_generator)
            is sync_override_generator
        )
        events.append("exit")

    async def async_override_generator() -> AsyncIterator[str]:
        events.append("enter")
        assert (
            get_dependency_overrides(generator_app).get(original_generator)
            is async_override_generator
        )
        yield "override"
        assert (
            get_dependency_overrides(generator_app).get(original_generator)
            is async_override_generator
        )
        events.append("exit")

    override = async_override_generator if is_async else sync_override_generator

    async with AsyncExitStack() as stack:
        with generator_app.dependency_overrides_context(
            {original_generator: override}
        ):
            solved = await _solve_generator(
                dependant=Dependant(call=override),
                stack=stack,
                sub_values={},
                dependency_overrides_provider=generator_app,
            )
            assert solved == "override"

        generator_app.dependency_overrides[original_generator] = lambda: "changed"
        await stack.aclose()

    assert events == ["enter", "exit"]


@pytest.mark.anyio
@pytest.mark.parametrize("is_async", [True, False], ids=["async", "sync"])
async def test_generator_cleanup_removes_nested_layers(is_async: bool) -> None:
    generator_app = FastAPI()
    labels: list[str] = []

    def original_generator() -> Iterator[str]:
        yield "original"

    def body_value() -> str:
        return "outer"

    def outer_override() -> Iterator[str]:
        with generator_app.dependency_overrides_context(
            {body_value: lambda: "inner"}
        ):
            labels.append(get_dependency_overrides(generator_app)[body_value]())
        labels.append(body_value())
        yield "outer"
        labels.append(body_value())

    async def async_outer_override() -> AsyncIterator[str]:
        async with generator_app.dependency_overrides_context(
            {body_value: lambda: "inner"}
        ):
            labels.append(get_dependency_overrides(generator_app)[body_value]())
        labels.append(body_value())
        yield "outer"
        labels.append(body_value())

    override = async_outer_override if is_async else outer_override

    async with AsyncExitStack() as stack:
        with generator_app.dependency_overrides_context(
            {original_generator: override}
        ):
            solved = await _solve_generator(
                dependant=Dependant(call=override),
                stack=stack,
                sub_values={},
                dependency_overrides_provider=generator_app,
            )
            assert solved == "outer"

        await stack.aclose()

    assert labels == ["inner", "outer", "outer"]
