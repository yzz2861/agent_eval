import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi import Depends, FastAPI, Security, WebSocket
from fastapi.security import SecurityScopes
from fastapi.testclient import TestClient


def get_value() -> str:
    return "original"


def get_other() -> str:
    return "other-original"


def get_outer() -> str:
    return "outer"


def get_inner() -> str:
    return "inner"


def get_security_value(required_scopes: SecurityScopes) -> tuple[str, list[str]]:
    return "original", required_scopes.scopes


def get_child() -> str:
    return "original-child"


def get_parent(child: str = Depends(get_child)) -> dict[str, str]:
    return {"child": child}


def get_broken() -> str:
    raise RuntimeError("broken dependency")


def make_yield_dependencies(events: list[str]):
    def original_yield_value():
        events.append("original-enter")
        yield "original-yield"
        events.append("original-cleanup")

    def override_sync_yield():
        events.append("override-enter")
        yield "override-yield"
        events.append("override-cleanup")

    async def override_async_yield():
        events.append("override-enter")
        yield "override-yield"
        events.append("override-cleanup")

    return original_yield_value, override_sync_yield, override_async_yield


def create_app(
    events: list[str] | None = None,
) -> tuple[FastAPI, list[str], object, object, object]:
    if events is None:
        events = []
    app = FastAPI()
    (
        original_yield_value,
        override_sync_yield,
        override_async_yield,
    ) = make_yield_dependencies(events)

    @app.get("/value")
    def read_value(value: str = Depends(get_value)) -> dict[str, str]:
        return {"value": value}

    @app.get("/values")
    def read_values(
        value: str = Depends(get_value),
        other: str = Depends(get_other),
    ) -> dict[str, str]:
        return {"value": value, "other": other}

    @app.get("/security")
    def read_security(
        security: tuple[str, list[str]] = Security(get_security_value, scopes=["read"]),
    ) -> dict[str, object]:
        return {"value": security[0], "scopes": security[1]}

    @app.get("/parent")
    def read_parent(parent: dict[str, str] = Depends(get_parent)) -> dict[str, str]:
        return parent

    @app.get("/broken")
    def read_broken(value: str = Depends(get_broken)) -> dict[str, str]:
        return {"value": value}

    @app.websocket("/ws/sync")
    async def ws_sync(
        websocket: WebSocket,
        value: str = Depends(original_yield_value),
    ) -> None:
        await websocket.accept()
        await websocket.send_text(value)
        await websocket.receive_text()

    @app.websocket("/ws/async")
    async def ws_async(
        websocket: WebSocket,
        value: str = Depends(original_yield_value),
    ) -> None:
        await websocket.accept()
        await websocket.send_text(value)
        await websocket.receive_text()

    return app, events, original_yield_value, override_sync_yield, override_async_yield


def test_nested_overrides_take_precedence_and_restore() -> None:
    app, *_ = create_app()
    client = TestClient(app)

    assert client.get("/value").json() == {"value": "original"}

    with app.dependency_overrides_context({get_value: get_outer}):
        assert client.get("/value").json() == {"value": "outer"}
        with app.dependency_overrides_context({get_value: get_inner}):
            assert client.get("/value").json() == {"value": "inner"}
        assert client.get("/value").json() == {"value": "outer"}

    assert client.get("/value").json() == {"value": "original"}
    assert app.dependency_overrides == {}


def test_inner_context_falls_back_to_outer_and_app_defaults() -> None:
    app, *_ = create_app()
    app.dependency_overrides[get_value] = lambda: "default"
    client = TestClient(app)

    with app.dependency_overrides_context({get_other: get_outer}):
        with app.dependency_overrides_context({get_value: get_inner}):
            response = client.get("/values")

    assert response.json() == {"value": "inner", "other": "outer"}
    assert app.dependency_overrides[get_value]() == "default"


def test_override_applies_to_security_and_sub_dependencies() -> None:
    app, *_ = create_app()
    client = TestClient(app)

    def override_security(required_scopes: SecurityScopes):
        return "overridden", required_scopes.scopes

    with app.dependency_overrides_context({get_security_value: override_security}):
        response = client.get("/security")

    assert response.json() == {
        "value": "overridden",
        "scopes": ["read"],
    }

    assert client.get("/security").json() == {
        "value": "original",
        "scopes": ["read"],
    }

    def override_child() -> str:
        return "override-child"

    with app.dependency_overrides_context({get_child: override_child}):
        response = client.get("/parent")

    assert response.json() == {"child": "override-child"}


def test_exception_exit_restores_overrides() -> None:
    app, *_ = create_app()
    client = TestClient(app)

    with pytest.raises(RuntimeError, match="context failure"):
        with app.dependency_overrides_context({get_value: get_inner}):
            assert client.get("/value").json() == {"value": "inner"}
            raise RuntimeError("context failure")

    assert client.get("/value").json() == {"value": "original"}

    with app.dependency_overrides_context({get_broken: get_inner}):
        assert client.get("/broken").json() == {"value": "inner"}

    error_client = TestClient(app, raise_server_exceptions=False)
    assert error_client.get("/broken").status_code == 500


def test_concurrent_threads_use_isolated_overrides() -> None:
    app, *_ = create_app()

    @app.get("/slow-value")
    def read_slow_value(value: str = Depends(get_value)) -> dict[str, str]:
        time.sleep(0.05)
        return {"value": value}

    def request_with_override(value: str, barrier: Barrier) -> dict[str, str]:
        with app.dependency_overrides_context({get_value: lambda: value}):
            barrier.wait(timeout=2)
            return TestClient(app).get("/slow-value").json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        barrier = Barrier(2)
        first = executor.submit(request_with_override, "first", barrier)
        second = executor.submit(request_with_override, "second", barrier)
        assert first.result() == {"value": "first"}
        assert second.result() == {"value": "second"}

    assert TestClient(app).get("/value").json() == {"value": "original"}


def test_mounted_subapplications_are_isolated() -> None:
    root, *_ = create_app()
    sub, *_ = create_app()
    root.mount("/sub", sub)
    root_client = TestClient(root)
    sub_client = TestClient(sub)

    sub.dependency_overrides[get_value] = lambda: "sub-default"

    with root.dependency_overrides_context({get_value: get_outer}):
        assert root_client.get("/value").json() == {"value": "outer"}
        assert root_client.get("/sub/value").json() == {"value": "sub-default"}
        assert sub_client.get("/value").json() == {"value": "sub-default"}

        with sub.dependency_overrides_context({get_value: get_inner}):
            assert root_client.get("/sub/value").json() == {"value": "inner"}
            assert root_client.get("/value").json() == {"value": "outer"}

    assert root_client.get("/value").json() == {"value": "original"}
    assert root_client.get("/sub/value").json() == {"value": "sub-default"}


@pytest.mark.parametrize(
    "path,event_name",
    [
        ("/ws/sync", "sync"),
        ("/ws/async", "async"),
    ],
)
def test_yield_cleanup_uses_creation_override_context(
    path: str, event_name: str
) -> None:
    app, events, original_dependency, sync_override, async_override = create_app()
    client = TestClient(app)
    override = sync_override if event_name == "sync" else async_override

    with app.dependency_overrides_context({original_dependency: override}):
        websocket = client.websocket_connect(path).__enter__()
        assert websocket.receive_text() == "override-yield"
        assert events == ["override-enter"]

    assert events == ["override-enter"]
    websocket.send_text("close")
    websocket.__exit__(None, None, None)
    assert events == ["override-enter", "override-cleanup"]
