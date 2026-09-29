from docs.examples.middleware.ordering import app

from litestar.testing import TestClient


def test_middleware_ordering() -> None:
    route = next(route for route in app.routes if route.path == "/")
    route_handler = route.route_handlers[0]

    order = route_handler.middleware_execution_order
    assert order.enter == ("session", "authentication")
    assert order.exit == ("authentication", "session")

    assert app.get_middleware_execution_order()[route_handler.name or str(route_handler)] == order

    with TestClient(app=app) as client:
        response = client.get("/")
        assert response.status_code == 200
