import asyncio
from collections.abc import Callable
from typing import Any

from secure import CacheControl, CachePolicy, Secure, Vary
from secure.middleware import SecureASGIMiddleware, SecureWSGIMiddleware


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [value for key, value in headers if key.lower() == lowered]


def _directive_names(value: str) -> set[str]:
    return {token.strip().lower() for token in value.split(",") if token.strip()}


def _shared_cache_storable(cache_control: str) -> bool:
    directives = _directive_names(cache_control)
    if "no-store" in directives or "private" in directives:
        return False
    if "public" in directives:
        return True
    return True


def _run_wsgi(
    app: Callable[..., Any],
    *,
    secure: Secure | None = None,
    environ: dict[str, Any] | None = None,
    **options: Any,
) -> dict[str, Any]:
    captured: dict[str, Any] = {"status": "", "headers": [], "body": b""}

    def start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Callable[[bytes], None]:
        captured["status"] = status
        captured["headers"] = headers
        return lambda _chunk: None

    request_environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", **(environ or {})}
    middleware = SecureWSGIMiddleware(app, secure=secure, **options)
    captured["body"] = b"".join(middleware(request_environ, start_response))
    return captured


def _wsgi_app(
    headers: list[tuple[str, str]],
    *,
    status: str = "200 OK",
    body: bytes = b"ok",
) -> Callable[..., Any]:
    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> list[bytes]:
        start_response(status, headers)
        return [body]

    return app


async def _run_asgi(
    app: Callable[..., Any],
    *,
    secure: Secure | None = None,
    scope: dict[str, Any] | None = None,
    **options: Any,
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    middleware = SecureASGIMiddleware(app, secure=secure, **options)

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    await middleware({"type": "http", **(scope or {})}, receive, send)
    return messages


def _asgi_app(
    headers: list[tuple[bytes, bytes]],
    *,
    status: int = 200,
    body: bytes = b"ok",
) -> Callable[..., Any]:
    async def app(scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return app


def _start_message(messages: list[dict[str, Any]]) -> dict[str, Any]:
    return next(message for message in messages if message["type"] == "http.response.start")


def _asgi_headers(message: dict[str, Any]) -> list[tuple[str, str]]:
    return [(name.decode("latin-1"), value.decode("latin-1")) for name, value in message["headers"]]


def test_authenticated_html_page_is_not_shared_storable() -> None:
    app = _wsgi_app(
        [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "private, max-age=600"),
            ("Vary", "Accept-Encoding"),
        ]
    )
    captured = _run_wsgi(
        app,
        environ={
            "PATH_INFO": "/orders/123",
            "HTTP_AUTHORIZATION": "Bearer token",
        },
    )

    cache_control = _header_values(captured["headers"], "cache-control")
    assert len(cache_control) == 1
    assert _directive_names(cache_control[0]) >= {"no-store", "private", "max-age=0"}
    assert _header_values(captured["headers"], "vary") == ["Accept-Encoding"]
    assert _shared_cache_storable(cache_control[0]) is False


def test_public_javascript_keeps_original_cache_headers() -> None:
    original = "public, max-age=31536000, immutable"
    app = _wsgi_app(
        [
            ("Content-Type", "application/javascript"),
            ("Cache-Control", original),
            ("Vary", "Accept-Encoding"),
        ]
    )
    captured = _run_wsgi(
        app,
        environ={
            "PATH_INFO": "/assets/app.4f3c1.js",
            "HTTP_AUTHORIZATION": "Bearer token",
        },
    )

    assert _header_values(captured["headers"], "cache-control") == [original]
    assert _header_values(captured["headers"], "vary") == ["Accept-Encoding"]
    assert _shared_cache_storable(original) is True


def test_existing_private_and_stricter_directives_are_preserved() -> None:
    app = _wsgi_app(
        [
            ("Content-Type", "text/html"),
            ("Cache-Control", "private, max-age=3600, no-cache, must-revalidate"),
        ]
    )
    captured = _run_wsgi(app, environ={"PATH_INFO": "/account"})

    value = _header_values(captured["headers"], "cache-control")[0]
    assert _directive_names(value) >= {"no-store", "private", "max-age=0", "no-cache", "must-revalidate"}
    assert "max-age=3600" not in value


def test_vary_is_merged_instead_of_overwritten() -> None:
    secure = Secure.with_default_headers()
    secure.headers_list.append(Vary().cookie().authorization())
    app = _wsgi_app(
        [
            ("Content-Type", "application/javascript"),
            ("Vary", "Accept-Encoding"),
            ("Vary", "Accept-Language"),
        ]
    )
    captured = _run_wsgi(app, secure=secure, environ={"PATH_INFO": "/app.js"})

    vary_values = _header_values(captured["headers"], "vary")
    assert len(vary_values) == 1
    assert vary_values[0] == "Accept-Encoding, Accept-Language, Authorization, Cookie"


def test_policy_vary_is_merged_for_sensitive_responses() -> None:
    policy = CachePolicy(vary=Vary().authorization().cookie())
    app = _wsgi_app(
        [
            ("Content-Type", "text/html"),
            ("Vary", "Accept-Encoding"),
        ]
    )
    captured = _run_wsgi(app, environ={"PATH_INFO": "/account"}, cache_policy=policy)

    assert _header_values(captured["headers"], "vary") == ["Accept-Encoding, Authorization, Cookie"]


def test_status_code_classification() -> None:
    policy = CachePolicy(sensitive_statuses={200})
    headers = [
        ("Content-Type", "text/html"),
        ("Cache-Control", "public, max-age=60"),
    ]

    ok = _run_wsgi(_wsgi_app(headers, status="200 OK"), environ={"PATH_INFO": "/page"}, cache_policy=policy)
    missing = _run_wsgi(_wsgi_app(headers, status="404 Not Found"), environ={"PATH_INFO": "/page"}, cache_policy=policy)

    assert "no-store" in _directive_names(_header_values(ok["headers"], "cache-control")[0])
    assert _header_values(missing["headers"], "cache-control") == ["public, max-age=60"]


def test_route_annotation_marks_response_sensitive() -> None:
    route = type("Route", (), {"cache_sensitive": True})()
    app = _asgi_app(
        [
            (b"content-type", b"application/json"),
            (b"cache-control", b"public, max-age=300"),
        ]
    )
    messages = asyncio.run(_run_asgi(app, scope={"path": "/dashboard", "route": route}))

    headers = _asgi_headers(_start_message(messages))
    assert "no-store" in _directive_names(_header_values(headers, "cache-control")[0])


def test_streaming_wsgi_applies_headers_before_body_is_consumed() -> None:
    captured_headers: list[tuple[str, str]] = []

    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Any:
        start_response(
            "200 OK",
            [
                ("Content-Type", "text/html"),
                ("Cache-Control", "private, max-age=60"),
            ],
        )

        def body() -> Any:
            captured_headers.extend(_header_values(captured["headers"], "cache-control"))
            yield b"first"
            yield b"second"

        return body()

    captured: dict[str, Any] = {}
    middleware = SecureWSGIMiddleware(app)

    def start_response(status: str, headers: list[tuple[str, str]], exc_info: Any = None) -> Callable[[bytes], None]:
        captured["headers"] = headers
        return lambda _chunk: None

    body = middleware({"REQUEST_METHOD": "GET", "PATH_INFO": "/orders"}, start_response)
    first_chunk = next(body)

    assert first_chunk == b"first"
    assert len(captured_headers) == 1
    assert "no-store" in _directive_names(captured_headers[0])


def test_streaming_asgi_applies_headers_before_body_messages() -> None:
    async def app(scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/html"),
                    (b"cache-control", b"private, max-age=60"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b"first", "more_body": True})
        await send({"type": "http.response.body", "body": b"second", "more_body": False})

    messages = asyncio.run(_run_asgi(app))
    start = _start_message(messages)
    headers = _asgi_headers(start)

    assert messages[0]["type"] == "http.response.start"
    assert "no-store" in _directive_names(_header_values(headers, "cache-control")[0])
    assert messages[1]["body"] == b"first"
    assert messages[2]["body"] == b"second"


def test_wsgi_and_asgi_produce_same_cache_headers() -> None:
    response_headers = [
        ("Content-Type", "text/html"),
        ("Cache-Control", "private, max-age=600, no-cache"),
        ("Vary", "Accept-Encoding"),
    ]
    secure = Secure.with_default_headers()
    secure.headers_list.append(Vary().cookie())

    wsgi = _run_wsgi(
        _wsgi_app(response_headers),
        secure=secure,
        environ={"PATH_INFO": "/orders/123", "HTTP_AUTHORIZATION": "Bearer token"},
    )
    asgi_messages = asyncio.run(
        _run_asgi(
            _asgi_app([(name.encode(), value.encode()) for name, value in response_headers]),
            secure=secure,
            scope={"path": "/orders/123", "headers": [(b"authorization", b"Bearer token")]},
        )
    )
    asgi_headers = _asgi_headers(_start_message(asgi_messages))

    assert _header_values(wsgi["headers"], "cache-control") == _header_values(asgi_headers, "cache-control")
    assert _header_values(wsgi["headers"], "vary") == _header_values(asgi_headers, "vary")


def test_default_configuration_remains_compatible() -> None:
    default_headers = Secure.with_default_headers().headers
    assert "Cache-Control" not in default_headers
    assert "Vary" not in default_headers

    explicit = Secure(cache=CacheControl().no_store().max_age(0))
    assert explicit.headers["Cache-Control"] == "no-store, max-age=0"


def test_public_asset_without_existing_cache_control_is_not_given_no_store() -> None:
    app = _wsgi_app([("Content-Type", "application/javascript")])
    captured = _run_wsgi(app, environ={"PATH_INFO": "/app.js"})

    assert _header_values(captured["headers"], "cache-control") == []
