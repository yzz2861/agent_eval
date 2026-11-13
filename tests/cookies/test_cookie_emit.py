from __future__ import annotations

import asyncio

from secure import SameSite, Secure, SetCookie
from secure.middleware import SecureASGIMiddleware, SecureWSGIMiddleware


class _SyncSetHeaderResponse:
    def __init__(self) -> None:
        self.captured: list[tuple[str, str]] = []

    def set_header(self, key: str, value: str) -> None:
        self.captured.append((key, value))


class _HeadersMappingResponse:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}


class _AsyncSetHeaderResponse:
    def __init__(self) -> None:
        self.captured: list[tuple[str, str]] = []

    async def set_header(self, key: str, value: str) -> None:
        self.captured.append((key, value))


def test_set_on_sync_response_via_set_header() -> None:
    cookie = SetCookie("__Host-session", "abc", path="/", secure=True, http_only=True)
    response = _SyncSetHeaderResponse()

    cookie.set_on(response)

    assert response.captured == [("Set-Cookie", cookie.header_value)]


def test_set_on_sync_response_via_headers_mapping() -> None:
    cookie = SetCookie("plain", "abc", same_site=SameSite.LAX)
    response = _HeadersMappingResponse()

    cookie.set_on(response)

    assert response.headers == {"Set-Cookie": cookie.header_value}


def test_set_on_async_response() -> None:
    cookie = SetCookie("sid", "abc", secure=True, same_site=SameSite.NONE)
    response = _AsyncSetHeaderResponse()

    asyncio.run(cookie.set_on_async(response))

    assert response.captured == [("Set-Cookie", cookie.header_value)]


def test_set_on_async_accepts_sync_response() -> None:
    cookie = SetCookie("sid", "abc")
    response = _SyncSetHeaderResponse()

    asyncio.run(cookie.set_on_async(response))

    assert response.captured == [("Set-Cookie", cookie.header_value)]


def test_cookie_coexists_with_secure_wsgi_middleware() -> None:
    secure_headers = Secure.with_default_headers()
    cookie = SetCookie("__Host-session", "abc", path="/", secure=True, http_only=True)

    def app(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]

    middleware = SecureWSGIMiddleware(app, secure=secure_headers)

    captured: dict[str, object] = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers
        return lambda _: None

    list(middleware({}, start_response))

    # The middleware emits the default security header set unchanged ...
    headers = captured["headers"]
    names = [name.lower() for name, _ in headers]
    assert "x-frame-options" in names
    assert "content-security-policy" in names
    assert "set-cookie" not in names

    # ... and the independently built Set-Cookie can be appended alongside it.
    headers.extend(cookie.header_items())
    set_cookie_values = [value for name, value in headers if name.lower() == "set-cookie"]
    assert set_cookie_values == [cookie.header_value]


def test_cookie_coexists_with_secure_asgi_middleware() -> None:
    secure_headers = Secure.with_default_headers()
    cookie = SetCookie("sid", "abc", secure=True, partitioned=True, same_site=SameSite.NONE)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    middleware = SecureASGIMiddleware(app, secure=secure_headers)
    messages: list[dict] = []

    async def send(message):
        messages.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    asyncio.run(middleware({"type": "http"}, receive, send))

    start_message = next(message for message in messages if message["type"] == "http.response.start")
    headers = start_message["headers"]
    raw_names = {name.lower() for name, _ in headers}
    assert b"x-frame-options" in raw_names
    assert b"set-cookie" not in raw_names

    headers.append((b"set-cookie", cookie.header_value.encode("latin-1")))
    set_cookie_headers = [value for name, value in headers if name == b"set-cookie"]
    assert len(set_cookie_headers) == 1


def test_multiple_cookies_emit_repeated_set_cookie_fields() -> None:
    first = SetCookie("a", "1", secure=True)
    second = SetCookie("b", "2", secure=True)
    response = _SyncSetHeaderResponse()

    first.set_on(response)
    second.set_on(response)

    assert response.captured == [
        ("Set-Cookie", first.header_value),
        ("Set-Cookie", second.header_value),
    ]
