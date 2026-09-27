"""
Tests for per-request cookie namespaces.
"""

import threading

import anyio
import pytest

import httpx


def cookie_header_dict(request: httpx.Request) -> dict:
    header = request.headers.get("cookie", "")
    return dict(
        item.strip().split("=", 1) for item in header.split(";") if item.strip()
    )


def session_app(request: httpx.Request) -> httpx.Response:
    """
    A mock server that hands out a different session cookie per tenant,
    sets an additional cookie mid-redirect, and echoes back the cookies
    it receives.
    """
    if request.url.path == "/login/a":
        return httpx.Response(200, headers={"set-cookie": "session=session-a; Path=/"})
    elif request.url.path == "/login/b":
        return httpx.Response(200, headers={"set-cookie": "session=session-b; Path=/"})
    elif request.url.path == "/redirect/a":
        return httpx.Response(
            302,
            headers={"location": "/final", "set-cookie": "hop=hop-a; Path=/"},
        )
    elif request.url.path == "/redirect/b":
        return httpx.Response(
            302,
            headers={"location": "/final", "set-cookie": "hop=hop-b; Path=/"},
        )
    elif request.url.path == "/expire":
        return httpx.Response(
            200,
            headers={
                "set-cookie": (
                    "session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"
                )
            },
        )
    elif request.url.path == "/final":
        return httpx.Response(200, json=cookie_header_dict(request))
    raise NotImplementedError()  # pragma: no cover


def test_namespaces_are_isolated() -> None:
    """
    Two namespaces receive different session cookies from the same origin.
    Each request only sends the cookies of its own namespace, and the
    default client cookies are left untouched.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))

    client.get("http://example.org/login/a", cookie_namespace="tenant-a")
    client.get("http://example.org/login/b", cookie_namespace="tenant-b")

    response_a = client.get("http://example.org/final", cookie_namespace="tenant-a")
    response_b = client.get("http://example.org/final", cookie_namespace="tenant-b")

    assert response_a.json() == {"session": "session-a"}
    assert response_b.json() == {"session": "session-b"}

    # The same cookie name, domain and path exists in both namespaces.
    assert client.cookies_for("tenant-a").get("session") == "session-a"
    assert client.cookies_for("tenant-b").get("session") == "session-b"

    # The default client-level cookies are not affected.
    assert client.cookies.get("session") is None
    assert client.cookie_namespaces == ["tenant-a", "tenant-b"]


def test_interleaved_redirects_keep_namespace() -> None:
    """
    Redirects follow the namespace of the original request, even when
    requests from two namespaces are interleaved, and cookies set
    mid-redirect are extracted into the matching namespace.
    """
    client = httpx.Client(
        transport=httpx.MockTransport(session_app), follow_redirects=True
    )

    client.get("http://example.org/login/a", cookie_namespace="tenant-a")
    client.get("http://example.org/login/b", cookie_namespace="tenant-b")

    url_a = "http://example.org/redirect/a"
    url_b = "http://example.org/redirect/b"
    response_a = client.get(url_a, cookie_namespace="tenant-a")
    response_b = client.get(url_b, cookie_namespace="tenant-b")
    final_a = client.get("http://example.org/final", cookie_namespace="tenant-a")
    final_b = client.get("http://example.org/final", cookie_namespace="tenant-b")

    assert response_a.json() == {"session": "session-a", "hop": "hop-a"}
    assert response_b.json() == {"session": "session-b", "hop": "hop-b"}
    assert final_a.json() == {"session": "session-a", "hop": "hop-a"}
    assert final_b.json() == {"session": "session-b", "hop": "hop-b"}


def test_expiry_only_affects_target_namespace() -> None:
    """
    An expired cookie is only removed from the namespace of the request
    that received the expiry response.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))

    client.get("http://example.org/login/a", cookie_namespace="tenant-a")
    client.get("http://example.org/login/b", cookie_namespace="tenant-b")

    client.get("http://example.org/expire", cookie_namespace="tenant-a")

    assert client.cookies_for("tenant-a").get("session") is None
    assert client.cookies_for("tenant-b").get("session") == "session-b"

    response_a = client.get("http://example.org/final", cookie_namespace="tenant-a")
    response_b = client.get("http://example.org/final", cookie_namespace="tenant-b")
    assert response_a.json() == {}
    assert response_b.json() == {"session": "session-b"}


def test_clear_cookies_by_namespace() -> None:
    """
    Clearing a namespace leaves the other namespaces and the default
    client cookies untouched.
    """
    client = httpx.Client(
        transport=httpx.MockTransport(session_app), cookies={"default": "1"}
    )
    client.get("http://example.org/login/a", cookie_namespace="tenant-a")
    client.get("http://example.org/login/b", cookie_namespace="tenant-b")

    client.clear_cookies("tenant-a")

    assert client.cookies_for("tenant-a").get("session") is None
    assert client.cookies_for("tenant-b").get("session") == "session-b"
    assert client.cookies.get("default") == "1"

    client.clear_cookies()
    assert client.cookies.get("default") is None


def test_default_namespace_matches_client_cookies() -> None:
    """
    Omitting the namespace preserves the existing client.cookies behaviour.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    assert client.cookies_for() is client.cookies

    client.get("http://example.org/login/a")
    assert client.cookies.get("session") == "session-a"
    assert client.cookie_namespaces == []

    response = client.get("http://example.org/final")
    assert response.json() == {"session": "session-a"}


def test_explicit_cookies_override_namespace_cookies() -> None:
    """
    When merging, namespace cookies are applied first and explicit
    per-request cookies take precedence on conflicts.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.get("http://example.org/login/a", cookie_namespace="tenant-a")

    request = client.build_request(
        "GET",
        "http://example.org/final",
        cookies={"session": "explicit", "extra": "1"},
        cookie_namespace="tenant-a",
    )
    response = client.send(request)

    assert response.json() == {"session": "explicit", "extra": "1"}
    # The explicit per-request cookie is not persisted into the namespace.
    assert client.cookies_for("tenant-a").get("session") == "session-a"


def test_send_uses_namespace_from_request_extensions() -> None:
    """
    A manually built request can opt into a namespace through the
    'cookie_namespace' request extension. Responses are then extracted
    into the matching namespace.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))

    request = httpx.Request(
        "GET", "http://example.org/login/a", extensions={"cookie_namespace": "tenant-a"}
    )
    client.send(request)

    assert client.cookies_for("tenant-a").get("session") == "session-a"
    assert client.cookies.get("session") is None


def test_auth_retry_keeps_namespace() -> None:
    """
    Auth flows that build a fresh request on retry still use the
    namespace of the original request.
    """
    seen = []

    class RebuildingAuth(httpx.Auth):
        def auth_flow(self, request):
            response = yield request
            if response.status_code == 401:
                retry = httpx.Request("GET", request.url)
                yield retry

    def auth_app(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions.get("cookie_namespace"))
        if len(seen) == 1:
            return httpx.Response(
                401, headers={"set-cookie": "session=from-retry; Path=/"}
            )
        return httpx.Response(200, json=cookie_header_dict(request))

    client = httpx.Client(transport=httpx.MockTransport(auth_app))
    response = client.get(
        "http://example.org/protected",
        auth=RebuildingAuth(),
        cookie_namespace="tenant-a",
    )

    assert response.status_code == 200
    # Both the initial request and the auth retry ran in the namespace.
    assert seen == ["tenant-a", "tenant-a"]
    # The cookie set by the 401 response landed in the namespace...
    assert client.cookies_for("tenant-a").get("session") == "from-retry"
    assert client.cookies.get("session") is None


def test_sync_threads_keep_namespaces_isolated() -> None:
    """
    Multiple threads sharing one client and one transport each get
    their own isolated cookie container.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    results = {}

    def use_namespace(namespace: str, tenant: str) -> None:
        client.get(f"http://example.org/login/{tenant}", cookie_namespace=namespace)
        response = client.get("http://example.org/final", cookie_namespace=namespace)
        results[namespace] = response.json()

    threads = [
        threading.Thread(target=use_namespace, args=(f"tenant-{n}", tenant))
        for n, tenant in enumerate("ab" * 5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for n, tenant in enumerate("ab" * 5):
        assert results[f"tenant-{n}"] == {"session": f"session-{tenant}"}


@pytest.mark.anyio
async def test_async_concurrency_keeps_namespaces_isolated() -> None:
    """
    Concurrent async tasks sharing one AsyncClient each get their own
    isolated cookie container, with redirects following each task's
    namespace.
    """

    async def async_app(request: httpx.Request) -> httpx.Response:
        await anyio.sleep(0)
        return session_app(request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(async_app), follow_redirects=True
    ) as client:
        results: dict = {}

        async def use_namespace(namespace: str, tenant: str) -> None:
            await client.get(
                f"http://example.org/login/{tenant}", cookie_namespace=namespace
            )
            response = await client.get(
                f"http://example.org/redirect/{tenant}", cookie_namespace=namespace
            )
            results[namespace] = response.json()

        async with anyio.create_task_group() as task_group:
            for n, tenant in enumerate("ab" * 5):
                task_group.start_soon(use_namespace, f"tenant-{n}", tenant)

    for n, tenant in enumerate("ab" * 5):
        assert results[f"tenant-{n}"] == {
            "session": f"session-{tenant}",
            "hop": f"hop-{tenant}",
        }
