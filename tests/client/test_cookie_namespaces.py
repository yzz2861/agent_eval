import threading

import anyio
import pytest

import httpx


def session_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/login":
        session = request.url.params["session"]
        return httpx.Response(200, headers={"set-cookie": f"session={session}; Path=/"})
    elif request.url.path == "/logout":
        return httpx.Response(
            200, headers={"set-cookie": "session=; Max-Age=0; Path=/"}
        )
    elif request.url.path == "/redirect":
        return httpx.Response(302, headers={"location": "/echo"})
    elif request.url.path == "/redirect_with_cookie":
        return httpx.Response(
            302,
            headers={
                "location": "/echo",
                "set-cookie": "redirect-hop=seen; Path=/",
            },
        )
    elif request.url.path == "/echo":
        return httpx.Response(200, json={"cookies": request.headers.get("cookie")})
    raise NotImplementedError()  # pragma: no cover


def test_cookie_namespaces_are_isolated() -> None:
    """
    Two namespaces sharing one client each keep their own cookies,
    even for the same origin and cookie name.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.get("http://example.org/login?session=aaa", cookie_namespace="tenant-a")
    client.get("http://example.org/login?session=bbb", cookie_namespace="tenant-b")

    response_a = client.get("http://example.org/echo", cookie_namespace="tenant-a")
    response_b = client.get("http://example.org/echo", cookie_namespace="tenant-b")

    assert response_a.json() == {"cookies": "session=aaa"}
    assert response_b.json() == {"cookies": "session=bbb"}
    assert client.cookies_for("tenant-a").get("session") == "aaa"
    assert client.cookies_for("tenant-b").get("session") == "bbb"
    # The default container is untouched by namespaced requests.
    assert not client.cookies


def test_default_namespace_uses_client_cookies() -> None:
    """
    Omitting the namespace preserves the existing client.cookies behaviour.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.get("http://example.org/login?session=default")

    assert client.cookies.get("session") == "default"
    assert client.cookie_namespaces == []

    response = client.get("http://example.org/echo")
    assert response.json() == {"cookies": "session=default"}


def test_cookies_for_default_namespace_is_client_cookies() -> None:
    client = httpx.Client(
        cookies={"example": "value"}, transport=httpx.MockTransport(session_app)
    )
    assert client.cookies_for() is client.cookies
    assert client.cookies_for(None) is client.cookies


def test_identical_cookies_coexist_across_namespaces() -> None:
    """
    Cookies with the same name, domain and path can exist in
    different namespaces at the same time.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.cookies_for("tenant-a").set("session", "aaa", domain="example.org")
    client.cookies_for("tenant-b").set("session", "bbb", domain="example.org")

    assert client.cookies_for("tenant-a").get("session", domain="example.org") == "aaa"
    assert client.cookies_for("tenant-b").get("session", domain="example.org") == "bbb"

    response_a = client.get("http://example.org/echo", cookie_namespace="tenant-a")
    response_b = client.get("http://example.org/echo", cookie_namespace="tenant-b")
    assert response_a.json() == {"cookies": "session=aaa"}
    assert response_b.json() == {"cookies": "session=bbb"}


def test_clear_cookies_only_affects_target_namespace() -> None:
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.get("http://example.org/login?session=aaa", cookie_namespace="tenant-a")
    client.get("http://example.org/login?session=bbb", cookie_namespace="tenant-b")
    assert client.cookie_namespaces == ["tenant-a", "tenant-b"]

    client.clear_cookies("tenant-a")

    assert client.cookie_namespaces == ["tenant-b"]
    assert client.cookies_for("tenant-b").get("session") == "bbb"
    response_b = client.get("http://example.org/echo", cookie_namespace="tenant-b")
    assert response_b.json() == {"cookies": "session=bbb"}


def test_delete_cookie_only_affects_target_namespace() -> None:
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.get("http://example.org/login?session=aaa", cookie_namespace="tenant-a")
    client.get("http://example.org/login?session=bbb", cookie_namespace="tenant-b")

    client.cookies_for("tenant-a").delete("session", domain="example.org")

    assert client.cookies_for("tenant-a").get("session") is None
    assert client.cookies_for("tenant-b").get("session") == "bbb"


def test_expiry_only_affects_target_namespace() -> None:
    """
    An expiring Set-Cookie response only clears the cookie in the
    namespace that made the request.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.get("http://example.org/login?session=aaa", cookie_namespace="tenant-a")
    client.get("http://example.org/login?session=bbb", cookie_namespace="tenant-b")

    client.get("http://example.org/logout", cookie_namespace="tenant-a")

    assert client.cookies_for("tenant-a").get("session") is None
    assert client.cookies_for("tenant-b").get("session") == "bbb"

    response_a = client.get("http://example.org/echo", cookie_namespace="tenant-a")
    response_b = client.get("http://example.org/echo", cookie_namespace="tenant-b")
    assert response_a.json() == {"cookies": None}
    assert response_b.json() == {"cookies": "session=bbb"}


def test_redirects_keep_the_original_namespace() -> None:
    """
    Redirected requests send cookies from, and extract cookies into,
    the namespace of the original request.
    """
    client = httpx.Client(
        transport=httpx.MockTransport(session_app), follow_redirects=True
    )
    client.get("http://example.org/login?session=aaa", cookie_namespace="tenant-a")
    client.get("http://example.org/login?session=bbb", cookie_namespace="tenant-b")

    response = client.get(
        "http://example.org/redirect_with_cookie", cookie_namespace="tenant-a"
    )

    # The redirect-hop cookie was extracted before the redirect was followed,
    # so it is included on the redirected request, matching the behaviour
    # of the default client.cookies container.
    assert response.json() == {"cookies": "session=aaa; redirect-hop=seen"}
    # The cookie set by the redirect response landed in the same namespace.
    assert client.cookies_for("tenant-a").get("redirect-hop") == "seen"
    assert client.cookies_for("tenant-b").get("redirect-hop") is None
    assert not client.cookies


def test_interleaved_redirects_across_namespaces() -> None:
    """
    Two namespaces receive different session cookies from the same address,
    then follow interleaved redirects. The server always sees each
    namespace's own cookie.
    """
    client = httpx.Client(
        transport=httpx.MockTransport(session_app), follow_redirects=True
    )
    client.get("http://example.org/login?session=aaa", cookie_namespace="tenant-a")
    client.get("http://example.org/login?session=bbb", cookie_namespace="tenant-b")

    seen = []
    pairs = (("tenant-a", "session=aaa"), ("tenant-b", "session=bbb"))
    for _ in range(3):
        for namespace, expected in pairs:
            response = client.get(
                "http://example.org/redirect", cookie_namespace=namespace
            )
            seen.append(response.json()["cookies"])
            assert response.json() == {"cookies": expected}

    assert seen == ["session=aaa", "session=bbb"] * 3


class FreshRequestAuth(httpx.Auth):
    """
    An auth flow that retries a 401 by building a brand-new request,
    which does not carry over the original request extensions.
    """

    def auth_flow(self, request: httpx.Request):
        response = yield request
        if response.status_code == 401:
            retry = httpx.Request(
                request.method,
                request.url,
                headers={"Authorization": "Bearer token"},
            )
            yield retry


def auth_app(request: httpx.Request) -> httpx.Response:
    if request.headers.get("authorization") == "Bearer token":
        return httpx.Response(200, headers={"set-cookie": "session=authed; Path=/"})
    return httpx.Response(401)


def test_auth_retries_keep_the_original_namespace() -> None:
    """
    Cookies extracted on an authentication retry go to the namespace of
    the original request, even if the auth flow builds a fresh request.
    """
    client = httpx.Client(transport=httpx.MockTransport(auth_app))
    response = client.get(
        "http://example.org/", auth=FreshRequestAuth(), cookie_namespace="tenant-a"
    )

    assert response.status_code == 200
    assert client.cookies_for("tenant-a").get("session") == "authed"
    assert not client.cookies


def test_request_cookies_take_priority_over_namespace_cookies() -> None:
    """
    Explicit request-level cookies are merged after, and take priority
    over, the cookies in the request's namespace container.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    client.cookies_for("tenant-a").set("session", "from-container")
    client.cookies_for("tenant-a").set("container-only", "kept")

    request = client.build_request(
        "GET",
        "http://example.org/echo",
        cookies={"session": "from-request"},
        cookie_namespace="tenant-a",
    )
    response = client.send(request)

    assert response.json() == {"cookies": "session=from-request; container-only=kept"}


def test_namespaces_isolated_across_threads() -> None:
    """
    A single client shared between threads keeps each thread's
    namespace container isolated.
    """
    client = httpx.Client(transport=httpx.MockTransport(session_app))
    results: dict[str, object] = {}

    def use_namespace(namespace: str, session: str) -> None:
        client.get(
            f"http://example.org/login?session={session}",
            cookie_namespace=namespace,
        )
        response = client.get("http://example.org/echo", cookie_namespace=namespace)
        results[namespace] = response.json()["cookies"]

    threads = [
        threading.Thread(target=use_namespace, args=(f"tenant-{index}", f"s{index}"))
        for index in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results == {f"tenant-{index}": f"session=s{index}" for index in range(8)}
    assert not client.cookies


@pytest.mark.anyio
async def test_namespaces_isolated_across_async_tasks() -> None:
    """
    A single async client shared between tasks keeps each task's
    namespace container isolated.
    """
    async with httpx.AsyncClient(transport=httpx.MockTransport(session_app)) as client:
        results: dict[str, str] = {}

        async def use_namespace(namespace: str, session: str) -> None:
            await client.get(
                f"http://example.org/login?session={session}",
                cookie_namespace=namespace,
            )
            response = await client.get(
                "http://example.org/echo", cookie_namespace=namespace
            )
            results[namespace] = response.json()["cookies"]

        async with anyio.create_task_group() as task_group:
            for index in range(8):
                task_group.start_soon(use_namespace, f"tenant-{index}", f"s{index}")

    assert results == {f"tenant-{index}": f"session=s{index}" for index in range(8)}


@pytest.mark.anyio
async def test_async_redirects_keep_the_original_namespace() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(session_app), follow_redirects=True
    ) as client:
        await client.get(
            "http://example.org/login?session=aaa", cookie_namespace="tenant-a"
        )
        await client.get(
            "http://example.org/login?session=bbb", cookie_namespace="tenant-b"
        )

        responses: dict[str, httpx.Response] = {}

        async def follow_redirect(namespace: str) -> None:
            responses[namespace] = await client.get(
                "http://example.org/redirect", cookie_namespace=namespace
            )

        async with anyio.create_task_group() as task_group:
            task_group.start_soon(follow_redirect, "tenant-a")
            task_group.start_soon(follow_redirect, "tenant-b")

    assert responses["tenant-a"].json() == {"cookies": "session=aaa"}
    assert responses["tenant-b"].json() == {"cookies": "session=bbb"}
