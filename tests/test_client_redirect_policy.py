# Functional tests for the ClientSession redirect_policy hook.
from __future__ import annotations  # TODO(PY311): Remove

import asyncio
from typing import NoReturn
from unittest import mock

import pytest
from pytest_aiohttp import AiohttpServer
from yarl import URL

import aiohttp
from aiohttp import web
from aiohttp.client import RedirectPolicyAction
from aiohttp.client_exceptions import RedirectPolicyError
from aiohttp.test_utils import TestServer


@pytest.fixture
async def target_server(aiohttp_server: AiohttpServer) -> TestServer:
    """Second server on its own local port, i.e. another origin."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=request.method)

    app = web.Application()
    app.router.add_route("*", "/target", handler)
    return await aiohttp_server(app)


def _recording_policy(calls: list, action: RedirectPolicyAction):
    async def policy(
        response: aiohttp.ClientResponse,
        location: str,
        url: URL,
        method: str,
    ) -> RedirectPolicyAction:
        calls.append((response, location, url, method))
        return action

    return policy


async def test_allow_follows_cross_origin_and_strips_credentials(
    aiohttp_server: AiohttpServer,
) -> None:
    seen_headers = None

    async def target(request: web.Request) -> web.Response:
        nonlocal seen_headers
        seen_headers = request.headers
        return web.Response(text="ok")

    target_app = web.Application()
    target_app.router.add_get("/target", target)
    target_server = await aiohttp_server(target_app)

    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(target_server.make_url("/target"))

    redirect_app = web.Application()
    redirect_app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(redirect_app)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.ALLOW)
    ) as session:
        async with session.get(
            server.make_url("/redirect"),
            headers={
                "Authorization": "Basic dXNlcjpwYXNz",
                "Cookie": "a=b",
            },
        ) as resp:
            assert resp.status == 200
            assert await resp.text() == "ok"
            assert len(resp.history) == 1
            assert resp.history[0].status == 302

    assert len(calls) == 1
    response, location, url, method = calls[0]
    assert response.status == 302
    assert location == str(target_server.make_url("/target"))
    assert url == target_server.make_url("/target")
    assert method == "GET"
    # Cross-origin credential stripping remains the client's job.
    assert seen_headers is not None
    assert "Authorization" not in seen_headers
    assert "Cookie" not in seen_headers


async def test_return_stops_following_and_response_is_readable(
    aiohttp_server: AiohttpServer, target_server: TestServer
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(target_server.make_url("/target"))

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    on_request_redirect = mock.AsyncMock()
    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_redirect.append(on_request_redirect)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.RETURN),
        trace_configs=[trace_config],
    ) as session:
        async with session.get(server.make_url("/redirect")) as resp:
            assert resp.status == 302
            # The caller can still read the returned 3xx response.
            await resp.read()
            assert resp.history == ()

    assert len(calls) == 1
    # A stopped redirect is not a followed one.
    on_request_redirect.assert_not_called()


async def test_deny_raises_without_touching_target(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        # Unresolvable host: proves no DNS resolution or connect happens.
        raise web.HTTPFound("http://redirect-target.invalid:12345/target")

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    on_request_redirect = mock.AsyncMock()
    trace_config = aiohttp.TraceConfig()
    trace_config.on_request_redirect.append(on_request_redirect)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.DENY),
        trace_configs=[trace_config],
    ) as session:
        with pytest.raises(RedirectPolicyError) as ctx:
            await session.get(server.make_url("/redirect"))

    assert ctx.value.status == 302
    assert ctx.value.history == ()
    assert len(calls) == 1
    on_request_redirect.assert_not_called()


async def test_return_with_unresolvable_target(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound("http://redirect-target.invalid:12345/target")

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.RETURN)
    ) as session:
        async with session.get(server.make_url("/redirect")) as resp:
            assert resp.status == 302
            await resp.read()

    response, location, url, method = calls[0]
    assert location == "http://redirect-target.invalid:12345/target"
    assert url == URL("http://redirect-target.invalid:12345/target")
    assert method == "GET"


async def test_relative_location_is_resolved_before_policy(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound("/target")

    async def target(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    app.router.add_get("/target", target)
    server = await aiohttp_server(app)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.ALLOW)
    ) as session:
        async with session.get(server.make_url("/redirect")) as resp:
            assert resp.status == 200

    response, location, url, method = calls[0]
    assert location == "/target"
    assert url == server.make_url("/target")


async def test_loop_is_still_bounded_by_max_redirects(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound("/loop")

    app = web.Application()
    app.router.add_get("/loop", redirect)
    server = await aiohttp_server(app)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.ALLOW)
    ) as session:
        with pytest.raises(aiohttp.TooManyRedirects) as ctx:
            await session.get(server.make_url("/loop"), max_redirects=3)

    assert len(calls) == 3
    assert len(ctx.value.history) == 3


async def test_policy_can_break_a_redirect_loop(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound("/loop")

    app = web.Application()
    app.router.add_get("/loop", redirect)
    server = await aiohttp_server(app)

    calls = []

    async def policy(
        response: aiohttp.ClientResponse, location: str, url: URL, method: str
    ) -> RedirectPolicyAction:
        calls.append((response, location, url, method))
        if len(calls) >= 2:
            return RedirectPolicyAction.RETURN
        return RedirectPolicyAction.ALLOW

    async with aiohttp.ClientSession(redirect_policy=policy) as session:
        async with session.get(server.make_url("/loop")) as resp:
            assert resp.status == 302
            await resp.read()
            # Only the actually followed hop is recorded as history.
            assert len(resp.history) == 1

    assert len(calls) == 2


async def test_non_replayable_body_still_fails_when_allowed(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        await request.read()
        raise web.HTTPTemporaryRedirect("/target")

    async def target(request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_post("/redirect", redirect)
    app.router.add_post("/target", target)
    server = await aiohttp_server(app)

    async def body():
        yield b"chunk"

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.ALLOW)
    ) as session:
        with pytest.raises(aiohttp.ClientPayloadError):
            async with session.post(server.make_url("/redirect"), data=body()):
                pass

    # The policy was consulted with the preserved method, then the client
    # enforced the 307 body replay check.
    assert len(calls) == 1
    assert calls[0][3] == "POST"


async def test_non_replayable_body_can_be_returned(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        await request.read()
        raise web.HTTPTemporaryRedirect("/target")

    app = web.Application()
    app.router.add_post("/redirect", redirect)
    server = await aiohttp_server(app)

    async def body():
        yield b"chunk"

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.RETURN)
    ) as session:
        async with session.post(server.make_url("/redirect"), data=body()) as resp:
            assert resp.status == 307
            await resp.read()
            assert resp.history == ()

    assert len(calls) == 1


async def test_policy_sees_rewritten_method_for_303(
    aiohttp_server: AiohttpServer, target_server: TestServer
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        await request.read()
        raise web.HTTPSeeOther(target_server.make_url("/target"))

    app = web.Application()
    app.router.add_post("/redirect", redirect)
    server = await aiohttp_server(app)

    calls = []
    async with aiohttp.ClientSession(
        redirect_policy=_recording_policy(calls, RedirectPolicyAction.ALLOW)
    ) as session:
        async with session.post(server.make_url("/redirect"), data=b"payload") as resp:
            assert resp.status == 200
            assert await resp.text() == "GET"

    assert calls[0][3] == "GET"


async def test_policy_exception_releases_response(
    aiohttp_server: AiohttpServer, target_server: TestServer
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(target_server.make_url("/target"))

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    async def policy(
        response: aiohttp.ClientResponse, location: str, url: URL, method: str
    ) -> RedirectPolicyAction:
        raise RuntimeError("policy broke")

    async with aiohttp.ClientSession(redirect_policy=policy) as session:
        with pytest.raises(RuntimeError, match="policy broke"):
            await session.get(server.make_url("/redirect"))
        # The current hop's response was released, not leaked.
        assert not session.connector._acquired


async def test_policy_cancellation_releases_response(
    aiohttp_server: AiohttpServer, target_server: TestServer
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(target_server.make_url("/target"))

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    async def policy(
        response: aiohttp.ClientResponse, location: str, url: URL, method: str
    ) -> RedirectPolicyAction:
        raise asyncio.CancelledError()

    async with aiohttp.ClientSession(redirect_policy=policy) as session:
        with pytest.raises(asyncio.CancelledError):
            await session.get(server.make_url("/redirect"))
        assert not session.connector._acquired


async def test_invalid_policy_action(
    aiohttp_server: AiohttpServer, target_server: TestServer
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(target_server.make_url("/target"))

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    async def policy(
        response: aiohttp.ClientResponse, location: str, url: URL, method: str
    ) -> RedirectPolicyAction:
        return "maybe"  # type: ignore[return-value]

    async with aiohttp.ClientSession(redirect_policy=policy) as session:
        with pytest.raises(ValueError, match="Invalid redirect policy action"):
            await session.get(server.make_url("/redirect"))


async def test_policy_not_called_when_redirects_disabled(
    aiohttp_server: AiohttpServer, target_server: TestServer
) -> None:
    async def redirect(request: web.Request) -> NoReturn:
        raise web.HTTPFound(target_server.make_url("/target"))

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    policy = mock.AsyncMock(return_value=RedirectPolicyAction.ALLOW)
    async with aiohttp.ClientSession(redirect_policy=policy) as session:
        async with session.get(
            server.make_url("/redirect"), allow_redirects=False
        ) as resp:
            assert resp.status == 302
            await resp.read()

    policy.assert_not_called()


async def test_policy_not_called_without_location(
    aiohttp_server: AiohttpServer,
) -> None:
    async def redirect(request: web.Request) -> web.Response:
        return web.Response(status=302, text="no location")

    app = web.Application()
    app.router.add_get("/redirect", redirect)
    server = await aiohttp_server(app)

    policy = mock.AsyncMock(return_value=RedirectPolicyAction.ALLOW)
    async with aiohttp.ClientSession(redirect_policy=policy) as session:
        async with session.get(server.make_url("/redirect")) as resp:
            assert resp.status == 302
            assert await resp.text() == "no location"

    policy.assert_not_called()
