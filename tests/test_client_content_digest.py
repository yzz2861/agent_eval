from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
from unittest import mock

import pytest
from multidict import CIMultiDict
from yarl import URL

import aiohttp
from aiohttp.content_digest import ContentDigestError
from aiohttp import http
from aiohttp.abc import AbstractStreamWriter
from aiohttp.client_proto import ResponseHandler
from aiohttp.client_reqrep import ClientResponse
from aiohttp.helpers import TimerNoop


def content_digest_header(
    data: bytes, *algorithms: str
) -> bytes:
    algorithms = algorithms or ("sha-256",)
    lines = []
    for algorithm in algorithms:
        content_hash = hashlib.new(algorithm.replace("sha-", "sha"))
        content_hash.update(data)
        value = base64.b64encode(content_hash.digest())
        lines.append(algorithm.encode() + b"=:" + value + b":")
    return b", ".join(lines)


async def start_response(
    body: bytes,
    *,
    coded: bytes | None = None,
    digest_value: bytes | None = None,
    chunked: bool = False,
    truncated: bool = False,
    policy: aiohttp.ContentDigestVerification | None = (
        aiohttp.ContentDigestVerification.IF_PRESENT
    ),
) -> tuple[ResponseHandler, ClientResponse]:
    loop = asyncio.get_running_loop()
    protocol = ResponseHandler(loop)
    protocol.connection_made(mock.Mock())
    protocol.set_response_params(content_digest_policy=policy)

    coded_body = coded if coded is not None else body
    headers = b""
    if coded is not None:
        headers += b"Content-Encoding: gzip\r\n"
    if digest_value is not None:
        headers += b"Content-Digest: " + digest_value + b"\r\n"
    if chunked:
        headers += b"Transfer-Encoding: chunked\r\n\r\n"
        headers += b"%x\r\n%b\r\n" % (len(coded_body), coded_body)
        if not truncated:
            headers += b"0\r\n\r\n"
    else:
        headers += b"Content-Length: %d\r\n\r\n%b" % (
            len(coded_body),
            coded_body,
        )
        if truncated:
            headers = headers[: -max(1, len(coded_body) // 2)]

    protocol.data_received(b"HTTP/1.1 200 OK\r\n" + headers)
    connection = mock.Mock(protocol=protocol)
    response = ClientResponse(
        "GET",
        URL("http://example.test/"),
        writer=mock.Mock(),
        continue100=None,
        timer=TimerNoop(),
        traces=[],
        loop=loop,
        session=None,
        request_headers=CIMultiDict[str](),
        original_url=URL("http://example.test/"),
        stream_writer=mock.create_autospec(
            AbstractStreamWriter, spec_set=True, instance=True
        ),
    )

    await response.start(connection)
    return protocol, response


@pytest.mark.parametrize("algorithm", ("sha-256", "sha-512"))
async def test_verifies_content_digest(algorithm: str) -> None:
    body = b"content digest payload"
    _protocol, resp = await start_response(
        body,
        digest_value=content_digest_header(body, algorithm),
    )
    assert await resp.read() == body
    assert resp.content_digest_verified


async def test_verifies_multiple_algorithms() -> None:
    body = b"multiple algorithms"
    _protocol, resp = await start_response(
        body,
        digest_value=content_digest_header(body, "sha-256", "sha-512"),
    )
    assert await resp.read() == body
    assert resp.content_digest_verified


async def test_digest_covers_coded_bytes() -> None:
    plain = b"uncompressed content" * 16
    coded = gzip.compress(plain)
    _protocol, resp = await start_response(
        plain,
        coded=coded,
        digest_value=content_digest_header(coded),
    )
    chunks = [chunk async for chunk in resp.content.iter_any()]
    assert b"".join(chunks) == plain
    assert resp.content_digest_verified


async def test_verified_only_after_stream_fully_read() -> None:
    body = b"streaming verification"
    _protocol, resp = await start_response(
        body,
        digest_value=content_digest_header(body),
    )
    collected = b""
    async for chunk in resp.content.iter_chunked(4):
        collected += chunk
        assert not resp.content_digest_verified
    assert collected == body
    assert resp.content_digest_verified


async def test_early_close_does_not_mark_verified() -> None:
    body = b"early close verification"
    _protocol, resp = await start_response(
        body, digest_value=content_digest_header(body)
    )
    partial = await resp.content.read(4)
    assert partial == body[:4]
    resp.close()
    assert not resp.content_digest_verified


async def test_empty_body_digest_verifies() -> None:
    _protocol, resp = await start_response(
        b"",
        digest_value=content_digest_header(b""),
    )
    assert await resp.read() == b""
    assert resp.content_digest_verified


async def test_mismatch_prevents_connection_reuse() -> None:
    body = b"actual response"
    protocol, resp = await start_response(
        body,
        digest_value=content_digest_header(b"different"),
    )
    with pytest.raises(ContentDigestError):
        await resp.read()
    assert not resp.content_digest_verified
    assert protocol.should_close


@pytest.mark.parametrize(
    "header",
    (
        b"",
        b"foo=:YmFy:",
        b"sha-256=:not-base64:",
        b"sha-256=:" + base64.b64encode(b"short") + b":",
    ),
)
async def test_required_policy_rejects_missing_malformed_and_unsupported(
    header: bytes,
) -> None:
    body = b"body"
    protocol, resp = await start_response(
        body,
        digest_value=header if header else None,
        policy=aiohttp.ContentDigestVerification.REQUIRED,
    )
    with pytest.raises(ContentDigestError):
        await resp.read()
    assert protocol.should_close


async def test_optional_policy_ignores_unsupported_algorithm() -> None:
    body = b"optional unsupported"
    _protocol, resp = await start_response(body, digest_value=b"foo=:YmFy:")
    assert await resp.read() == body
    assert not resp.content_digest_verified


async def test_chunked_truncation_fails() -> None:
    body = b"truncated chunked payload"
    protocol, resp = await start_response(
        body,
        digest_value=content_digest_header(body),
        chunked=True,
        truncated=True,
    )
    protocol.connection_lost(None)
    with pytest.raises(aiohttp.ClientError):
        await resp.read()
    assert protocol.should_close


async def test_compressed_mismatch_fails_at_stream_end() -> None:
    body = b"compressed mismatch" * 8
    coded = gzip.compress(body)
    protocol, resp = await start_response(
        body,
        coded=coded,
        digest_value=content_digest_header(coded + b"x"),
    )
    with pytest.raises(ContentDigestError):
        await resp.read()
    assert protocol.should_close
