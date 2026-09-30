from __future__ import annotations

import asyncio
from urllib.parse import urlencode

import pytest
from hypercorn.typing import HTTPScope
from werkzeug.datastructures import Headers
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.exceptions import RequestTimeout

from quart.testing import no_op_push
from quart.wrappers.base import ClientDisconnectedError
from quart.wrappers.request import Body
from quart.wrappers.request import JSONSeqError
from quart.wrappers.request import Request


async def _fill_body(body: Body, semaphore: asyncio.Semaphore, limit: int) -> None:
    for number in range(limit):
        await body.put(b"%d" % number)
        await semaphore.acquire()
    body.set_complete()


async def test_full_body() -> None:
    body = Body(None, None)
    limit = 3
    semaphore = asyncio.Semaphore(limit)
    asyncio.ensure_future(_fill_body(body, semaphore, limit))
    assert b"012" == await body


async def test_body_streaming() -> None:
    body = Body(None, None)
    limit = 3
    semaphore = asyncio.Semaphore(0)
    asyncio.ensure_future(_fill_body(body, semaphore, limit))
    index = 0
    result = []
    async for data in body:
        semaphore.release()
        result.append(data)
        index += 1
    assert result == [b"0", b"1", b"2", b""]
    assert b"" == await body


async def test_body_stream_single_chunk() -> None:
    body = Body(None, None)
    body.set_result(b"data")

    async def _check_data() -> None:
        async for data in body:
            assert data == b"data"

    await asyncio.wait_for(_check_data(), 1)


async def test_body_streaming_no_data() -> None:
    body = Body(None, None)
    semaphore = asyncio.Semaphore(0)
    asyncio.ensure_future(_fill_body(body, semaphore, 0))
    async for data in body:
        assert data == b""
    assert b"" == await body


async def test_body_exceeds_max_content_length() -> None:
    max_content_length = 5
    body = Body(None, max_content_length)
    semaphore = asyncio.Semaphore(max_content_length + 1)
    asyncio.ensure_future(_fill_body(body, semaphore, max_content_length + 1))
    with pytest.raises(RequestEntityTooLarge):
        await body


async def test_request_exceeds_max_content_length(http_scope: HTTPScope) -> None:
    max_content_length = 5
    headers = Headers()
    headers["Content-Length"] = str(max_content_length + 1)
    request = Request(
        "POST",
        "http",
        "/",
        b"",
        headers,
        "",
        "1.1",
        http_scope,
        max_content_length=max_content_length,
        send_push_promise=no_op_push,
    )
    with pytest.raises(RequestEntityTooLarge):
        await request.get_data()


async def test_request_get_data_timeout(http_scope: HTTPScope) -> None:
    request = Request(
        "POST",
        "http",
        "/",
        b"",
        Headers(),
        "",
        "1.1",
        http_scope,
        body_timeout=1,
        send_push_promise=no_op_push,
    )
    with pytest.raises(RequestTimeout):
        await request.get_data()


@pytest.mark.parametrize(
    "method, expected",
    [("GET", ["b", "c"]), ("POST", ["b", "c", "d"])],
)
async def test_request_values(
    method: str, expected: list[str], http_scope: HTTPScope
) -> None:
    request = Request(
        method,
        "http",
        "/",
        b"a=b&a=c",
        Headers(
            {"host": "quart.com", "Content-Type": "application/x-www-form-urlencoded"}
        ),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    request.body.set_result(urlencode({"a": "d"}).encode())
    assert (await request.values).getlist("a") == expected


async def test_request_send_push_promise(http_scope: HTTPScope) -> None:
    push_promise: tuple[str, Headers] = None

    async def _push(path: str, headers: Headers) -> None:
        nonlocal push_promise
        push_promise = (path, headers)

    request = Request(
        "GET",
        "http",
        "/",
        b"a=b&a=c",
        Headers(
            {
                "host": "quart.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Accept-Encoding": "gzip",
                "User-Agent": "quart",
            }
        ),
        "",
        "2",
        http_scope,
        send_push_promise=_push,
    )
    await request.send_push_promise("/")
    assert push_promise[0] == "/"
    valid_headers = {"Accept": "*/*", "Accept-Encoding": "gzip", "User-Agent": "quart"}
    assert len(push_promise[1]) == len(valid_headers)
    for name, value in valid_headers.items():
        assert push_promise[1][name] == value


def _json_seq_request(http_scope: HTTPScope) -> Request:
    return Request(
        "POST",
        "http",
        "/",
        b"",
        Headers({"Content-Type": "application/json-seq"}),
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )


# A JSON text sequence (RFC 7464) containing a valid multi-line record
# (with string escapes and multi-byte UTF-8), an empty record, an
# invalid record, and a final valid record.
JSON_SEQ_PAYLOAD = (
    b'\x1e{"name": "first",\n"tags": [1,\n2, 3], '
    b'"esc": "\\u00e9\\n", "char": "\xc3\xa9"}\n'
    b"\x1e\x1e"  # Empty record, ignored
    b'\x1e{"broken": \n'  # Invalid JSON record
    b'\x1e{"name": "second", "ok": true}\n'
)
JSON_SEQ_FIRST = {
    "name": "first",
    "tags": [1, 2, 3],
    "esc": "\u00e9\n",
    "char": "\u00e9",
}
JSON_SEQ_SECOND = {"name": "second", "ok": True}


async def _feed_json_seq(request: Request, chunk_size: int = 7) -> None:
    for index in range(0, len(JSON_SEQ_PAYLOAD), chunk_size):
        await request.body.put(JSON_SEQ_PAYLOAD[index : index + chunk_size])
    request.body.set_complete()


async def test_iter_json_seq_raise(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    await _feed_json_seq(request)
    values = []
    with pytest.raises(JSONSeqError) as exc_info:
        async for value in request.iter_json_seq():
            values.append(value)
    assert values == [JSON_SEQ_FIRST]
    assert isinstance(exc_info.value, BadRequest)
    assert exc_info.value.offset == JSON_SEQ_PAYLOAD.index(b'\x1e{"broken"')


async def test_iter_json_seq_skip(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    await _feed_json_seq(request)
    values = [value async for value in request.iter_json_seq(on_error="skip")]
    assert values == [JSON_SEQ_FIRST, JSON_SEQ_SECOND]
    assert len(request.json_seq_errors) == 1
    error = request.json_seq_errors[0]
    assert error.offset == JSON_SEQ_PAYLOAD.index(b'\x1e{"broken"')
    assert "not valid JSON" in error.description


@pytest.mark.parametrize("chunk_size", [1, 3, 7, 64, 1024])
async def test_iter_json_seq_chunking(chunk_size: int, http_scope: HTTPScope) -> None:
    # Records, UTF-8 sequences, and escapes are split across chunks.
    request = _json_seq_request(http_scope)
    await _feed_json_seq(request, chunk_size)
    values = [value async for value in request.iter_json_seq(on_error="skip")]
    assert values == [JSON_SEQ_FIRST, JSON_SEQ_SECOND]
    assert len(request.json_seq_errors) == 1


async def test_iter_json_seq_truncated_final_record(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'\x1e{"a": 1}\n\x1e{"trunc')
    values = []
    with pytest.raises(JSONSeqError, match="truncated"):
        async for value in request.iter_json_seq():
            values.append(value)
    assert values == [{"a": 1}]


async def test_iter_json_seq_truncated_final_record_skip(
    http_scope: HTTPScope,
) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'\x1e{"a": 1}\n\x1e{"trunc')
    values = [value async for value in request.iter_json_seq(on_error="skip")]
    assert values == [{"a": 1}]
    assert len(request.json_seq_errors) == 1
    assert "truncated" in request.json_seq_errors[0].description


async def test_iter_json_seq_max_record_size(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'\x1e{"a": 12345}\n\x1e{"b": 2}\n')
    with pytest.raises(JSONSeqError, match="maximum size"):
        async for _ in request.iter_json_seq(max_record_size=10):
            pass


async def test_iter_json_seq_max_record_size_skip(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'\x1e{"a": 12345}\n\x1e{"b": 2}\n')
    values = [
        value
        async for value in request.iter_json_seq(max_record_size=10, on_error="skip")
    ]
    assert values == [{"b": 2}]
    assert len(request.json_seq_errors) == 1
    assert "maximum size" in request.json_seq_errors[0].description


async def test_iter_json_seq_data_before_first_separator(
    http_scope: HTTPScope,
) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'garbage\x1e{"a": 1}\n')
    values = [value async for value in request.iter_json_seq(on_error="skip")]
    assert values == [{"a": 1}]
    assert len(request.json_seq_errors) == 1
    assert request.json_seq_errors[0].offset == 0


async def test_iter_json_seq_backpressure_and_disconnect(
    http_scope: HTTPScope,
) -> None:
    request = _json_seq_request(http_scope)
    await request.body.put(b'\x1e{"a": 1}\n\x1e{"b": 2}\n')
    iterator = request.iter_json_seq()
    assert await iterator.__anext__() == {"a": 1}
    # The iterator waits for more data rather than reading ahead.
    task = asyncio.ensure_future(iterator.__anext__())
    await asyncio.sleep(0.05)
    assert not task.done()
    await request.body.put(b'\x1e{"c": 3}\n')
    assert await task == {"b": 2}
    # A disconnect promptly ends the wait.
    request.body.disconnect()
    with pytest.raises(ClientDisconnectedError):
        await iterator.__anext__()


async def test_iter_json_seq_after_get_data(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'\x1e{"a": 1}\n')
    await request.get_data()
    with pytest.raises(RuntimeError, match="already been consumed"):
        request.iter_json_seq()


async def test_iter_json_seq_invalid_on_error(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    with pytest.raises(ValueError, match="on_error"):
        request.iter_json_seq(on_error="invalid")  # type: ignore[arg-type]


async def test_get_data_after_partial_iter_json_seq(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    await request.body.put(b'\x1e{"a": 1}\n\x1e')
    await request.body.put(b'{"b": 2}\n')
    request.body.set_complete()
    iterator = request.iter_json_seq()
    assert await iterator.__anext__() == {"a": 1}
    await iterator.aclose()
    # Stopping the iteration leaves the unread body data available.
    assert await request.get_data() == b'{"b": 2}\n'


async def test_get_data_get_json_after_iter_json_seq(http_scope: HTTPScope) -> None:
    request = _json_seq_request(http_scope)
    request.body.set_result(b'\x1e{"a": 1}\n')
    assert [value async for value in request.iter_json_seq()] == [{"a": 1}]
    # The stream is consumed, so no data remains and JSON parsing fails.
    assert await request.get_data() == b""
    with pytest.raises(BadRequest):
        await request.get_json(force=True)
