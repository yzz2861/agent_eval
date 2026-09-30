from __future__ import annotations

import asyncio

import pytest
from hypercorn.typing import HTTPScope
from werkzeug.datastructures import Headers
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import UnsupportedMediaType

from quart import Quart
from quart import request
from quart.json_seq import iter_json_seq
from quart.json_seq import JSONSeqDecodeError
from quart.json_seq import JSONSeqRecordTooLargeError
from quart.json_seq import JSONSeqTruncatedError
from quart.testing import no_op_push
from quart.wrappers.base import ClientDisconnectedError
from quart.wrappers.request import Request

RS = b"\x1e"

# A valid JSON text spanning multiple lines, containing a multi-byte
# UTF-8 character and escaped control characters (\u001e and \n).
RECORD_0_TEXT = '{\n  "name": "咖啡店",\n  "esc": "a\\u001eb\\nc",\n  "n": 1\n}'
RECORD_0 = RECORD_0_TEXT.encode("utf-8")
RECORD_0_VALUE = {"name": "咖啡店", "esc": "a\x1eb\nc", "n": 1}
BAD_RECORD = b'{"broken": tru}'
GOOD_RECORD = b'{"n": 2}'
TAIL_RECORD = '{"tail": "未完'.encode()

# A stream holding a valid multi-line record, an empty record, a bad
# record, a good record and a truncated final record.
PAYLOAD = b"".join(
    [
        RS,
        RECORD_0,
        b"\n",
        RS,
        b"\n",
        RS,
        BAD_RECORD,
        b"\n",
        RS,
        GOOD_RECORD,
        b"\n",
        RS,
        TAIL_RECORD,
    ]
)


def _demo_chunks() -> list[bytes]:
    """Split the payload at awkward points (mid UTF-8, mid escape)."""
    points = [
        PAYLOAD.index("咖".encode()) + 1,  # inside a multi-byte character
        PAYLOAD.index(b"\\u001e") + 3,  # inside the \u001e escape
        PAYLOAD.index(BAD_RECORD) + 5,  # inside the bad record
        PAYLOAD.index("未".encode()) + 2,  # inside a multi-byte character
    ]
    chunks = []
    start = 0
    for point in points:
        chunks.append(PAYLOAD[start:point])
        start = point
    chunks.append(PAYLOAD[start:])
    return chunks


async def _make_request(
    http_scope: HTTPScope,
    chunks: list[bytes] | None = None,
    content_type: str | None = "application/json-seq",
) -> Request:
    headers = Headers()
    if content_type is not None:
        headers["Content-Type"] = content_type
    request_ = Request(
        "POST",
        "http",
        "/",
        b"",
        headers,
        "",
        "1.1",
        http_scope,
        send_push_promise=no_op_push,
    )
    if chunks is not None:
        for chunk in chunks:
            await request_.body.put(chunk)
        request_.body.set_complete()
    return request_


async def test_abort_strategy(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, _demo_chunks())
    values = []
    with pytest.raises(JSONSeqDecodeError) as exc_info:
        async for value in iter_json_seq(request_):
            values.append(value)
    assert values == [RECORD_0_VALUE]
    error = exc_info.value
    assert error.record_index == 2
    assert error.byte_offset == PAYLOAD.index(BAD_RECORD)


async def test_skip_strategy(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, _demo_chunks())
    errors = []
    values = []
    async for value in iter_json_seq(
        request_, on_error="skip", on_record_error=errors.append
    ):
        values.append(value)
    assert values == [RECORD_0_VALUE, {"n": 2}]
    assert [type(error) for error in errors] == [
        JSONSeqDecodeError,
        JSONSeqTruncatedError,
    ]
    assert [error.record_index for error in errors] == [2, 4]
    assert [error.byte_offset for error in errors] == [
        PAYLOAD.index(BAD_RECORD),
        PAYLOAD.index(TAIL_RECORD),
    ]


async def test_record_too_large_aborts(http_scope: HTTPScope) -> None:
    payload = RS + b'{"a": 123456}' + b"\n" + RS + b'{"b": 2}' + b"\n"
    request_ = await _make_request(http_scope, [payload])
    with pytest.raises(JSONSeqRecordTooLargeError) as exc_info:
        async for _ in iter_json_seq(request_, max_record_bytes=10):
            pass
    assert exc_info.value.record_index == 0


async def test_record_too_large_skips(http_scope: HTTPScope) -> None:
    payload = RS + b'{"a": 123456}' + b"\n" + RS + b'{"b": 2}' + b"\n"
    request_ = await _make_request(http_scope, [payload])
    errors = []
    values = []
    async for value in iter_json_seq(
        request_,
        max_record_bytes=10,
        on_error="skip",
        on_record_error=errors.append,
    ):
        values.append(value)
    assert values == [{"b": 2}]
    assert len(errors) == 1
    assert isinstance(errors[0], JSONSeqRecordTooLargeError)
    assert errors[0].record_index == 0


async def test_truncated_final_record_aborts(http_scope: HTTPScope) -> None:
    payload = RS + b'{"a": 1}\n' + RS + b'{"trunc'
    request_ = await _make_request(http_scope, [payload])
    values = []
    with pytest.raises(JSONSeqTruncatedError) as exc_info:
        async for value in iter_json_seq(request_):
            values.append(value)
    assert values == [{"a": 1}]
    assert exc_info.value.record_index == 1


async def test_junk_before_first_separator(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, [b"garbage" + RS + b'{"a": 1}\n'])
    with pytest.raises(JSONSeqDecodeError) as exc_info:
        async for _ in iter_json_seq(request_):
            pass
    assert exc_info.value.byte_offset == 0


async def test_junk_before_first_separator_skipped(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, [b"garbage" + RS + b'{"a": 1}\n'])
    errors = []
    values = []
    async for value in iter_json_seq(
        request_, on_error="skip", on_record_error=errors.append
    ):
        values.append(value)
    assert values == [{"a": 1}]
    assert len(errors) == 1


async def test_empty_body(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, [])
    assert [value async for value in iter_json_seq(request_)] == []


async def test_disconnect(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope)
    await request_.body.put(RS + b'{"a": 1}\n')
    iterator = iter_json_seq(request_)
    task = asyncio.ensure_future(anext(iterator))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    request_.body.disconnect()
    with pytest.raises(ClientDisconnectedError):
        await task


async def test_closing_leaves_body_unread(http_scope: HTTPScope) -> None:
    chunk1 = RS + b'{"a": 1}\n' + RS
    chunk2 = b'{"b": 2}\n'
    request_ = await _make_request(http_scope, [chunk1, chunk2])
    iterator = iter_json_seq(request_)
    assert await anext(iterator) == {"a": 1}
    await iterator.aclose()
    # The iterator must not have drained the rest of the request body.
    assert await request_.get_data() == chunk2


async def test_get_data_before_iteration(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, [PAYLOAD])
    assert await request_.get_data() == PAYLOAD
    # The stream is already consumed, nothing is left to iterate over.
    assert [value async for value in iter_json_seq(request_)] == []


async def test_get_data_after_iteration(http_scope: HTTPScope) -> None:
    request_ = await _make_request(http_scope, [PAYLOAD])
    errors = []
    values = []
    async for value in iter_json_seq(
        request_, on_error="skip", on_record_error=errors.append
    ):
        values.append(value)
    assert values == [RECORD_0_VALUE, {"n": 2}]
    # The stream has been consumed, only unconsumed bytes remain.
    assert await request_.get_data() == b""
    # application/json-seq is not a JSON mimetype.
    assert await request_.get_json() is None
    with pytest.raises(BadRequest):
        await request_.get_json(force=True)


async def test_content_type_required(http_scope: HTTPScope) -> None:
    request_ = await _make_request(
        http_scope, [PAYLOAD], content_type="application/json"
    )
    with pytest.raises(UnsupportedMediaType):
        iter_json_seq(request_)


async def test_within_view() -> None:
    app = Quart(__name__)

    @app.post("/")
    async def index():
        errors = []
        values = []
        async for value in iter_json_seq(
            request, on_error="skip", on_record_error=errors.append
        ):
            values.append(value)
        return {
            "values": values,
            "errors": [
                {"index": error.record_index, "offset": error.byte_offset}
                for error in errors
            ],
        }

    client = app.test_client()
    response = await client.post(
        "/", data=PAYLOAD, headers={"Content-Type": "application/json-seq"}
    )
    assert response.status_code == 200
    result = await response.get_json()
    assert result["values"] == [RECORD_0_VALUE, {"n": 2}]
    assert [error["index"] for error in result["errors"]] == [2, 4]
