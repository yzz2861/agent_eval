import os

from collections import namedtuple
from email.parser import BytesParser
from email.utils import formatdate

import pytest

import sanic.handlers.content_range as content_range_module

from sanic.compat import Header
from sanic.exceptions import InvalidHeader, RangeNotSatisfiable
from sanic.handlers.content_range import (
    MAX_RANGES,
    ContentRangeHandler,
)
from sanic.response import file_stream


DATA = bytes(range(256))


@pytest.fixture
def range_file(tmp_path):
    path = tmp_path / "range.bin"
    path.write_bytes(DATA)
    return path


def range_handler(path, header, content_type="application/octet-stream"):
    request = type("Request", (), {"headers": Header(header)})()
    return ContentRangeHandler(
        request,
        os.stat(path),
        content_type=content_type,
    )


def parse_multipart(content_type, body):
    message = BytesParser().parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    )
    assert message.is_multipart()
    return message


def test_ranges_are_clamped_sorted_and_merged(range_file):
    handler = range_handler(
        range_file,
        {"Range": "bytes=200-299,10-14,0-4,20-24,5-9,12-19"},
    )

    assert handler.ranges == ((0, 24), (200, 255))
    assert handler.multipart
    assert handler.size == 81
    assert (
        int(handler.headers["Content-Length"])
        == len(DATA[:25]) + len(DATA[200:]) + handler.overhead
    )


@pytest.mark.asyncio
async def test_overlapping_and_adjacent_ranges_become_single_206(
    app, range_file
):
    app.static("/file", range_file, use_content_range=True)

    _, response = await app.asgi_client.get(
        "/file", headers={"Range": "bytes=10-14,0-4,3-9,14-20"}
    )

    assert response.status == 206
    assert response.headers["Content-Range"] == f"bytes 0-20/{len(DATA)}"
    assert response.body == DATA[:21]


@pytest.mark.asyncio
async def test_multipart_response_matches_original_bytes(app, range_file):
    app.static("/file", range_file, use_content_range=True)

    _, response = await app.asgi_client.get(
        "/file",
        headers={"Range": "bytes=0-9,20-29,250-"},
    )

    assert response.status == 206
    content_type = response.headers["Content-Type"]
    assert content_type.startswith("multipart/byteranges; boundary=")
    assert int(response.headers["Content-Length"]) == len(response.content)

    message = parse_multipart(content_type, response.content)
    expected_ranges = ((0, 9), (20, 29), (250, 255))
    parts = list(message.walk())[1:]

    assert len(parts) == len(expected_ranges)
    for part, (start, end) in zip(parts, expected_ranges):
        assert part.get_content_type() == "application/octet-stream"
        assert part["Content-Range"] == (f"bytes {start}-{end}/{len(DATA)}")
        payload = part.get_payload(decode=True)
        assert payload == DATA[start : end + 1]


@pytest.mark.asyncio
async def test_head_reports_exact_multipart_length(app, range_file):
    app.static("/file", range_file, use_content_range=True)

    _, head_response = await app.asgi_client.head(
        "/file", headers={"Range": "bytes=0-9,20-29"}
    )
    _, get_response = await app.asgi_client.get(
        "/file", headers={"Range": "bytes=0-9,20-29"}
    )

    assert head_response.status == 206
    assert head_response.content == b""
    assert head_response.headers["Content-Type"].startswith(
        "multipart/byteranges"
    )
    assert int(head_response.headers["Content-Length"]) == int(
        get_response.headers["Content-Length"]
    )


@pytest.mark.asyncio
async def test_suffix_and_out_of_bounds_ranges_are_clamped(app, range_file):
    app.static("/file", range_file, use_content_range=True)

    _, response = await app.asgi_client.get(
        "/file", headers={"Range": "bytes=-10,300-400,100-149"}
    )

    assert response.status == 206
    content_type = response.headers["Content-Type"]
    message = parse_multipart(content_type, response.content)
    parts = list(message.walk())[1:]
    expected_ranges = ((100, 149), (246, 255))

    assert [part["Content-Range"] for part in parts] == [
        f"bytes {start}-{end}/{len(DATA)}" for start, end in expected_ranges
    ]
    assert parts[0].get_payload(decode=True) == DATA[100:150]
    assert parts[1].get_payload(decode=True) == DATA[-10:]


@pytest.mark.asyncio
async def test_only_unsatisfiable_ranges_return_416(app, range_file):
    app.static("/file", range_file, use_content_range=True)

    _, response = await app.asgi_client.get(
        "/file", headers={"Range": "bytes=300-400,500-"}
    )

    assert response.status == 416
    assert response.headers["Content-Range"] == f"bytes */{len(DATA)}"


@pytest.mark.asyncio
async def test_range_count_limit_returns_400(app, range_file):
    app.static("/file", range_file, use_content_range=True)
    requested_range = ",".join(f"{i}-{i}" for i in range(MAX_RANGES + 1))

    _, response = await app.asgi_client.get(
        "/file", headers={"Range": f"bytes={requested_range}"}
    )

    assert response.status == 400


def test_invalid_ranges_still_return_416(range_file):
    with pytest.raises(RangeNotSatisfiable):
        range_handler(range_file, {"Range": "bytes=abc-10"})
    with pytest.raises(InvalidHeader):
        value = ",".join(["0-0"] * (MAX_RANGES + 1))
        range_handler(range_file, {"Range": f"bytes={value}"})


def test_multipart_overhead_limit(range_file, monkeypatch):
    monkeypatch.setattr(content_range_module, "MAX_MULTIPART_OVERHEAD", 1)
    with pytest.raises(InvalidHeader):
        range_handler(range_file, {"Range": "bytes=0-0,2-2"})


@pytest.mark.asyncio
async def test_if_range_etag_controls_range_semantics(app, range_file):
    app.static("/file", range_file, use_content_range=True)
    _, full_head = await app.asgi_client.head("/file")
    etag = full_head.headers["ETag"]

    _, partial = await app.asgi_client.get(
        "/file",
        headers={"Range": "bytes=0-9", "If-Range": etag},
    )
    _, complete = await app.asgi_client.get(
        "/file",
        headers={"Range": "bytes=0-9", "If-Range": '"stale"'},
    )

    assert partial.status == 206
    assert partial.body == DATA[:10]
    assert complete.status == 200
    assert complete.body == DATA


@pytest.mark.asyncio
async def test_if_range_last_modified_controls_range_semantics(
    app, range_file
):
    app.static("/file", range_file, use_content_range=True)
    _, full_head = await app.asgi_client.head("/file")
    last_modified = full_head.headers["Last-Modified"]

    _, partial = await app.asgi_client.get(
        "/file",
        headers={"Range": "bytes=0-9", "If-Range": last_modified},
    )
    _, complete = await app.asgi_client.get(
        "/file",
        headers={
            "Range": "bytes=0-9",
            "If-Range": formatdate(0, usegmt=True),
        },
    )

    assert partial.status == 206
    assert complete.status == 200


@pytest.mark.asyncio
async def test_empty_file_range_and_full_request(app, tmp_path):
    empty_file = tmp_path / "empty"
    empty_file.write_bytes(b"")
    app.static("/empty", empty_file, use_content_range=True)

    _, full = await app.asgi_client.get("/empty")
    _, unsatisfiable = await app.asgi_client.get(
        "/empty", headers={"Range": "bytes=0-0"}
    )

    assert full.status == 200
    assert full.content == b""
    assert int(full.headers["Content-Length"]) == 0
    assert unsatisfiable.status == 416
    assert unsatisfiable.headers["Content-Range"] == "bytes */0"


@pytest.mark.asyncio
async def test_stream_reads_file_in_bounded_chunks(range_file, monkeypatch):
    class Writer:
        def __init__(self):
            self.chunks = []

        async def send(self, data):
            self.chunks.append(data)

        async def write(self, data):
            await self.send(data)

    handler = range_handler(range_file, {"Range": "bytes=0-9,20-24"})
    response = await file_stream(
        range_file,
        chunk_size=3,
        headers=dict(handler.headers),
        mime_type="application/octet-stream",
        _range=handler,
    )
    writer = Writer()
    read_sizes = []
    seek_positions = []
    original_open_async = file_stream.__globals__["open_async"]

    class TrackedFile:
        def __init__(self, file):
            self.file = file

        async def seek(self, position):
            seek_positions.append(position)
            return await self.file.seek(position)

        async def read(self, size):
            read_sizes.append(size)
            return await self.file.read(size)

    class TrackedContext:
        def __init__(self, context_manager):
            self.context_manager = context_manager

        async def __aenter__(self):
            file = await self.context_manager.__aenter__()
            return TrackedFile(file)

        async def __aexit__(self, exc_type, exc, traceback):
            return await self.context_manager.__aexit__(
                exc_type, exc, traceback
            )

    async def tracked_open_async(*args, **kwargs):
        context_manager = await original_open_async(*args, **kwargs)
        return TrackedContext(context_manager)

    monkeypatch.setattr(
        "sanic.response.convenience.open_async", tracked_open_async
    )
    response.response = writer
    await response.streaming_fn(response)

    body = b"".join(writer.chunks)
    message = parse_multipart(handler.content_type, body)
    parts = list(message.walk())[1:]
    assert parts[0].get_payload(decode=True) == DATA[:10]
    assert parts[1].get_payload(decode=True) == DATA[20:25]
    assert len(body) == int(handler.headers["Content-Length"])

    assert seek_positions == [0, 20]
    assert read_sizes == [3, 3, 3, 1, 3, 2]


@pytest.mark.asyncio
async def test_single_range_stream_remains_plain_206(range_file):
    class Writer:
        def __init__(self):
            self.chunks = []

        async def send(self, data):
            self.chunks.append(data)

    single_range = namedtuple("Range", ["start", "end", "size", "total"])(
        2, 5, 4, len(DATA)
    )
    response = await file_stream(range_file, chunk_size=2, _range=single_range)
    response.response = Writer()
    await response.streaming_fn(response)

    assert response.status == 206
    assert response.headers["Content-Range"] == (f"bytes 2-5/{len(DATA)}")
    assert "multipart/byteranges" not in response.headers.get(
        "Content-Type", ""
    )
    assert b"".join(response.response.chunks) == DATA[2:6]
