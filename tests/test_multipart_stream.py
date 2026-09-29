import unicodedata

from collections.abc import AsyncIterator

import pytest

from sanic.exceptions import BadRequest
from sanic.request import MultipartStream
from sanic.response import json


# Boundaries are nested prefixes of each other on purpose: PARENT-NEST-2
# extends PARENT-NEST which extends PARENT, so a delimiter of one level is
# a lookalike prefix of the delimiters of the deeper levels.
BIG_SIZE = 512 * 1024


def build_body() -> bytes:
    tricky = (
        b"\r\n--PARENT-NEST\r\nnot a parent delimiter\r\n"
        b"--PARENTXX--\r\n"
        b"\r\n--PARENT"  # lookalike, followed by non-delimiter bytes
    )
    big = tricky + b"B" * BIG_SIZE + b"\r\n--PARENTISH--\r\nmore"

    level2 = (
        b"--PARENT-NEST-2\r\n"
        b'Content-Disposition: form-data; name="file"; '
        b'filename="r\xc3\xa9sum\xc3\xa9.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"first file"
        b"\r\n"
        b"--PARENT-NEST-2\r\n"
        b'Content-Disposition: form-data; name="file"; '
        b"filename*=utf-8''%E6%8A%A5%E5%91%8A.txt\r\n"
        b"\r\n"
        b"second file"
        b"\r\n"
        b"--PARENT-NEST-2--"
    )
    nfd_filename = unicodedata.normalize("NFD", "caf\u00e9.txt").encode(
        "utf-8"
    )
    level1 = (
        b"--PARENT-NEST\r\n"
        b'Content-Disposition: form-data; name="note"\r\n'
        b"\r\n" + "\u7b2c\u4e00\u5c42".encode("utf-8") + b"\r\n"
        b"--PARENT-NEST\r\n"
        b'Content-Disposition: form-data; name="nfd"; filename="'
        + nfd_filename
        + b'"\r\n'
        b"\r\n"
        b"nfd body"
        b"\r\n"
        b"--PARENT-NEST\r\n"
        b'Content-Disposition: form-data; name="inner"\r\n'
        b"Content-Type: multipart/mixed; boundary=PARENT-NEST-2\r\n"
        b"\r\n" + level2 + b"\r\n"
        b"--PARENT-NEST--"
    )
    return (
        b"--PARENT\r\n"
        b'Content-Disposition: form-data; name="title"\r\n'
        b"\r\n"
        b"hello world"
        b"\r\n"
        b"--PARENT\r\n"
        b'Content-Disposition: form-data; name="big"; filename="big.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n" + big + b"\r\n"
        b"--PARENT\r\n"
        b'Content-Disposition: form-data; name="pack"\r\n'
        b"Content-Type: multipart/mixed; boundary=PARENT-NEST\r\n"
        b"\r\n" + level1 + b"\r\n"
        b"--PARENT\r\n"
        b'Content-Disposition: form-data; name="tail"\r\n'
        b"\r\n"
        b"after"
        b"\r\n"
        b"--PARENT--\r\n"
    )


async def chunk_source(data: bytes, size: int) -> AsyncIterator[bytes]:
    for pos in range(0, len(data), size):
        yield data[pos : pos + size]


async def traverse(stream: MultipartStream, events: list) -> None:
    async for part in stream:
        if part.is_container:
            await traverse(part.children(), events)
        elif part.name == "big":
            # Skip the large part without reading a single byte of it.
            events.append((part.full_name, part.filename, part.index, None))
        else:
            body = await part.read()
            events.append((part.full_name, part.filename, part.index, body))


EXPECTED_EVENTS = [
    ("title", None, 0, b"hello world"),
    ("big", "big.bin", 1, None),
    ("pack.note", None, 0, "\u7b2c\u4e00\u5c42".encode("utf-8")),
    ("pack.nfd", "caf\u00e9.txt", 1, b"nfd body"),
    ("pack.inner.file", "r\u00e9sum\u00e9.txt", 0, b"first file"),
    ("pack.inner.file", "\u62a5\u544a.txt", 1, b"second file"),
    ("tail", None, 3, b"after"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("chunk_size", [13, 4096, 10_000_000])
async def test_nested_traversal(chunk_size):
    body = build_body()
    stream = MultipartStream(chunk_source(body, chunk_size), b"PARENT")
    events: list = []
    await traverse(stream, events)
    assert events == EXPECTED_EVENTS


@pytest.mark.asyncio
async def test_partial_read_then_skip():
    body = build_body()
    stream = MultipartStream(chunk_source(body, 4096), b"PARENT")
    part = await stream.__anext__()
    assert part.name == "title"
    assert await part.text() == "hello world"

    big = await stream.__anext__()
    assert big.name == "big"
    chunks = big.stream()
    first = await chunks.__anext__()
    assert first  # read only the first chunk, abandon the rest

    pack = await stream.__anext__()
    assert pack.is_container
    assert pack.full_name == "pack"
    await stream.aclose()


@pytest.mark.asyncio
async def test_close_stops_consuming_request():
    body = build_body()
    pulled = 0

    async def counting_source() -> AsyncIterator[bytes]:
        nonlocal pulled
        for pos in range(0, len(body), 4096):
            pulled += 1
            yield body[pos : pos + 4096]

    stream = MultipartStream(counting_source(), b"PARENT")
    part = await stream.__anext__()
    assert part.name == "title"
    await stream.aclose()
    pulled_at_close = pulled
    with pytest.raises(StopAsyncIteration):
        await stream.__anext__()
    assert pulled == pulled_at_close
    assert pulled * 4096 < len(body)


@pytest.mark.asyncio
async def test_max_headers_size():
    body = (
        b"--PARENT\r\n"
        b'Content-Disposition: form-data; name="x"\r\n'
        b"X-Pad: " + b"y" * 10000 + b"\r\n"
        b"\r\n"
        b"v\r\n"
        b"--PARENT--\r\n"
    )
    stream = MultipartStream(
        chunk_source(body, 4096), b"PARENT", max_headers_size=1024
    )
    with pytest.raises(BadRequest, match="headers exceed"):
        async for _ in stream:
            pass


@pytest.mark.asyncio
async def test_max_depth():
    body = build_body()
    stream = MultipartStream(chunk_source(body, 4096), b"PARENT", max_depth=1)
    async for part in stream:
        if not part.is_container:
            continue
        async for child in part.children():
            if child.is_container:
                with pytest.raises(BadRequest, match="nesting depth"):
                    child.children()
            else:
                await child.read()


@pytest.mark.asyncio
async def test_part_no_longer_readable():
    body = build_body()
    stream = MultipartStream(chunk_source(body, 4096), b"PARENT")
    first = await stream.__anext__()
    await stream.__anext__()
    with pytest.raises(BadRequest, match="no longer readable"):
        await first.read()


@pytest.mark.asyncio
async def test_multipart_stream_endpoint(app):
    body = build_body()

    @app.post("/upload", stream=True)
    async def upload(request):
        events: list = []
        async with request.multipart_stream() as stream:
            await traverse(stream, events)
        return json(
            {
                "events": [
                    [
                        name,
                        filename,
                        index,
                        None if data is None else len(data),
                    ]
                    for name, filename, index, data in events
                ]
            }
        )

    _, response = await app.asgi_client.post(
        "/upload",
        data=body,
        headers={"content-type": "multipart/form-data; boundary=PARENT"},
    )
    assert response.status == 200
    expected = [
        [name, filename, index, None if data is None else len(data)]
        for name, filename, index, data in EXPECTED_EVENTS
    ]
    assert response.json["events"] == expected


@pytest.mark.asyncio
async def test_multipart_stream_endpoint_buffered(app):
    body = build_body()

    @app.post("/upload", stream=False)
    async def upload(request):
        events: list = []
        async with request.multipart_stream() as stream:
            await traverse(stream, events)
        return json({"count": len(events)})

    _, response = await app.asgi_client.post(
        "/upload",
        data=body,
        headers={"content-type": "multipart/form-data; boundary=PARENT"},
    )
    assert response.status == 200
    assert response.json["count"] == len(EXPECTED_EVENTS)


@pytest.mark.asyncio
async def test_multipart_stream_rejects_non_multipart(app):
    @app.post("/plain")
    async def plain(request):
        request.multipart_stream()
        return json({"ok": True})

    _, response = await app.asgi_client.post("/plain", data="a=1")
    assert response.status == 400
