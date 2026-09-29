import pytest

from sanic.request.multipart import MultipartError, MultipartReader
from sanic.response import json, text


PARENT = b"----parent"
CHILD = b"----child"

TWO_LEVEL_BODY = (
    b"------parent\r\n"
    b'Content-Disposition: form-data; name="title"\r\n'
    b"\r\n"
    b"Hello world\r\n"
    b"------parent\r\n"
    b'Content-Disposition: form-data; name="attachments"\r\n'
    b"Content-Type: multipart/mixed; boundary=----child\r\n"
    b"\r\n"
    b"------child\r\n"
    b'Content-Disposition: form-data; name="note"\r\n'
    b"\r\n"
    b"first note\r\n"
    b"------child\r\n"
    b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"AAAA\r\n"
    b"------child\r\n"
    b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"BBBB\r\n"
    b"------child\r\n"
    b"\r\n"
    b"no headers at all\r\n"
    b"------child--\r\n"
    b"------parent\r\n"
    b'Content-Disposition: form-data; name="tail"\r\n'
    b"\r\n"
    b"done\r\n"
    b"------parent--\r\n"
)


def split_chunks(body: bytes, size: int):
    return [body[i : i + size] for i in range(0, len(body), size)]


def make_source(chunks):
    async def source():
        for chunk in chunks:
            yield chunk

    return source()


async def traverse(reader):
    """Fully traverse a reader, returning (field_name, filename, body)
    tuples, descending into nested containers."""
    results = []
    async for part in reader:
        if part.is_multipart:
            async for sub in part.open():
                results.append(
                    (sub.field_name, sub.filename, await sub.read())
                )
        else:
            results.append((part.field_name, part.filename, await part.read()))
    return results


EXPECTED_TWO_LEVEL = [
    ("title", None, b"Hello world"),
    ("attachments[note]", None, b"first note"),
    ("attachments[file]", "a.txt", b"AAAA"),
    ("attachments[file]", "a.txt", b"BBBB"),
    ("attachments[3]", None, b"no headers at all"),
    ("tail", None, b"done"),
]


@pytest.mark.asyncio
async def test_two_level_container_traversal():
    reader = MultipartReader(make_source([TWO_LEVEL_BODY]), PARENT)
    assert await traverse(reader) == EXPECTED_TWO_LEVEL
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_hierarchy_metadata_is_traceable():
    reader = MultipartReader(make_source([TWO_LEVEL_BODY]), PARENT)
    await reader.next_part()  # title
    container = await reader.next_part()  # attachments
    assert container.is_multipart
    child = container.open()

    note = await child.next_part()
    assert note.path == ("attachments", "note")
    assert note.occurrence == 0

    first = await child.next_part()
    second = await child.next_part()
    # Duplicate filenames are both preserved and distinguishable
    assert first.filename == second.filename == "a.txt"
    assert first.index == 1 and second.index == 2
    assert first.occurrence == 0 and second.occurrence == 1
    assert first.path == ("attachments", "file")
    assert second.path == ("attachments", "file")
    await first.skip()
    await second.skip()

    unnamed = await child.next_part()
    assert unnamed.name is None
    assert unnamed.field_name == "attachments[3]"
    assert unnamed.path == ("attachments", 3)
    await unnamed.skip()

    assert await child.next_part() is None
    # The child's closing boundary must not terminate the parent
    tail = await reader.next_part()
    assert tail.name == "tail"
    assert await tail.read() == b"done"
    assert await reader.next_part() is None


@pytest.mark.asyncio
@pytest.mark.parametrize("chunk_size", [1, 2, 3, 5, 7, 64, 4096])
async def test_boundaries_and_headers_split_across_chunks(chunk_size):
    chunks = split_chunks(TWO_LEVEL_BODY, chunk_size)
    reader = MultipartReader(make_source(chunks), PARENT)
    assert await traverse(reader) == EXPECTED_TWO_LEVEL


@pytest.mark.asyncio
async def test_similar_boundaries_do_not_terminate_parent():
    body = (
        b"--sanic-boundary\r\n"
        b'Content-Disposition: form-data; name="box"\r\n'
        b"Content-Type: multipart/mixed; boundary=sanic-boundary-inner\r\n"
        b"\r\n"
        b"--sanic-boundary-inner\r\n"
        b'Content-Disposition: form-data; name="item"\r\n'
        b"\r\n"
        b"inner value\r\n"
        b"--sanic-boundary-inner--\r\n"
        b"--sanic-boundary\r\n"
        b'Content-Disposition: form-data; name="tricky"\r\n'
        b"\r\n"
        b"line1\r\n"
        b"--sanic-boundaries are fun\r\n"
        b"--sanic-boundary-inner\r\n"
        b"line2\r\n"
        b"--sanic-boundary--\r\n"
    )
    reader = MultipartReader(
        make_source(split_chunks(body, 3)), b"sanic-boundary"
    )

    box = await reader.next_part()
    assert box.is_multipart
    child = box.open()
    item = await child.next_part()
    assert item.field_name == "box[item]"
    assert await item.read() == b"inner value"
    assert await child.next_part() is None

    tricky = await reader.next_part()
    assert await tricky.read() == (
        b"line1\r\n"
        b"--sanic-boundaries are fun\r\n"
        b"--sanic-boundary-inner\r\n"
        b"line2"
    )
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_skip_large_part_only_drains_current_part():
    big = b"x" * 1_000_000
    body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="big"; filename="big.bin"\r\n'
        b"\r\n" + big + b"\r\n"
        b"--b\r\n"
        b'Content-Disposition: form-data; name="after"\r\n'
        b"\r\n"
        b"small\r\n"
        b"--b--\r\n"
    )
    reader = MultipartReader(make_source(split_chunks(body, 65536)), b"b")

    part = await reader.next_part()
    assert part.filename == "big.bin"
    # Read only the beginning, then move on: the rest is drained,
    # and only this part is consumed.
    stream = part.iter_chunks()
    first = await stream.__anext__()
    assert first
    after = await reader.next_part()
    assert after.name == "after"
    assert await after.read() == b"small"
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_explicit_skip_of_unread_part():
    big = b"y" * 500_000
    body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="big"\r\n'
        b"\r\n" + big + b"\r\n"
        b"--b\r\n"
        b'Content-Disposition: form-data; name="after"\r\n'
        b"\r\n"
        b"still here\r\n"
        b"--b--\r\n"
    )
    reader = MultipartReader(make_source(split_chunks(body, 32768)), b"b")
    part = await reader.next_part()
    await part.skip()
    after = await reader.next_part()
    assert await after.text() == "still here"
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_skip_container_part_drains_nested_reader():
    reader = MultipartReader(make_source([TWO_LEVEL_BODY]), PARENT)
    await reader.next_part()  # title
    container = await reader.next_part()
    child = container.open()
    note = await child.next_part()
    assert note.name == "note"
    # Skipping the parent part drains the rest of the nested container
    # and lands on the next parent-level part.
    await container.skip()
    tail = await reader.next_part()
    assert tail.name == "tail"
    assert await tail.read() == b"done"
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_close_stops_consuming_request():
    pulls = 0
    chunks = split_chunks(TWO_LEVEL_BODY, 100)

    async def source():
        nonlocal pulls
        for chunk in chunks:
            pulls += 1
            yield chunk

    reader = MultipartReader(source(), PARENT)
    part = await reader.next_part()
    assert await part.read() == b"Hello world"
    await reader.close()
    pulled_at_close = pulls
    assert await reader.next_part() is None
    assert pulls == pulled_at_close


@pytest.mark.asyncio
async def test_header_size_limit():
    body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="x"\r\n'
        b"X-Padding: " + b"p" * 5000 + b"\r\n"
        b"\r\n"
        b"v\r\n"
        b"--b--\r\n"
    )
    reader = MultipartReader(make_source([body]), b"b", max_header_size=1024)
    with pytest.raises(MultipartError, match="headers exceed"):
        await reader.next_part()


@pytest.mark.asyncio
async def test_nesting_depth_limit():
    body = (
        b"--l0\r\n"
        b'Content-Disposition: form-data; name="a"\r\n'
        b"Content-Type: multipart/mixed; boundary=l1\r\n"
        b"\r\n"
        b"--l1\r\n"
        b'Content-Disposition: form-data; name="b"\r\n'
        b"Content-Type: multipart/mixed; boundary=l2\r\n"
        b"\r\n"
        b"--l2\r\n"
        b'Content-Disposition: form-data; name="c"\r\n'
        b"\r\n"
        b"deep\r\n"
        b"--l2--\r\n"
        b"--l1--\r\n"
        b"--l0--\r\n"
    )
    reader = MultipartReader(make_source([body]), b"l0", max_depth=1)
    level0_part = await reader.next_part()
    level1 = level0_part.open()
    level1_part = await level1.next_part()
    assert level1_part.is_multipart
    assert level1_part.field_name == "a[b]"
    with pytest.raises(MultipartError, match="maximum depth"):
        level1_part.open()


@pytest.mark.asyncio
async def test_non_ascii_filenames():
    body = (
        "--b\r\n"
        'Content-Disposition: form-data; name="f1"; '
        "filename*=utf-8''%E4%B8%AD%E6%96%87.txt\r\n"
        "\r\n"
        "x\r\n"
        "--b\r\n"
        'Content-Disposition: form-data; name="f2"; '
        'filename="e\u0301.txt"\r\n'
        "\r\n"
        "y\r\n"
        "--b--\r\n"
    ).encode("utf-8")
    reader = MultipartReader(make_source([body]), b"b")
    part = await reader.next_part()
    assert part.filename == "\u4e2d\u6587.txt"
    part = await reader.next_part()
    # NFD input is normalized to NFC
    assert part.filename == "\u00e9.txt"
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_truncated_stream_raises():
    body = (
        b"--b\r\n"
        b'Content-Disposition: form-data; name="x"\r\n'
        b"\r\n"
        b"never terminated"
    )
    reader = MultipartReader(make_source([body]), b"b")
    part = await reader.next_part()
    with pytest.raises(MultipartError, match="closing boundary"):
        await part.read()


@pytest.mark.asyncio
async def test_empty_multipart():
    reader = MultipartReader(make_source([b"--b--\r\n"]), b"b")
    assert await reader.next_part() is None


@pytest.mark.asyncio
async def test_stream_multipart_on_streaming_route(app):
    @app.post("/upload", stream=True)
    async def upload(request):
        results = []
        async with request.stream_multipart() as reader:
            async for part in reader:
                if part.is_multipart:
                    async for sub in part.open():
                        results.append(
                            [sub.field_name, (await sub.read()).decode()]
                        )
                else:
                    results.append(
                        [part.field_name, (await part.read()).decode()]
                    )
        return json({"parts": results})

    _, response = await app.asgi_client.post(
        "/upload",
        data=TWO_LEVEL_BODY,
        headers={"content-type": "multipart/form-data; boundary=----parent"},
    )
    assert response.status == 200
    assert response.json["parts"] == [
        [field_name, body.decode()]
        for field_name, _, body in EXPECTED_TWO_LEVEL
    ]


@pytest.mark.asyncio
async def test_stream_multipart_on_buffered_route(app):
    @app.post("/upload")
    async def upload(request):
        names = []
        async for part in request.stream_multipart():
            names.append(part.field_name)
        return json({"names": names})

    _, response = await app.asgi_client.post(
        "/upload",
        data=TWO_LEVEL_BODY,
        headers={"content-type": "multipart/form-data; boundary=----parent"},
    )
    assert response.status == 200
    assert response.json["names"] == ["title", "attachments", "tail"]


@pytest.mark.asyncio
async def test_stream_multipart_rejects_non_multipart(app):
    @app.post("/nope")
    async def nope(request):
        with pytest.raises(MultipartError):
            request.stream_multipart()
        return text("ok")

    _, response = await app.asgi_client.post(
        "/nope", data="a=1", headers={"content-type": "text/plain"}
    )
    assert response.status == 200


@pytest.mark.asyncio
async def test_simple_upload_form_files_still_work(app):
    @app.post("/simple")
    async def simple(request):
        return json(
            {
                "form": request.form.get("title"),
                "file": request.files.get("upload").name,
                "body": request.files.get("upload").body.decode(),
            }
        )

    body = (
        b"------simple\r\n"
        b'Content-Disposition: form-data; name="title"\r\n'
        b"\r\n"
        b"legacy\r\n"
        b"------simple\r\n"
        b'Content-Disposition: form-data; name="upload"; filename="f.txt"\r\n'
        b"\r\n"
        b"content\r\n"
        b"------simple--\r\n"
    )
    _, response = await app.asgi_client.post(
        "/simple",
        data=body,
        headers={"content-type": "multipart/form-data; boundary=----simple"},
    )
    assert response.status == 200
    assert response.json == {
        "form": "legacy",
        "file": "f.txt",
        "body": "content",
    }
