import logging
import os
import sys

from collections import Counter
from pathlib import Path
from time import gmtime, strftime
from urllib.parse import unquote

import pytest

from sanic import Sanic, text
from sanic.exceptions import BadRequest, FileNotFound, ServerError
from sanic.handlers.content_range import MAX_RANGES
from sanic.mixins import static as static_mixin
from sanic.response import file
from sanic.response import file_stream as original_file_stream
from sanic.response.types import ResponseStream


pytestmark = pytest.mark.xdist_group(name="static_files")


@pytest.fixture(scope="module")
def double_dotted_directory_file(static_file_directory: str):
    """Generate double dotted directory and its files"""
    if sys.platform == "win32":
        raise Exception("Windows doesn't support double dotted directories")

    file_path = Path(static_file_directory) / "dotted.." / "dot.txt"
    double_dotted_dir = file_path.parent
    Path.mkdir(double_dotted_dir, exist_ok=True)
    with open(file_path, "w") as f:
        f.write("DOT\n")
    yield file_path
    Path.unlink(file_path)
    Path.rmdir(double_dotted_dir)


def get_file_path(static_file_directory, file_name):
    return os.path.join(static_file_directory, file_name)


def get_file_content(static_file_directory, file_name):
    """The content of the static file to check"""
    with open(get_file_path(static_file_directory, file_name), "rb") as file:
        return file.read()


def parse_multipart_byteranges(body, boundary):
    delimiter = boundary.encode("ascii")
    expected_start = b"--" + delimiter + b"\r\n"
    expected_end = b"\r\n--" + delimiter + b"--\r\n"
    assert body.startswith(expected_start)
    assert body.endswith(expected_end)

    sections = body[len(expected_start) : -len(expected_end)].split(
        b"\r\n--" + delimiter + b"\r\n"
    )
    parts = []
    for section in sections:
        header_block, payload = section.split(b"\r\n\r\n", 1)
        headers = {}
        for line in header_block.split(b"\r\n"):
            name, value = line.split(b":", 1)
            headers[name.decode().lower()] = value.strip().decode()
        parts.append((headers, payload))
    return parts


def static_app(app, static_file_directory, file_name, **kwargs):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
        **kwargs,
    )


@pytest.fixture(scope="module")
def large_file(static_file_directory):
    large_file_path = os.path.join(static_file_directory, "large.file")

    size = 2 * 1024 * 1024
    with open(large_file_path, "w") as f:
        f.write("a" * size)

    yield large_file_path

    os.remove(large_file_path)


@pytest.fixture(autouse=True, scope="module")
def symlink(static_file_directory):
    src = os.path.abspath(
        os.path.join(os.path.dirname(static_file_directory), "conftest.py")
    )
    symlink = "symlink"
    dist = os.path.join(static_file_directory, symlink)
    if os.path.islink(dist):
        os.remove(dist)
    os.symlink(src, dist)
    yield symlink
    if os.path.exists(dist):
        os.remove(dist)


@pytest.fixture(autouse=True, scope="module")
def hard_link(static_file_directory):
    src = os.path.abspath(
        os.path.join(os.path.dirname(static_file_directory), "conftest.py")
    )
    hard_link = "hard_link"
    dist = os.path.join(static_file_directory, hard_link)
    if os.path.exists(dist):
        os.remove(dist)
    os.link(src, dist)
    yield hard_link
    if os.path.exists(dist):
        os.remove(dist)


@pytest.mark.parametrize(
    "file_name",
    ["test.file", "decode me.txt", "python.png", "symlink", "hard_link"],
)
def test_static_file(app, static_file_directory, file_name):
    app.static(
        "/testing.file", get_file_path(static_file_directory, file_name)
    )

    request, response = app.test_client.get("/testing.file")
    assert response.status == 200
    assert response.body == get_file_content(static_file_directory, file_name)


@pytest.mark.parametrize(
    "file_name",
    ["test.file", "decode me.txt", "python.png", "symlink", "hard_link"],
)
def test_static_file_pathlib(app, static_file_directory, file_name):
    file_path = Path(get_file_path(static_file_directory, file_name))
    app.static("/testing.file", file_path)
    request, response = app.test_client.get("/testing.file")
    assert response.status == 200
    assert response.body == get_file_content(static_file_directory, file_name)


@pytest.mark.parametrize(
    "file_name",
    [
        "test.file",
        "decode me.txt",
        "python.png",
        "symlink",
        "hard_link",
    ],
)
def test_static_file_pathlib_relative_path_traversal(
    app, static_file_directory, file_name
):
    """Get the current working directory and check if it ends with "sanic" """
    cwd = Path.cwd()
    if not str(cwd).endswith("sanic"):
        pytest.skip("Current working directory does not end with 'sanic'")

    file_path = "./tests/static/../static/"
    app.static("/", file_path, follow_external_symlink_files=True)
    _, response = app.test_client.get(f"/{file_name}")
    assert response.status == 200
    assert response.body == get_file_content(static_file_directory, file_name)


@pytest.mark.parametrize(
    "file_name",
    [b"test.file", b"decode me.txt", b"python.png"],
)
def test_static_file_bytes(app, static_file_directory, file_name):
    bsep = os.path.sep.encode("utf-8")
    file_path = static_file_directory.encode("utf-8") + bsep + file_name
    message = "Static file or directory must be a path-like object or string"
    with pytest.raises(TypeError, match=message):
        app.static("/testing.file", file_path)


@pytest.mark.parametrize(
    "file_name",
    [{}, [], object()],
)
def test_static_file_invalid_path(app, static_file_directory, file_name):
    app.route("/")(lambda x: x)
    with pytest.raises(ValueError):
        app.static("/testing.file", file_name)
    request, response = app.test_client.get("/testing.file")
    assert response.status == 404


@pytest.mark.parametrize(
    "file_name,expected_content_type",
    [
        ("decode me.txt", "text/plain; charset=utf-8"),
        ("test.html", "text/html; charset=utf-8"),
        ("python.png", "image/png"),
        # Note: file() default for unknown types differs from app.static
        ("test.file", "text/plain; charset=utf-8"),
    ],
)
def test_file_response_content_type(
    app: Sanic, file_name, expected_content_type, static_file_directory
):
    """Responses by file() rather than app.static."""

    @app.get("/files/<filename>")
    def file_route(request, filename):
        file_path = os.path.join(static_file_directory, filename)
        file_path = os.path.abspath(unquote(file_path))
        return file(file_path)

    request, response = app.test_client.get(f"/files/{file_name}")
    assert response.status == 200
    assert response.headers["Content-Type"] == expected_content_type


@pytest.mark.parametrize(
    "file_name,expected_content_type",
    [
        ("decode me.txt", "text/plain; charset=utf-8"),
        ("test.html", "text/html; charset=utf-8"),
        ("python.png", "image/png"),
        ("test.file", "application/octet-stream"),
    ],
)
def test_static_file_content_type(
    app: Sanic, file_name, expected_content_type, static_file_directory
):
    """Test that file responses automatically include charset for text."""

    app.static("/", static_file_directory)
    request, response = app.test_client.get(file_name)
    assert response.status == 200
    assert response.headers["Content-Type"] == expected_content_type


def test_static_file_content_type_forced(app, static_file_directory):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, "decode me.txt"),
        content_type="text/plain;charset=ISO-8859-1",
    )

    request, response = app.test_client.get("/testing.file")
    assert response.status == 200
    assert response.headers["Content-Type"] == "text/plain;charset=ISO-8859-1"


@pytest.mark.parametrize(
    "file_name", ["test.file", "decode me.txt", "symlink", "hard_link"]
)
@pytest.mark.parametrize("base_uri", ["/static", "", "/dir"])
def test_static_directory(app, file_name, base_uri, static_file_directory):
    app.static(
        base_uri,
        static_file_directory,
        follow_external_symlink_files=(file_name == "symlink"),
    )

    request, response = app.test_client.get(uri=f"{base_uri}/{file_name}")
    assert response.status == 200
    assert response.body == get_file_content(static_file_directory, file_name)


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_head_request(app, file_name, static_file_directory):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    request, response = app.test_client.head("/testing.file")
    assert response.status == 200
    assert "Accept-Ranges" in response.headers
    assert "Content-Length" in response.headers
    assert int(response.headers["Content-Length"]) == len(
        get_file_content(static_file_directory, file_name)
    )


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_correct(app, file_name, static_file_directory):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    headers = {"Range": "bytes=12-19"}
    request, response = app.test_client.get("/testing.file", headers=headers)
    assert response.status == 206
    assert "Content-Length" in response.headers
    assert "Content-Range" in response.headers
    static_content = bytes(get_file_content(static_file_directory, file_name))[
        12:20
    ]
    assert int(response.headers["Content-Length"]) == len(static_content)
    assert response.body == static_content


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_front(app, file_name, static_file_directory):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    headers = {"Range": "bytes=12-"}
    request, response = app.test_client.get("/testing.file", headers=headers)
    assert response.status == 206
    assert "Content-Length" in response.headers
    assert "Content-Range" in response.headers
    static_content = bytes(get_file_content(static_file_directory, file_name))[
        12:
    ]
    assert int(response.headers["Content-Length"]) == len(static_content)
    assert response.body == static_content


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_back(app, file_name, static_file_directory):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    headers = {"Range": "bytes=-12"}
    request, response = app.test_client.get("/testing.file", headers=headers)
    assert response.status == 206
    assert "Content-Length" in response.headers
    assert "Content-Range" in response.headers
    static_content = bytes(get_file_content(static_file_directory, file_name))[
        -12:
    ]
    assert int(response.headers["Content-Length"]) == len(static_content)
    assert response.body == static_content


@pytest.mark.asyncio
async def test_static_content_range_full_get_and_head(
    app, static_file_directory
):
    static_app(app, static_file_directory, "test.file")
    source = get_file_content(static_file_directory, "test.file")

    _, get_response = await app.asgi_client.get("/testing.file")
    _, head_response = await app.asgi_client.head("/testing.file")

    assert get_response.status == 200
    assert get_response.body == source
    assert get_response.headers["Content-Length"] == str(len(source))
    assert get_response.headers["Content-Type"] == "application/octet-stream"
    assert head_response.status == 200
    assert head_response.body == b""
    assert head_response.headers["Content-Length"] == str(len(source))
    assert head_response.headers["Content-Type"] == "application/octet-stream"


@pytest.mark.asyncio
async def test_static_content_multipart_ranges(app, static_file_directory):
    static_app(app, static_file_directory, "test.file")
    _, response = await app.asgi_client.get(
        "/testing.file",
        headers={"Range": "bytes=0-4,20-24"},
    )

    source = get_file_content(static_file_directory, "test.file")
    content_type, boundary = response.headers["Content-Type"].split(
        "boundary=", 1
    )
    assert response.status == 206
    assert content_type.strip() == "multipart/byteranges;"
    assert int(response.headers["Content-Length"]) == len(response.body)
    assert "Content-Range" not in response.headers

    parts = parse_multipart_byteranges(response.body, boundary)
    assert [part[1] for part in parts] == [
        source[0:5],
        source[20:25],
    ]
    assert [part[0]["content-range"] for part in parts] == [
        "bytes 0-4/32",
        "bytes 20-24/32",
    ]
    assert all(
        part[0]["content-type"] == "application/octet-stream" for part in parts
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "range_header,expected_ranges,expected_slices",
    [
        (
            "bytes=10-19,0-14,21-24",
            ["bytes 0-19/32", "bytes 21-24/32"],
            [(0, 20), (21, 25)],
        ),
        (
            "bytes=10-14,15-19,21-23",
            ["bytes 10-19/32", "bytes 21-23/32"],
            [(10, 20), (21, 24)],
        ),
        (
            "bytes=100-200,20-,21-100,-5,0-4",
            ["bytes 0-4/32", "bytes 20-31/32"],
            [(0, 5), (20, 32)],
        ),
    ],
)
async def test_static_content_multipart_normalization(
    app,
    static_file_directory,
    range_header,
    expected_ranges,
    expected_slices,
):
    static_app(app, static_file_directory, "test.file")
    _, response = await app.asgi_client.get(
        "/testing.file", headers={"Range": range_header}
    )

    boundary = response.headers["Content-Type"].split("boundary=", 1)[1]
    parts = parse_multipart_byteranges(response.body, boundary)
    source = get_file_content(static_file_directory, "test.file")

    assert response.status == 206
    assert [part[0]["content-range"] for part in parts] == expected_ranges
    assert [part[1] for part in parts] == [
        source[start:end] for start, end in expected_slices
    ]
    assert int(response.headers["Content-Length"]) == len(response.body)


@pytest.mark.asyncio
async def test_static_content_single_merged_range(app, static_file_directory):
    static_app(app, static_file_directory, "test.file")
    _, response = await app.asgi_client.get(
        "/testing.file", headers={"Range": "bytes=0-9,5-15"}
    )

    assert response.status == 206
    assert response.headers["Content-Type"] == "application/octet-stream"
    assert response.headers["Content-Range"] == "bytes 0-15/32"
    assert response.headers["Content-Length"] == "16"
    assert (
        response.body
        == get_file_content(static_file_directory, "test.file")[0:16]
    )


@pytest.mark.asyncio
async def test_static_content_range_head_multipart(app, static_file_directory):
    static_app(app, static_file_directory, "test.file")
    _, response = await app.asgi_client.head(
        "/testing.file", headers={"Range": "bytes=0-4,20-24"}
    )

    assert response.status == 206
    assert response.headers["Content-Type"].startswith("multipart/byteranges;")
    assert response.headers["Content-Length"] == "286"
    assert response.body == b""


@pytest.mark.asyncio
async def test_static_content_range_all_unsatisfiable(
    app, static_file_directory
):
    static_app(app, static_file_directory, "test.file")
    _, response = await app.asgi_client.get(
        "/testing.file",
        headers={"Range": "bytes=32-40,100-200,5-3"},
    )

    assert response.status == 416
    assert response.headers["Content-Range"] == "bytes */32"


@pytest.mark.asyncio
async def test_static_content_range_count_limit(app, static_file_directory):
    static_app(app, static_file_directory, "test.file")
    header_value = "bytes=" + ",".join(
        str(index) + "-" + str(index) for index in range(MAX_RANGES + 1)
    )
    _, response = await app.asgi_client.get(
        "/testing.file", headers={"Range": header_value}
    )

    assert response.status == BadRequest.status_code


@pytest.mark.asyncio
async def test_static_content_range_overhead_limit(app, static_file_directory):
    static_app(
        app,
        static_file_directory,
        "decode me.txt",
        content_type="application/x-sanic-test-range-output",
    )
    header_value = "bytes=" + ",".join(
        f"{index}-{index}" for index in range(0, 68, 2)
    )
    _, response = await app.asgi_client.get(
        "/testing.file", headers={"Range": header_value}
    )

    assert response.status == BadRequest.status_code


@pytest.mark.asyncio
async def test_static_content_range_if_range(app, static_file_directory):
    file_path = get_file_path(static_file_directory, "test.file")
    file_stat = os.stat(file_path)
    last_modified = strftime(
        "%a, %d %b %Y %H:%M:%S GMT", gmtime(file_stat.st_mtime)
    )
    stale = strftime(
        "%a, %d %b %Y %H:%M:%S GMT",
        gmtime(file_stat.st_mtime - 10),
    )
    static_app(app, static_file_directory, "test.file")

    _, partial = await app.asgi_client.get(
        "/testing.file",
        headers={"Range": "bytes=0-4", "If-Range": last_modified},
    )
    _, full = await app.asgi_client.get(
        "/testing.file",
        headers={"Range": "bytes=0-4", "If-Range": stale},
    )

    assert partial.status == 206
    assert partial.headers["Content-Range"] == "bytes 0-4/32"
    assert full.status == 200
    assert full.headers["Content-Length"] == "32"
    assert full.body == get_file_content(static_file_directory, "test.file")


@pytest.mark.asyncio
async def test_static_content_range_empty_file(app, static_file_directory):
    empty_file = Path(static_file_directory) / "empty-range.file"
    empty_file.write_bytes(b"")
    try:
        app.static(
            "/testing.file",
            empty_file,
            use_content_range=True,
        )
        _, full = await app.asgi_client.get("/testing.file")
        _, partial = await app.asgi_client.get(
            "/testing.file", headers={"Range": "bytes=0-9"}
        )
    finally:
        empty_file.unlink()

    assert full.status == 200
    assert full.headers["Content-Length"] == "0"
    assert full.body == b""
    assert partial.status == 416
    assert partial.headers["Content-Range"] == "bytes */0"


@pytest.mark.asyncio
async def test_static_multipart_streamed_in_chunks(
    app, static_file_directory, monkeypatch
):
    chunks = []
    original_write = ResponseStream.write

    async def recording_write(self, message):
        chunks.append(bytes(message))
        return await original_write(self, message)

    async def small_chunk_stream(*args, **kwargs):
        kwargs.setdefault("chunk_size", 3)
        return await original_file_stream(*args, **kwargs)

    monkeypatch.setattr(ResponseStream, "write", recording_write)
    monkeypatch.setattr(static_mixin, "file_stream", small_chunk_stream)

    static_app(app, static_file_directory, "test.file")
    _, response = await app.asgi_client.get(
        "/testing.file",
        headers={"Range": "bytes=0-4,10-19"},
    )

    body = b"".join(chunks)
    assert body == response.body
    assert len(response.body) == int(response.headers["Content-Length"])
    assert len(chunks) == 11
    assert chunks[0].startswith(b"--sanic-")
    assert b"Content-Range: bytes 0-4/32" in chunks[0]
    assert chunks[3] == bytes((13, 10))
    assert b"Content-Range: bytes 10-19/32" in chunks[4]
    assert chunks[9] == bytes((13, 10))
    assert chunks[-1].startswith(b"--sanic-")
    assert chunks[-1].endswith(b"--" + bytes((13, 10)))
    payload_chunks = [
        chunk
        for chunk in chunks
        if not chunk.startswith((b"--", b"Content-Type", b"Content-Range"))
        and chunk != b"\r\n"
    ]
    assert payload_chunks == [
        b"I a",
        b"m ",
        b"a r",
        b"egu",
        b"lar",
        b" ",
    ]


@pytest.mark.parametrize("use_modified_since", [True, False])
@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_empty(
    app, file_name, static_file_directory, use_modified_since
):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
        use_modified_since=use_modified_since,
    )

    request, response = app.test_client.get("/testing.file")
    assert response.status == 200
    assert "Content-Length" in response.headers
    assert "Content-Range" not in response.headers
    assert int(response.headers["Content-Length"]) == len(
        get_file_content(static_file_directory, file_name)
    )
    assert response.body == bytes(
        get_file_content(static_file_directory, file_name)
    )


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_error(app, file_name, static_file_directory):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    headers = {"Range": "bytes=1-0"}
    request, response = app.test_client.get("/testing.file", headers=headers)
    assert response.status == 416
    assert "Content-Length" in response.headers
    assert "Content-Range" in response.headers
    assert response.headers["Content-Range"] == "bytes */{}".format(
        len(get_file_content(static_file_directory, file_name)),
    )


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_invalid_unit(
    app, file_name, static_file_directory
):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    unit = "bit"
    headers = {"Range": f"{unit}=1-0"}
    request, response = app.test_client.get("/testing.file", headers=headers)

    assert response.status == 416
    assert f"{unit} is not a valid Range Type" in response.text


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_invalid_start(
    app, file_name, static_file_directory
):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    start = "start"
    headers = {"Range": f"bytes={start}-0"}
    request, response = app.test_client.get("/testing.file", headers=headers)

    assert response.status == 416
    assert f"'{start}' is invalid for Content Range" in response.text


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_invalid_end(
    app, file_name, static_file_directory
):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    end = "end"
    headers = {"Range": f"bytes=1-{end}"}
    request, response = app.test_client.get("/testing.file", headers=headers)

    assert response.status == 416
    assert f"'{end}' is invalid for Content Range" in response.text


@pytest.mark.parametrize("file_name", ["test.file", "decode me.txt"])
def test_static_content_range_invalid_parameters(
    app, file_name, static_file_directory
):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_content_range=True,
    )

    headers = {"Range": "bytes=-"}
    request, response = app.test_client.get("/testing.file", headers=headers)

    assert response.status == 416
    assert "Invalid for Content Range parameters" in response.text


@pytest.mark.parametrize(
    "file_name", ["test.file", "decode me.txt", "python.png"]
)
def test_static_file_specified_host(app, static_file_directory, file_name):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        host="www.example.com",
    )

    headers = {"Host": "www.example.com"}
    request, response = app.test_client.get("/testing.file", headers=headers)
    assert response.status == 200
    assert response.body == get_file_content(static_file_directory, file_name)
    request, response = app.test_client.get("/testing.file")
    assert response.status == 404


@pytest.mark.parametrize("use_modified_since", [True, False])
@pytest.mark.parametrize("stream_large_files", [True, 1024])
@pytest.mark.parametrize("file_name", ["test.file", "large.file"])
def test_static_stream_large_file(
    app,
    static_file_directory,
    file_name,
    use_modified_since,
    stream_large_files,
    large_file,
):
    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_modified_since=use_modified_since,
        stream_large_files=stream_large_files,
    )

    request, response = app.test_client.get("/testing.file")

    assert response.status == 200
    assert response.body == get_file_content(static_file_directory, file_name)


@pytest.mark.parametrize(
    "file_name", ["test.file", "decode me.txt", "python.png"]
)
def test_use_modified_since(app, static_file_directory, file_name):
    file_stat = os.stat(get_file_path(static_file_directory, file_name))
    modified_since = strftime(
        "%a, %d %b %Y %H:%M:%S GMT", gmtime(file_stat.st_mtime)
    )

    app.static(
        "/testing.file",
        get_file_path(static_file_directory, file_name),
        use_modified_since=True,
    )

    request, response = app.test_client.get(
        "/testing.file", headers={"If-Modified-Since": modified_since}
    )

    assert response.status == 304


def test_file_not_found(app, static_file_directory):
    app.static("/static", static_file_directory)

    request, response = app.test_client.get("/static/not_found")

    assert response.status == 404
    assert "File not found" in response.text


@pytest.mark.parametrize("static_name", ["_static_name", "static"])
@pytest.mark.parametrize("file_name", ["test.html"])
def test_static_name(app, static_file_directory, static_name, file_name):
    app.static("/static", static_file_directory, name=static_name)

    request, response = app.test_client.get(f"/static/{file_name}")

    assert response.status == 200


def test_nested_dir(app, static_file_directory):
    app.static("/static", static_file_directory)

    request, response = app.test_client.get("/static/nested/dir/foo.txt")

    assert response.status == 200
    assert response.text == "foo\n"


def test_handle_is_a_directory_error(app, static_file_directory):
    error_text = "Is a directory. Access denied"
    app.static("/static", static_file_directory)

    @app.exception(Exception)
    async def handleStaticDirError(request, exception):
        if isinstance(exception, IsADirectoryError):
            return text(error_text, status=403)
        raise exception

    request, response = app.test_client.get("/static/")

    assert response.status == 403
    assert response.text == error_text


def test_stack_trace_on_not_found(app, static_file_directory, caplog):
    app.static("/static", static_file_directory)

    with caplog.at_level(logging.INFO):
        _, response = app.test_client.get("/static/non_existing_file.file")

    counter = Counter([(r[0], r[1]) for r in caplog.record_tuples])

    assert response.status == 404
    assert counter[("sanic.root", logging.INFO)] == 10
    assert counter[("sanic.root", logging.ERROR)] == 0
    assert counter[("sanic.error", logging.ERROR)] == 0
    assert counter[("sanic.server", logging.INFO)] == 4


def test_no_stack_trace_on_not_found(app, static_file_directory, caplog):
    app.static("/static", static_file_directory)

    @app.exception(FileNotFound)
    async def file_not_found(request, exception):
        return text(f"No file: {request.path}", status=404)

    with caplog.at_level(logging.INFO):
        _, response = app.test_client.get("/static/non_existing_file.file")

    counter = Counter([(r[0], r[1]) for r in caplog.record_tuples])

    assert response.status == 404
    assert counter[("sanic.root", logging.INFO)] == 10
    assert counter[("sanic.root", logging.ERROR)] == 0
    assert counter[("sanic.error", logging.ERROR)] == 0
    assert counter[("sanic.server", logging.INFO)] == 4
    assert response.text == "No file: /static/non_existing_file.file"


@pytest.mark.asyncio
async def test_multiple_statics_error(app, static_file_directory):
    app.static("/file", get_file_path(static_file_directory, "test.file"))
    app.static("/png", get_file_path(static_file_directory, "python.png"))

    message = (
        r"Duplicate route names detected: test_multiple_statics_error\.static"
    )
    with pytest.raises(ServerError, match=message):
        await app._startup()


def test_multiple_statics(app, static_file_directory):
    app.static(
        "/file", get_file_path(static_file_directory, "test.file"), name="file"
    )
    app.static(
        "/png", get_file_path(static_file_directory, "python.png"), name="png"
    )

    _, response = app.test_client.get("/file")
    assert response.status == 200
    assert response.body == get_file_content(
        static_file_directory, "test.file"
    )

    _, response = app.test_client.get("/png")
    assert response.status == 200
    assert response.body == get_file_content(
        static_file_directory, "python.png"
    )


@pytest.mark.asyncio
async def test_resource_type_default_error(app, static_file_directory):
    app.static("/static", static_file_directory)
    app.static("/file", get_file_path(static_file_directory, "test.file"))

    message = (
        r"Duplicate route names "
        r"detected: test_resource_type_default_error\.static"
    )
    with pytest.raises(ServerError, match=message):
        await app._startup()


def test_resource_type_default(app, static_file_directory):
    app.static("/static", static_file_directory, name="static")
    app.static(
        "/file", get_file_path(static_file_directory, "test.file"), name="file"
    )

    _, response = app.test_client.get("/static")
    assert response.status == 404

    _, response = app.test_client.get("/file")
    assert response.status == 200
    assert response.body == get_file_content(
        static_file_directory, "test.file"
    )


def test_resource_type_file(app, static_file_directory):
    app.static(
        "/file",
        get_file_path(static_file_directory, "test.file"),
        resource_type="file",
    )

    _, response = app.test_client.get("/file")
    assert response.status == 200
    assert response.body == get_file_content(
        static_file_directory, "test.file"
    )

    with pytest.raises(TypeError):
        app.static("/static", static_file_directory, resource_type="file")


def test_resource_type_dir(app, static_file_directory):
    app.static("/static", static_file_directory, resource_type="dir")

    _, response = app.test_client.get("/static/test.file")
    assert response.status == 200
    assert response.body == get_file_content(
        static_file_directory, "test.file"
    )

    with pytest.raises(TypeError):
        app.static(
            "/file",
            get_file_path(static_file_directory, "test.file"),
            resource_type="dir",
        )


def test_resource_type_unknown(app, static_file_directory, caplog):
    with pytest.raises(ValueError):
        app.static("/static", static_file_directory, resource_type="unknown")


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows does not support double dotted directories",
)
def test_dotted_dir_ok(
    app: Sanic, static_file_directory: str, double_dotted_directory_file: Path
):
    app.static("/foo", static_file_directory)
    dot_relative_path = str(
        double_dotted_directory_file.relative_to(static_file_directory)
    )
    _, response = app.test_client.get("/foo/" + dot_relative_path)
    assert response.status == 200
    assert response.body == b"DOT\n"


def test_breakout(app: Sanic, static_file_directory: str):
    app.static("/foo", static_file_directory)

    _, response = app.test_client.get("/foo/..%2Ffake/server.py")
    assert response.status == 404

    _, response = app.test_client.get("/foo/..%2Fstatic/test.file")
    assert response.status == 404


@pytest.mark.skipif(
    sys.platform != "win32", reason="Block backslash on Windows only"
)
def test_double_backslash_prohibited_on_win32(
    app: Sanic, static_file_directory: str
):
    app.static("/foo", static_file_directory)

    _, response = app.test_client.get("/foo/static/..\\static/test.file")
    assert response.status == 404
    _, response = app.test_client.get("/foo/static\\../static/test.file")
    assert response.status == 404
