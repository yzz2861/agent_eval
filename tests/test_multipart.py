from __future__ import annotations

import io
import tempfile
import typing
from email.parser import BytesParser
from email.policy import default

import anyio
import pytest

import httpx
from httpx._transports.base import AsyncBaseTransport


class StreamingAsyncTransport(AsyncBaseTransport):
    def __init__(
        self, handler: typing.Callable[[httpx.Request], httpx.Response]
    ) -> None:
        self.handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        async for _chunk in request.stream:
            pass
        return self.handler(request)


def parse_multipart_request(request: httpx.Request) -> list[dict[str, typing.Any]]:
    boundary = request.headers["Content-Type"].split("boundary=", 1)[1].encode()
    body = (
        b"Content-Type: multipart/form-data; boundary="
        + boundary
        + b"\r\n\r"
        + request.content
    )
    message = BytesParser(policy=default).parsebytes(body)
    return [
        {
            "name": part.get_param("name", header="content-disposition"),
            "filename": part.get_filename(),
            "content": part.get_payload(decode=True) or b"",
        }
        for part in message.iter_parts()
    ]


@pytest.mark.anyio
async def test_multipart_async_file_with_mixed_fields() -> None:
    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"async-"
        await anyio.sleep(0)
        yield b"content"

    seen_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(200, content=request.content)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await client.post(
            "http://example.org/upload",
            data={"field": "value", "repeated": ["one", "two"]},
            files=[
                ("bytes_file", b"bytes"),
                ("bytesio_file", io.BytesIO(b"bytesio")),
                ("async_file", ("async.txt", file_content(), "text/plain")),
                ("repeated", ("a", b"first")),
                ("repeated", ("b", b"second")),
            ],
        )

    assert response.status_code == 200
    request = seen_requests[0]
    assert "Content-Length" not in request.headers
    assert request.headers["Transfer-Encoding"] == "chunked"

    parts = parse_multipart_request(request)
    assert [(part["name"], part["filename"]) for part in parts] == [
        ("field", None),
        ("repeated", None),
        ("repeated", None),
        ("bytes_file", "upload"),
        ("bytesio_file", "upload"),
        ("async_file", "async.txt"),
        ("repeated", "a"),
        ("repeated", "b"),
    ]
    assert [part["content"] for part in parts] == [
        b"value",
        b"one",
        b"two",
        b"bytes",
        b"bytesio",
        b"async-content",
        b"first",
        b"second",
    ]


@pytest.mark.anyio
async def test_multipart_async_file_allows_concurrent_heartbeat() -> None:
    heartbeats = 0

    async def heartbeat() -> None:
        nonlocal heartbeats
        while True:
            await anyio.sleep(0)
            heartbeats += 1

    async def slow_file_content() -> typing.AsyncIterator[bytes]:
        for index in range(5):
            await anyio.sleep(0)
            yield bytes([index])

    async with anyio.create_task_group() as task_group:
        task_group.start_soon(heartbeat)

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        ) as client:
            response = await client.post(
                "http://example.org/upload",
                files={"file": slow_file_content()},
            )
            assert response.status_code == 200

        task_group.cancel_scope.cancel()

    assert heartbeats > 0


@pytest.mark.anyio
async def test_multipart_async_file_closes_source_on_send_failure() -> None:
    send_failed = anyio.Event()
    source_closed = anyio.Event()

    async def file_content() -> typing.AsyncIterator[bytes]:
        try:
            yield b"content"
            await send_failed.wait()
        finally:
            source_closed.set()

    class FailingTransport(AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            async for chunk in request.stream:
                if b"content" in chunk:
                    send_failed.set()
                    raise httpx.WriteError("send failed")
            raise AssertionError("unreachable")

    async with httpx.AsyncClient(transport=FailingTransport()) as client:
        with pytest.raises(httpx.HTTPError):
            await client.post(
                "http://example.org/upload",
                files={"file": file_content()},
            )

    assert source_closed.is_set()


@pytest.mark.anyio
async def test_multipart_async_file_closes_source_on_cancellation() -> None:
    started = anyio.Event()
    source_closed = anyio.Event()

    async def file_content() -> typing.AsyncIterator[bytes]:
        try:
            yield b"content"
            started.set()
            await anyio.sleep_forever()
        finally:
            source_closed.set()

    class CancellingTransport(AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            async for chunk in request.stream:
                if b"content" in chunk:
                    await started.wait()
                    raise anyio.get_cancelled_exc_class()("cancelled")
            raise AssertionError("unreachable")

    with anyio.move_on_after(0):
        async with httpx.AsyncClient(transport=CancellingTransport()) as client:
            await client.post(
                "http://example.org/upload",
                files={"file": file_content()},
            )

    assert source_closed.is_set()


@pytest.mark.anyio
async def test_multipart_async_file_cannot_be_redirected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(307, headers={"location": "/target"})
        return httpx.Response(200)

    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"content"  # pragma: no cover

    async with httpx.AsyncClient(transport=StreamingAsyncTransport(handler)) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                "http://example.org/redirect",
                files={"file": file_content()},
                follow_redirects=True,
            )


@pytest.mark.anyio
async def test_multipart_replayable_fields_keep_content_length() -> None:
    with tempfile.TemporaryFile() as upload:
        upload.write(b"disk content")
        upload.seek(0)
        request = httpx.Request(
            "POST",
            "http://example.org/upload",
            data={"field": "value"},
            files={
                "bytes": b"bytes",
                "bytesio": io.BytesIO(b"bytesio"),
                "disk": upload,
            },
            headers={"Content-Type": "multipart/form-data; boundary=BOUNDARY"},
        )
        body = await request.aread()

        assert "Transfer-Encoding" not in request.headers
        assert request.headers["Content-Length"] == str(len(body))


@pytest.mark.anyio
async def test_multipart_async_file_cannot_be_authenticated_again() -> None:
    class RetryAuth(httpx.Auth):
        async def async_auth_flow(
            self, request: httpx.Request
        ) -> typing.AsyncGenerator[httpx.Request, httpx.Response]:
            yield request
            yield request

    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"content"  # pragma: no cover

    async with httpx.AsyncClient(
        transport=StreamingAsyncTransport(lambda request: httpx.Response(200)),
        auth=RetryAuth(),
    ) as client:
        with pytest.raises(httpx.StreamConsumed):
            await client.post(
                "http://example.org/upload",
                files={"file": file_content()},
            )


@pytest.mark.anyio
async def test_multipart_custom_async_iterator_cannot_be_replayed() -> None:
    class CustomAsyncIterator:
        def __init__(self) -> None:
            self.chunks = [b"content"]

        def __aiter__(self) -> "CustomAsyncIterator":
            return self

        async def __anext__(self) -> bytes:
            if not self.chunks:
                raise StopAsyncIteration
            return self.chunks.pop(0)

    request = httpx.Request(
        "POST",
        "http://example.org/upload",
        files={"file": CustomAsyncIterator()},
    )

    async for _chunk in request.stream:
        pass

    with pytest.raises(httpx.StreamConsumed):
        async for _chunk in request.stream:
            pass


def test_multipart_async_file_rejected_by_sync_client() -> None:
    async def file_content() -> typing.AsyncIterator[bytes]:
        yield b"content"  # pragma: no cover

    request = httpx.Request(
        "POST",
        "http://example.org/upload",
        files={"file": file_content()},
    )
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(AssertionError("request was sent"))
        )
    )

    with pytest.raises(TypeError, match="AsyncClient"):
        client.send(request)


def echo_request_content(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=request.content)


@pytest.mark.parametrize(("value,output"), (("abc", b"abc"), (b"abc", b"abc")))
def test_multipart(value, output):
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    # Test with a single-value 'data' argument, and a plain file 'files' argument.
    data = {"text": value}
    files = {"file": io.BytesIO(b"<file content>")}
    response = client.post("http://127.0.0.1:8000/", data=data, files=files)
    boundary = response.request.headers["Content-Type"].split("boundary=")[-1]
    boundary_bytes = boundary.encode("ascii")

    assert response.status_code == 200
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="text"\r\n',
            b"\r\n",
            b"abc\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="upload"\r\n',
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )


@pytest.mark.parametrize(
    "header",
    [
        "multipart/form-data; boundary=+++; charset=utf-8",
        "multipart/form-data; charset=utf-8; boundary=+++",
        "multipart/form-data; boundary=+++",
        "multipart/form-data; boundary=+++ ;",
        'multipart/form-data; boundary="+++"; charset=utf-8',
        'multipart/form-data; charset=utf-8; boundary="+++"',
        'multipart/form-data; boundary="+++"',
        'multipart/form-data; boundary="+++" ;',
    ],
)
def test_multipart_explicit_boundary(header: str) -> None:
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    files = {"file": io.BytesIO(b"<file content>")}
    headers = {"content-type": header}
    response = client.post("http://127.0.0.1:8000/", files=files, headers=headers)
    boundary_bytes = b"+++"

    assert response.status_code == 200
    assert response.request.headers["Content-Type"] == header
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="upload"\r\n',
            b"Content-Type: application/octet-stream\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )


@pytest.mark.parametrize(
    "header",
    [
        "multipart/form-data; charset=utf-8",
        "multipart/form-data; charset=utf-8; ",
    ],
)
def test_multipart_header_without_boundary(header: str) -> None:
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    files = {"file": io.BytesIO(b"<file content>")}
    headers = {"content-type": header}
    response = client.post("http://127.0.0.1:8000/", files=files, headers=headers)

    assert response.status_code == 200
    assert response.request.headers["Content-Type"] == header


@pytest.mark.parametrize(("key"), (b"abc", 1, 2.3, None))
def test_multipart_invalid_key(key):
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    data = {key: "abc"}
    files = {"file": io.BytesIO(b"<file content>")}
    with pytest.raises(TypeError) as e:
        client.post(
            "http://127.0.0.1:8000/",
            data=data,
            files=files,
        )
    assert "Invalid type for name" in str(e.value)
    assert repr(key) in str(e.value)


@pytest.mark.parametrize(("value"), (object(), {"key": "value"}))
def test_multipart_invalid_value(value):
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    data = {"text": value}
    files = {"file": io.BytesIO(b"<file content>")}
    with pytest.raises(TypeError) as e:
        client.post("http://127.0.0.1:8000/", data=data, files=files)
    assert "Invalid type for value" in str(e.value)


def test_multipart_file_tuple():
    client = httpx.Client(transport=httpx.MockTransport(echo_request_content))

    # Test with a list of values 'data' argument,
    #     and a tuple style 'files' argument.
    data = {"text": ["abc"]}
    files = {"file": ("name.txt", io.BytesIO(b"<file content>"))}
    response = client.post("http://127.0.0.1:8000/", data=data, files=files)
    boundary = response.request.headers["Content-Type"].split("boundary=")[-1]
    boundary_bytes = boundary.encode("ascii")

    assert response.status_code == 200
    assert response.content == b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="text"\r\n',
            b"\r\n",
            b"abc\r\n",
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="file"; filename="name.txt"\r\n',
            b"Content-Type: text/plain\r\n",
            b"\r\n",
            b"<file content>\r\n",
            b"--" + boundary_bytes + b"--\r\n",
        ]
    )


@pytest.mark.parametrize("file_content_type", [None, "text/plain"])
def test_multipart_file_tuple_headers(file_content_type: str | None) -> None:
    file_name = "test.txt"
    file_content = io.BytesIO(b"<file content>")
    file_headers = {"Expires": "0"}

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (file_name, file_content, file_content_type, file_headers)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        f'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\nExpires: 0\r\nContent-Type: '
        f"text/plain\r\n\r\n<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_headers_include_content_type() -> None:
    """
    Content-Type from 4th tuple parameter (headers) should
    override the 3rd parameter (content_type)
    """
    file_name = "test.txt"
    file_content = io.BytesIO(b"<file content>")
    file_content_type = "text/plain"
    file_headers = {"Content-Type": "image/png"}

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (file_name, file_content, file_content_type, file_headers)}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        f'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\nContent-Type: '
        f"image/png\r\n\r\n<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode(tmp_path: typing.Any) -> None:
    path = str(tmp_path / "name.txt")
    with open(path, "wb") as f:
        f.write(b"<file content>")

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    data = {
        "a": "1",
        "b": b"C",
        "c": ["11", "22", "33"],
        "d": "",
        "e": True,
        "f": "",
    }
    with open(path, "rb") as input_file:
        files = {"file": ("name.txt", input_file)}

        request = httpx.Request("POST", url, headers=headers, data=data, files=files)
        request.read()

        assert request.headers == {
            "Host": "www.example.com",
            "Content-Type": "multipart/form-data; boundary=BOUNDARY",
            "Content-Length": str(len(request.content)),
        }
        assert request.content == (
            '--BOUNDARY\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="b"\r\n\r\nC\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="c"\r\n\r\n11\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="c"\r\n\r\n22\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="c"\r\n\r\n33\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="d"\r\n\r\n\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="e"\r\n\r\ntrue\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="f"\r\n\r\n\r\n'
            '--BOUNDARY\r\nContent-Disposition: form-data; name="file";'
            ' filename="name.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n<file content>\r\n"
            "--BOUNDARY--\r\n"
            "".encode("ascii")
        )


def test_multipart_encode_unicode_file_contents() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("name.txt", b"<bytes content>")}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        b'--BOUNDARY\r\nContent-Disposition: form-data; name="file";'
        b' filename="name.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n<bytes content>\r\n"
        b"--BOUNDARY--\r\n"
    )


def test_multipart_encode_files_allows_filenames_as_none() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (None, io.BytesIO(b"<file content>"))}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        '--BOUNDARY\r\nContent-Disposition: form-data; name="file"\r\n\r\n'
        "<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


@pytest.mark.parametrize(
    "file_name,expected_content_type",
    [
        ("example.json", "application/json"),
        ("example.txt", "text/plain"),
        ("no-extension", "application/octet-stream"),
    ],
)
def test_multipart_encode_files_guesses_correct_content_type(
    file_name: str, expected_content_type: str
) -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": (file_name, io.BytesIO(b"<file content>"))}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        f'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        f'filename="{file_name}"\r\nContent-Type: '
        f"{expected_content_type}\r\n\r\n<file content>\r\n--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode_files_allows_bytes_content() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("test.txt", b"<bytes content>", "text/plain")}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        '--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        'filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n<bytes content>\r\n"
        "--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode_files_allows_str_content() -> None:
    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    files = {"file": ("test.txt", "<str content>", "text/plain")}

    request = httpx.Request("POST", url, headers=headers, data={}, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Content-Length": str(len(request.content)),
    }
    assert request.content == (
        '--BOUNDARY\r\nContent-Disposition: form-data; name="file"; '
        'filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n<str content>\r\n"
        "--BOUNDARY--\r\n"
        "".encode("ascii")
    )


def test_multipart_encode_files_raises_exception_with_StringIO_content() -> None:
    url = "https://www.example.com"
    files = {"file": ("test.txt", io.StringIO("content"), "text/plain")}
    with pytest.raises(TypeError):
        httpx.Request("POST", url, data={}, files=files)  # type: ignore


def test_multipart_encode_files_raises_exception_with_text_mode_file() -> None:
    url = "https://www.example.com"
    with tempfile.TemporaryFile(mode="w") as upload:
        files = {"file": ("test.txt", upload, "text/plain")}
        with pytest.raises(TypeError):
            httpx.Request("POST", url, data={}, files=files)  # type: ignore


def test_multipart_encode_non_seekable_filelike() -> None:
    """
    Test that special readable but non-seekable filelike objects are supported.
    In this case uploads with use 'Transfer-Encoding: chunked', instead of
    a 'Content-Length' header.
    """

    class IteratorIO(io.IOBase):
        def __init__(self, iterator: typing.Iterator[bytes]) -> None:
            self._iterator = iterator

        def read(self, *args: typing.Any) -> bytes:
            return b"".join(self._iterator)

    def data() -> typing.Iterator[bytes]:
        yield b"Hello"
        yield b"World"

    url = "https://www.example.com/"
    headers = {"Content-Type": "multipart/form-data; boundary=BOUNDARY"}
    fileobj: typing.Any = IteratorIO(data())
    files = {"file": fileobj}

    request = httpx.Request("POST", url, headers=headers, files=files)
    request.read()

    assert request.headers == {
        "Host": "www.example.com",
        "Content-Type": "multipart/form-data; boundary=BOUNDARY",
        "Transfer-Encoding": "chunked",
    }
    assert request.content == (
        b"--BOUNDARY\r\n"
        b'Content-Disposition: form-data; name="file"; filename="upload"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n"
        b"HelloWorld\r\n"
        b"--BOUNDARY--\r\n"
    )


def test_multipart_rewinds_files():
    with tempfile.TemporaryFile() as upload:
        upload.write(b"Hello, world!")

        transport = httpx.MockTransport(echo_request_content)
        client = httpx.Client(transport=transport)

        files = {"file": upload}
        response = client.post("http://127.0.0.1:8000/", files=files)
        assert response.status_code == 200
        assert b"\r\nHello, world!\r\n" in response.content

        # POSTing the same file instance a second time should have the same content.
        files = {"file": upload}
        response = client.post("http://127.0.0.1:8000/", files=files)
        assert response.status_code == 200
        assert b"\r\nHello, world!\r\n" in response.content


class TestHeaderParamHTML5Formatting:
    def test_unicode(self):
        filename = "n\u00e4me"
        expected = b'filename="n\xc3\xa4me"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()

    def test_ascii(self):
        filename = "name"
        expected = b'filename="name"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()

    def test_unicode_escape(self):
        filename = "hello\\world\u0022"
        expected = b'filename="hello\\\\world%22"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()

    def test_unicode_with_control_character(self):
        filename = "hello\x1a\x1b\x1c"
        expected = b'filename="hello%1A\x1b%1C"'
        files = {"upload": (filename, b"<file content>")}
        request = httpx.Request("GET", "https://www.example.com", files=files)
        assert expected in request.read()
