from __future__ import annotations

import os
import threading
from collections.abc import AsyncGenerator, Generator
from contextlib import AbstractContextManager, nullcontext as does_not_raise
from io import BytesIO
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import Any, ClassVar
from unittest import mock

import anyio
import pytest

from starlette.applications import Starlette
from starlette.datastructures import Headers, UploadFile
from starlette.formparsers import FormLimitExceeded, FormParser, MultiPartException, MultiPartParser
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send
from tests.types import TestClientFactory


class ForceMultipartDict(dict[Any, Any]):
    def __bool__(self) -> bool:
        return True


# FORCE_MULTIPART is an empty dict that boolean-evaluates as `True`.
FORCE_MULTIPART = ForceMultipartDict()


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    data = await request.form()
    output: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key] = {
                "filename": value.filename,
                "size": value.size,
                "content": content.decode(),
                "content_type": value.content_type,
            }
        else:
            output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def multi_items_app(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    data = await request.form()
    output: dict[str, list[Any]] = {}
    for key, value in data.multi_items():
        if key not in output:
            output[key] = []
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key].append(
                {
                    "filename": value.filename,
                    "size": value.size,
                    "content": content.decode(),
                    "content_type": value.content_type,
                }
            )
        else:
            output[key].append(value)
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_with_headers(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    data = await request.form()
    output: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key] = {
                "filename": value.filename,
                "size": value.size,
                "content": content.decode(),
                "content_type": value.content_type,
                "headers": list(value.headers.items()),
            }
        else:
            output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_read_body(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    # Read bytes, to force request.stream() to return the already parsed body
    await request.body()
    data = await request.form()
    output = {}
    for key, value in data.items():
        output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_monitor_thread(scope: Scope, receive: Receive, send: Send) -> None:
    """Helper app to monitor what thread the app was called on.

    This can later be used to validate thread/event loop operations.
    """
    request = Request(scope, receive)

    # Make sure we parse the form
    await request.form()
    await request.close()

    # Send back the current thread id
    response = JSONResponse({"thread_ident": threading.current_thread().ident})
    await response(scope, receive, send)


def make_app_max_parts(max_files: int = 1000, max_fields: int = 1000, max_part_size: int = 1024 * 1024) -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        data = await request.form(max_files=max_files, max_fields=max_fields, max_part_size=max_part_size)
        output: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, UploadFile):
                content = await value.read()
                output[key] = {
                    "filename": value.filename,
                    "size": value.size,
                    "content": content.decode(),
                    "content_type": value.content_type,
                }
            else:
                output[key] = value
        await request.close()
        response = JSONResponse(output)
        await response(scope, receive, send)

    return app


def test_multipart_request_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"some": "data"}, files=FORCE_MULTIPART)
    assert response.json() == {"some": "data"}


def test_multipart_request_files(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = test_client_factory(app)
    with open(path, "rb") as f:
        response = client.post("/", files={"test": f})
        assert response.json() == {
            "test": {
                "filename": "test.txt",
                "size": 14,
                "content": "<file content>",
                "content_type": "text/plain",
            }
        }


def test_multipart_request_files_with_content_type(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = test_client_factory(app)
    with open(path, "rb") as f:
        response = client.post("/", files={"test": ("test.txt", f, "text/plain")})
        assert response.json() == {
            "test": {
                "filename": "test.txt",
                "size": 14,
                "content": "<file content>",
                "content_type": "text/plain",
            }
        }


def test_multipart_request_multiple_files(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(app)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post("/", files={"test1": f1, "test2": ("test2.txt", f2, "text/plain")})
        assert response.json() == {
            "test1": {
                "filename": "test1.txt",
                "size": 15,
                "content": "<file1 content>",
                "content_type": "text/plain",
            },
            "test2": {
                "filename": "test2.txt",
                "size": 15,
                "content": "<file2 content>",
                "content_type": "text/plain",
            },
        }


def test_multipart_request_multiple_files_with_headers(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(app_with_headers)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post(
            "/",
            files=[
                ("test1", (None, f1)),
                ("test2", ("test2.txt", f2, "text/plain", {"x-custom": "f2"})),
            ],
        )
        assert response.json() == {
            "test1": "<file1 content>",
            "test2": {
                "filename": "test2.txt",
                "size": 15,
                "content": "<file2 content>",
                "content_type": "text/plain",
                "headers": [
                    [
                        "content-disposition",
                        'form-data; name="test2"; filename="test2.txt"',
                    ],
                    ["x-custom", "f2"],
                    ["content-type", "text/plain"],
                ],
            },
        }


def test_multi_items(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(multi_items_app)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post(
            "/",
            data={"test1": "abc"},
            files=[("test1", f1), ("test1", ("test2.txt", f2, "text/plain"))],
        )
        assert response.json() == {
            "test1": [
                "abc",
                {
                    "filename": "test1.txt",
                    "size": 15,
                    "content": "<file1 content>",
                    "content_type": "text/plain",
                },
                {
                    "filename": "test2.txt",
                    "size": 15,
                    "content": "<file2 content>",
                    "content_type": "text/plain",
                },
            ]
        }


def test_multipart_request_mixed_files_and_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            # data
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
            b'Content-Disposition: form-data; name="field0"\r\n\r\n'
            b"value0\r\n"
            # file
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"
            b'Content-Disposition: form-data; name="file"; filename="file.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"<file content>\r\n"
            # data
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"
            b'Content-Disposition: form-data; name="field1"\r\n\r\n'
            b"value1\r\n"
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
    )
    assert response.json() == {
        "file": {
            "filename": "file.txt",
            "size": 14,
            "content": "<file content>",
            "content_type": "text/plain",
        },
        "field0": "value0",
        "field1": "value1",
    }


class ThreadTrackingSpooledTemporaryFile(SpooledTemporaryFile[bytes]):
    """Helper class to track which threads performed the rollover operation.

    This is not threadsafe/multi-test safe.
    """

    rollover_threads: ClassVar[set[int | None]] = set()

    def rollover(self) -> None:
        ThreadTrackingSpooledTemporaryFile.rollover_threads.add(threading.current_thread().ident)
        super().rollover()


@pytest.fixture
def mock_spooled_temporary_file() -> Generator[None]:
    try:
        with mock.patch("starlette.formparsers.SpooledTemporaryFile", ThreadTrackingSpooledTemporaryFile):
            yield
    finally:
        ThreadTrackingSpooledTemporaryFile.rollover_threads.clear()


def test_multipart_request_large_file_rollover_in_background_thread(
    mock_spooled_temporary_file: None, test_client_factory: TestClientFactory
) -> None:
    """Test that Spooled file rollovers happen in background threads."""
    data = BytesIO(b" " * (MultiPartParser.spool_max_size + 1))

    client = test_client_factory(app_monitor_thread)
    response = client.post("/", files=[("test_large", data)])
    assert response.status_code == 200

    # Parse the event thread id from the API response and ensure we have one
    app_thread_ident = response.json().get("thread_ident")
    assert app_thread_ident is not None

    # Ensure the app thread was not the same as the rollover one and that a rollover thread exists
    assert app_thread_ident not in ThreadTrackingSpooledTemporaryFile.rollover_threads
    assert len(ThreadTrackingSpooledTemporaryFile.rollover_threads) == 1


def test_multipart_request_with_charset_for_filename(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            # file
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
            b'Content-Disposition: form-data; name="file"; filename="\xe6\x96\x87\xe6\x9b\xb8.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"<file content>\r\n"
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; charset=utf-8; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
    )
    assert response.json() == {
        "file": {
            "filename": "文書.txt",
            "size": 14,
            "content": "<file content>",
            "content_type": "text/plain",
        }
    }


def test_multipart_request_without_charset_for_filename(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            # file
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
            b'Content-Disposition: form-data; name="file"; filename="\xe7\x94\xbb\xe5\x83\x8f.jpg"\r\n'
            b"Content-Type: image/jpeg\r\n\r\n"
            b"<file content>\r\n"
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
    )
    assert response.json() == {
        "file": {
            "filename": "画像.jpg",
            "size": 14,
            "content": "<file content>",
            "content_type": "image/jpeg",
        }
    }


def test_multipart_request_with_encoded_value(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            b"--20b303e711c4ab8c443184ac833ab00f\r\n"  # type: ignore
            b"Content-Disposition: form-data; "
            b'name="value"\r\n\r\n'
            b"Transf\xc3\xa9rer\r\n"
            b"--20b303e711c4ab8c443184ac833ab00f--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; charset=utf-8; boundary=20b303e711c4ab8c443184ac833ab00f")},
    )
    assert response.json() == {"value": "Transférer"}


def test_urlencoded_request_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"some": "data"})
    assert response.json() == {"some": "data"}


def test_no_request_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/")
    assert response.json() == {}


def test_urlencoded_percent_encoding(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"some": "da ta"})
    assert response.json() == {"some": "da ta"}


def test_urlencoded_percent_encoding_keys(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"so me": "data"})
    assert response.json() == {"so me": "data"}


def test_urlencoded_multi_field_app_reads_body(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app_read_body)
    response = client.post("/", data={"some": "data", "second": "key pair"})
    assert response.json() == {"some": "data", "second": "key pair"}


def test_multipart_multi_field_app_reads_body(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app_read_body)
    response = client.post("/", data={"some": "data", "second": "key pair"}, files=FORCE_MULTIPART)
    assert response.json() == {"some": "data", "second": "key pair"}


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_urlencoded_too_many_fields_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    data = "&".join(f"N{i}=" for i in range(1001))
    with expectation:
        res = client.post(
            "/",
            content=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert res.status_code == 400
        assert res.text == "Too many fields. Maximum number of fields is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_urlencoded_field_exceeds_max_part_size_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    data = "field=" + "x" * (1024 * 1024 + 1)
    with expectation:
        res = client.post(
            "/",
            content=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert res.status_code == 400
        assert res.text == "Field exceeded maximum size of 1024KB."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_urlencoded_field_name_exceeds_max_part_size_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    data = "x" * (1024 * 1024 + 1) + "=value"
    with expectation:
        res = client.post(
            "/",
            content=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert res.status_code == 400
        assert res.text == "Field exceeded maximum size of 1024KB."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_fields=1), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_fields=1))]),
            does_not_raise(),
        ),
    ],
)
def test_urlencoded_max_fields_is_customizable(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    with expectation:
        res = client.post(
            "/",
            content="a=1&b=2",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert res.status_code == 400
        assert res.text == "Too many fields. Maximum number of fields is 1."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_part_size=1024 * 10), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_part_size=1024 * 10))]),
            does_not_raise(),
        ),
    ],
)
def test_urlencoded_max_part_size_is_customizable(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    with expectation:
        res = client.post(
            "/",
            content="field=" + "x" * (1024 * 10 + 1),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert res.status_code == 400
        assert res.text == "Field exceeded maximum size of 10KB."


@pytest.mark.anyio
async def test_urlencoded_limits_stop_parsing_within_a_single_chunk() -> None:
    async def single_chunk(body: bytes) -> AsyncGenerator[bytes, None]:
        yield body

    headers = Headers({"content-type": "application/x-www-form-urlencoded"})

    too_many = "&".join(f"f{i}=" for i in range(100_000)).encode()
    stream = single_chunk(too_many)
    parser = FormParser(headers, stream, max_fields=10)
    with pytest.raises(MultiPartException, match="Too many fields"):
        await parser.parse()
    await stream.aclose()
    assert parser._current_fields == 11

    too_big = ("field=" + "x" * (1024 * 1024 * 50)).encode()
    stream = single_chunk(too_big)
    parser = FormParser(headers, stream, max_part_size=1024)
    with pytest.raises(MultiPartException, match="Field exceeded maximum size"):
        await parser.parse()
    await stream.aclose()
    assert sum(len(data) for _, data in parser.messages) <= 1024


@pytest.mark.parametrize(
    "charset,value,expected",
    [
        ("utf-8", b"\xc4\x99\xc5\xbc\xc4\x87", "ężć"),
        ("utf-8", b"\xe9", "é"),
        ("invalid-charset", b"\xe9", "é"),
    ],
)
def test_multipart_request_decodes_charset(
    charset: str, value: bytes, expected: str, test_client_factory: TestClientFactory
) -> None:
    content = b'--boundary\r\nContent-Disposition: form-data; name="value"\r\n\r\n' + value + b"\r\n--boundary--\r\n"
    client = test_client_factory(app)
    response = client.post(
        "/",
        content=content,
        headers={"Content-Type": f"multipart/form-data; charset={charset}; boundary=boundary"},
    )
    assert response.status_code == 200
    assert response.json() == {"value": expected}


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_missing_boundary_parameter(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    with expectation:
        res = client.post(
            "/",
            data=(
                # file
                b'Content-Disposition: form-data; name="file"; filename="\xe6\x96\x87\xe6\x9b\xb8.txt"\r\n'  # type: ignore
                b"Content-Type: text/plain\r\n\r\n"
                b"<file content>\r\n"
            ),
            headers={"Content-Type": "multipart/form-data; charset=utf-8"},
        )
        assert res.status_code == 400
        assert res.text == "Missing boundary in multipart."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_multipart_boundary_exceeds_limit(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    boundary = "X" * 257
    with expectation:
        response = client.post(
            "/",
            content=f"--{boundary}\r\n\r\n--{boundary}--\r\n".encode(),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert response.status_code == 400
        assert response.text == "Invalid multipart data."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_multipart_headers_exceed_limit(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    extra_headers = b"".join(f"X-Extra-{index}: value\r\n".encode() for index in range(8))
    with expectation:
        response = client.post(
            "/",
            content=(
                b"--boundary\r\n"
                b'Content-Disposition: form-data; name="field"\r\n' + extra_headers + b"\r\nvalue\r\n--boundary--\r\n"
            ),
            headers={"Content-Type": "multipart/form-data; boundary=boundary"},
        )
        assert response.status_code == 400
        assert response.text == "Invalid multipart data."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_missing_name_parameter_on_content_disposition(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    with expectation:
        res = client.post(
            "/",
            data=(
                # data
                b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
                b'Content-Disposition: form-data; ="field0"\r\n\r\n'
                b"value0\r\n"
            ),
            headers={"Content-Type": ("multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
        )
        assert res.status_code == 400
        assert res.text == 'The Content-Disposition header field "name" must be provided.'


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_fields_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        fields.append(f'--B\r\nContent-Disposition: form-data; name="N{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many fields. Maximum number of fields is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_files_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        fields.append(f'--B\r\nContent-Disposition: form-data; name="N{i}"; filename="F{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_files_single_field_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        # This uses the same field name "N" for all files, equivalent to a
        # multifile upload form field
        fields.append(f'--B\r\nContent-Disposition: form-data; name="N"; filename="F{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_files_and_fields_raise(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        fields.append(f'--B\r\nContent-Disposition: form-data; name="F{i}"; filename="F{i}";\r\n\r\n\r\n')
        fields.append(f'--B\r\nContent-Disposition: form-data; name="N{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_fields=1), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_fields=1))]),
            does_not_raise(),
        ),
    ],
)
def test_max_fields_is_customizable_low_raises(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(2):
        fields.append(f'--B\r\nContent-Disposition: form-data; name="N{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many fields. Maximum number of fields is 1."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_files=1), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_files=1))]),
            does_not_raise(),
        ),
    ],
)
def test_max_files_is_customizable_low_raises(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(2):
        fields.append(f'--B\r\nContent-Disposition: form-data; name="F{i}"; filename="F{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1."


def test_max_fields_is_customizable_high(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(make_app_max_parts(max_fields=2000, max_files=2000))
    fields = []
    for i in range(2000):
        fields.append(f'--B\r\nContent-Disposition: form-data; name="N{i}";\r\n\r\n\r\n')
        fields.append(f'--B\r\nContent-Disposition: form-data; name="F{i}"; filename="F{i}";\r\n\r\n\r\n')
    data = "".join(fields).encode("utf-8")
    data += b"--B--\r\n"
    res = client.post(
        "/",
        data=data,  # type: ignore
        headers={"Content-Type": ("multipart/form-data; boundary=B")},
    )
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["N1999"] == ""
    assert res_data["F1999"] == {
        "filename": "F1999",
        "size": 0,
        "content": "",
        "content_type": None,
    }


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_max_part_size_exceeds_limit(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    boundary = "------------------------4K1ON9fZkj9uCUmqLHRbbR"

    multipart_data = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="small"\r\n\r\n'
        "small content\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="large"\r\n\r\n'
        + ("x" * 1024 * 1024 + "x")  # 1MB + 1 byte of data
        + "\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Transfer-Encoding": "chunked",
    }

    with expectation:
        response = client.post("/", data=multipart_data, headers=headers)  # type: ignore
        assert response.status_code == 400
        assert response.text == "Part exceeded maximum size of 1024KB."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_part_size=1024 * 10), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_part_size=1024 * 10))]),
            does_not_raise(),
        ),
    ],
)
def test_max_part_size_exceeds_custom_limit(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    boundary = "------------------------4K1ON9fZkj9uCUmqLHRbbR"

    multipart_data = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="small"\r\n\r\n'
        "small content\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="large"\r\n\r\n'
        + ("x" * 1024 * 10 + "x")  # 1MB + 1 byte of data
        + "\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Transfer-Encoding": "chunked",
    }

    with expectation:
        response = client.post("/", content=multipart_data, headers=headers)
        assert response.status_code == 400
        assert response.text == "Part exceeded maximum size of 10KB."


@pytest.mark.anyio
async def test_multipart_closes_tempfile_on_stream_error() -> None:
    async def stream() -> AsyncGenerator[bytes, None]:
        yield (
            b"--boundary\r\n"
            b'Content-Disposition: form-data; name="file"; filename="example.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"content"
        )
        raise RuntimeError("stream failed")

    parser = MultiPartParser(
        Headers({"Content-Type": "multipart/form-data; boundary=boundary"}),
        stream(),
    )
    tempfile = SpooledTemporaryFile[bytes]()

    with (
        mock.patch("starlette.formparsers.SpooledTemporaryFile", return_value=tempfile),
        pytest.raises(RuntimeError, match="stream failed"),
    ):
        await parser.parse()

    assert tempfile.closed


def test_multipart_closes_tempfile_on_oserror(
    test_client_factory: TestClientFactory,
) -> None:
    """Temporary files must be closed when an OSError (e.g. disk full) is raised during parsing."""
    close_called = False

    class FailingSpooledTemporaryFile(SpooledTemporaryFile[bytes]):
        def write(self, s: Any) -> int:
            raise OSError("disk full")

        def close(self) -> None:
            nonlocal close_called
            close_called = True
            super().close()

    async def error_app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        with mock.patch("starlette.formparsers.SpooledTemporaryFile", FailingSpooledTemporaryFile):
            await request.form()

    client = test_client_factory(error_app)
    boundary = "a7f7ac8d4e2e437c877bb7b8d7cc549c"
    content = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
        f"file content\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}

    with pytest.raises(OSError, match="disk full"):
        client.post("/", content=content, headers=headers)

    assert close_called


def make_app_form_limits(max_file_size: int | None = None, max_total_size: int | None = None) -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        data = await request.form(max_file_size=max_file_size, max_total_size=max_total_size)
        output: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, UploadFile):
                content = await value.read()
                output[key] = {"filename": value.filename, "size": value.size, "content": content.decode()}
            else:
                output[key] = value
        await request.close()
        response = JSONResponse(output)
        await response(scope, receive, send)

    return app


def two_part_body() -> bytes:
    return (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n"
        b"12345\r\n"
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="field"\r\n\r\n'
        b"abcde\r\n"
        b"--boundary--\r\n"
    )


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_form_limits(max_file_size=10), pytest.raises(FormLimitExceeded)),
        (
            Starlette(routes=[Mount("/", app=make_app_form_limits(max_file_size=10))]),
            does_not_raise(),
        ),
    ],
)
def test_max_file_size_exceeded(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n'
        b"0123456789X\r\n"  # 11 bytes, one over the 10 byte limit
        b"--boundary--\r\n"
    )
    with expectation:
        response = client.post("/", content=body, headers={"Content-Type": "multipart/form-data; boundary=boundary"})
        assert response.status_code == 413
        assert response.text == "File exceeded maximum size of 10 bytes."


def test_max_file_size_exact_limit_ok(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(Starlette(routes=[Mount("/", app=make_app_form_limits(max_file_size=10))]))
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n'
        b"0123456789\r\n"  # exactly 10 bytes
        b"--boundary--\r\n"
    )
    response = client.post("/", content=body, headers={"Content-Type": "multipart/form-data; boundary=boundary"})
    assert response.status_code == 200
    assert response.json() == {"file": {"filename": "a.txt", "size": 10, "content": "0123456789"}}


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_form_limits(max_total_size=9), pytest.raises(FormLimitExceeded)),
        (
            Starlette(routes=[Mount("/", app=make_app_form_limits(max_total_size=9))]),
            does_not_raise(),
        ),
    ],
)
def test_max_total_size_exceeded(
    app: ASGIApp,
    expectation: AbstractContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    # The two parts carry 10 content bytes in total (5 file + 5 field),
    # one over the 9 byte budget.
    client = test_client_factory(app)
    with expectation:
        response = client.post(
            "/", content=two_part_body(), headers={"Content-Type": "multipart/form-data; boundary=boundary"}
        )
        assert response.status_code == 413
        assert response.text == "Form exceeded maximum total size of 9 bytes."


def test_max_total_size_exact_limit_ok(test_client_factory: TestClientFactory) -> None:
    # The budget only counts part content (10 bytes here), so the multipart
    # boundaries and headers that make the raw body much larger are ignored.
    client = test_client_factory(Starlette(routes=[Mount("/", app=make_app_form_limits(max_total_size=10))]))
    response = client.post(
        "/", content=two_part_body(), headers={"Content-Type": "multipart/form-data; boundary=boundary"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "file": {"filename": "a.txt", "size": 5, "content": "12345"},
        "field": "abcde",
    }


def test_max_total_size_accumulates_across_files(test_client_factory: TestClientFactory) -> None:
    # Each file is within the per-file limit, but together they exceed the
    # cumulative form budget.
    client = test_client_factory(
        Starlette(routes=[Mount("/", app=make_app_form_limits(max_file_size=10, max_total_size=15))])
    )
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file1"; filename="a.txt"\r\n\r\n'
        b"0123456789\r\n"
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file2"; filename="b.txt"\r\n\r\n'
        b"0123456789\r\n"
        b"--boundary--\r\n"
    )
    response = client.post("/", content=body, headers={"Content-Type": "multipart/form-data; boundary=boundary"})
    assert response.status_code == 413
    assert response.text == "Form exceeded maximum total size of 15 bytes."


@pytest.mark.anyio
async def test_multipart_limits_with_chunks_split_at_boundaries() -> None:
    # Feed the parser with every possible two-chunk split of the body, so
    # chunks repeatedly fall exactly on part boundaries.
    body = two_part_body()
    headers = Headers({"Content-Type": "multipart/form-data; boundary=boundary"})
    for split in range(1, len(body)):

        async def stream() -> AsyncGenerator[bytes, None]:
            yield body[:split]
            yield body[split:]

        parser_stream = stream()
        parser = MultiPartParser(headers, parser_stream, max_total_size=10, max_file_size=5)
        form = await parser.parse()
        upload = form["file"]
        assert isinstance(upload, UploadFile)
        assert await upload.read() == b"12345"
        assert form["field"] == "abcde"
        await form.close()
        await parser_stream.aclose()

        parser_stream = stream()
        parser = MultiPartParser(headers, parser_stream, max_total_size=9)
        with pytest.raises(FormLimitExceeded, match="Form exceeded maximum total size of 9 bytes."):
            await parser.parse()
        await parser_stream.aclose()


@pytest.mark.anyio
async def test_multipart_limit_stops_consuming_stream() -> None:
    # A single chunk carries multiple parts; once the budget is exceeded the
    # parser must not pull any further chunks from the stream.
    pulled = 0

    async def stream() -> AsyncGenerator[bytes, None]:
        nonlocal pulled
        pulled += 1
        yield two_part_body()
        pulled += 1
        yield b"this chunk must never be consumed"

    headers = Headers({"Content-Type": "multipart/form-data; boundary=boundary"})
    parser_stream = stream()
    parser = MultiPartParser(headers, parser_stream, max_total_size=9)
    with pytest.raises(FormLimitExceeded, match="Form exceeded maximum total size of 9 bytes."):
        await parser.parse()
    assert pulled == 1
    await parser_stream.aclose()


@pytest.mark.anyio
async def test_multipart_limit_closes_all_tempfiles() -> None:
    # When the second file exceeds the per-file limit, the temporary files of
    # both the incomplete part and the already completed part must be closed.
    created: list[SpooledTemporaryFile[bytes]] = []
    real_spooled_temporary_file = SpooledTemporaryFile

    def factory(*args: Any, **kwargs: Any) -> SpooledTemporaryFile[bytes]:
        file = real_spooled_temporary_file(*args, **kwargs)
        created.append(file)
        return file

    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file1"; filename="a.txt"\r\n\r\n'
        b"aaa\r\n"
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file2"; filename="b.txt"\r\n\r\n'
        b"0123456789X\r\n"
        b"--boundary--\r\n"
    )

    async def stream() -> AsyncGenerator[bytes, None]:
        yield body

    headers = Headers({"Content-Type": "multipart/form-data; boundary=boundary"})
    parser_stream = stream()
    parser = MultiPartParser(headers, parser_stream, max_file_size=10)
    with (
        mock.patch("starlette.formparsers.SpooledTemporaryFile", factory),
        pytest.raises(FormLimitExceeded, match="File exceeded maximum size of 10 bytes."),
    ):
        await parser.parse()
    assert len(created) == 2
    assert all(file.closed for file in created)
    await parser_stream.aclose()


@pytest.mark.anyio
async def test_multipart_invalid_data_closes_tempfiles() -> None:
    # A parse error (FormParserError from python-multipart) must close the
    # temporary files created for parts that already completed.
    extra_headers = b"".join(f"X-Extra-{index}: value\r\n".encode() for index in range(8))
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\n'
        b"content\r\n"
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="field"\r\n' + extra_headers + b"\r\nvalue\r\n"
        b"--boundary--\r\n"
    )

    async def stream() -> AsyncGenerator[bytes, None]:
        yield body

    headers = Headers({"Content-Type": "multipart/form-data; boundary=boundary"})
    parser_stream = stream()
    parser = MultiPartParser(headers, parser_stream)
    tempfile = SpooledTemporaryFile[bytes]()
    with (
        mock.patch("starlette.formparsers.SpooledTemporaryFile", return_value=tempfile),
        pytest.raises(MultiPartException, match="Invalid multipart data."),
    ):
        await parser.parse()
    assert tempfile.closed
    await parser_stream.aclose()


@pytest.mark.anyio
async def test_multipart_cancellation_closes_tempfiles() -> None:
    # If the caller is cancelled while the upload stream is being consumed,
    # the temporary files created so far must be closed.
    cancelled_exc: BaseException | None = None
    with anyio.CancelScope() as cancel_scope:
        cancel_scope.cancel()
        try:
            await anyio.sleep(0)
        except anyio.get_cancelled_exc_class() as exc:
            cancelled_exc = exc
    assert cancelled_exc is not None

    async def stream() -> AsyncGenerator[bytes, None]:
        yield (b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\npartial content')
        raise cancelled_exc

    headers = Headers({"Content-Type": "multipart/form-data; boundary=boundary"})
    parser_stream = stream()
    parser = MultiPartParser(headers, parser_stream)
    tempfile = SpooledTemporaryFile[bytes]()
    with (
        mock.patch("starlette.formparsers.SpooledTemporaryFile", return_value=tempfile),
        pytest.raises(anyio.get_cancelled_exc_class()),
    ):
        await parser.parse()
    assert tempfile.closed
    await parser_stream.aclose()


@pytest.mark.anyio
async def test_urlencoded_max_total_size() -> None:
    headers = Headers({"content-type": "application/x-www-form-urlencoded"})

    async def stream() -> AsyncGenerator[bytes, None]:
        yield b"field=value"
        yield b""

    # The field name and value content add up to exactly 10 bytes.
    parser_stream = stream()
    parser = FormParser(headers, parser_stream, max_total_size=10)
    form = await parser.parse()
    assert form["field"] == "value"
    await parser_stream.aclose()

    parser_stream = stream()
    parser = FormParser(headers, parser_stream, max_total_size=9)
    with pytest.raises(FormLimitExceeded, match="Form exceeded maximum total size of 9 bytes."):
        await parser.parse()
    await parser_stream.aclose()


def test_urlencoded_max_total_size_exceeded_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        await request.form(max_total_size=9)

    client = test_client_factory(Starlette(routes=[Mount("/", app=app)]))
    response = client.post(
        "/",
        content=b"field=value",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413
    assert response.text == "Form exceeded maximum total size of 9 bytes."
