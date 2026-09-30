import json
import uuid
from typing import Annotated

import pytest
from fastapi import Body, FastAPI, Form, UploadFile
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.datastructures import UploadFile as StarletteUploadFile


class Metadata(BaseModel):
    name: str
    tags: list[str] = []


class OptionalMetadata(BaseModel):
    name: str | None = None


def make_app() -> FastAPI:
    app = FastAPI()

    @app.post("/upload")
    async def upload(
        file: UploadFile,
        metadata: Annotated[Metadata, Body()],
        note: Annotated[str, Form()] = "default note",
    ):
        return {
            "filename": file.filename,
            "content": (await file.read()).decode(),
            "metadata": metadata,
            "note": note,
        }

    @app.post("/optional")
    async def optional(
        file: UploadFile,
        metadata: Annotated[OptionalMetadata | None, Body()] = OptionalMetadata(),
    ):
        return {"metadata": metadata}

    @app.post("/form-json")
    async def form_json(
        metadata: Annotated[Metadata, Body()],
        note: Annotated[str, Form()],
    ):
        return {"metadata": metadata, "note": note}

    return app


TextPart = tuple[str, str]
FilePart = tuple[str, str, str]


def multipart_request(
    parts: list[tuple[str, TextPart | FilePart]],
) -> tuple[dict[str, str], bytes]:
    boundary = f"----fastapi-test-{uuid.uuid4()}"
    body = b""
    for name, part in parts:
        body += f"--{boundary}\r\n".encode()
        if len(part) == 3:
            filename, value, content_type = part
            body += (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n'
            ).encode()
            body += value.encode()
        else:
            value, content_type = part
            body += (
                f'Content-Disposition: form-data; name="{name}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            ).encode()
            body += value.encode()
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body


def multipart_request_without_part_content_type(
    parts: list[tuple[str, tuple[str, str] | tuple[str, str, str]]],
) -> tuple[dict[str, str], bytes]:
    boundary = f"----fastapi-test-{uuid.uuid4()}"
    body = b""
    for name, part in parts:
        body += f"--{boundary}\r\n".encode()
        if len(part) == 3:
            filename, value, _ = part
            body += (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n\r\n'
            ).encode()
            body += value.encode()
        else:
            value, _ = part
            body += (f'Content-Disposition: form-data; name="{name}"\r\n\r\n').encode()
            body += value.encode()
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body


@pytest.mark.parametrize("file_first", [True, False])
def test_json_part_with_file_and_form(file_first: bool) -> None:
    client = TestClient(make_app())
    metadata = {"name": "Mëtàdätà", "tags": ["a", "b"]}
    file_part: tuple[str, FilePart] = (
        "file",
        ("example.txt", "file contents", "text/plain"),
    )
    json_part: tuple[str, TextPart] = (
        "metadata",
        (json.dumps(metadata, ensure_ascii=False), "application/json; charset=utf-8"),
    )
    note_part: tuple[str, TextPart] = ("note", ("custom note", "text/plain"))
    parts = (
        [file_part, json_part, note_part]
        if file_first
        else [
            json_part,
            note_part,
            file_part,
        ]
    )
    headers, request_body = multipart_request(parts)

    response = client.post("/upload", headers=headers, content=request_body)

    assert response.status_code == 200, response.text
    assert response.json() == {
        "filename": "example.txt",
        "content": "file contents",
        "metadata": metadata,
        "note": "custom note",
    }


def test_json_part_without_part_content_type() -> None:
    client = TestClient(make_app())
    headers, request_body = multipart_request_without_part_content_type(
        [
            ("file", ("example.txt", "file", "text/plain")),
            ("metadata", ('{"name": "metadata"}', "application/json")),
        ]
    )

    response = client.post("/upload", headers=headers, content=request_body)

    assert response.status_code == 200, response.text
    assert response.json()["metadata"] == {"name": "metadata", "tags": []}


def test_json_part_validation_error_points_to_model_field() -> None:
    client = TestClient(make_app())
    headers, request_body = multipart_request(
        [
            ("file", ("example.txt", "x", "text/plain")),
            (
                "metadata",
                (json.dumps({"tags": ["a"]}), "application/json"),
            ),
        ]
    )

    response = client.post("/upload", headers=headers, content=request_body)

    assert response.status_code == 422, response.text
    assert response.json()["detail"] == [
        {
            "type": "missing",
            "loc": ["body", "metadata", "name"],
            "msg": "Field required",
            "input": {"tags": ["a"]},
        }
    ]


def test_json_part_with_form_but_no_file() -> None:
    client = TestClient(make_app())
    headers, request_body = multipart_request(
        [
            ("metadata", ('{"name": "metadata"}', "application/json")),
            ("note", ("note", "text/plain")),
        ]
    )

    response = client.post("/form-json", headers=headers, content=request_body)

    assert response.status_code == 200, response.text
    assert response.json() == {
        "metadata": {"name": "metadata", "tags": []},
        "note": "note",
    }
    request_body_schema = make_app().openapi()["paths"]["/form-json"]["post"][
        "requestBody"
    ]["content"]
    assert set(request_body_schema) == {"multipart/form-data"}
    assert request_body_schema["multipart/form-data"]["encoding"] == {
        "metadata": {"contentType": "application/json"}
    }


def test_duplicate_json_part_reports_part() -> None:
    client = TestClient(make_app())
    headers, request_body = multipart_request(
        [
            ("file", ("example.txt", "x", "text/plain")),
            ("metadata", ('{"name": "first"}', "application/json")),
            ("metadata", ('{"name": "second"}', "application/json")),
        ]
    )

    response = client.post("/upload", headers=headers, content=request_body)

    assert response.status_code == 422, response.text
    error = response.json()["detail"][0]
    assert error["loc"] == ["body", "metadata"]
    assert error["input"] == "metadata"
    assert "Duplicate JSON part" in error["msg"]


@pytest.mark.parametrize("payload", ["", "{broken"])
def test_invalid_json_part_reports_json_position(payload: str) -> None:
    client = TestClient(make_app())
    headers, request_body = multipart_request(
        [
            ("file", ("example.txt", "x", "text/plain")),
            ("metadata", (payload, "application/json")),
        ]
    )

    response = client.post("/upload", headers=headers, content=request_body)

    assert response.status_code == 422, response.text
    error = response.json()["detail"][0]
    assert error["type"] == "json_invalid"
    assert error["loc"][:2] == ["body", "metadata"]
    assert error["input"] == payload


def test_missing_and_null_json_part_are_distinct() -> None:
    client = TestClient(make_app())
    missing_headers, missing_body = multipart_request(
        [("file", ("example.txt", "x", "text/plain"))]
    )
    missing = client.post("/upload", headers=missing_headers, content=missing_body)
    null_headers, null_body = multipart_request(
        [
            ("file", ("example.txt", "x", "text/plain")),
            ("metadata", ("null", "application/json")),
        ]
    )
    null = client.post("/upload", headers=null_headers, content=null_body)

    assert missing.status_code == 422
    assert missing.json()["detail"][0] == {
        "type": "missing",
        "loc": ["body", "metadata"],
        "msg": "Field required",
        "input": None,
    }
    assert null.status_code == 422
    assert null.json()["detail"][0]["type"] == "model_attributes_type"
    assert null.json()["detail"][0]["loc"] == ["body", "metadata"]


def test_optional_json_part_default_and_explicit_null() -> None:
    client = TestClient(make_app())
    default_headers, default_body = multipart_request(
        [("file", ("example.txt", "x", "text/plain"))]
    )
    default_response = client.post(
        "/optional", headers=default_headers, content=default_body
    )
    null_headers, null_body = multipart_request(
        [
            ("file", ("example.txt", "x", "text/plain")),
            ("metadata", ("null", "application/json")),
        ]
    )
    null_response = client.post("/optional", headers=null_headers, content=null_body)

    assert default_response.status_code == 200, default_response.text
    assert default_response.json() == {"metadata": {"name": None}}
    assert null_response.status_code == 200, null_response.text
    assert null_response.json() == {"metadata": None}


def test_validation_error_closes_created_upload_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str | None] = []
    original_close = StarletteUploadFile.close

    async def close(self: StarletteUploadFile) -> None:
        closed.append(self.filename)
        await original_close(self)

    monkeypatch.setattr(StarletteUploadFile, "close", close)
    client = TestClient(make_app())
    headers, request_body = multipart_request(
        [
            ("file", ("example.txt", "x", "text/plain")),
            ("metadata", ("not json", "application/json")),
        ]
    )

    response = client.post("/upload", headers=headers, content=request_body)

    assert response.status_code == 422
    assert closed == ["example.txt"]


def test_openapi_encoding_marks_json_part() -> None:
    openapi = make_app().openapi()
    request_body = openapi["paths"]["/upload"]["post"]["requestBody"]

    assert request_body["content"]["multipart/form-data"]["encoding"] == {
        "metadata": {"contentType": "application/json"}
    }
