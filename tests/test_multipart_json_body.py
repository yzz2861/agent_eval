import pytest
from fastapi import Body, Depends, FastAPI, Form, UploadFile
from fastapi.testclient import TestClient
from pydantic import BaseModel
from starlette.datastructures import UploadFile as StarletteUploadFile


class Metadata(BaseModel):
    name: str
    age: int


app = FastAPI()


@app.post("/items")
async def create_item(
    file: UploadFile,
    metadata: Metadata = Body(),
    note: str = Form(),
):
    return {
        "filename": file.filename,
        "name": metadata.name,
        "age": metadata.age,
        "note": note,
    }


@app.post("/nullable-items")
async def create_nullable_item(
    file: UploadFile,
    metadata: Metadata | None = Body(...),
):
    return {"metadata": metadata}


@app.post("/required-items")
async def create_required_item(
    file: UploadFile,
    metadata: Metadata = Body(),
):
    return {"metadata": metadata}


def metadata_dependency(metadata: Metadata = Body()) -> Metadata:
    return metadata


@app.post("/dependency-items")
async def create_dependency_item(
    file: UploadFile,
    metadata: Metadata = Depends(metadata_dependency),
    note: str = Form(),
):
    return {
        "filename": file.filename,
        "name": metadata.name,
        "age": metadata.age,
        "note": note,
    }


client = TestClient(app)


def _multipart_body(
    order: tuple[str, ...], metadata: bytes = b'{"name": "Sara", "age": 20}'
):
    part_payloads: list[bytes] = []
    for part_name in order:
        headers: list[bytes]
        if part_name == "metadata":
            headers = [
                b'Content-Disposition: form-data; name="metadata"',
                b"Content-Type: application/json; charset=utf-8",
            ]
        elif part_name == "file":
            headers = [
                b'Content-Disposition: form-data; name="file"; filename="item.txt"',
                b"Content-Type: text/plain",
            ]
        else:
            headers = [b'Content-Disposition: form-data; name="note"']
        content = (
            metadata
            if part_name == "metadata"
            else b"file contents"
            if part_name == "file"
            else b"hello"
        )
        part_payloads.append(b"\r\n".join([*headers, b"", content]))
    boundary = b"----FastAPIMultipartJSON"
    body = b"".join(
        b"--" + boundary + b"\r\n" + part_payload + b"\r\n"
        for part_payload in part_payloads
    )
    body += b"--" + boundary + b"--\r\n"
    return boundary, body


def _multipart_file_body(metadata: bytes = b"null"):
    boundary = b"----FastAPIMultipartJSON"
    body = (
        b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="file"; filename="item.txt"\r\n'
        + b"Content-Type: text/plain\r\n\r\n"
        + b"file contents\r\n"
        + b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="metadata"\r\n'
        + b"Content-Type: application/json; charset=utf-8\r\n\r\n"
        + metadata
        + b"\r\n"
        + b"--"
        + boundary
        + b"--\r\n"
    )
    return boundary, body


def _multipart_file_only_body():
    boundary = b"----FastAPIMultipartJSON"
    body = (
        b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="file"; filename="item.txt"\r\n'
        + b"Content-Type: text/plain\r\n\r\n"
        + b"file contents\r\n"
        + b"--"
        + boundary
        + b"--\r\n"
    )
    return boundary, body


@pytest.mark.parametrize(
    "order",
    [
        ("metadata", "file", "note"),
        ("file", "metadata", "note"),
        ("note", "file", "metadata"),
    ],
)
def test_json_body_part_with_file_and_form(order):
    boundary, body = _multipart_body(order, b'{"name": "Sara", "age": 20}')
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "filename": "item.txt",
        "name": "Sara",
        "age": 20,
        "note": "hello",
    }


def test_json_body_part_supports_utf8():
    boundary, body = _multipart_body(
        ("file", "metadata", "note"), '{"name": "Sara✓", "age": 20}'.encode()
    )
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Sara✓"


def test_json_body_part_works_in_dependency():
    boundary, body = _multipart_body(("note", "file", "metadata"))
    response = client.post(
        "/dependency-items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 200, response.text


def test_missing_json_body_part():
    boundary, body = _multipart_body(("file", "note"))
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == [
        {
            "type": "missing",
            "loc": ["body", "metadata"],
            "msg": "Field required",
            "input": None,
        }
    ]


def test_null_json_body_part_is_distinct_from_missing():
    boundary, body = _multipart_file_body(b"null")
    response = client.post(
        "/nullable-items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"metadata": None}

    boundary, body = _multipart_file_only_body()
    response = client.post(
        "/nullable-items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    error = response.json()["detail"][0]
    assert error["loc"] == ["body", "metadata"]
    assert error["type"] == "missing"


def test_required_json_body_part_rejects_null():
    boundary, body = _multipart_file_body(b"null")
    response = client.post(
        "/required-items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "metadata"]
    assert response.json()["detail"][0]["type"] == "model_attributes_type"


def test_invalid_json_error_points_to_part():
    boundary, body = _multipart_body(
        ("file", "metadata", "note"), b'{"name": "Sara", "age": }'
    )
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    error = response.json()["detail"][0]
    assert error["loc"] == ["body", "metadata"]
    assert error["type"] == "json_invalid"


def test_model_validation_error_points_to_field():
    boundary, body = _multipart_body(
        ("file", "metadata", "note"), b'{"name": "Sara", "age": "twenty"}'
    )
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "metadata", "age"]


def test_duplicate_json_body_part_errors_and_closes_file(monkeypatch):
    boundary, _ = _multipart_body(("file", "metadata", "note"))
    closed_files = []
    original_close = StarletteUploadFile.close

    async def close_upload_file(self):
        closed_files.append(self)
        await original_close(self)

    monkeypatch.setattr(StarletteUploadFile, "close", close_upload_file)
    duplicate_metadata = (
        b'Content-Disposition: form-data; name="metadata"\r\n'
        b"Content-Type: application/json\r\n\r\n"
        b'{"name": "Other", "age": 21}\r\n'
    )
    body = (
        b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="file"; filename="item.txt"\r\n'
        + b"Content-Type: text/plain\r\n\r\nfile contents\r\n"
        + b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="metadata"\r\n'
        + b"Content-Type: application/json\r\n\r\n"
        + b'{"name": "Sara", "age": 20}\r\n'
        + b"--"
        + boundary
        + b"\r\n"
        + duplicate_metadata
        + b"--"
        + boundary
        + b"--\r\n"
    )
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "metadata"]
    assert response.json()["detail"][0]["msg"] == "Value error, Duplicate JSON part"
    assert response.json()["detail"][0]["ctx"] == {"error": "Duplicate JSON part"}
    assert len(closed_files) == 1


@pytest.mark.parametrize(
    ("metadata", "expected_loc"),
    [
        (b'{"name": "Sara", "age": }', ["body", "metadata"]),
        (b'{"name": "Sara", "age": "twenty"}', ["body", "metadata", "age"]),
    ],
)
def test_validation_error_closes_uploaded_file(monkeypatch, metadata, expected_loc):
    closed_files = []
    original_close = StarletteUploadFile.close

    async def close_upload_file(self):
        closed_files.append(self)
        await original_close(self)

    monkeypatch.setattr(StarletteUploadFile, "close", close_upload_file)
    boundary, body = _multipart_body(("file", "metadata", "note"), metadata)
    response = client.post(
        "/items",
        content=body,
        headers={"content-type": f"multipart/form-data; boundary={boundary.decode()}"},
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == expected_loc
    assert len(closed_files) == 1


def test_openapi_marks_json_part_encoding():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    media_type = response.json()["paths"]["/items"]["post"]["requestBody"]["content"][
        "multipart/form-data"
    ]
    assert media_type["encoding"]["metadata"] == {"contentType": "application/json"}
    dependency_media_type = response.json()["paths"]["/dependency-items"]["post"][
        "requestBody"
    ]["content"]["multipart/form-data"]
    assert dependency_media_type["encoding"]["metadata"] == {
        "contentType": "application/json"
    }
