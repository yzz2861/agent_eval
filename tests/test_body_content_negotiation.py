import xml.etree.ElementTree as ET
from typing import Annotated

from fastapi import Body, Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


class JsonItem(BaseModel):
    name: str


class XmlItem(BaseModel):
    title: str


def parse_xml_item(body: bytes, media_type):
    root = ET.fromstring(body)
    if media_type.parameters.get("charset", "utf-8").lower() != "utf-8":
        raise ValueError("unsupported charset")
    return {"title": root.attrib.get("title")}


def create_app(*, strict_content_type: bool = True):
    app = FastAPI(strict_content_type=strict_content_type)
    app.add_body_decoder("application/xml", parse_xml_item)

    item_body = Body(
        media_types={
            "application/json": JsonItem,
            "application/xml": XmlItem,
        }
    )

    def shared_dependency(item: Annotated[JsonItem | XmlItem, item_body]):
        return item

    @app.post("/items")
    def create_item(
        item: Annotated[JsonItem | XmlItem, item_body],
        shared: Annotated[JsonItem | XmlItem, Depends(shared_dependency)],
    ):
        return {"same": item is shared, "item": item}

    return app


client = TestClient(create_app())


def test_json_content_type_selects_json_model():
    response = client.post("/items", json={"name": "Pen"})
    assert response.status_code == 200, response.text
    assert response.json() == {"same": True, "item": {"name": "Pen"}}


def test_xml_content_type_parameters_select_xml_model():
    response = client.post(
        "/items",
        content='<item title="Pen" />',
        headers={"content-type": 'application/xml; charset="utf-8"; version=1'},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"same": True, "item": {"title": "Pen"}}


def test_structured_xml_suffix_uses_registered_xml_decoder():
    suffix_app = FastAPI()
    suffix_app.add_body_decoder("application/xml", parse_xml_item)

    @suffix_app.post("/items")
    def create_suffix_item(
        item: Annotated[
            JsonItem | XmlItem,
            Body(
                media_types={
                    "application/json": JsonItem,
                    "application/vnd.example+xml": XmlItem,
                }
            ),
        ],
    ):
        return item

    suffix_client = TestClient(suffix_app)
    response = suffix_client.post(
        "/items",
        content='<item title="Pen" />',
        headers={"content-type": "application/vnd.example+xml; charset=UTF-8"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"title": "Pen"}


def test_unsupported_content_type_returns_415():
    response = client.post(
        "/items",
        content='{"name": "Pen"}',
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 415, response.text


def test_invalid_content_type_returns_415():
    response = client.post(
        "/items",
        content='{"name": "Pen"}',
        headers={"content-type": "application/"},
    )
    assert response.status_code == 415, response.text


def test_missing_content_type_returns_415_under_strict_declaration():
    response = client.post("/items", content='{"name": "Pen"}')
    assert response.status_code == 415, response.text


def test_malformed_json_is_distinct_from_field_validation():
    response = client.post(
        "/items",
        content="{broken",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"][0]["type"] == "json_invalid"


def test_malformed_xml_returns_decode_error():
    response = client.post(
        "/items",
        content="<item",
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 400, response.text


def test_field_validation_error_returns_422_for_each_model():
    response = client.post(
        "/items", json={}, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"] == ["body", "name"]

    response = client.post(
        "/items",
        content="<item />",
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"] == ["body", "title"]


def test_required_empty_body_missing_content_type_is_missing_field_error():
    response = client.post("/items", content="")
    assert response.status_code == 422, response.text
    assert response.json()["detail"][0]["loc"] == ["body"]


def test_optional_empty_body_uses_declared_default():
    optional_app = FastAPI()

    @optional_app.post("/optional")
    def optional_item(
        item: Annotated[
            JsonItem | None,
            Body(
                media_types={
                    "application/json": JsonItem,
                    "application/xml": XmlItem,
                },
            ),
        ] = None,
    ):
        return item

    response = TestClient(optional_app).post("/optional", content="")
    assert response.status_code == 200, response.text
    assert response.json() is None


def test_openapi_lists_each_schema():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    content = response.json()["paths"]["/items"]["post"]["requestBody"]["content"]
    assert set(content) == {"application/json", "application/xml"}
    assert content["application/json"]["schema"] == {
        "$ref": "#/components/schemas/JsonItem"
    }
    assert content["application/xml"]["schema"] == {
        "$ref": "#/components/schemas/XmlItem"
    }


def test_multiple_body_fields_use_matching_media_type_models():
    class JsonExtra(BaseModel):
        count: int

    class XmlExtra(BaseModel):
        number: int

    multi_app = FastAPI()
    multi_app.add_body_decoder("application/xml", parse_xml_item)

    @multi_app.post("/multi")
    def create_multi(
        item: Annotated[
            JsonItem | XmlItem,
            Body(
                media_types={
                    "application/json": JsonItem,
                    "application/xml": XmlItem,
                }
            ),
        ],
        extra: Annotated[
            JsonExtra | XmlExtra,
            Body(
                media_types={
                    "application/json": JsonExtra,
                    "application/xml": XmlExtra,
                }
            ),
        ],
    ):
        return {"item": item, "extra": extra}

    multi_client = TestClient(multi_app)
    response = multi_client.post(
        "/multi",
        json={"item": {"name": "Pen"}, "extra": {"count": 1}},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "item": {"name": "Pen"},
        "extra": {"count": 1},
    }

    response = multi_client.post(
        "/multi",
        content="<ignore />",
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 422, response.text

    schema = multi_client.get("/openapi.json").json()["paths"]["/multi"]["post"][
        "requestBody"
    ]["content"]
    assert set(schema) == {"application/json", "application/xml"}
    assert (
        "Body_create_multi_multi_post_application_json"
        in schema["application/json"]["schema"]["$ref"]
    )
    assert (
        "Body_create_multi_multi_post_application_xml"
        in schema["application/xml"]["schema"]["$ref"]
    )


def test_lax_app_without_content_type_uses_json_declaration():
    lax_client = TestClient(create_app(strict_content_type=False))
    response = lax_client.post("/items", json={"name": "Pen"})
    assert response.status_code == 200, response.text


def test_decoder_is_called_once(monkeypatch):
    app = create_app()
    calls = 0
    original = parse_xml_item

    def counted(body, media_type):
        nonlocal calls
        calls += 1
        return original(body, media_type)

    app.add_body_decoder("application/xml", counted)
    counted_client = TestClient(app)
    response = counted_client.post(
        "/items",
        content='<item title="Pen" />',
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 200, response.text
    assert calls == 1
