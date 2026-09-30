import xml.etree.ElementTree as ET
from typing import Annotated

from fastapi import Body, Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel


class JsonItem(BaseModel):
    name: str
    value: int


class XmlItem(BaseModel):
    name: str
    value: int


def decode_xml_item(
    body: bytes, media_type: str, media_type_params: dict[str, str]
) -> dict[str, object]:
    charset = media_type_params.get("charset", "utf-8")
    root = ET.fromstring(body.decode(charset))
    return {
        "name": root.findtext("name"),
        "value": root.findtext("value"),
    }


def create_app() -> tuple[FastAPI, list[str]]:
    app = FastAPI()
    app.add_body_decoder("application/xml", decode_xml_item)
    calls: list[str] = []

    original_json_decoder = app.request_body_decoders["application/json"]

    async def counted_json_decoder(
        body: bytes, media_type: str, media_type_params: dict[str, str]
    ) -> object:
        calls.append(media_type)
        return await original_json_decoder(body, media_type, media_type_params)

    def counted_xml_decoder(
        body: bytes, media_type: str, media_type_params: dict[str, str]
    ) -> object:
        calls.append(media_type)
        return decode_xml_item(body, media_type, media_type_params)

    app.request_body_decoders["application/json"] = counted_json_decoder
    app.request_body_decoders["application/xml"] = counted_xml_decoder

    def shared_item(
        item: JsonItem | XmlItem = Body(
            content={
                "application/json": JsonItem,
                "application/xml": XmlItem,
            }
        ),
    ) -> JsonItem | XmlItem:
        return item

    @app.post("/items")
    async def create_item(
        item: JsonItem | XmlItem = Body(
            content={
                "application/json": JsonItem,
                "application/xml": XmlItem,
            }
        ),
        shared: Annotated[JsonItem | XmlItem, Depends(shared_item)] = None,
    ):
        assert item == shared
        assert type(item) is type(shared)
        return {"type": type(item).__name__, "name": item.name, "value": item.value}

    @app.post("/optional-items")
    async def create_optional_item(
        item: JsonItem | XmlItem | None = Body(
            default=None,
            content={
                "application/json": JsonItem,
                "application/xml": XmlItem,
            },
        ),
    ):
        return {"present": item is not None}

    return app, calls


app, decoder_calls = create_app()
client = TestClient(app)

ItemBody = Annotated[
    JsonItem | XmlItem,
    Body(
        content={
            "application/json": JsonItem,
            "application/xml": XmlItem,
        }
    ),
]

lax_app = FastAPI(strict_content_type=False)


@lax_app.post("/items")
async def create_lax_item(
    item: ItemBody,
):
    return {"type": type(item).__name__}


lax_client = TestClient(lax_app)


def test_selects_json_model_and_decoder_once():
    response = client.post("/items", json={"name": "n", "value": 1})
    assert response.status_code == 200, response.text
    assert response.json() == {"type": "JsonItem", "name": "n", "value": 1}
    assert decoder_calls == ["application/json"]


def test_selects_xml_model_with_media_type_params():
    response = client.post(
        "/items",
        content='<?xml version="1.0"?><item><name>n</name><value>1</value></item>',
        headers={"Content-Type": 'application/xml; charset="utf-8"'},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"type": "XmlItem", "name": "n", "value": 1}


def test_json_suffix_content_type_accepts_params():
    response = client.post(
        "/items",
        content=b'{"name":"n","value":1}',
        headers={"Content-Type": "application/vnd.test+json; charset=UTF-8"},
    )
    assert response.status_code == 415


def test_accepts_async_request_body_decoder():
    async_app = FastAPI()

    async def decode_async_xml(
        body: bytes, media_type: str, media_type_params: dict[str, str]
    ) -> dict[str, object]:
        return decode_xml_item(body, media_type, media_type_params)

    async_app.add_body_decoder("application/xml", decode_async_xml)

    @async_app.post("/items")
    async def create_async_item(item: ItemBody):
        return {"type": type(item).__name__}

    async_client = TestClient(async_app)
    response = async_client.post(
        "/items",
        content=b"<item><name>n</name><value>1</value></item>",
        headers={"Content-Type": "application/xml"},
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"type": "XmlItem"}


def test_unsupported_content_type_returns_415():
    response = client.post(
        "/items",
        content=b"name,n\n",
        headers={"Content-Type": "text/csv"},
    )
    assert response.status_code == 415


def test_missing_content_type_returns_415_by_default():
    response = client.post("/items", content=b"{}")
    assert response.status_code == 415


def test_missing_content_type_can_be_declared_lax():
    response = lax_client.post("/items", content=b'{"name":"n","value":1}')
    assert response.status_code == 200, response.text
    assert response.json() == {"type": "JsonItem"}


def test_malformed_content_type_returns_415():
    response = client.post(
        "/items",
        content=b"{}",
        headers={"Content-Type": "application"},
    )
    assert response.status_code == 415


def test_malformed_and_validation_errors_are_distinct():
    malformed_xml = client.post(
        "/items",
        content=b"<item>",
        headers={"Content-Type": "application/xml"},
    )
    assert malformed_xml.status_code == 400

    invalid_xml = client.post(
        "/items",
        content=b"<item><name>n</name><value>bad</value></item>",
        headers={"Content-Type": "application/xml; charset=utf-8"},
    )
    assert invalid_xml.status_code == 422
    error = invalid_xml.json()["detail"][0]
    assert error["loc"] == ["body", "value"]
    assert error["type"] == "int_parsing"


def test_empty_body_policy_comes_from_body_declaration():
    required_response = client.post("/items")
    assert required_response.status_code == 422

    optional_response = client.post("/optional-items")
    assert optional_response.status_code == 200
    assert optional_response.json() == {"present": False}


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
