import json
from collections.abc import Awaitable, Callable, Mapping

RequestBodyDecoder = Callable[
    [bytes, str, Mapping[str, str]], object | Awaitable[object]
]


class DefaultRequestBodyDecoders(dict[str, RequestBodyDecoder]):
    def get(self, key: object, default: object = None) -> object:
        decoder = super().get(key, default)
        if decoder is default and isinstance(key, str) and matches_json_media_type(key):
            return decode_json_request_body
        return decoder


async def decode_json_request_body(
    body: bytes, media_type: str, media_type_params: Mapping[str, str]
) -> object:
    try:
        return json.loads(body.decode(media_type_params.get("charset", "utf-8")))
    except (LookupError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise exc from None


def matches_json_media_type(media_type: str) -> bool:
    return media_type == "application/json" or media_type.endswith("+json")


def get_default_request_body_decoders() -> dict[str, RequestBodyDecoder]:
    return DefaultRequestBodyDecoders({"application/json": decode_json_request_body})
