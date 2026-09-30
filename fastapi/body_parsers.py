"""Request body parser registration helpers."""

import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from email.message import Message
from typing import Any

from starlette.concurrency import run_in_threadpool


@dataclass(frozen=True, slots=True)
class MediaType:
    maintype: str
    subtype: str
    parameters: Mapping[str, str]

    @property
    def value(self) -> str:
        return f"{self.maintype}/{self.subtype}"


BodyDecoder = Callable[[bytes, MediaType], Any | Awaitable[Any]]

_MEDIA_TYPE_RE = re.compile(
    r"^([^\s/()<>@,;:\\\"\[\]?={}]+)/([^\s/()<>@,;:\\\"\[\]?={}]+)"
    r"(?:\s*;\s*[^\s=;]+=(?:[^;\"]+|\"(?:[^\\\"]|\\.)*\"))*\s*$"
)


def parse_media_type(value: str | None) -> MediaType | None:
    if not value:
        return None
    match = _MEDIA_TYPE_RE.match(value.strip())
    if match is None:
        return None
    message = Message()
    message["content-type"] = value
    maintype = message.get_content_maintype().lower()
    subtype = message.get_content_subtype().lower()
    parameters = {
        key.lower(): value
        for key, value in message.get_params() or []
        if key != message.get_content_type()
    }
    return MediaType(maintype=maintype, subtype=subtype, parameters=parameters)


def decode_json(body: bytes, media_type: MediaType) -> Any:
    return json.loads(body)


DEFAULT_BODY_DECODERS: dict[str, BodyDecoder] = {
    "application/json": decode_json,
}


class BodyDecoderRegistry:
    def __init__(self) -> None:
        self._decoders: dict[str, BodyDecoder] = dict(DEFAULT_BODY_DECODERS)

    def register(self, media_type: str, decoder: BodyDecoder) -> None:
        self._decoders[media_type.lower()] = decoder

    def get(self, media_type: MediaType) -> BodyDecoder | None:
        value = media_type.value
        decoder = self._decoders.get(value)
        if decoder is not None:
            return decoder
        if media_type.maintype == "application" and (
            media_type.subtype == "json" or media_type.subtype.endswith("+json")
        ):
            return decode_json
        if media_type.maintype == "application" and "+" in media_type.subtype:
            suffix = media_type.subtype.rsplit("+", 1)[1]
            return self._decoders.get(f"application/{suffix}")
        return None


async def call_body_decoder(
    decoder: BodyDecoder, body: bytes, media_type: MediaType
) -> Any:
    from fastapi.dependencies.models import _is_coroutine_callable

    if _is_coroutine_callable(decoder):
        return await decoder(body, media_type)
    return await run_in_threadpool(decoder, body, media_type)
