"""
Tests for client-registered custom content decoders.
"""

from __future__ import annotations

import typing
import zlib

import pytest

import httpx


class ReverseDecoder(httpx.ContentDecoder):
    """
    Toy decoder for an "x-reverse" encoding, where the content is
    byte-reversed. The decoded content is only emitted on flush(),
    exercising the flush-then-outer-decoder chaining.
    """

    def __init__(self) -> None:
        self._buffer = b""

    def decode(self, data: bytes) -> bytes:
        self._buffer += data
        return b""

    def flush(self) -> bytes:
        data, self._buffer = self._buffer[::-1], b""
        return data


class UpperDecoder(httpx.ContentDecoder):
    """
    Toy decoder for an "x-upper" encoding, decoding to uppercase.
    """

    def decode(self, data: bytes) -> bytes:
        return data.upper()

    def flush(self) -> bytes:
        return b""


class BrokenDecoder(httpx.ContentDecoder):
    """
    A decoder that raises an arbitrary exception while decoding.
    """

    def decode(self, data: bytes) -> bytes:
        raise ValueError("broken decoder")

    def flush(self) -> bytes:
        raise ValueError("broken decoder")


def gzip_compress(body: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(body) + compressor.flush()


def reversed_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Encoding": "x-reverse"},
        content=b"Hello, world!"[::-1],
    )


def test_client_decoders_argument():
    client = httpx.Client(
        transport=httpx.MockTransport(reversed_response),
        decoders={"x-reverse": ReverseDecoder},
    )
    response = client.get("http://example.org/")

    assert response.content == b"Hello, world!"
    assert response.text == "Hello, world!"
    # The registered encoding is included in the default Accept-Encoding.
    assert response.request.headers["Accept-Encoding"] == (
        "gzip, deflate, br, zstd, x-reverse"
    )


def test_register_decoder():
    client = httpx.Client(transport=httpx.MockTransport(reversed_response))
    assert client.headers["Accept-Encoding"] == "gzip, deflate, br, zstd"

    client.register_decoder("x-reverse", ReverseDecoder)
    assert client.headers["Accept-Encoding"] == "gzip, deflate, br, zstd, x-reverse"

    response = client.get("http://example.org/")
    assert response.content == b"Hello, world!"


def test_register_decoder_does_not_override_explicit_accept_encoding():
    client = httpx.Client(
        transport=httpx.MockTransport(reversed_response),
        headers={"Accept-Encoding": "identity"},
    )
    client.register_decoder("x-reverse", ReverseDecoder)
    assert client.headers["Accept-Encoding"] == "identity"


def test_register_decoder_does_not_leak_into_other_clients():
    def upper_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "x-custom"}, content=b"hello"
        )

    def reverse_response(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "x-custom"}, content=b"hello"[::-1]
        )

    upper_client = httpx.Client(
        transport=httpx.MockTransport(upper_response),
        decoders={"x-custom": UpperDecoder},
    )
    reverse_client = httpx.Client(
        transport=httpx.MockTransport(reverse_response),
        decoders={"x-custom": ReverseDecoder},
    )
    plain_client = httpx.Client(transport=httpx.MockTransport(upper_response))

    # The same encoding name resolves to each client's own registration.
    assert upper_client.get("http://example.org/").content == b"HELLO"
    assert reverse_client.get("http://example.org/").content == b"hello"
    # Clients without a registration keep the default behaviour of
    # passing unknown encodings through undecoded.
    assert plain_client.get("http://example.org/").content == b"hello"
    # The module-level defaults are untouched.
    assert "x-custom" not in httpx._decoders.SUPPORTED_DECODERS


def test_request_level_decoder_override():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "x-custom"}, content=b"hello"[::-1]
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-custom": UpperDecoder},
    )

    # The client-level registration applies by default...
    assert client.get("http://example.org/").content == b"OLLEH"

    # ...and a request-level "decoders" extension takes precedence.
    response = client.get(
        "http://example.org/",
        extensions={"decoders": {"x-custom": ReverseDecoder}},
    )
    assert response.content == b"hello"

    # The client-level registration is unaffected by the override.
    assert client.get("http://example.org/").content == b"OLLEH"


def test_request_level_decoder_registration():
    client = httpx.Client(transport=httpx.MockTransport(reversed_response))
    response = client.get(
        "http://example.org/",
        extensions={"decoders": {"x-reverse": ReverseDecoder}},
    )
    assert response.content == b"Hello, world!"


def test_custom_decoder_streaming_and_read_are_consistent():
    def streaming_response(request: httpx.Request) -> httpx.Response:
        def body() -> typing.Iterator[bytes]:
            yield b"Hello, "
            yield b"world!"

        return httpx.Response(
            200,
            headers={"Content-Encoding": "x-reverse"},
            content=reversed_stream(body()),
        )

    def reversed_stream(chunks: typing.Iterator[bytes]) -> typing.Iterator[bytes]:
        # Reverse the overall content, delivered across chunk boundaries.
        content = b"".join(chunks)[::-1]
        yield content[:5]
        yield content[5:]

    client = httpx.Client(
        transport=httpx.MockTransport(streaming_response),
        decoders={"x-reverse": ReverseDecoder},
    )

    with client.stream("GET", "http://example.org/") as response:
        assert b"".join(response.iter_bytes()) == b"Hello, world!"
    with client.stream("GET", "http://example.org/") as response:
        assert response.read() == b"Hello, world!"
    with client.stream("GET", "http://example.org/") as response:
        response.read()
        assert response.text == "Hello, world!"
    with client.stream("GET", "http://example.org/") as response:
        assert b"".join(response.iter_raw()) == b"Hello, world!"[::-1]


def test_multi_decoder_flush_chained_through_outer_decoders():
    # Content-Encoding is listed in the order the encodings were applied,
    # so this content was gzipped first and then byte-reversed.
    # The reversed decoder only emits its output on flush(), and those
    # tail bytes must still pass through the gzip decoder.
    body = b"Hello, world!"
    compressed = gzip_compress(body)[::-1]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip, x-reverse"},
            content=compressed,
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-reverse": ReverseDecoder},
    )
    response = client.get("http://example.org/")
    assert response.content == body


def test_in_flight_response_unaffected_by_later_registration():
    client = httpx.Client(
        transport=httpx.MockTransport(reversed_response),
        decoders={"x-reverse": ReverseDecoder},
    )
    with client.stream("GET", "http://example.org/") as response:
        # Registering a different decoder under the same name must not
        # affect a response that has already been received.
        client.register_decoder("x-reverse", UpperDecoder)
        assert response.read() == b"Hello, world!"

    # Subsequent responses use the new registration.
    response = client.get("http://example.org/")
    assert response.content == b"Hello, world!"[::-1].upper()


def test_custom_decoder_errors_raise_decoding_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "x-broken"}, content=b"Hello, world!"
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        decoders={"x-broken": BrokenDecoder},
    )
    with pytest.raises(httpx.DecodingError) as exc_info:
        client.get("http://example.org/")
    assert isinstance(exc_info.value.__cause__, ValueError)


def test_unknown_encoding_remains_passthrough():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "x-unknown"}, content=b"Hello, world!"
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = client.get("http://example.org/")
    assert response.content == b"Hello, world!"


@pytest.mark.anyio
async def test_async_client_custom_decoder():
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(reversed_response),
        decoders={"x-reverse": ReverseDecoder},
    )
    response = await client.get("http://example.org/")
    assert response.content == b"Hello, world!"
    assert response.request.headers["Accept-Encoding"] == (
        "gzip, deflate, br, zstd, x-reverse"
    )

    async with client.stream("GET", "http://example.org/") as response:
        assert await response.aread() == b"Hello, world!"
