from __future__ import annotations

import socket
import struct

import pytest

from hypercorn.config import Config
from hypercorn.proxy_protocol import (
    ProxyProtocolError,
    ProxyProtocolNegotiator,
    ProxyProtocolParser,
    SIGNATURE,
    proxy_protocol_scope_extension,
)


def ipv4_header(tlvs: bytes = b"", length: int | None = None) -> bytes:
    address = struct.pack(
        "!4s4sHH",
        socket.inet_aton("203.0.113.1"),
        socket.inet_aton("198.51.100.1"),
        5678,
        443,
    )
    payload = address + tlvs
    return (
        SIGNATURE
        + bytes([0x21, 0x11])
        + struct.pack("!H", len(payload) if length is None else length)
        + payload
    )


def test_parse_ipv4_with_tlv_and_remainder() -> None:
    tlv = bytes([0x01]) + struct.pack("!H", 2) + b"h2"
    remainder = b"PRI * HTTP/2.0\r\n\r\nSM"
    parser = ProxyProtocolParser()

    result = parser.feed(ipv4_header(tlv) + remainder)

    assert result is not None
    data, parsed_remainder = result
    assert data.command == "proxy"
    assert data.address_family == "ipv4"
    assert data.transport_protocol == "stream"
    assert data.client == ("203.0.113.1", 5678)
    assert data.server == ("198.51.100.1", 443)
    assert data.tlvs == {1: b"h2"}
    assert parsed_remainder == remainder


def test_parse_header_split_arbitrarily() -> None:
    header = ipv4_header()
    request = b"GET / HTTP/1.1\r\n\r\n"

    for split in range(len(header)):
        parser = ProxyProtocolParser()
        result = parser.feed(header[:split])
        if split < len(header):
            assert result is None
            result = parser.feed(header[split:] + request)

        assert result is not None
        assert result[0].client == ("203.0.113.1", 5678)
        assert result[1] == request


def test_parse_ipv6() -> None:
    payload = struct.pack(
        "!16s16sHH",
        socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
        socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
        5678,
        443,
    )
    header = SIGNATURE + bytes([0x21, 0x21]) + struct.pack("!H", len(payload)) + payload

    data, remainder = ProxyProtocolParser().feed(header)  # type: ignore[misc]

    assert data.client == ("2001:db8::1", 5678)
    assert data.server == ("2001:db8::2", 443)
    assert remainder == b""


def test_parse_local_with_tlv() -> None:
    tlv = bytes([0x30]) + struct.pack("!H", 3) + b"net"
    header = SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", len(tlv)) + tlv

    data, _ = ProxyProtocolParser().feed(header)  # type: ignore[misc]

    assert data.command == "local"
    assert data.address_family == "unspecified"
    assert data.transport_protocol == "unspecified"
    assert data.client is None
    assert data.server is None
    assert data.tlvs == {0x30: b"net"}


@pytest.mark.parametrize(
        ("header", "message"),
        [
            (b"not a proxy protocol header", "signature"),
            (SIGNATURE + bytes([0x22, 0x00]) + b"\x00\x00", "command"),
            (SIGNATURE + bytes([0x20, 0x11]) + b"\x00\x00", "LOCAL"),
            (SIGNATURE + bytes([0x21, 0x00]) + b"\x00\x00", "IPv4 and IPv6"),
            (ipv4_header(b"\x01", 13), "TLV"),
            (
                ipv4_header(bytes([0x01]) + struct.pack("!H", 10), 15),
                "TLV",
            ),
        ],
    )
def test_invalid_headers_are_rejected(header: bytes, message: str) -> None:
    with pytest.raises(ProxyProtocolError, match=message):
        ProxyProtocolParser().feed(header)


def test_untrusted_negotiator_accepts_normal_data() -> None:
    request = b"GET / HTTP/1.1\r\n\r\n"
    assert ProxyProtocolNegotiator(False).feed(request) == (None, request)


def test_untrusted_negotiator_rejects_proxy_signature() -> None:
    with pytest.raises(ProxyProtocolError, match="untrusted"):
        ProxyProtocolNegotiator(False).feed(ipv4_header())


def test_trusted_sources() -> None:
    config = Config()
    config.proxy_protocol_trusted_sources = ["127.0.0.0/8", "::1"]

    assert config.is_trusted_proxy_protocol_source(("127.0.0.1", 1234))
    assert config.is_trusted_proxy_protocol_source(("::1", 1234))
    assert not config.is_trusted_proxy_protocol_source(("10.0.0.1", 1234))


def test_scope_extension() -> None:
    data, _ = ProxyProtocolParser().feed(ipv4_header())  # type: ignore[misc]

    extension = proxy_protocol_scope_extension(data)["hypercorn.proxy_protocol"]

    assert extension["client"] == ("203.0.113.1", 5678)
    assert extension["tlvs"] == {}
