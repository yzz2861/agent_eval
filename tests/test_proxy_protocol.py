from __future__ import annotations

import struct

import pytest

from hypercorn.proxy_protocol import (
    MAX_HEADER_LENGTH,
    ProxyProtocolError,
    ProxyProtocolParser,
    crc32c,
    is_trusted_source,
)

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def header(command: int, family_protocol: int, address_block: bytes) -> bytes:
    return (
        SIGNATURE
        + bytes([0x20 | command, family_protocol])
        + struct.pack("!H", len(address_block))
        + address_block
    )


def ipv4_block(
    source: str = "192.168.0.1",
    destination: str = "10.0.0.1",
    source_port: int = 12345,
    destination_port: int = 443,
    tlvs: bytes = b"",
) -> bytes:
    import socket

    return (
        socket.inet_pton(socket.AF_INET, source)
        + socket.inet_pton(socket.AF_INET, destination)
        + struct.pack("!HH", source_port, destination_port)
        + tlvs
    )


def feed_in_chunks(data: bytes, chunk_sizes: list[int]) -> tuple:
    parser = ProxyProtocolParser()
    info = None
    trailing = b""
    offset = 0
    for size in chunk_sizes:
        part = data[offset : offset + size]
        offset += size
        info, trailing = parser.feed(part)
    assert info is not None
    return info, trailing


def test_parse_ipv4_header() -> None:
    data = header(1, 0x11, ipv4_block()) + b"GET / HTTP/1.1\r\n"
    info, trailing = ProxyProtocolParser().feed(data)
    assert info is not None
    assert info.command == "proxy"
    assert info.family == "inet"
    assert info.protocol == "stream"
    assert info.client == ("192.168.0.1", 12345)
    assert info.server == ("10.0.0.1", 443)
    assert trailing == b"GET / HTTP/1.1\r\n"
    assert info.scope_extension() == {
        "version": "2",
        "command": "proxy",
        "family": "inet",
        "protocol": "stream",
        "client": ["192.168.0.1", 12345],
        "server": ["10.0.0.1", 443],
    }


def test_parse_ipv6_header() -> None:
    import socket

    block = (
        socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        + socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        + struct.pack("!HH", 5555, 443)
    )
    info, trailing = ProxyProtocolParser().feed(header(1, 0x21, block) + b"remainder")
    assert info is not None
    assert info.client == ("2001:db8::1", 5555)
    assert info.server == ("2001:db8::2", 443)
    assert trailing == b"remainder"


def test_parse_local_header() -> None:
    info, trailing = ProxyProtocolParser().feed(header(0, 0x00, b"") + b"extra")
    assert info is not None
    assert info.command == "local"
    assert info.family == "unspec"
    assert info.protocol == "unspec"
    assert info.client is None
    assert info.server is None
    assert trailing == b"extra"


def test_parse_unix_header() -> None:
    source = b"/run/source.sock".ljust(108, b"\x00")
    destination = b"/run/destination.sock".ljust(108, b"\x00")
    info, _ = ProxyProtocolParser().feed(header(1, 0x31, source + destination))
    assert info is not None
    assert info.source_path == "/run/source.sock"
    assert info.destination_path == "/run/destination.sock"
    assert info.family == "unix"
    assert info.protocol == "stream"


def test_local_header_with_tlv_and_crc() -> None:
    authority = bytes([0x02]) + struct.pack("!H", 7) + b"example"
    address_block = authority + bytes([0x03, 0, 4, 0, 0, 0, 0])
    raw = SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", len(address_block)) + address_block
    checksum = crc32c(raw)
    data = raw[:-4] + struct.pack("!I", checksum)
    info, _ = ProxyProtocolParser().feed(data)
    assert info is not None
    assert info.command == "local"
    assert info.tlvs["authority"] == "example"
    assert info.tlvs["crc32c"] == checksum


def test_header_split_arbitrarily() -> None:
    data = header(1, 0x11, ipv4_block()) + b"GET / "
    for chunk_sizes in ([1, 1, 1, 13, 3, 1, 50], [12, 4, 12, 100], [28, 100]):
        info, trailing = feed_in_chunks(data, chunk_sizes)
        assert info.client == ("192.168.0.1", 12345)
        assert trailing == b"GET / "


def test_tlvs_parsed_and_bounded() -> None:
    alpn = bytes([0x01]) + struct.pack("!H", 8) + b"http/1.1"
    authority = bytes([0x02]) + struct.pack("!H", 7) + b"example"
    unique_id = bytes([0x05]) + struct.pack("!H", 3) + b"abc"
    netns = bytes([0x30]) + struct.pack("!H", 2) + b"ns"
    unknown = bytes([0xE0]) + struct.pack("!H", 2) + b"\x01\x02"
    tlvs = alpn + authority + unique_id + netns + unknown
    info, _ = ProxyProtocolParser().feed(header(1, 0x11, ipv4_block(tlvs=tlvs)))
    assert info is not None
    assert info.tlvs == {
        "alpn": "http/1.1",
        "authority": "example",
        "unique_id": b"abc",
        "netns": "ns",
        "224": b"\x01\x02",
    }


def test_ssl_tlv_parsed() -> None:
    inner = (
        bytes([0x21]) + struct.pack("!H", 7) + b"TLSv1.3"
        + bytes([0x22]) + struct.pack("!H", 5) + b"hello"
    )
    ssl_value = b"\x01" + struct.pack("!I", 0) + inner
    ssl = bytes([0x20]) + struct.pack("!H", len(ssl_value)) + ssl_value
    info, _ = ProxyProtocolParser().feed(header(1, 0x11, ipv4_block(tlvs=ssl)))
    assert info is not None
    assert info.tlvs["ssl"] == {
        "client": True,
        "verify": 0,
        "version": "TLSv1.3",
        "common_name": "hello",
    }


def test_crc32c_valid() -> None:
    address_block = ipv4_block()
    data = (
        SIGNATURE
        + bytes([0x21, 0x11])
        + struct.pack("!H", len(address_block) + 7)
        + address_block
        + bytes([0x03, 0, 4, 0, 0, 0, 0])
    )
    checksum = crc32c(data)
    data = data[:-4] + struct.pack("!I", checksum)
    info, _ = ProxyProtocolParser().feed(data)
    assert info is not None
    assert info.tlvs["crc32c"] == checksum


@pytest.mark.parametrize(
    "data",
    [
        b"GET / HTTP/1.1\r\n",  # Not a PROXY header
        SIGNATURE + bytes([0x11, 0x00, 0, 0]),  # Version 1
        SIGNATURE + bytes([0x22, 0x00, 0, 0]),  # Unknown command
        SIGNATURE + bytes([0x21, 0x51, 0, 12]) + b"\x00" * 12,  # Unknown family
        SIGNATURE + bytes([0x21, 0x12, 0, 12]) + b"\x00" * 12,  # DGRAM on TCP
        SIGNATURE + bytes([0x21, 0x01, 0, 12]) + b"\x00" * 12,  # PROXY + UNSPEC
        SIGNATURE + bytes([0x21, 0x11, 0, 11]) + b"\x00" * 11,  # Short address
    ],
)
def test_invalid_headers(data: bytes) -> None:
    with pytest.raises(ProxyProtocolError):
        ProxyProtocolParser().feed(data)


def test_truncated_tlv_rejected() -> None:
    # Length claims 10 bytes but only 3 are present.
    tlvs = bytes([0x01, 0, 10]) + b"abc"
    with pytest.raises(ProxyProtocolError):
        ProxyProtocolParser().feed(header(1, 0x11, ipv4_block(tlvs=tlvs)))


def test_truncated_tlv_split_rejected() -> None:
    tlvs = bytes([0x01, 0, 10]) + b"abc"
    data = header(1, 0x11, ipv4_block(tlvs=tlvs))
    parser = ProxyProtocolParser()
    with pytest.raises(ProxyProtocolError):
        for index in range(0, len(data), 7):
            parser.feed(data[index : index + 7])


def test_header_length_capped() -> None:
    data = SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", MAX_HEADER_LENGTH + 1)
    with pytest.raises(ProxyProtocolError):
        ProxyProtocolParser().feed(data)


def test_partial_header_waits_for_more_data() -> None:
    parser = ProxyProtocolParser()
    data = header(1, 0x11, ipv4_block())
    info, trailing = parser.feed(data[:10])
    assert info is None
    info, trailing = parser.feed(data[10:])
    assert info is not None
    assert info.client == ("192.168.0.1", 12345)


def test_is_trusted_source() -> None:
    assert is_trusted_source(("127.0.0.1", 1234), ["127.0.0.0/8"])
    assert is_trusted_source(("10.1.2.3", 1234), ["10.0.0.0/8", "192.168.0.0/16"])
    assert not is_trusted_source(("8.8.8.8", 1234), ["10.0.0.0/8"])
    assert not is_trusted_source(None, ["10.0.0.0/8"])
    assert not is_trusted_source(("10.0.0.1", 1234), [])
    assert not is_trusted_source(("not-an-ip", 1234), ["10.0.0.0/8"])
