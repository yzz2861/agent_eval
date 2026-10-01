from __future__ import annotations

import ipaddress
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

# PROXY protocol v2, RFC 9264
SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"

COMMAND_LOCAL = 0x00
COMMAND_PROXY = 0x01

FAMILY_UNSPEC = 0x00
FAMILY_INET = 0x01
FAMILY_INET6 = 0x02
FAMILY_UNIX = 0x03

PROTOCOL_UNSPEC = 0x00
PROTOCOL_STREAM = 0x01
PROTOCOL_DGRAM = 0x02

HEADER_LENGTH = 16
MAX_HEADER_LENGTH = 16 * 1024

# Type length value types, RFC 9264 section 2.2.
TLV_ALPN = 0x01
TLV_AUTHORITY = 0x02
TLV_CRC32C = 0x03
TLV_NOOP = 0x04
TLV_UNIQUE_ID = 0x05
TLV_SSL = 0x20
TLV_NETNS = 0x30

# Sub-TLVs of the SSL type length value.
TLV_SSL_VERSION = 0x21
TLV_SSL_COMMON_NAME = 0x22
TLV_SSL_CIPHER = 0x23
TLV_SSL_SIGNATURE_ALGORITHM = 0x24
TLV_SSL_KEY_ALGORITHM = 0x25

SCOPE_EXTENSION = "hypercorn.proxy_protocol"

Receive = Callable[[], Awaitable[bytes]]


class ProxyProtocolError(Exception):
    """The PROXY protocol preamble is invalid or not allowed."""


@dataclass(frozen=True)
class ProxyInfo:
    """Useful information parsed from a PROXY protocol v2 header."""

    command: str
    family: str | None = None
    protocol: str | None = None
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    source_path: str | None = None
    destination_path: str | None = None
    tlvs: dict[str, Any] = field(default_factory=dict)

    def scope_extension(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version": "2",
            "command": self.command,
        }
        if self.family is not None:
            data["family"] = self.family
        if self.protocol is not None:
            data["protocol"] = self.protocol
        if self.client is not None:
            data["client"] = list(self.client)
        if self.server is not None:
            data["server"] = list(self.server)
        if self.source_path is not None:
            data["source_path"] = self.source_path
        if self.destination_path is not None:
            data["destination_path"] = self.destination_path
        if self.tlvs:
            data["tlvs"] = self.tlvs
        return data


class ProxyProtocolParser:
    """Incremental PROXY protocol v2 header parser.

    Feed arbitrary byte chunks to feed until it returns the parsed
    ProxyInfo together with the trailing bytes that belong to the
    proxied stream.
    """

    def __init__(self, max_header_length: int = MAX_HEADER_LENGTH) -> None:
        self.buffer = bytearray()
        self.max_header_length = max_header_length

    def feed(self, data: bytes) -> tuple[ProxyInfo | None, bytes]:
        self.buffer.extend(data)
        if len(self.buffer) < len(SIGNATURE):
            return None, b""
        if bytes(self.buffer[: len(SIGNATURE)]) != SIGNATURE:
            raise ProxyProtocolError("Invalid PROXY protocol signature")
        if len(self.buffer) < HEADER_LENGTH:
            return None, b""

        version_command = self.buffer[12]
        if version_command >> 4 != 2:
            raise ProxyProtocolError("Unsupported PROXY protocol version")
        command = version_command & 0x0F
        if command not in (COMMAND_LOCAL, COMMAND_PROXY):
            raise ProxyProtocolError("Unsupported PROXY protocol command")

        family_protocol = self.buffer[13]
        family = family_protocol >> 4
        transport_protocol = family_protocol & 0x0F
        address_length = int.from_bytes(self.buffer[14:16], "big")
        header_length = HEADER_LENGTH + address_length
        if header_length > self.max_header_length:
            raise ProxyProtocolError("PROXY protocol header exceeds the maximum length")
        if len(self.buffer) < header_length:
            return None, b""

        address_block = bytes(self.buffer[HEADER_LENGTH:header_length])
        trailing = bytes(self.buffer[header_length:])

        if family not in (FAMILY_UNSPEC, FAMILY_INET, FAMILY_INET6, FAMILY_UNIX):
            raise ProxyProtocolError("Unsupported PROXY protocol address family")
        if transport_protocol not in (PROTOCOL_UNSPEC, PROTOCOL_STREAM, PROTOCOL_DGRAM):
            raise ProxyProtocolError("Unsupported PROXY protocol transport protocol")
        if family == FAMILY_UNIX and address_length != 216:
            raise ProxyProtocolError("Invalid UNIX PROXY protocol address length")
        if family == FAMILY_INET and address_length < 12:
            raise ProxyProtocolError("Invalid IPv4 PROXY protocol address length")
        if family == FAMILY_INET6 and address_length < 36:
            raise ProxyProtocolError("Invalid IPv6 PROXY protocol address length")

        info, crc_offset = _parse_addresses(
            command, family, transport_protocol, address_block
        )
        if crc_offset is not None:
            _verify_crc32c(bytes(self.buffer[:header_length]), crc_offset, info.tlvs["crc32c"])
        return info, trailing


def _decode_ascii(value: bytes, description: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        raise ProxyProtocolError(f"Invalid ASCII value in the {description} TLV") from None


def _decode_path(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", "surrogateescape")


def _parse_addresses(
    command: int,
    family: int,
    transport_protocol: int,
    address_block: bytes,
) -> tuple[ProxyInfo, int | None]:
    command_name = "local" if command == COMMAND_LOCAL else "proxy"
    family_names = {
        FAMILY_UNSPEC: "unspec",
        FAMILY_INET: "inet",
        FAMILY_INET6: "inet6",
        FAMILY_UNIX: "unix",
    }
    protocol_names = {
        PROTOCOL_UNSPEC: "unspec",
        PROTOCOL_STREAM: "stream",
        PROTOCOL_DGRAM: "dgram",
    }

    kwargs: dict[str, Any] = {
        "command": command_name,
        "family": family_names[family],
        "protocol": protocol_names[transport_protocol],
    }

    if family in (FAMILY_INET, FAMILY_INET6, FAMILY_UNIX) and transport_protocol != PROTOCOL_STREAM:
            raise ProxyProtocolError("TCP listeners only accept STREAM proxied addresses")

    if command == COMMAND_PROXY:
        if family == FAMILY_UNSPEC:
            raise ProxyProtocolError("PROXY command requires a supported address family")

        tlv_offset: int | None = None

        if family == FAMILY_INET:
            source_ip = socket.inet_ntop(socket.AF_INET, address_block[0:4])
            destination_ip = socket.inet_ntop(socket.AF_INET, address_block[4:8])
            source_port = int.from_bytes(address_block[8:10], "big")
            destination_port = int.from_bytes(address_block[10:12], "big")
            kwargs["client"] = (source_ip, source_port)
            kwargs["server"] = (destination_ip, destination_port)
            kwargs["tlvs"], tlv_offset = _parse_tlvs(address_block[12:], 12)
        elif family == FAMILY_INET6:
            source_ip = socket.inet_ntop(socket.AF_INET6, address_block[0:16])
            destination_ip = socket.inet_ntop(socket.AF_INET6, address_block[16:32])
            source_port = int.from_bytes(address_block[32:34], "big")
            destination_port = int.from_bytes(address_block[34:36], "big")
            kwargs["client"] = (source_ip, source_port)
            kwargs["server"] = (destination_ip, destination_port)
            kwargs["tlvs"], tlv_offset = _parse_tlvs(address_block[36:], 36)
        elif family == FAMILY_UNIX:
            kwargs["source_path"] = _decode_path(address_block[0:108])
            kwargs["destination_path"] = _decode_path(address_block[108:216])
    else:
        # LOCAL: any remaining address bytes are type length values.
        kwargs["tlvs"], tlv_offset = _parse_tlvs(address_block)
    return ProxyInfo(**kwargs), tlv_offset


def _parse_tlvs(
    data: bytes, offset_base: int = 0
) -> tuple[dict[str, Any], int | None]:
    tlvs: dict[str, Any] = {}
    crc_offset: int | None = None
    offset = 0
    while offset < len(data):
        if offset + 3 > len(data):
            raise ProxyProtocolError("Truncated PROXY protocol TLV header")
        tlv_type = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 3], "big")
        start = offset + 3
        end = start + length
        if end > len(data):
            raise ProxyProtocolError("PROXY protocol TLV exceeds the address block")
        value = data[start:end]
        if tlv_type == TLV_CRC32C:
            crc_offset = HEADER_LENGTH + offset_base + start
        offset = end

        if tlv_type == TLV_NOOP:
            continue
        elif tlv_type == TLV_ALPN:
            tlvs["alpn"] = _decode_ascii(value, "ALPN")
        elif tlv_type == TLV_AUTHORITY:
            tlvs["authority"] = _decode_ascii(value, "authority")
        elif tlv_type == TLV_CRC32C:
            if length != 4:
                raise ProxyProtocolError("Invalid PROXY protocol CRC32C TLV")
            tlvs["crc32c"] = int.from_bytes(value, "big")
        elif tlv_type == TLV_UNIQUE_ID:
            tlvs["unique_id"] = value
        elif tlv_type == TLV_NETNS:
            tlvs["netns"] = _decode_path(value)
        elif tlv_type == TLV_SSL:
            tlvs["ssl"] = _parse_ssl_tlv(value)
        else:
            tlvs[str(tlv_type)] = value
    return tlvs, crc_offset


def _parse_ssl_tlv(value: bytes) -> dict[str, Any]:
    if len(value) < 5:
        raise ProxyProtocolError("Invalid PROXY protocol SSL TLV")
    result: dict[str, Any] = {
        "client": bool(value[0]),
        "verify": int.from_bytes(value[1:5], "big"),
    }
    offset = 5
    while offset < len(value):
        if offset + 3 > len(value):
            raise ProxyProtocolError("Truncated PROXY protocol SSL sub-TLV header")
        sub_type = value[offset]
        length = int.from_bytes(value[offset + 1 : offset + 3], "big")
        start = offset + 3
        end = start + length
        if end > len(value):
            raise ProxyProtocolError("PROXY protocol SSL sub-TLV exceeds the TLV")
        sub_value = value[start:end]
        offset = end
        if sub_type == TLV_SSL_VERSION:
            result["version"] = _decode_path(sub_value)
        elif sub_type == TLV_SSL_COMMON_NAME:
            result["common_name"] = _decode_path(sub_value)
        elif sub_type == TLV_SSL_CIPHER:
            result["cipher"] = _decode_path(sub_value)
        elif sub_type == TLV_SSL_SIGNATURE_ALGORITHM:
            result["signature_algorithm"] = _decode_path(sub_value)
        elif sub_type == TLV_SSL_KEY_ALGORITHM:
            result["key_algorithm"] = _decode_path(sub_value)
        else:
            result[str(sub_type)] = sub_value
    return result


_CRC32C_TABLE: tuple[int, ...] | None = None


def _crc32c_table() -> tuple[int, ...]:
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        table = []
        for index in range(256):
            crc = index
            for _ in range(8):
                crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
            table.append(crc)
        _CRC32C_TABLE = tuple(table)
    return _CRC32C_TABLE


def crc32c(data: bytes) -> int:
    table = _crc32c_table()
    crc = 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _verify_crc32c(header: bytes, value_offset: int, expected: int) -> None:
    check_data = bytearray(header)
    check_data[value_offset : value_offset + 4] = b"\x00\x00\x00\x00"
    if crc32c(check_data) != expected:
        raise ProxyProtocolError("Invalid PROXY protocol CRC32C checksum")


def is_trusted_source(peer: tuple[str, int] | None, trusted: Sequence[object]) -> bool:
    if peer is None or not trusted:
        return False
    try:
        address = ipaddress.ip_address(peer[0])
    except ValueError:
        return False
    for network in trusted:
        if isinstance(network, str):
            network = ipaddress.ip_network(network, strict=False)
        if address in network:
            return True
    return False


async def read_proxy_header(
    receive: Receive, max_header_length: int = MAX_HEADER_LENGTH
) -> tuple[ProxyInfo, bytes]:
    """Read a complete PROXY protocol v2 header using the receive callable.

    The callable must return an empty bytes object on end of file. The
    returned bytes are any trailing bytes that arrived with the header
    and must be passed on to the HTTP protocol untouched.
    """
    parser = ProxyProtocolParser(max_header_length)
    while True:
        data = await receive()
        if data == b"":
            raise ProxyProtocolError("Connection closed before the PROXY protocol header ended")
        info, trailing = parser.feed(data)
        if info is not None:
            return info, trailing
