from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Literal

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
HEADER_SIZE = 16

VERSION = 0x2
COMMAND_LOCAL = 0x0
COMMAND_PROXY = 0x1

ADDRESS_FAMILY_UNSPECIFIED = 0x0
ADDRESS_FAMILY_INET = 0x1
ADDRESS_FAMILY_INET6 = 0x2
TRANSPORT_PROTOCOL_UNSPECIFIED = 0x0
TRANSPORT_PROTOCOL_STREAM = 0x1


class ProxyProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ProxyProtocolData:
    command: Literal["local", "proxy"]
    address_family: Literal["unspecified", "ipv4", "ipv6"]
    transport_protocol: Literal["unspecified", "stream"]
    client: tuple[str, int] | None = None
    server: tuple[str, int] | None = None
    tlvs: dict[int, bytes] = field(default_factory=dict)


class ProxyProtocolParser:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self._length: int | None = None

    def feed(self, data: bytes) -> tuple[ProxyProtocolData, bytes] | None:
        if self._length is not None and len(self.buffer) == HEADER_SIZE + self._length:
            raise ProxyProtocolError("The PROXY protocol preamble has already been received")

        self.buffer.extend(data)

        if len(self.buffer) < len(SIGNATURE):
            if not SIGNATURE.startswith(bytes(self.buffer)):
                raise ProxyProtocolError("Invalid PROXY protocol signature")
            return None

        if bytes(self.buffer[: len(SIGNATURE)]) != SIGNATURE:
            raise ProxyProtocolError("Invalid PROXY protocol signature")

        if len(self.buffer) < HEADER_SIZE:
            return None

        version_and_command = self.buffer[12]
        address_family_and_transport = self.buffer[13]
        self._length = struct.unpack("!H", self.buffer[14:16])[0]

        if version_and_command >> 4 != VERSION:
            raise ProxyProtocolError("Unsupported PROXY protocol version")

        command = version_and_command & 0x0F
        if command not in {COMMAND_LOCAL, COMMAND_PROXY}:
            raise ProxyProtocolError("Unsupported PROXY protocol command")

        address_family = address_family_and_transport >> 4
        transport_protocol = address_family_and_transport & 0x0F
        if command == COMMAND_LOCAL:
            if address_family_and_transport != 0:
                raise ProxyProtocolError("LOCAL PROXY protocol commands must be unspecified")
        elif address_family not in {
            ADDRESS_FAMILY_INET,
            ADDRESS_FAMILY_INET6,
        } or transport_protocol != TRANSPORT_PROTOCOL_STREAM:
            raise ProxyProtocolError(
                "Only IPv4 and IPv6 stream PROXY protocol commands are supported"
            )

        if len(self.buffer) < HEADER_SIZE + self._length:
            return None

        data_ = self._parse(
            command,
            address_family,
            transport_protocol,
        )
        remainder = bytes(self.buffer[HEADER_SIZE + self._length :])
        return data_, remainder

    def _parse(
        self, command: int, address_family: int, transport_protocol: int
    ) -> ProxyProtocolData:
        assert self._length is not None
        payload = bytes(self.buffer[HEADER_SIZE : HEADER_SIZE + self._length])

        if address_family == ADDRESS_FAMILY_UNSPECIFIED:
            if transport_protocol != TRANSPORT_PROTOCOL_UNSPECIFIED:
                raise ProxyProtocolError("Invalid PROXY protocol transport protocol")
            address_size = 0
            client = None
            server = None
        elif address_family == ADDRESS_FAMILY_INET:
            if transport_protocol != TRANSPORT_PROTOCOL_STREAM:
                raise ProxyProtocolError("Only stream PROXY protocol connections are supported")
            address_size = 12
            if len(payload) < address_size:
                raise ProxyProtocolError("Truncated PROXY protocol address")
            source, destination, source_port, destination_port = struct.unpack(
                "!4s4sHH", payload[:address_size]
            )
            client = (socket.inet_ntoa(source), source_port)
            server = (socket.inet_ntoa(destination), destination_port)
        elif address_family == ADDRESS_FAMILY_INET6:
            if transport_protocol != TRANSPORT_PROTOCOL_STREAM:
                raise ProxyProtocolError("Only stream PROXY protocol connections are supported")
            address_size = 36
            if len(payload) < address_size:
                raise ProxyProtocolError("Truncated PROXY protocol address")
            source, destination, source_port, destination_port = struct.unpack(
                "!16s16sHH", payload[:address_size]
            )
            client = (
                socket.inet_ntop(socket.AF_INET6, source),
                source_port,
            )
            server = (
                socket.inet_ntop(socket.AF_INET6, destination),
                destination_port,
            )
        else:
            raise ProxyProtocolError("Unsupported PROXY protocol address family")

        tlvs = self._parse_tlvs(payload, address_size)

        if command == COMMAND_LOCAL:
            client = None
            server = None

        return ProxyProtocolData(
            command="local" if command == COMMAND_LOCAL else "proxy",
            address_family={
                ADDRESS_FAMILY_UNSPECIFIED: "unspecified",
                ADDRESS_FAMILY_INET: "ipv4",
                ADDRESS_FAMILY_INET6: "ipv6",
            }[address_family],
            transport_protocol=(
                "stream"
                if transport_protocol == TRANSPORT_PROTOCOL_STREAM
                else "unspecified"
            ),
            client=client,
            server=server,
            tlvs=tlvs,
        )

    @staticmethod
    def _parse_tlvs(payload: bytes, offset: int) -> dict[int, bytes]:
        tlvs: dict[int, bytes] = {}
        position = offset

        while position < len(payload):
            if len(payload) - position < 3:
                raise ProxyProtocolError("Truncated PROXY protocol TLV")

            type_, length = struct.unpack("!BH", payload[position : position + 3])
            end = position + 3 + length
            if end > len(payload):
                raise ProxyProtocolError("Truncated PROXY protocol TLV value")

            tlvs[type_] = payload[position + 3 : end]
            position = end

        return tlvs


class ProxyProtocolNegotiator:
    def __init__(self, trusted: bool) -> None:
        self.buffer = bytearray()
        self.parser = ProxyProtocolParser() if trusted else None

    def feed(self, data: bytes) -> tuple[ProxyProtocolData | None, bytes | None]:
        if self.parser is None:
            self.buffer.extend(data)
            if len(self.buffer) < len(SIGNATURE):
                if SIGNATURE.startswith(bytes(self.buffer)):
                    return None, None
            elif bytes(self.buffer[: len(SIGNATURE)]) == SIGNATURE:
                raise ProxyProtocolError("PROXY protocol preamble from an untrusted source")
            return None, bytes(self.buffer)

        result = self.parser.feed(data)
        if result is None:
            return None, None
        return result


def proxy_protocol_scope_extension(data: ProxyProtocolData) -> dict[str, dict]:
    return {
        "hypercorn.proxy_protocol": {
            "command": data.command,
            "address_family": data.address_family,
            "transport_protocol": data.transport_protocol,
            "client": data.client,
            "server": data.server,
            "tlvs": data.tlvs,
        }
    }
