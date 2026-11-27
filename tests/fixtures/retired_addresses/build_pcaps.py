#!/usr/bin/env python3
"""Rebuild the tiny deterministic pcaps used by the audit fixture."""
from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

import dpkt


HERE = Path(__file__).resolve().parent


def mac(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def ip(value: str) -> bytes:
    return socket.inet_aton(value)


def ts(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp()


def dhcp_ack(client_mac: str, address: str, lease_seconds: int, xid: int, server: str) -> bytes:
    options = [
        (53, b"\x05"),
        (51, struct.pack("!I", lease_seconds)),
        (54, ip(server)),
        (1, struct.pack("!I", 0xFFFFFF00)),
        (3, ip(server)),
    ]
    message = dpkt.dhcp.DHCP(
        op=dpkt.dhcp.DHCP_OP_REPLY,
        hrd=1,
        hln=6,
        xid=xid,
        flags=0x8000,
        yiaddr=struct.unpack("!I", ip(address))[0],
        siaddr=struct.unpack("!I", ip(server))[0],
        chaddr=mac(client_mac) + b"\x00" * 10,
        opts=options,
    )
    udp = dpkt.udp.UDP(sport=67, dport=68, ulen=8 + len(message), data=message)
    packet = dpkt.ip.IP(src=ip(server), dst=ip("255.255.255.255"), p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ethernet = dpkt.ethernet.Ethernet(
        dst=b"\xff" * 6,
        src=mac(client_mac),
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=packet,
    )
    return bytes(ethernet)


def arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    message = dpkt.arp.ARP(
        op=dpkt.arp.ARP_OP_REPLY,
        sha=mac(sender_mac),
        spa=ip(sender_ip),
        tha=mac(target_mac),
        tpa=ip(target_ip),
    )
    ethernet = dpkt.ethernet.Ethernet(
        dst=mac(target_mac),
        src=mac(sender_mac),
        type=dpkt.ethernet.ETH_TYPE_ARP,
        data=message,
    )
    return bytes(ethernet)


def arp_request(sender_mac: str, sender_ip: str, target_ip: str) -> bytes:
    message = dpkt.arp.ARP(
        op=dpkt.arp.ARP_OP_REQUEST,
        sha=mac(sender_mac),
        spa=ip(sender_ip),
        tha=b"\x00" * 6,
        tpa=ip(target_ip),
    )
    ethernet = dpkt.ethernet.Ethernet(
        dst=b"\xff" * 6,
        src=mac(sender_mac),
        type=dpkt.ethernet.ETH_TYPE_ARP,
        data=message,
    )
    return bytes(ethernet)


def write_pcap(path: Path, packets) -> None:
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for timestamp, packet in packets:
            writer.writepkt(packet, timestamp)
        writer.close()


def main() -> None:
    gateway = "10.20.0.1"
    old_a = "00:1a:2b:3c:4d:01"
    new_a = "00:1a:2b:3c:4d:11"
    unknown = "00:aa:bb:cc:dd:ee"

    dhcp_packets = [
        (
            ts("2026-10-29T00:00:00Z"),
            dhcp_ack(old_a, "10.20.0.10", 30 * 24 * 3600, 0x10000001, gateway),
        ),
        (
            ts("2026-11-03T02:00:00Z"),
            dhcp_ack(new_a, "10.20.0.10", 30 * 24 * 3600, 0x10000002, gateway),
        ),
        (
            ts("2026-11-05T02:00:00Z"),
            dhcp_ack(old_a, "10.20.0.11", 30 * 24 * 3600, 0x10000003, gateway),
        ),
    ]
    arp_packets = [
        (
            ts("2026-11-03T02:05:00Z"),
            arp_reply(new_a, "10.20.0.10", "00:1a:2b:3c:4d:fe", gateway),
        ),
        (
            ts("2026-11-05T02:05:00Z"),
            arp_reply(old_a, "10.20.0.11", "00:1a:2b:3c:4d:fe", gateway),
        ),
        (
            ts("2026-11-06T00:05:00Z"),
            arp_reply(unknown, "10.20.0.12", "00:1a:2b:3c:4d:fe", gateway),
        ),
    ]
    write_pcap(HERE / "dhcp-east.pcap", dhcp_packets)
    write_pcap(HERE / "arp-east.pcap", arp_packets)


if __name__ == "__main__":
    main()
