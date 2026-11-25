"""用 dpkt 的 pcap/Ethernet/IP/UDP 栈在内存里合成 DNS 抓包。

注意：dpkt 1.9.8 的 ``DNS`` 打包器会把压缩指针算到头部偏移，生成的
RR 名指针无效，其自身解析器无法往返。真实抓包里的压缩指针是标准的，
dpkt 可以正常解析；因此这里按 RFC 1035 手工编码 DNS wire 数据，
链路层与 pcap 容器仍然使用 dpkt，再由 dpkt.dns.DNS 离线解析验证。
"""
from __future__ import annotations

import io
import socket
import struct
from typing import List, Optional, Sequence, Tuple

import dpkt
from dpkt.dns import DNS_A, DNS_AAAA, DNS_CNAME, DNS_QR, DNS_RD, DNS_RA

CLIENT_MAC = b'\x02\x00\x00\x00\x00\x01'
RESOLVER_MAC = b'\x02\x00\x00\x00\x00\x02'
CLIENT_IP_TEXT = '10.0.0.10'
RESOLVER_IP_TEXT = '8.8.8.8'
CLIENT_IP = socket.inet_pton(socket.AF_INET, CLIENT_IP_TEXT)
RESOLVER_IP = socket.inet_pton(socket.AF_INET, RESOLVER_IP_TEXT)


def encode_name(name: str) -> bytes:
    wire = b''
    for label in name.rstrip('.').split('.'):
        encoded = label.encode('ascii')
        wire += bytes([len(encoded)]) + encoded
    return wire + b'\x00'


def dns_question(name: str, qtype: int = DNS_A, qclass: int = 1) -> Tuple[str, int, int]:
    return name, qtype, qclass


def a_rr(name: str, address: str, ttl: int = 300) -> Tuple[str, int, int, int, bytes]:
    return name, DNS_A, 1, ttl, socket.inet_pton(socket.AF_INET, address)


def aaaa_rr(name: str, address: str, ttl: int = 300) -> Tuple[str, int, int, int, bytes]:
    return name, DNS_AAAA, 1, ttl, socket.inet_pton(socket.AF_INET6, address)


def cname_rr(name: str, target: str, ttl: int = 300) -> Tuple[str, int, int, int, bytes]:
    return name, DNS_CNAME, 1, ttl, encode_name(target)


def dns_query(txid: int, questions: Sequence[Tuple[str, int, int]], flags: int = DNS_RD) -> bytes:
    return _encode_dns(txid, flags, questions, [])


def dns_response(
    txid: int,
    questions: Sequence[Tuple[str, int, int]],
    answers: Optional[Sequence[Tuple[str, int, int, int, bytes]]] = None,
    rcode: int = 0,
    truncated: bool = False,
) -> bytes:
    flags = DNS_QR | DNS_RD | DNS_RA | rcode
    if truncated:
        flags |= dpkt.dns.DNS_TC
    return _encode_dns(txid, flags, questions, list(answers or []))


def _encode_dns(txid: int, flags: int, questions, answers) -> bytes:
    header = struct.pack('>HHHHHH', txid, flags, len(questions), len(answers), 0, 0)
    body = b''
    name_offsets = {}

    def name_wire(name: str) -> bytes:
        key = name.lower()
        if key in name_offsets:
            return struct.pack('>H', 0xC000 | name_offsets[key])
        name_offsets[key] = len(header) + len(body)
        return encode_name(name)

    for name, qtype, qclass in questions:
        body += name_wire(name)
        body += struct.pack('>HH', qtype, qclass)
    for name, rtype, rclass, ttl, rdata in answers:
        body += name_wire(name)
        body += struct.pack('>HHIH', rtype, rclass, ttl, len(rdata))
        body += rdata
    return header + body


def _frame(dns_wire: bytes, *, from_client: bool, sport: int, dport: int) -> bytes:
    if from_client:
        src_ip, dst_ip = CLIENT_IP, RESOLVER_IP
        src_mac, dst_mac = CLIENT_MAC, RESOLVER_MAC
    else:
        src_ip, dst_ip = RESOLVER_IP, CLIENT_IP
        src_mac, dst_mac = RESOLVER_MAC, CLIENT_MAC
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=dns_wire)
    udp.ulen = 8 + len(dns_wire)
    ip_layer = dpkt.ip.IP(src=src_ip, dst=dst_ip, p=17, data=udp)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=src_mac, dst=dst_mac, type=dpkt.ethernet.ETH_TYPE_IP, data=ip_layer
        )
    )


def build_pcap(packets: Sequence[Tuple[float, bytes, bool, int, int]]) -> bytes:
    """packets 元素为 (时间戳, DNS wire 字节, 是否客户端发出, 源端口, 目的端口)。"""
    buffer = io.BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    for timestamp, dns_wire, from_client, sport, dport in packets:
        writer.writepkt(
            _frame(dns_wire, from_client=from_client, sport=sport, dport=dport),
            ts=timestamp,
        )
    return buffer.getvalue()


def write_pcap(path: str, packets: Sequence[Tuple[float, bytes, bool, int, int]]) -> str:
    with open(path, 'wb') as handle:
        handle.write(build_pcap(packets))
    return path


def exchange_packets(
    txid: int,
    name: str,
    answers: Sequence[Tuple[str, int, int, int, bytes]],
    *,
    t0: float = 100.0,
    qtype: int = DNS_A,
    client_port: int = 40000,
    rcode: int = 0,
    truncated: bool = False,
) -> List[Tuple[float, bytes, bool, int, int]]:
    """一组标准的一问一答，可指定客户端口以构造同号场景。"""
    question = dns_question(name, qtype)
    return [
        (t0, dns_query(txid, [question]), True, client_port, 53),
        (
            t0 + 0.05,
            dns_response(
                txid, [question], answers, rcode=rcode, truncated=truncated
            ),
            False,
            53,
            client_port,
        ),
    ]
