"""离线读取 pcap，逐帧提取 UDP DNS 报文摘要。

读取阶段不做任何跨帧推断，只忠实记录每一帧属于哪个采集点、
来自哪个文件的第几帧，以及解析失败的原因。
"""
from __future__ import annotations

import socket
from typing import Iterator, Optional, Tuple

import dpkt

from .model import (
    CaptureResult,
    DnsMessage,
    PacketRef,
    Question,
    RR,
    ReadError,
)

_IP_TYPES = (dpkt.ip.IP, dpkt.ip6.IP6)
_OPEN_ERRORS = (OSError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError, EOFError)


def _ip_to_str(packed: bytes) -> str:
    if len(packed) == 4:
        return socket.inet_ntop(socket.AF_INET, packed)
    return socket.inet_ntop(socket.AF_INET6, packed)


def _norm_name(name: str) -> str:
    """统一名称形态：小写并去掉根标签的结尾点，便于跨帧比较。"""
    return name.rstrip('.').lower()


def _frame_to_ip(linktype: int, buf: bytes):
    """按链路类型拆出 IP 层；非 IP / 不支持的链路返回 None。"""
    if linktype == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        frame = eth
        # 跳过一层 802.1Q VLAN，继续取内层类型
        while isinstance(getattr(frame, 'data', None), dpkt.ethernet.VLANtag8021Q):
            frame = frame.data
        if not isinstance(frame.data, _IP_TYPES):
            return None
        return frame.data
    if linktype == dpkt.pcap.DLT_NULL:
        loop = dpkt.loopback.Loopback(buf)
        return loop.data if isinstance(loop.data, _IP_TYPES) else None
    if linktype == dpkt.pcap.DLT_RAW:
        if buf[:1] == b'\x4f':
            return dpkt.ip6.IP6(buf)
        return dpkt.ip.IP(buf)
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        sll = dpkt.sll.SLL(buf)
        return sll.data if isinstance(sll.data, _IP_TYPES) else None
    return None


def _rr_value(rr) -> Optional[str]:
    if rr.type == dpkt.dns.DNS_A:
        return socket.inet_ntop(socket.AF_INET, rr.ip)
    if rr.type == dpkt.dns.DNS_AAAA:
        return socket.inet_ntop(socket.AF_INET6, rr.ip6)
    if rr.type == dpkt.dns.DNS_CNAME:
        return _norm_name(rr.cname)
    return None


def _summarize_dns(ref: PacketRef, ip_layer, udp: dpkt.udp.UDP) -> DnsMessage:
    dns = dpkt.dns.DNS(udp.data)
    questions = tuple(
        Question(name=_norm_name(q.name), qtype=q.type, qclass=q.cls)
        for q in dns.qd
    )
    answers = tuple(
        RR(
            name=_norm_name(a.name),
            rtype=a.type,
            rclass=a.cls,
            ttl=a.ttl,
            value=_rr_value(a),
        )
        for a in dns.an
    )
    return DnsMessage(
        ref=ref,
        txid=dns.id,
        is_response=bool(dns.qr),
        rcode=dns.rcode,
        qr_names=tuple(_norm_name(q.name) for q in dns.qd),
        questions=questions,
        answers=answers,
        src_ip=_ip_to_str(ip_layer.src),
        dst_ip=_ip_to_str(ip_layer.dst),
        src_port=udp.sport,
        dst_port=udp.dport,
        truncated=bool(dns.tc),
    )


def iter_packets(source: str, site: str) -> Iterator[Tuple[PacketRef, bytes, int]]:
    """逐帧产出 (帧引用, 原始字节, 链路类型)，来源与采集点在每帧上留痕。"""
    with open(source, 'rb') as fh:
        reader = dpkt.pcap.Reader(fh)
        linktype = reader.datalink()
        for frame_index, (timestamp, buf) in enumerate(reader):
            ref = PacketRef(
                source=source,
                site=site,
                frame_index=frame_index,
                timestamp=timestamp,
            )
            yield ref, buf, linktype


def read_capture(source: str, site: str) -> CaptureResult:
    """读取一个抓包文件，输出该采集点下的 DNS 报文摘要与读取异常。"""
    result = CaptureResult(source=source, site=site)
    try:
        for ref, buf, linktype in iter_packets(source, site):
            try:
                ip_layer = _frame_to_ip(linktype, buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as exc:
                result.read_errors.append(
                    ReadError(ref=ref, reason='frame: %s' % exc)
                )
                continue
            if ip_layer is None:
                continue
            udp = ip_layer.data
            if not isinstance(udp, dpkt.udp.UDP) or 53 not in (udp.sport, udp.dport):
                continue
            try:
                result.messages.append(_summarize_dns(ref, ip_layer, udp))
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError) as exc:
                result.read_errors.append(
                    ReadError(ref=ref, reason='dns: %s' % exc)
                )
    except _OPEN_ERRORS as exc:
        result.read_errors.append(
            ReadError(
                ref=PacketRef(
                    source=source, site=site, frame_index=-1, timestamp=0.0
                ),
                reason='open failed: %s' % exc,
            )
        )
    return result
