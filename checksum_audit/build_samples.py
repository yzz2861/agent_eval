"""合成离线抓包样本：假采集器声明 + 覆盖每一层的校验差分。

采集器声明是离线核对唯一的卸载上下文来源；本模块用三个虚构采集点
演示方向/卸载配置如何把同一批字节判成不同结论。
"""
from __future__ import annotations

import struct
import zlib

import dpkt

from .offloadcheck import CollectorDecl


# ---------------------------------------------------------------------------
# 假采集器声明（真实环境应由采集平台下发，而不是从报文反推）
# ---------------------------------------------------------------------------
COLLECTORS = {
    "COL-ING-01": CollectorDecl(
        name="COL-ING-01",
        direction="ingress",
        tx_ip_offload=False,
        tx_l4_offload=False,
        keeps_eth_fcs=False,
        note="核心交换机镜像口（入向，面向服务器 RX），镜像在网卡校验之后，"
                    "链路上的校验和应为最终值",
    ),
    "COL-EG-02": CollectorDecl(
        name="COL-EG-02",
        direction="egress",
        tx_ip_offload=True,
        tx_l4_offload=True,
        keeps_eth_fcs=False,
        note="宿主机 vSwitch 出口（出向，抓在 NIC 卸载之前），"
                    "TCP/UDP/IP 校验字段可能保持 0，不能按篡改上报",
    ),
    "COL-TAP-03": CollectorDecl(
        name="COL-TAP-03",
        direction="ingress",
        tx_ip_offload=False,
        tx_l4_offload=False,
        keeps_eth_fcs=True,
        note="光纤 TAP（物理线路侧，保留 FCS），帧尾 4 字节是以太网 FCS，"
                    "可做 L2 校验",
    ),
}

ETHERTYPE_IPV4 = 0x0800
PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1


def _ipsum(buf: bytes) -> int:
    return dpkt.dpkt.in_cksum(buf)


def _pseudo(iph: bytes, l4_len: int) -> bytes:
    src, dst = iph[12:16], iph[16:20]
    proto = iph[9]
    return struct.pack("!4s4sBBH", src, dst, 0, proto, l4_len)


def _ipv4(proto: int, src: bytes, dst: bytes, payload: bytes,
          ident: int = 0, ttl: int = 64) -> bytearray:
    total = 20 + len(payload)
    iph = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, ident, 0, ttl, proto, 0, src, dst))
    iph[10:12] = struct.pack("!H", _ipsum(bytes(iph)))
    return iph + bytearray(payload)


def _tcp_packet(sport=443, dport=51000, seq=1, ack=1, payload=b"",
                 doff_words=5) -> bytearray:
    hdr = bytearray(struct.pack(
        "!HHIIHHHHH", sport, dport, seq, ack, (doff_words << 12), 0x10,
        8192, 0, 0))
    return hdr + bytearray(payload)


def _udp_packet(sport=5353, dport=53, payload=b"", zero_sum=False) -> bytearray:
    length = 8 + len(payload)
    hdr = bytearray(struct.pack("!HHHH", sport, dport, length, 0))
    seg = hdr + bytearray(payload)
    if not zero_sum:
        seg[6:8] = struct.pack("!H", _ipsum(bytes(seg)))
    return seg


def _icmp_packet(typ=8, code=0, ident=1, seq=1, payload=b"ping-data") -> bytearray:
    hdr = bytearray(struct.pack("!BBHHH", typ, code, 0, ident, seq))
    seg = hdr + bytearray(payload)
    seg[2:4] = struct.pack("!H", _ipsum(bytes(seg)))
    return seg


def _frame(ip_pkt: bytearray,
           src=b"\x02\x00\x00\x00\x00\x01",
           dst=b"\x02\x00\x00\x00\x00\x02",
           fcs: bool = False) -> bytearray:
    eth = struct.pack("!6s6sH", dst, src, ETHERTYPE_IPV4)
    body = bytearray(eth) + ip_pkt
    if fcs:
        body += struct.pack("!I", zlib.crc32(bytes(body)) & 0xFFFFFFFF)
    return body


def _finalize_l4(frame: bytearray, proto: int, *, zero_sum: bool = False,
                 corrupt: bool = False) -> bytearray:
    """按伪首部重算 L4 校验和并写回帧内字段（输入可为裸 IP 包或以太网帧）。"""
    ip_off = 14 if len(frame) > 14 and frame[12] == 0x08 and frame[13] == 0x00 else 0
    ihl = (frame[ip_off] & 0x0F) * 4
    l4_off = ip_off + ihl
    if proto == PROTO_ICMP:
        seg = bytes(frame[l4_off:])
        field_off = l4_off + 2
        if zero_sum:
            frame[field_off:field_off + 2] = b"\x00\x00"
        else:
            val = _ipsum(seg)
            frame[field_off:field_off + 2] = struct.pack("!H", val)
        if corrupt:
            frame[field_off] ^= 0xFF
        return frame
    seg_len = len(frame) - l4_off
    pseudo = _pseudo(bytes(frame[ip_off:ip_off + ihl]), seg_len)
    field_off = l4_off + 16 if proto == PROTO_TCP else l4_off + 6
    frame[field_off:field_off + 2] = b"\x00\x00"  # 先清零再重算
    seg = bytes(frame[l4_off:l4_off + seg_len])
    if not zero_sum:
        val = _ipsum(pseudo + seg)
        frame[field_off:field_off + 2] = struct.pack("!H", val)
    if corrupt:
        frame[field_off] ^= 0xFF
    return frame


def build_frames() -> list[dict]:
    """返回每条样本：说明、采集器、原始帧、模拟捕获长度。"""
    src, dst = b"\x0a\x01\x02\x03", b"\x0a\x09\x08\x07"
    samples: list[dict] = []

    def add(name, layer, note, collector, frame, cap_len=None, wire_len=None, expect=None):
        full_len = wire_len if wire_len is not None else len(frame)
        samples.append({
            "name": name,
            "layer": layer,
            "note": note,
            "collector": collector,
            "wire": bytes(frame),
            "cap_len": cap_len if cap_len is not None else len(frame),
            "wire_len": full_len,
            "expect": expect or {},
        })

    # --- L2：FCS（只有保留 FCS 的 TAP 可验） ---
    fcs_good = _frame(_ipv4(PROTO_ICMP, src, dst, _icmp_packet()), fcs=True)
    add("L2-FCS-OK", "L2", "TAP 保留 FCS 且帧未改动", "COL-TAP-03", fcs_good)
    fcs_bad = bytearray(fcs_good)
    fcs_bad[30] ^= 0x01  # 改 IP 载荷方向的字节，使 CRC 失配
    add("L2-FCS-BAD", "L2", "帧体被改、FCS 未重算（L2 真实失配）",
        "COL-TAP-03", fcs_bad)
    add("L2-FCS-ABSENT", "L2", "镜像口已剥离 FCS，设备未填写该层",
        "COL-ING-01", _frame(_ipv4(PROTO_ICMP, src, dst, _icmp_packet())))
    fcs_short = bytearray(fcs_good)[:-2]
    add("L2-FCS-SHORT", "L2", "snaplen 截断，FCS 4 字节只抓到 2 字节",
        "COL-TAP-03", fcs_short, cap_len=len(fcs_short), wire_len=len(fcs_good))

    # --- L3：IPv4 首部校验和（用 L4 已正确填好的 TCP 包，保证只有 L3 出差分） ---
    ip_ok = _ipv4(PROTO_TCP, src, dst, _tcp_packet(payload=b"l3-probe"))
    _finalize_l4(ip_ok, PROTO_TCP)
    add("L3-IP-OK", "L3", "IPv4 首部校验和正确，L4 同样正确", "COL-ING-01", _frame(ip_ok))
    ip_bad = bytearray(ip_ok)
    ip_bad[10] ^= 0xFF  # 改 sum 字段本身（裸 IP 包，偏移从 0 起）
    add("L3-IP-BAD", "L3", "IP sum 字段被破坏（仅 L3 真实失配，L4 仍正确）",
        "COL-ING-01", _frame(ip_bad))
    ip_zero = bytearray(ip_ok)
    ip_zero[10:12] = b"\x00\x00"  # 模拟卸载态：IP sum 留空
    ip_zero[20 + 16:20 + 18] = b"\x00\x00"  # 同一卸载点 TCP sum 同样留空
    add("L3-IP-ZERO-EGRESS", "L3",
        "IP sum 为 0：出向卸载点应判设备未填写而非篡改",
        "COL-EG-02", _frame(ip_zero))
    add("L3-IP-ZERO-INGRESS", "L3",
        "同样的 0 值到了入向镜像口：没有卸载声明，判失配",
        "COL-ING-01", _frame(bytearray(ip_zero)))
    ip_short = bytearray(_frame(ip_ok))[:14 + 12]  # 20 字节首部只到第 12 字节
    add("L3-IP-SHORT", "L3", "截断点落在 IP 首部，sum 字段不完整",
        "COL-ING-01", ip_short, cap_len=len(ip_short), wire_len=len(_frame(ip_ok)))

    # --- L4 TCP ---
    tcp_good = _ipv4(PROTO_TCP, src, dst, _tcp_packet(payload=b"hello-tcp"))
    _finalize_l4(tcp_good, PROTO_TCP)
    add("L4-TCP-OK", "L4", "TCP 校验和（含伪首部）正确", "COL-ING-01",
        _frame(tcp_good))
    tcp_bad = bytearray(tcp_good)
    tcp_bad[-1] ^= 0x01  # 改应用载荷，TCP 校验失配、IP 首部仍正确
    add("L4-TCP-BAD", "L4", "仅应用载荷被改：L3 通过、L4 失配",
        "COL-ING-01", _frame(tcp_bad))
    tcp_zero = bytearray(tcp_good)
    tcp_zero[20 + 16:20 + 18] = b"\x00\x00"
    add("L4-TCP-ZERO-EGRESS", "L4",
        "TCP sum 为 0：出向 NIC 卸载点判设备未填写",
        "COL-EG-02", _frame(tcp_zero))
    add("L4-TCP-ZERO-INGRESS", "L4",
        "同样的 0 值在入向点：无卸载声明，判失配",
        "COL-ING-01", _frame(bytearray(tcp_zero)))
    tcp_short = bytearray(_frame(tcp_good))[:14 + 20 + 12]  # TCP 首部被截断
    add("L4-TCP-SHORT", "L4", "截断在 TCP 首部，校验字段缺失；L3 仍可验",
        "COL-ING-01", tcp_short, cap_len=len(tcp_short), wire_len=len(_frame(tcp_good)))
    # 载荷缺口：TCP 头与校验字段都在，但分段尾部缺失 -> L3 可验、L4 只能 SH
    tcp_payload_gap = bytearray(_frame(tcp_good))[:-4]
    add("L4-TCP-PAYLOAD-GAP", "L4",
        "TCP 头与校验字段读得到，但载荷缺 4 字节：L3 可验、L4 覆盖范围不闭合判 SH",
        "COL-ING-01", tcp_payload_gap,
        cap_len=len(tcp_payload_gap), wire_len=len(_frame(tcp_good)))

    # --- L4 UDP（含合法 0 值语义） ---
    udp_good = _ipv4(PROTO_UDP, src, dst,
                     _udp_packet(payload=b"dns-query"))
    _finalize_l4(udp_good, PROTO_UDP)
    add("L4-UDP-OK", "L4", "UDP 校验和正确", "COL-ING-01", _frame(udp_good))
    udp_bad = bytearray(udp_good)
    udp_bad[-1] ^= 0x01
    add("L4-UDP-BAD", "L4", "UDP 载荷被改：L4 失配", "COL-ING-01",
        _frame(udp_bad))
    udp_zero = bytearray(udp_good)
    udp_zero[20 + 6:20 + 8] = b"\x00\x00"
    add("L4-UDP-ZERO-LEGAL", "L4",
        "UDP sum 为 0：IPv4 下表示发送方刻意不校验，任何方向都合法",
        "COL-ING-01", _frame(udp_zero))
    add("L4-UDP-ZERO-EGRESS", "L4",
        "UDP sum 为 0 且出向声明卸载：按设备未填写处理",
        "COL-EG-02", _frame(bytearray(udp_zero)))
    udp_short = bytearray(_frame(udp_good))[:14 + 20 + 6]  # 只剩 UDP 前 6 字节
    add("L4-UDP-SHORT", "L4",
        "能读到 src/dst/len 三个 UDP 字段，却读不到 checksum：字段可读≠完整",
        "COL-ING-01", udp_short, cap_len=len(udp_short), wire_len=len(_frame(udp_good)))

    # --- L4 ICMP ---
    icmp_good = _ipv4(PROTO_ICMP, src, dst, _icmp_packet())
    add("L4-ICMP-OK", "L4", "ICMP 校验和正确", "COL-ING-01", _frame(icmp_good))
    icmp_bad = bytearray(icmp_good)
    icmp_bad[14 + 20 + 2] ^= 0x0F
    add("L4-ICMP-BAD", "L4", "ICMP 校验字段被破坏", "COL-ING-01",
        _frame(icmp_bad))
    icmp_short = bytearray(_frame(icmp_good))[:14 + 20 + 2]
    add("L4-ICMP-SHORT", "L4", "截断在 ICMP 校验字段之前",
        "COL-ING-01", icmp_short, cap_len=len(icmp_short), wire_len=len(_frame(icmp_good)))

    return samples
