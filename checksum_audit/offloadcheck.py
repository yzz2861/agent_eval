"""离线抓包校验和声明引擎。

目标：把 Wireshark/tcpdump 常见的 "checksum incorrect" 提示，按采集点方向
（ingress/egress）与已知卸载（checksum offload）配置，区分为三类结论：

* verifiable_ok    —— 样本字节完整，字段由设备真实填写且重算一致；
* device_unfilled  —— 字段为卸载占位（出方向 0/伪头），本就不该期待已填；
* mismatch         —— 字段已填写且重算不一致，才是疑似篡改/损坏；
* insufficient     —— 样本字节不足，无法重算（注意区别于"字段读得到"）；
* not_present      —— 该层在本帧不存在（如纯 IPv6 无 IP 头校验和、无 FCS）。

每条结论都带字段在 *原始捕获字节* 中的 [start, end) 范围，支持回看 hex。
"""
from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass, field
from typing import Optional

from dpkt.dpkt import in_cksum


# ---- 结论词表 -------------------------------------------------------------

VERIFIABLE_OK = "verifiable_ok"
DEVICE_UNFILLED = "device_unfilled"
MISMATCH = "mismatch"
INSUFFICIENT = "insufficient"
NOT_PRESENT = "not_present"

L2_ETHERNET = "eth"
L3_IPV4 = "ipv4"
L4_TRANSPORT = "l4"

LAYER_ORDER = (L2_ETHERNET, L3_IPV4, L4_TRANSPORT)
LAYER_TITLES = {
    L2_ETHERNET: "以太网 FCS",
    L3_IPV4: "IPv4 首部校验和",
    L4_TRANSPORT: "传输层校验和 (TCP/UDP/ICMP)",
}

VERDICT_ZH = {
    VERIFIABLE_OK: "可校验·一致",
    DEVICE_UNFILLED: "设备未填写（卸载占位）",
    MISMATCH: "可校验·不一致",
    INSUFFICIENT: "样本字节不足",
    NOT_PRESENT: "本层不存在",
}

# 报告模块使用的别名
STATUS_LABEL = VERDICT_ZH


@dataclass
class CollectorDecl:
    """假采集器声明：采集点方向 + 已知卸载配置 + 是否保留以太网 FCS。"""

    name: str
    direction: str  # "ingress" | "egress"
    tx_ip_offload: bool
    tx_l4_offload: bool
    keeps_eth_fcs: bool
    note: str = ""

    @property
    def tx_offload(self) -> bool:
        """任一传输层/IP 层 TX 卸载开启即视为存在卸载占位。"""
        return self.tx_ip_offload or self.tx_l4_offload


@dataclass
class LayerVerdict:
    layer: str
    verdict: str
    field: Optional[str]          # 字段名，如 ip.sum / tcp.sum
    wire_range: Optional[tuple]   # 原始字节 [start, end)，含越界部分的声明范围
    have_range: Optional[tuple]   # 样本中实际读到的字节范围
    stored: Optional[int]         # 字段现值（不足时为已读到的部分或 None）
    expected: Optional[int]       # 重算期望值
    reason: str

    def to_dict(self) -> dict:
        return {
            "layer": self.layer,
            "verdict": self.verdict,
            "verdict_zh": VERDICT_ZH[self.verdict],
            "field": self.field,
            "wire_range": list(self.wire_range) if self.wire_range else None,
            "have_range": list(self.have_range) if self.have_range else None,
            "stored": None if self.stored is None else "0x%04x" % self.stored,
            "expected": None if self.expected is None else "0x%04x" % self.expected,
            "reason": self.reason,
        }


@dataclass
class FrameAudit:
    frame_id: str
    collector: str
    cap_len: int
    wire_len: int
    truncated: bool
    name: str = ""
    note: str = ""
    verdicts: list = field(default_factory=list)

    def get(self, layer: str) -> Optional[LayerVerdict]:
        for verdict in self.verdicts:
            if verdict.layer == layer:
                return verdict
        return None

    def to_dict(self) -> dict:
        return {
            "frame_id": self.frame_id,
            "name": self.name,
            "note": self.note,
            "collector": self.collector,
            "cap_len": self.cap_len,
            "wire_len": self.wire_len,
            "truncated": self.truncated,
            "layers": [v.to_dict() for v in self.verdicts],
        }


# ---- 校验和原语 -----------------------------------------------------------

def _csum(buf: bytes) -> int:
    """RFC 1071 互联网校验和（字段位置先置 0 后调用）。"""
    return in_cksum(buf)


def _pseudo_v4(src: bytes, dst: bytes, proto: int, seg_len: int) -> bytes:
    return struct.pack("!4s4sBBH", src, dst, 0, proto, seg_len)


def _fcs(frame_without_fcs: bytes) -> int:
    """以太网 FCS：CRC-32（与网卡硬件一致，初值/结果异或全 1）。"""
    return binascii.crc32(frame_without_fcs) & 0xFFFFFFFF


# ---- 分层判定 -------------------------------------------------------------

def _audit_eth(sample: bytes, wire_len: int, decl: CollectorDecl) -> LayerVerdict:
    """L2 FCS。常规抓包点在 MAC 之后，FCS 已被驱动剥离 -> not_present。"""
    if not decl.keeps_eth_fcs:
        return LayerVerdict(
            "eth", NOT_PRESENT, "eth.fcs", None, None, None, None,
            "采集点在 MAC 与驱动之间，FCS 已被网卡/驱动剥离，样本中不存在该字段",
        )
    declared = (wire_len - 4, wire_len)
    if len(sample) < wire_len:
        have = (declared[0], min(declared[1], len(sample)))
        return LayerVerdict(
            "eth", INSUFFICIENT, "eth.fcs", declared,
            have if have[0] < have[1] else None, None, None,
            "采集声明保留 FCS，但样本在 FCS 字段处截断，4 字节未取全",
        )
    stored = struct.unpack("!I", sample[declared[0]:declared[1]])[0]
    expected = _fcs(sample[: declared[0]])
    verdict = VERIFIABLE_OK if stored == expected else MISMATCH
    reason = (
        "对完整帧重算 CRC-32 一致"
        if verdict == VERIFIABLE_OK
        else "FCS 已填写但与重算 CRC-32 不一致，链路层损坏或被篡改"
    )
    return LayerVerdict(
        "eth", verdict, "eth.fcs", declared, declared, stored, expected, reason
    )


def _audit_ipv4(sample: bytes, ip_off: int, decl: CollectorDecl) -> tuple:
    """返回 (LayerVerdict, 解析信息 dict)。IP 头校验和只覆盖头部。"""
    if len(sample) < ip_off + 20:
        return LayerVerdict(
            "ipv4", INSUFFICIENT, "ip.sum", (ip_off + 10, ip_off + 12),
            (ip_off, min(len(sample), ip_off + 20)) if len(sample) > ip_off else None,
            None, None,
            "IP 固定头 20 字节未取全，头校验和无法重算",
        ), None

    ihl = sample[ip_off] & 0x0F
    hdr_len = ihl * 4
    sum_off = ip_off + 10
    declared = (sum_off, sum_off + 2)
    if len(sample) < ip_off + hdr_len:
        return LayerVerdict(
            "ipv4", INSUFFICIENT, "ip.sum", declared,
            (ip_off, len(sample)), None, None,
            "IHL 声明 %d 字节头部，但样本在选项区截断" % hdr_len,
        ), None

    stored = struct.unpack("!H", sample[sum_off:sum_off + 2])[0]
    header = bytearray(sample[ip_off:ip_off + hdr_len])
    header[10:12] = b"\x00\x00"
    expected = _csum(bytes(header))

    info = {
        "ip_off": ip_off,
        "hdr_len": hdr_len,
        "proto": sample[ip_off + 9],
        "src": sample[ip_off + 12:ip_off + 16],
        "dst": sample[ip_off + 16:ip_off + 20],
        "total_len": struct.unpack("!H", sample[ip_off + 2:ip_off + 4])[0],
    }

    if stored == 0 and decl.direction == "egress" and decl.tx_ip_offload:
        return LayerVerdict(
            "ipv4", DEVICE_UNFILLED, "ip.sum", declared, declared, 0, expected,
            "出方向且声明 TX IP 校验卸载，0 是 NIC 接管前的占位，不是篡改",
        ), info
    verdict = VERIFIABLE_OK if stored == expected else MISMATCH
    reason = (
        "头部完整，重算 RFC1071 校验和一致"
        if verdict == VERIFIABLE_OK
        else "IP 头校验和已填写但重算不一致，头部被改动或损坏"
    )
    return LayerVerdict(
        "ipv4", verdict, "ip.sum", declared, declared, stored, expected, reason
    ), info


def _audit_l4(sample: bytes, info: dict, decl: CollectorDecl) -> LayerVerdict:
    proto = info["proto"]
    if proto not in (6, 17, 1):
        return LayerVerdict(
            "l4", NOT_PRESENT, None, None, None, None, None,
            "proto=%d 非 TCP/UDP/ICMP，本工具不声明其传输层校验" % proto,
        )

    l4_off = info["ip_off"] + info["hdr_len"]
    name = {6: "tcp", 17: "udp", 1: "icmp"}[proto]
    field = "%s.sum" % name
    min_hdr = 8 if proto == 17 else (8 if proto == 6 else 8)

    # 传输层校验和覆盖"伪头 + 整个分段"。分段长度取 IP total_len - IP 头长，
    # 这是线上应有的完整长度；样本若更短即为缺口。
    seg_len = info["total_len"] - info["hdr_len"]
    seg_end = l4_off + seg_len
    if proto == 6:
        declared = (l4_off + 16, l4_off + 18)   # TCP 校验和在第 8 个 16 位字
    elif proto == 17:
        declared = (l4_off + 6, l4_off + 8)     # UDP 校验和
    else:
        declared = (l4_off + 2, l4_off + 4)     # ICMP 校验和

    if len(sample) < l4_off + min_hdr:
        return LayerVerdict(
            "l4", INSUFFICIENT, field, declared,
            (l4_off, len(sample)) if len(sample) > l4_off else None,
            None, None,
            "%s 头部未取全，校验和字段本身都读不完整" % name.upper(),
        )
    if len(sample) < seg_end:
        # 关键字段（UDP 长度/端口等）读得到，但载荷缺口使覆盖范围无法闭合。
        field_bytes = sample[declared[0]:declared[1]]
        partial_stored = struct.unpack("!H", field_bytes)[0] if len(field_bytes) == 2 else None
        return LayerVerdict(
            "l4", INSUFFICIENT, field, declared,
            (l4_off, len(sample)),
            partial_stored, None,
            "字段可读，但校验和覆盖 %d 字节分段，样本仅覆盖到第 %d 字节；"
            "读到 UDP/TCP 头部不等于分段完整，不能据此判篡改"
            % (seg_len, len(sample) - l4_off),
        )

    stored = struct.unpack("!H", sample[declared[0]:declared[1]])[0]
    segment = bytearray(sample[l4_off:seg_end])
    csum_pos = 16 if proto == 6 else (2 if proto == 1 else 6)
    segment[csum_pos:csum_pos + 2] = b"\x00\x00"

    if proto == 17:
        # IPv4 上 UDP 校验和 0 表示"发送方省略"，属合法已填写语义。
        if stored == 0 and not (decl.direction == "egress" and decl.tx_l4_offload):
            return LayerVerdict(
                "l4", VERIFIABLE_OK, field, declared, declared, 0, 0,
                "UDP 校验和为 0 是 IPv4 合法的'发送方省略'，设备已显式填写该语义",
            )
        covered = _pseudo_v4(info["src"], info["dst"], 17, seg_len) + bytes(segment)
    elif proto == 6:
        covered = _pseudo_v4(info["src"], info["dst"], 6, seg_len) + bytes(segment)
    else:
        covered = bytes(segment)  # ICMP 无伪头
    expected = _csum(covered)

    if stored == 0 and decl.direction == "egress" and decl.tx_l4_offload:
        return LayerVerdict(
            "l4", DEVICE_UNFILLED, field, declared, declared, 0, expected,
            "出方向且声明 TX 传输层校验卸载，0 为 NIC 接管前占位，"
            "Wireshark 的 incorrect 提示在此场景应判设备未填写",
        )
    verdict = VERIFIABLE_OK if stored == expected else MISMATCH
    reason = (
        "分段完整，伪头+分段重算一致"
        if verdict == VERIFIABLE_OK
        else "字段已填写且分段完整，重算不一致，疑似载荷被篡改或损坏"
    )
    return LayerVerdict(
        "l4", verdict, field, declared, declared, stored, expected, reason
    )


def audit_frame(frame_id: str, sample: bytes, wire_len: int,
                decl: CollectorDecl) -> FrameAudit:
    """对一帧（可能被截断的样本）给出分层校验声明。"""
    result = FrameAudit(
        frame_id=frame_id,
        collector=decl.name,
        cap_len=len(sample),
        wire_len=wire_len,
        truncated=len(sample) < wire_len,
    )
    result.verdicts.append(_audit_eth(sample, wire_len, decl))

    eth_hdr = 14
    if len(sample) < eth_hdr + 20:
        result.verdicts.append(LayerVerdict(
            "ipv4", INSUFFICIENT, "ip.sum", (eth_hdr + 10, eth_hdr + 12),
            (eth_hdr, len(sample)) if len(sample) > eth_hdr else None,
            None, None, "以太网载荷不足，IP 头未取全",
        ))
        result.verdicts.append(LayerVerdict(
            "l4", NOT_PRESENT, None, None, None, None, None,
            "IP 层不可解析，传输层声明无法建立",
        ))
        return result

    ip_verdict, info = _audit_ipv4(sample, eth_hdr, decl)
    result.verdicts.append(ip_verdict)
    if info is None:
        result.verdicts.append(LayerVerdict(
            "l4", INSUFFICIENT, None, None, None, None, None,
            "IP 头不完整，无法定位传输层",
        ))
    else:
        result.verdicts.append(_audit_l4(sample, info, decl))
    return result
