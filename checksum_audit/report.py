# -*- coding: utf-8 -*-
"""Render layered checksum declarations into one Markdown report."""
from __future__ import annotations

from .offloadcheck import LAYER_ORDER, LAYER_TITLES, STATUS_LABEL

MATRIX_MARK = {
    "verifiable_ok": "OK",
    "mismatch": "XX",
    "device_unfilled": "UN",
    "insufficient": "SH",
    "not_present": "--",
}


def _hex(value, width):
    if value is None:
        return "—"
    return ("0x%0" + str(width) + "x") % value


def _range_text(verdict):
    if verdict.wire_range is None:
        return "无对应字段"
    start, end = verdict.wire_range
    text = "原始字节 [%d, %d)" % (start, end)
    if verdict.have_range and verdict.have_range != verdict.wire_range:
        text += "，样本实得 [%d, %d)" % verdict.have_range
    return text


def _collector_section(collectors):
    lines = ["## 1. 采集点（假采集器）声明", ""]
    lines.append("| 采集器 | 方向 | 保留 FCS | TX IPv4 卸载 | TX L4 卸载 | 说明 |")
    lines.append("|---|---|---|---|---|---|")
    for decl in collectors.values():
        lines.append("| `%s` | %s | %s | %s | %s | %s |" % (
            decl.name, decl.direction,
            "是" if decl.keeps_eth_fcs else "否",
            "是" if decl.tx_ip_offload else "否",
            "是" if decl.tx_l4_offload else "否",
            decl.note))
    lines.append("")
    return lines


def _criteria_section():
    return [
        "## 2. 判定口径（三态 + 两个辅助态）",
        "",
        "- 可校验：字段字节与重算覆盖范围全部在样本内；再分 OK（一致）与 XX（不一致，才是篡改/损坏候选）。",
        "- 设备未填写 UN：egress 且该层声明了 TX 卸载，字段读到 0；这是 NIC 接管前占位，不是篡改。",
        "- 样本字节不足 SH：字段或重算所需字节落在 cap_len 之外；读到 UDP/TCP 头部不代表该层可验。",
        "- 不存在 --：该抓包点没有这一层校验字段（如驱动已剥离 FCS）。",
        "",
        "截断只影响真实可验的层次：IP 头校验仅覆盖 IP 头，头完整即可验；L4 校验覆盖伪首部加整个分段，载荷缺口只能判 SH。",
        "",
    ]

def _matrix_section(audits):
    lines = ["## 3. 差分矩阵（差分出现在每一层）", ""]
    head = "| # | 样本 | 采集器 | cap/wire | " + " | ".join(LAYER_TITLES[l] for l in LAYER_ORDER) + " |"
    lines.append(head)
    lines.append("|" + "---|" * (4 + len(LAYER_ORDER)))
    for audit in audits:
        by_layer = {v.layer: v for v in audit.verdicts}
        marks = [MATRIX_MARK.get(by_layer[l].verdict, "--") for l in LAYER_ORDER]
        lines.append("| %d | `%s` | `%s` | %d/%d | %s |" % (
            audit.frame_id, audit.name, audit.collector,
            audit.cap_len, audit.wire_len, " | ".join(marks)))
    lines.append("")
    lines.append("标记：OK 可校验且一致；XX 可校验但不一致；UN 设备未填写（卸载占位）；SH 样本字节不足；-- 本层不存在。")
    lines.append("")
    return lines


def _detail_section(audits):
    lines = ["## 4. 逐帧分层声明（含原始字节范围）", ""]
    for audit in audits:
        gap = "" if not audit.truncated else "，缺口 %d 字节" % (audit.wire_len - audit.cap_len)
        lines.append("### 4.%d `%s` — %s" % (audit.frame_id, audit.name, audit.note))
        lines.append("")
        lines.append("- 采集器 `%s`；wire_len=%d，cap_len=%d%s。" % (
            audit.collector, audit.wire_len, audit.cap_len, gap))
        lines.append("")
        lines.append("| 层 | 判定 | 原始范围 | 线上值 | 重算期望 | 依据 |")
        lines.append("|---|---|---|---|---|---|")
        for verdict in audit.verdicts:
            width = 8 if verdict.layer == "eth" else 4
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                LAYER_TITLES[verdict.layer],
                STATUS_LABEL[verdict.verdict],
                _range_text(verdict),
                _hex(verdict.stored, width),
                _hex(verdict.expected, width),
                verdict.reason))
        lines.append("")
    return lines


def _replay_section(pcap_path):
    return [
        "## 5. 回放与复核",
        "",
        "- 截断后的实际样本已写入 `%s`（DLT_EN10MB）。" % pcap_path,
        "- 复核：`tcpdump -nn -vv -r %s`，或用 dpkt 重读后调用 `offloadcheck.audit_frame`。" % pcap_path,
        "- 范围为相对帧缓冲的半开区间 [start, end)；范围超出 cap_len 的层只给 SH，不下校验结论。",
        "",
    ]


def render(collectors, audits, pcap_path):
    lines = [
        "# 离线抓包校验和声明审计报告",
        "",
        "本报告基于 dpkt %s 离线生成，把抓包软件的 checksum incorrect 提示拆成可回看的分层声明，避免把采集点卸载导致的设备未填写误判为篡改。" % __import__("dpkt").__version__,
        "",
    ]
    lines += _collector_section(collectors)
    lines += _criteria_section()
    lines += _matrix_section(audits)
    lines += _detail_section(audits)
    lines += _replay_section(pcap_path)
    return chr(10).join(lines)
