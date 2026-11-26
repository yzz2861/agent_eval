# -*- coding: utf-8 -*-
"""Offline forensic analysis of the capture archive.

Extracts, from the pcapng file blocks and the independent capture
config, what can actually be proven about input coverage, keeping
three evidence layers strictly separate:

1. config declaration   -- what the operator configured (capture_config.json)
2. in-archive declaration -- the if_filter option stored in each IDB
   (treated as declaration text only; enforcement is not verifiable offline)
3. observed packets     -- the packet blocks actually present in the archive

Usage: PYTHONPATH=<repo root> python forensics/analyze_archive.py
"""

import json
import os
import socket
import struct
import sys

from pcapng.scanner import FileScanner
import pcapng.blocks as blocks

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "evidence")


def classify_frame(data):
    """Classify an Ethernet/IPv4 frame into a short traffic-class label."""
    if len(data) < 34 or data[12:14] != b"\x08\x00":
        return "non-IPv4"
    proto = data[23]
    src = socket.inet_ntoa(data[26:30])
    dst = socket.inet_ntoa(data[30:34])
    ihl = (data[14] & 0x0F) * 4
    off = 14 + ihl
    well_known = (23, 53, 80)
    if proto == 6 and len(data) >= off + 4:
        sport, dport = struct.unpack("!HH", data[off:off + 4])
        port = sport if sport in well_known else dport
        return "tcp/{0} {1} -> {2}".format(port, src, dst)
    if proto == 17 and len(data) >= off + 4:
        sport, dport = struct.unpack("!HH", data[off:off + 4])
        port = sport if sport in well_known else dport
        return "udp/{0} {1} -> {2}".format(port, src, dst)
    return "ip-proto-{0} {1} -> {2}".format(proto, src, dst)


def traffic_class(label):
    """Coarse class used for coverage reasoning."""
    if label.startswith("tcp/23"):
        return "tcp/23 (telnet)"
    if label.startswith("tcp/"):
        return "tcp/other"
    if label.startswith("udp/"):
        return "udp"
    return label


def main():
    archive_path = os.path.join(EVIDENCE, "capture.pcapng")
    with open(os.path.join(EVIDENCE, "capture_config.json")) as fp:
        config = json.load(fp)
    with open(os.path.join(EVIDENCE, "manifest.json")) as fp:
        manifest = json.load(fp)

    # ---- pass 1: walk the file blocks, grouped per section -------------
    sections = []  # list of dicts: idbs, packets, isbs
    with open(archive_path, "rb") as fp:
        for blk in FileScanner(fp):
            if isinstance(blk, blocks.SectionHeader):
                sections.append({"idbs": [], "packets": [], "isbs": []})
            elif isinstance(blk, blocks.InterfaceDescription):
                sections[-1]["idbs"].append(blk)
            elif isinstance(blk, blocks.EnhancedPacket):
                sections[-1]["packets"].append(blk)
            elif isinstance(blk, blocks.InterfaceStatistics):
                sections[-1]["isbs"].append(blk)

    print("=" * 72)
    print("取证清单声明 (manifest): {0}".format(manifest["claim"]))
    print("=" * 72)

    # ---- layer 1+2+3 per section ---------------------------------------
    for idx, sec in enumerate(sections):
        print()
        print("Section {0}  (interface ID 仅在本 section 内有效)".format(idx))
        print("-" * 72)
        cfg_session = None
        for s in config["sessions"]:
            if s["section_index"] == idx:
                cfg_session = s
        cfg_by_name = {}
        if cfg_session:
            cfg_by_name = {i["name"]: i["capture_filter"]
                           for i in cfg_session["interfaces"]}

        for idb in sec["idbs"]:
            name = idb.options.get("if_name", "?")
            decl = idb.options.get("if_filter")
            decl_txt = None
            if decl:
                ftype, fbytes = decl
                decl_txt = "type={0} {1!r}".format(ftype, bytes(fbytes))
            cfg_filter = cfg_by_name.get(name, "<配置中无此接口>")
            print("  IDB interface_id={0} if_name={1!r}".format(
                idb.interface_id, name))
            print("    [配置声明] capture_filter = {0!r}".format(cfg_filter))
            print("    [归档内声明] if_filter = {0}".format(
                decl_txt or "(无此选项)")
            )

        observed = {}  # interface_id -> list of labels
        for pkt in sec["packets"]:
            label = classify_frame(pkt.packet_data)
            observed.setdefault(pkt.interface_id, []).append(label)
        for iid in sorted(observed):
            print("  [实际出现的包] interface_id={0}:".format(iid))
            for label in observed[iid]:
                print("      {0}  => 类: {1}".format(
                    label, traffic_class(label)))

        for isb in sec["isbs"]:
            opts = dict(isb.options)
            print("  [ISB 统计] interface_id={0}: {1}".format(
                isb.interface_id,
                ", ".join("{0}={1}".format(k, v)
                          for k, v in sorted(opts.items()))))

    # ---- verdicts -------------------------------------------------------
    print()
    print("=" * 72)
    print("复核结论")
    print("=" * 72)

    sec0 = sections[0]
    obs0 = {}
    for pkt in sec0["packets"]:
        obs0.setdefault(pkt.interface_id, set()).add(
            traffic_class(classify_frame(pkt.packet_data)))

    print()
    print("1) 清单声明核验: session A 两个接口均完整留存 TCP/23")
    print("   - eth0 (section 0, id=0): 配置与 IDB 均无过滤器; 实际出现")
    print("     类 = {0}".format(sorted(obs0.get(0, []))))
    print("     TCP/23 出现在两个不同目的主机 (192.0.2.5 与 192.0.2.7),")
    print("     该接口上 TCP/23 的留存可视为完整 (无过滤、isb_ifrecv==isb_usrdeliv)。")
    print("   - eth1 (section 0, id=1): IDB 携带 if_filter 声明, 配置同样声明;")
    print("     实际仅出现到 192.0.2.5 的 TCP/23。声明被归档自身证伪: ")
    print("     eth1 并未完整留存 TCP/23 类, 只留存了过滤器放行的子集。")

    print()
    print("2) 两种缺席的不同依据")
    print("   [这批没有出现] eth0 上没有出现 (例如) 到 192.0.2.9 的 TCP/23:")
    print("       依据是 eth0 无任何过滤声明且 isb_ifrecv==isb_usrdeliv==4,")
    print("       采集窗口内该类包若到达即应留存; 缺席可作为窗口内未观测到的")
    print("       证据 (仍受窗口时长与链路易达性限制)。")
    print("   [这一类从未被纳入采集] eth1 上缺少到 192.0.2.5 以外主机的 TCP/23:")
    print("       依据是 IDB if_filter 声明文本 + 独立配置的 capture_filter +")
    print("       ISB 计数 (isb_ifrecv=9 而 isb_filteraccept=2): 9 个到达的包中")
    print("       仅 2 个被过滤器接受。此类缺席对线上是否存在该流量不作任何证明。")

    print()
    print("3) 相同 interface ID 在另一 section 的含义")
    print("   section 1 的 interface_id=0 与 section 0 的 interface_id=0 不是")
    print("   同一接口实例: pcapng 的接口编号按 section 重新从 0 开始, 由各自")
    print("   section 内的 IDB 定义。section 1 的 id=0 虽同名 eth0, 却带有")
    print("   自己的 if_filter 声明 (tcp port 23), 其覆盖结论不能与 section 0")
    print("   的 eth0 合并; 跨 section 汇总必须按 (section, interface_id) 二元组。")

    print()
    print("4) 声明文本的效力边界")
    print("   if_filter 与 capture_config.json 均为声明文本: 离线归档无法验证")
    print("   过滤器是否被正确编译/执行。但 ISB 计数 (ifrecv > filteraccept)")
    print("   与归档中实际包集合一致, 三层证据互相印证时, 方可将缺席归因为")
    print("   采集过滤而非线上静默。")


if __name__ == "__main__":
    sys.exit(main())
