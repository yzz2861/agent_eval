"""生成复盘场景的两个采集点 pcap，供 CLI 端到端演示。

场景：有人声称 svc-a 与 svc-b 一直指向同一组地址；两个采集点里
存在同号 txid，其中 edge_b 上同号的回答并不是 edge_a 那次请求的来源。
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from pcap_builder import (  # noqa: E402
    a_rr,
    cname_rr,
    dns_question,
    dns_response,
    exchange_packets,
    write_pcap,
)


def build(out_dir: str):
    # edge_a：同号 txid 0x1234 的正常问答，两个名字在观察窗内地址集合不同
    edge_a = []
    edge_a += exchange_packets(
        0x1234, 'svc-a.example.',
        [a_rr('svc-a.example.', '10.0.0.1'), a_rr('svc-a.example.', '10.0.0.2')],
        t0=100.0, client_port=40000,
    )
    edge_a += exchange_packets(
        0x1235, 'svc-b.example.', [a_rr('svc-b.example.', '10.0.0.2')],
        t0=101.0, client_port=40001,
    )
    # 一条看不全的 CNAME 链（终点地址不在本采集点窗口内）
    edge_a += exchange_packets(
        0x1236, 'portal.example.',
        [cname_rr('portal.example.', 'portal.cdn.example.')],
        t0=102.0, client_port=40002,
    )

    # edge_b：复用了相同 txid 0x1234，但问题/回答属于另一个采集域；
    # 另外放一个没有对应问题的孤立回答，验证不会被跨点“认领”
    edge_b = []
    edge_b += exchange_packets(
        0x1234, 'svc-a.example.', [a_rr('svc-a.example.', '198.51.100.20')],
        t0=100.0, client_port=40000,
    )
    orphan_q = dns_question('svc-b.example.')
    edge_b.append(
        (103.0,
         dns_response(0x1235, [orphan_q], [a_rr('svc-b.example.', '10.0.0.2')]),
         False, 53, 40001),
    )

    path_a = write_pcap(os.path.join(out_dir, 'edge_a.pcap'), edge_a)
    path_b = write_pcap(os.path.join(out_dir, 'edge_b.pcap'), edge_b)
    return path_a, path_b


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    print('\n'.join(build(out_dir)))
