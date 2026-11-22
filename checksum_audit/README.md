# checksum_audit

离线抓包校验和声明工具。把 Wireshark/tcpdump 的 checksum incorrect 提示，
按采集点方向与已知 checksum offload 配置，拆成可回看原始字节范围的分层声明，
避免值班同事把卸载占位误判为篡改。

## 判定口径

- verifiable_ok：字段与重算覆盖范围都在样本内，且重算一致。
- mismatch：字段已填写、范围完整，但重算不一致（真正的篡改/损坏候选）。
- device_unfilled：egress 且该层声明了 TX 卸载，字段为 0 的 NIC 占位。
- insufficient：字段或重算所需字节落在 cap_len 之外；读到 UDP/TCP 头部
  不等于该层可验，L4 覆盖伪首部加整个分段，载荷缺口只能判不足。
- not_present：该抓包点没有这一层字段（如驱动已剥离以太网 FCS）。

每条结论带字段在原始捕获字节中的半开区间 [start, end)，并区分线上声明范围
与样本实得范围，支持回看 hex。

## 运行

    python3 -m checksum_audit.run       # 生成 out/ 下 pcap、verdicts.json、report.md
    python3 -m checksum_audit.selfcheck # 断言 23 条合成样本的分层判定

## 模块

- offloadcheck.py：分层判定引擎（L2 FCS / IPv4 头 / TCP、UDP、ICMP）。
- build_samples.py：三个假采集器声明与本地合成包。
- cases.py：把合成样本适配为引擎输入。
- report.py：单份 Markdown 报告渲染。
