# 方向归属核对报告

与可信镜像端口台账直接冲突的方向主张: R-B。
- R-B: 主张 outbound；冲突证据 probe_b.pcap#1。
同一 MAC 出现在不同采集点: 02:11:22:33:44:55；必须按采集点/台账分别归属，不能全局贴同一方向。
截断帧已保留原始链路字节和长度差异，MAC 缺失时只能作证据不足处理: truncated_header#1。
外层 VLAN/QinQ 标签已单独保留；VLAN 不一致属于台账或捕获范围冲突。

## 帧证据

| 证据 | 采集点 | 源MAC | 目的MAC | 外层VLAN | 可能方向 | 截断 |
|---|---|---|---|---:|---|---|
| probe_a.pcap#1 | probe_a | 02:11:22:33:44:55 | 02:aa:bb:cc:dd:ee | 100 | outbound | no |
| probe_b.pcap#1 | probe_b | 02:11:22:33:44:55 | 02:cc:dd:ee:ff:00 | 200 | inbound | no |
| truncated_header#1 | probe_a | 02:11:22:33:44:55 | 02:aa:bb:cc:dd:ee | None | outbound | yes |

## 主张核对

| 主张 | 方向 | 状态 | 直接冲突 | 冲突证据 |
|---|---|---|---|---|
| R-A | outbound | supported | no |  |
| R-B | outbound | conflict | yes | probe_b.pcap#1 |
| R-TRUNC | outbound | supported | no |  |
